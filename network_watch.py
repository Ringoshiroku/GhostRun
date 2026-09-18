import json
import os
import shutil
import socket
import subprocess

TELEGRAM_IP_RANGES = [
    ("149.154.0.0", "149.154.255.255"),
    ("91.108.0.0", "91.108.255.255"),
]
DISCORD_DOMAINS = ["discord.com", "discordapp.com", "discord.gg", "gateway.discord.gg"]
DISCORD_IP_PREFIX = ["162.159.", "104.16.", "104.17."]


def ip_to_int(ip):
    try:
        return int.from_bytes(socket.inet_aton(ip), "big")
    except Exception:
        return None


def ip_in_range(ip, start, end):
    ip_i = ip_to_int(ip)
    if ip_i is None:
        return False
    return ip_to_int(start) <= ip_i <= ip_to_int(end)


def infer_service(domain_hits, remote_ip, remote_port):
    if remote_port == 443:
        for start, end in TELEGRAM_IP_RANGES:
            if ip_in_range(remote_ip, start, end):
                return {"service": "Telegram", "confidence": "medium", "domains": list(domain_hits)}

    for d in domain_hits:
        for sig in DISCORD_DOMAINS:
            if sig in d.lower():
                return {"service": "Discord", "confidence": "high", "domains": list(domain_hits)}

    for prefix in DISCORD_IP_PREFIX:
        if remote_ip and remote_ip.startswith(prefix) and remote_port == 443:
            return {"service": "Discord", "confidence": "medium", "domains": list(domain_hits)}

    return None


def parse_eve_line(line):
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return None

    if not isinstance(raw, dict):
        return None

    event_type = raw.get("event_type")
    base = {
        "event_type": event_type,
        "src_ip": raw.get("src_ip"),
        "dest_ip": raw.get("dest_ip"),
        "dest_port": raw.get("dest_port"),
    }

    if event_type == "dns":
        dns = raw.get("dns", {})
        if dns.get("type") != "query":
            return None
        base.update({"query_name": dns.get("rrname"), "query_type": dns.get("rrtype")})
        return base

    if event_type == "tls":
        tls = raw.get("tls", {})
        base.update({
            "sni": tls.get("sni"),
            "ja3": (tls.get("ja3") or {}).get("hash"),
            "ja3s": (tls.get("ja3s") or {}).get("hash"),
        })
        return base

    if event_type == "http":
        http = raw.get("http", {})
        base.update({
            "hostname": http.get("hostname"),
            "url": http.get("url"),
            "user_agent": http.get("http_user_agent"),
        })
        return base

    if event_type == "flow":
        flow = raw.get("flow", {})
        base.update({
            "start": flow.get("start"),
            "end": flow.get("end"),
            "pkts_toserver": flow.get("pkts_toserver"),
            "pkts_toclient": flow.get("pkts_toclient"),
        })
        return base

    return None


def parse_eve_file(path):
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parsed = parse_eve_line(line)
            if parsed is not None:
                events.append(parsed)
    return events


# events from the capture pipeline that mean real network activity happened.
# capture_unavailable and capture_failed are excluded: they're degradation
# notices, not activity. network_finding_engine's own derived
# malware_network_activity output is excluded too.
# downstream detectors use this list instead of hardcoding event names, so
# renaming an event here can't silently break them.
CAPTURE_ACTIVITY_EVENTS = frozenset({
    "dns_query", "tls_connection", "http_request", "flow_summary",
})
CAPTURE_CONNECTION_EVENTS = frozenset({
    "tls_connection", "http_request", "flow_summary",
})


_JA3_PIVOT_NOTE = (
    "Pivotable indicator only; TLS fingerprints are randomizable and not "
    "a standalone confidence signal."
)

# pid is a capture-wide stamp, not per-process attribution: dumpcap captures
# the whole VM. every emitted event carries this disclaimer alongside pid.
_PID_ATTRIBUTION_NOTE = (
    "capture-derived; stamped with the analysis root PID, not per-process attributed"
)


def emit_network_evidence(events, emit_func, root_pid=None):
    for event in events:
        if event["event_type"] == "dns":
            emit_func("network_behavior", "dns_query", {
                "query_name": event["query_name"], "query_type": event["query_type"],
                "src_ip": event["src_ip"], "dest_ip": event["dest_ip"],
                "dest_port": event["dest_port"],
                "pid": root_pid, "pid_attribution": _PID_ATTRIBUTION_NOTE,
            })
        elif event["event_type"] == "tls":
            data = {
                "src_ip": event["src_ip"],
                "dest_ip": event["dest_ip"], "dest_port": event["dest_port"],
                "sni": event["sni"],
                "ja3_pivot": {"ja3": event["ja3"], "ja3s": event["ja3s"], "note": _JA3_PIVOT_NOTE},
                "pid": root_pid, "pid_attribution": _PID_ATTRIBUTION_NOTE,
            }
            service_info = infer_service({event["sni"]} if event["sni"] else set(), event["dest_ip"], event["dest_port"])
            if service_info:
                data.update(service_info)
            emit_func("network_behavior", "tls_connection", data)
        elif event["event_type"] == "http":
            emit_func("network_behavior", "http_request", {
                "src_ip": event["src_ip"],
                "dest_ip": event["dest_ip"], "dest_port": event["dest_port"],
                "hostname": event["hostname"],
                "url": event["url"], "user_agent": event["user_agent"],
                "pid": root_pid, "pid_attribution": _PID_ATTRIBUTION_NOTE,
            })
        elif event["event_type"] == "flow":
            emit_func("network_behavior", "flow_summary", {
                "src_ip": event["src_ip"],
                "dest_ip": event["dest_ip"], "dest_port": event["dest_port"],
                "start": event["start"], "end": event["end"],
                "pkts_toserver": event["pkts_toserver"], "pkts_toclient": event["pkts_toclient"],
                "pid": root_pid, "pid_attribution": _PID_ATTRIBUTION_NOTE,
            })


class NetworkCapture:
    def __init__(self, pcap_path, eve_log_dir, emit_func, sslkeylogfile_path=None, root_pid=None,
                 exclude_host=None, exclude_port=None):
        self.pcap_path = pcap_path
        self.eve_log_dir = eve_log_dir
        self.emit = emit_func
        self.sslkeylogfile_path = sslkeylogfile_path
        self.root_pid = root_pid
        # excluded from capture so GhostRun's own evidence-sender traffic to the
        # receiver isn't mistaken for the sample's own C2 traffic. Suricata would
        # otherwise parse it as real http/flow events and stamp it with root_pid
        # like any other traffic.
        self.exclude_host = exclude_host
        self.exclude_port = exclude_port
        self._proc = None
        self._tools_available = bool(shutil.which("dumpcap")) and bool(shutil.which("suricata"))

    @property
    def tools_available(self):
        return self._tools_available

    def start(self):
        if not self._tools_available:
            return
        cmd = ["dumpcap", "-w", self.pcap_path, "-q"]
        if self.exclude_host:
            filter_parts = f"not (host {self.exclude_host}"
            if self.exclude_port:
                filter_parts += f" and tcp port {self.exclude_port}"
            filter_parts += ")"
            cmd += ["-f", filter_parts]
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def stop_and_analyze(self):
        # any exception below must turn into a logged evidence event, never
        # propagate. this runs before ghostrun.py writes the local evidence backup,
        # so an unhandled exception here used to destroy all evidence from the
        # whole analysis run.
        try:
            self._stop_and_analyze()
        except Exception as exc:
            self.emit("network_behavior", "capture_failed", {
                "reason": f"{type(exc).__name__}: {exc}",
                "pid": self.root_pid,
            })

    def _stop_and_analyze(self):
        if not self._tools_available:
            self.emit("network_behavior", "capture_unavailable", {
                "reason": "dumpcap and/or suricata not found on PATH",
                "pid": self.root_pid,
            })
            return

        if self._proc is not None:
            self._proc.terminate()
            self._proc.wait(timeout=10)

        env = os.environ.copy()
        if self.sslkeylogfile_path:
            env["SSLKEYLOGFILE"] = self.sslkeylogfile_path

        result = subprocess.run(
            [
                "suricata", "-r", self.pcap_path, "-l", self.eve_log_dir, "-k", "none",
                "--set", "app-layer.protocols.tls.ja3-fingerprints=yes",
                "--set", "app-layer.protocols.tls.ja4-fingerprints=yes",
            ],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=120,
        )

        if result.returncode != 0:
            stderr_tail = (result.stderr or "")[-2000:]
            self.emit("network_behavior", "capture_failed", {
                "reason": f"suricata exited with code {result.returncode}: {stderr_tail}",
                "pid": self.root_pid,
            })
            return

        eve_path = os.path.join(self.eve_log_dir, "eve.json")
        if os.path.exists(eve_path):
            emit_network_evidence(parse_eve_file(eve_path), self.emit, root_pid=self.root_pid)
