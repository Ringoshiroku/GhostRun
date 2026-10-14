import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone

from rules_loader import load_rule_file

# curated, extensible list of known legitimate services often abused for
# C2/exfil, same shape as registry_snapshot.py's PERSISTENCE_KEYS.
# domain matching is the reliable signal: SNI reflects the hostname the
# client actually asked for, regardless of how the connection is routed
# (e.g. through a sinkhole/proxy). ip_ranges/ip_prefixes are real signal
# too, but only observable against the service's genuine infrastructure.
# no port check here: a tls_connection event already means Suricata's own
# content-based protocol detection identified this as TLS, independent of
# port, the same technique FakeNet-NG's taste() uses. re-gating on
# port==443 would just miss a sample using a non-standard port.
def _validate_network_service_signature_entry(entry):
    # checked unconditionally, not gated on "is not None": domains is a
    # required_fields key, so it's always present by now.
    # ip_ranges/ip_prefixes are genuinely optional, so they're gated on key
    # *presence* (`"x" in entry`), not on the value being non-None. an entry
    # can have the key present with an explicit YAML `null` value, which
    # `is not None` would wrongly read as "absent, nothing to check" and let
    # it fall straight through to infer_service's unguarded iteration.
    domains = entry.get("domains")
    if not isinstance(domains, list) or not all(isinstance(d, str) for d in domains):
        return "'domains' must be a list of strings"

    has_ip_signal = "ip_ranges" in entry or "ip_prefixes" in entry
    if has_ip_signal and "ip_confidence" not in entry:
        return "'ip_confidence' is required when 'ip_ranges' or 'ip_prefixes' is present"

    if "ip_ranges" in entry:
        ip_ranges = entry["ip_ranges"]
        if not isinstance(ip_ranges, list):
            return "'ip_ranges' must be a list"
        for r in ip_ranges:
            if not (isinstance(r, list) and len(r) == 2 and all(isinstance(x, str) for x in r)):
                return "each 'ip_ranges' entry must be a 2-element list of IP strings"
            try:
                ipaddress.IPv4Address(r[0])
                ipaddress.IPv4Address(r[1])
            except ValueError:
                return "each 'ip_ranges' entry must contain valid IPv4 addresses"

    if "ip_prefixes" in entry:
        ip_prefixes = entry["ip_prefixes"]
        if not isinstance(ip_prefixes, list) or not all(isinstance(p, str) for p in ip_prefixes):
            return "'ip_prefixes' must be a list of strings"

    return None


KNOWN_SERVICE_SIGNATURES = load_rule_file(
    "network_service_signatures.yml",
    required_fields=["service", "domain_confidence", "domains"],
    validate_entry=_validate_network_service_signature_entry,
)


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
    domain_hits_l = [d.lower() for d in domain_hits]
    for sig in KNOWN_SERVICE_SIGNATURES:
        for d in domain_hits_l:
            for domain_sig in sig.get("domains", []):
                if domain_sig in d:
                    return {"service": sig["service"], "confidence": sig["domain_confidence"],
                            "domains": list(domain_hits)}

        for start, end in sig.get("ip_ranges", []):
            if remote_ip and ip_in_range(remote_ip, start, end):
                return {"service": sig["service"], "confidence": sig["ip_confidence"],
                        "domains": list(domain_hits)}

        for prefix in sig.get("ip_prefixes", []):
            if remote_ip and remote_ip.startswith(prefix):
                return {"service": sig["service"], "confidence": sig["ip_confidence"],
                        "domains": list(domain_hits)}

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
        "src_port": raw.get("src_port"),
        "dest_ip": raw.get("dest_ip"),
        "dest_port": raw.get("dest_port"),
        "timestamp": raw.get("timestamp"),
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

    if event_type == "alert":
        alert = raw.get("alert", {})
        base.update({
            "signature": alert.get("signature"),
            "category": alert.get("category"),
            "severity": alert.get("severity"),
            "signature_id": alert.get("signature_id"),
            "gid": alert.get("gid"),
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
    "dns_query", "tls_connection", "http_request", "flow_summary", "ids_alert",
})
CAPTURE_CONNECTION_EVENTS = frozenset({
    "tls_connection", "http_request", "flow_summary", "ids_alert",
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


def _parse_suricata_timestamp(raw):
    """
    Suricata's real eve.json timestamps have no colon in the UTC offset
    (e.g. "2023-09-18T06:13:41.532140+0000"), per Suricata's own
    eve-json-format docs, which also note older versions omit the offset
    entirely ("2009-11-24T21:27:09.534255").
    Python's datetime.fromisoformat() needs a colon in the offset on this
    project's 3.10 floor, so one is inserted before parsing if missing.
    returns a float epoch timestamp, or None if raw is missing, not a
    string, or unparseable in either form.
    """
    if not raw or not isinstance(raw, str):
        return None
    s = raw
    had_offset = False
    if len(s) >= 5 and s[-5] in "+-" and s[-4:].isdigit():
        s = s[:-2] + ":" + s[-2:]
        had_offset = True
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if not had_offset:
        # Suricata's older no-offset format still means UTC. newer versions just
        # spell the offset out explicitly. .timestamp() on a naive datetime
        # otherwise silently assumes local time (per Python's own docs), which
        # would be off by the host's UTC offset on any non-UTC sandbox host and
        # quietly corrupt the whole attribution chain's time comparisons.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _resolve_attributed_pid(event, connection_monitor, procmon, root_pid):
    """
    finds the specific descendant process a captured flow belongs to,
    falling back to root_pid when that's not possible: no monitor/procmon
    wired in, no parseable timestamp, neither src_port nor dest_port found
    in any ConnectionMonitor snapshot, or the resolved PID isn't actually a
    descendant of root_pid (e.g. the port got reused by an unrelated
    process).
    checks src_port then dest_port instead of picking one by event
    direction: only one of the two is ever a real local port a process on
    this machine could hold, the other is the remote side's port and won't
    appear in the local snapshot table at all.
    """
    if connection_monitor is None or procmon is None:
        return root_pid
    ts = _parse_suricata_timestamp(event.get("timestamp"))
    if ts is None:
        return root_pid
    for port in (event.get("src_port"), event.get("dest_port")):
        if port is None:
            continue
        candidate = connection_monitor.resolve_pid(port, ts)
        if candidate is not None and procmon.is_descendant(candidate, root_pid):
            return candidate
    return root_pid


def emit_network_evidence(events, emit_func, root_pid=None, connection_monitor=None, procmon=None):
    for event in events:
        if event["event_type"] == "dns":
            emit_func("network_behavior", "dns_query", {
                "query_name": event["query_name"], "query_type": event["query_type"],
                "src_ip": event["src_ip"], "dest_ip": event["dest_ip"],
                "dest_port": event["dest_port"],
                "pid": _resolve_attributed_pid(event, connection_monitor, procmon, root_pid), "pid_attribution": _PID_ATTRIBUTION_NOTE,
            })
        elif event["event_type"] == "tls":
            data = {
                "src_ip": event["src_ip"],
                "dest_ip": event["dest_ip"], "dest_port": event["dest_port"],
                "sni": event["sni"],
                "ja3_pivot": {"ja3": event["ja3"], "ja3s": event["ja3s"], "note": _JA3_PIVOT_NOTE},
                "pid": _resolve_attributed_pid(event, connection_monitor, procmon, root_pid), "pid_attribution": _PID_ATTRIBUTION_NOTE,
            }
            service_info = infer_service({event["sni"]} if event["sni"] else set(), event["dest_ip"], event["dest_port"])
            if service_info:
                data.update(service_info)
            elif not event["sni"]:
                # no SNI at all means the client connected straight to an IP literal, not
                # a hostname. uncommon for ordinary browser/application traffic, so it's a
                # weak, generic indicator on its own, not a named service match.
                data["raw_ip_literal"] = True
            emit_func("network_behavior", "tls_connection", data)
        elif event["event_type"] == "http":
            data = {
                "src_ip": event["src_ip"],
                "dest_ip": event["dest_ip"], "dest_port": event["dest_port"],
                "hostname": event["hostname"],
                "url": event["url"], "user_agent": event["user_agent"],
                "pid": _resolve_attributed_pid(event, connection_monitor, procmon, root_pid), "pid_attribution": _PID_ATTRIBUTION_NOTE,
            }
            service_info = infer_service(
                {event["hostname"]} if event["hostname"] else set(), event["dest_ip"], event["dest_port"],
            )
            if service_info:
                data.update(service_info)
            emit_func("network_behavior", "http_request", data)
        elif event["event_type"] == "flow":
            emit_func("network_behavior", "flow_summary", {
                "src_ip": event["src_ip"],
                "dest_ip": event["dest_ip"], "dest_port": event["dest_port"],
                "start": event["start"], "end": event["end"],
                "pkts_toserver": event["pkts_toserver"], "pkts_toclient": event["pkts_toclient"],
                "pid": _resolve_attributed_pid(event, connection_monitor, procmon, root_pid), "pid_attribution": _PID_ATTRIBUTION_NOTE,
            })
        elif event["event_type"] == "alert":
            emit_func("network_behavior", "ids_alert", {
                "src_ip": event["src_ip"],
                "dest_ip": event["dest_ip"], "dest_port": event["dest_port"],
                "signature": event["signature"], "category": event["category"],
                "severity": event["severity"], "signature_id": event["signature_id"],
                "gid": event["gid"],
                "pid": _resolve_attributed_pid(event, connection_monitor, procmon, root_pid), "pid_attribution": _PID_ATTRIBUTION_NOTE,
            })


# suricata-update's own source hardcodes /var/lib/suricata as its default
# output dir on every platform, with no Windows-aware branch at all, so
# that default isn't worth keeping here. GhostRun already overrides the
# output path via -o regardless, so the default is ours to choose.
# uses the same ~/.ghostrun/ convention _DEFAULT_YARA_RULES_CACHE already
# uses, so it resolves to a real, writable, native path on every platform
# GhostRun runs on.
_DEFAULT_SURICATA_RULES_PATH = os.path.expanduser("~/.ghostrun/rules/suricata/suricata.rules")


# suricata-update has no __main__.py: `python -m suricata.update` fails
# with "'suricata.update' is a package and cannot be directly executed",
# confirmed against its real source. so -m can't reach it.
# its own installed console script (bin/suricata-update upstream) is a
# thin wrapper doing the same import-and-call. verified this reproduces
# the real CLI, including a correct `--version` response.
_SURICATA_UPDATE_MODULE_INVOCATION = (
    "from suricata.update import main; import sys; sys.exit(main.main())"
)


def _find_suricata_update_command():
    """
    finds how to run suricata-update on this machine.
    prefers the bare command if it's on PATH, else falls back to directly
    importing and calling its entry point via `python -c`, since a pip
    install can succeed while the installed console-script entry point
    still isn't on PATH (same issue dumpcap/suricata hit during manual
    setup earlier).
    returns None (never raises) if neither works.
    """
    if shutil.which("suricata-update"):
        return ["suricata-update"]

    try:
        result = subprocess.run(
            [sys.executable, "-c", _SURICATA_UPDATE_MODULE_INVOCATION, "--version"],
            capture_output=True, timeout=10,
        )
    except Exception:
        return None
    return [sys.executable, "-c", _SURICATA_UPDATE_MODULE_INVOCATION] if result.returncode == 0 else None


def _resolve_suricata_rules_path(configured_path=None, default_path=_DEFAULT_SURICATA_RULES_PATH,
                                  interactive=None):
    """
    finds a Suricata rules file to load, so capture gets real
    signature-based alerting (the Emerging Threats Open ruleset, free and
    BSD-licensed) instead of just protocol parsing.
    order: an explicit configured path, then whatever suricata-update
    already left on this system, then, only if interactive, offer to fetch
    it now via suricata-update.
    returns None (never raises) if nothing is available or the user says
    no, same degrade-gracefully pattern as every other optional tool here:
    capture still runs, just without rules.
    """
    if configured_path and os.path.exists(configured_path):
        return configured_path

    if os.path.exists(default_path):
        return default_path

    if interactive is None:
        interactive = sys.stdin.isatty()
    if not interactive:
        return None

    cmd = _find_suricata_update_command()
    if cmd is None:
        return None

    answer = input(
        "No Suricata rules found. Fetch the free Emerging Threats Open "
        "ruleset now via suricata-update? [y/N] "
    ).strip().lower()
    if answer != "y":
        return None

    try:
        os.makedirs(os.path.dirname(default_path), exist_ok=True)
        subprocess.run(
            cmd + ["-o", os.path.dirname(default_path)],
            check=True, timeout=300,
        )
    except Exception:
        return None

    return default_path if os.path.exists(default_path) else None


class NetworkCapture:
    def __init__(self, pcap_path, eve_log_dir, emit_func, sslkeylogfile_path=None, root_pid=None,
                 exclude_host=None, exclude_port=None, rules_path=None):
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
        self.rules_path = rules_path
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

        # Suricata's eve-log defaults to append mode across runs, and eve_log_dir
        # is just dirname(the run's output file). so two runs sharing an output
        # directory would share eve.json, and a stale alert from an earlier run
        # could get silently re-emitted and misattributed to this run's PID.
        eve_path = os.path.join(self.eve_log_dir, "eve.json")
        if os.path.exists(eve_path):
            os.remove(eve_path)

        cmd = [
            "suricata", "-r", self.pcap_path, "-l", self.eve_log_dir, "-k", "none",
            "--set", "app-layer.protocols.tls.ja3-fingerprints=yes",
            "--set", "app-layer.protocols.tls.ja4-fingerprints=yes",
        ]
        resolved_rules_path = self.rules_path or _resolve_suricata_rules_path()
        if resolved_rules_path:
            cmd += ["-S", resolved_rules_path]

        result = subprocess.run(
            cmd,
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=120,
        )

        if result.returncode != 0:
            stderr_tail = (result.stderr or "")[-2000:]
            self.emit("network_behavior", "capture_failed", {
                "reason": f"suricata exited with code {result.returncode}: {stderr_tail}",
                "pid": self.root_pid,
            })
            return

        if os.path.exists(eve_path):
            emit_network_evidence(parse_eve_file(eve_path), self.emit, root_pid=self.root_pid)
