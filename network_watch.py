import json
import socket

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
        if remote_ip.startswith(prefix) and remote_port == 443:
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


_JA3_PIVOT_NOTE = (
    "Pivotable indicator only; TLS fingerprints are randomizable and not "
    "a standalone confidence signal."
)


def emit_network_evidence(events, emit_func, root_pid=None):
    for event in events:
        if event["event_type"] == "dns":
            emit_func("network_behavior", "dns_query", {
                "query_name": event["query_name"], "query_type": event["query_type"],
                "dest_ip": event["dest_ip"],
                "pid": root_pid,
            })
        elif event["event_type"] == "tls":
            data = {
                "dest_ip": event["dest_ip"], "dest_port": event["dest_port"],
                "sni": event["sni"],
                "ja3_pivot": {"ja3": event["ja3"], "ja3s": event["ja3s"], "note": _JA3_PIVOT_NOTE},
                "pid": root_pid,
            }
            service_info = infer_service({event["sni"]} if event["sni"] else set(), event["dest_ip"], event["dest_port"])
            if service_info:
                data.update(service_info)
            emit_func("network_behavior", "tls_connection", data)
        elif event["event_type"] == "http":
            emit_func("network_behavior", "http_request", {
                "dest_ip": event["dest_ip"], "hostname": event["hostname"],
                "url": event["url"], "user_agent": event["user_agent"],
                "pid": root_pid,
            })
        elif event["event_type"] == "flow":
            emit_func("network_behavior", "flow_summary", {
                "dest_ip": event["dest_ip"], "dest_port": event["dest_port"],
                "start": event["start"], "end": event["end"],
                "pkts_toserver": event["pkts_toserver"], "pkts_toclient": event["pkts_toclient"],
                "pid": root_pid,
            })
