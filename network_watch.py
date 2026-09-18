import json


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
            emit_func("network_behavior", "tls_connection", {
                "dest_ip": event["dest_ip"], "dest_port": event["dest_port"],
                "sni": event["sni"],
                "ja3_pivot": {"ja3": event["ja3"], "ja3s": event["ja3s"], "note": _JA3_PIVOT_NOTE},
                "pid": root_pid,
            })
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
