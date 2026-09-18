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
