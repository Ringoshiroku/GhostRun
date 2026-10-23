from network_watch import CAPTURE_CONNECTION_EVENTS, _RESOLVED_PID_NOTE
from rules_loader import load_rule_file

# same idea as timeline_builder.py's SYSTEM_PATH_KEYWORDS/is_system_noise,
# but for network destinations instead of filesystem paths.
# filters out routine OS telemetry/update/certificate-check traffic so it
# doesn't become a malware_network_activity finding.
# this matters more here because every network_behavior event is
# capture-derived and stamped with root_pid no matter which process
# actually made the connection. see _PID_ATTRIBUTION_NOTE in
# network_watch.py.
# the pid-attribution filter below can't tell sample traffic from
# background OS noise by itself, so without this filter every telemetry
# connection in the analysis window would look like it came from the sample.
def _validate_benign_domain_entry(entry):
    if not isinstance(entry, str) or not entry.strip():
        return "entry must be a non-empty hostname string"
    return None


KNOWN_BENIGN_DOMAINS = load_rule_file("benign_domains.yml", validate_entry=_validate_benign_domain_entry)


def _is_known_benign(hostname):
    if not hostname:
        return False
    h = hostname.lower()
    return any(sig in h for sig in KNOWN_BENIGN_DOMAINS)


def _format_raddr(dest_ip, dest_port):
    # an ipv6 address already uses colons as its own separator, so a bare
    # f"{ip}:{port}" join is ambiguous/malformed -- confirmed live, a
    # real Suricata flow (dest_ip ff02:0000:0000:0000:0000:0000:0001:0003,
    # a valid 8-group address, port 5355) produced a 9-group string that
    # isn't a valid ipv6 address at all. bracket it, same convention
    # every other tool uses (RFC 3986, netstat, browsers). a colon is
    # never valid in an ipv4 address or a hostname, so its presence
    # alone is enough to tell the two apart here, no need for the
    # ipaddress module's stricter (and slower) validation.
    if not dest_ip or not dest_port:
        return dest_ip
    if ":" in dest_ip:
        return f"[{dest_ip}]:{dest_port}"
    return f"{dest_ip}:{dest_port}"


class NetworkFindingEngine:
    def __init__(self, root_pid, process_monitor):
        self.root_pid = root_pid
        self.procmon = process_monitor
        self.findings = []
        self._seen = set()

    def ingest(self, evidence):
        if evidence.get("category") != "network_behavior":
            return
        event = evidence.get("event")
        # CAPTURE_CONNECTION_EVENTS (not CAPTURE_ACTIVITY_EVENTS), on purpose.
        # dns_query is skipped: its dest_ip is just the resolver (e.g. 8.8.8.8),
        # not the real target, so keeping it would give misleading
        # "outbound activity to 8.8.8.8" findings.
        # capture_unavailable and capture_failed are skipped too.
        # so is this engine's own malware_network_activity output, since
        # emit() feeds it straight back into ingest(). without that,
        # analyze() below would append to the list it's iterating and never stop.
        if event not in CAPTURE_CONNECTION_EVENTS:
            return

        data = evidence.get("data", {})
        pid = data.get("pid")

        if not pid:
            return

        # main filter: PID attribution
        if not self.procmon.is_descendant(pid, self.root_pid):
            return

        dest_ip = data.get("dest_ip")
        dest_port = data.get("dest_port")
        raddr = _format_raddr(dest_ip, dest_port)
        hostname = data.get("sni") or data.get("hostname") or data.get("query_name")

        if _is_known_benign(hostname):
            return

        # three-way attribution: "resolved" only when pid_attribution is
        # exactly _RESOLVED_PID_NOTE. anything else, the fallback note, a
        # missing key, a future third value, counts as "unknown".
        attribution_confidence = "resolved" if data.get("pid_attribution") == _RESOLVED_PID_NOTE else "unknown"

        # an ids_alert's own signature is part of the dedup identity: two
        # distinct real Suricata signatures firing on the same connection
        # (e.g. two different rules both matching one DNS lookup) are each
        # independently meaningful and must not collapse into one finding
        # just because dest/hostname/url match. every other event type has
        # no signature field, so this is a no-op (None) for them, same key
        # as before.
        key = (raddr, hostname, data.get("url"), data.get("signature"))
        # dedup keeps whichever event arrives first, but attribution can
        # differ per event since resolution is per-connection: an early
        # "unknown" can later get a "resolved" for the same destination.
        # a duplicate carrying "resolved" upgrades the stored finding's tag.
        # it never downgrades a tag, and never adds a new entry.
        if key in self._seen:
            self._upgrade_attribution(
                attribution_confidence,
                lambda f: (f.get("raddr"), f.get("hostname"), f.get("url"), f.get("signature")) == key,
            )
            return
        # flow_summary has no hostname/url, so it won't match the _seen key
        # above when a tls_connection/http_request for the same destination
        # already produced a finding. collapse it here instead.
        if event == "flow_summary" and raddr is not None and any(
            f.get("raddr") == raddr for f in self.findings
        ):
            self._upgrade_attribution(
                attribution_confidence,
                lambda f: f.get("raddr") == raddr,
            )
            return
        self._seen.add(key)

        self.findings.append({
            "pid": pid,
            "event": event,
            "raddr": raddr,
            "hostname": hostname,
            "url": data.get("url"),
            "service": data.get("service"),
            "signature": data.get("signature"),
            "category": data.get("category"),
            "severity": data.get("severity"),
            "attribution_confidence": attribution_confidence,
        })

    def _upgrade_attribution(self, confidence, matches):
        if confidence != "resolved":
            return
        for f in self.findings:
            if matches(f):
                f["attribution_confidence"] = "resolved"

    def analyze(self, emit):
        for f in list(self.findings):
            if f.get("event") == "ids_alert":
                confidence = "high"
            elif f.get("service"):
                confidence = "medium"
            else:
                confidence = "low"
            emit(
                category="network_behavior",
                event="malware_network_activity",
                data=f,
                confidence=confidence,
            )
