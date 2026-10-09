from network_watch import CAPTURE_CONNECTION_EVENTS
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
KNOWN_BENIGN_DOMAINS = load_rule_file("benign_domains.yml")


def _is_known_benign(hostname):
    if not hostname:
        return False
    h = hostname.lower()
    return any(sig in h for sig in KNOWN_BENIGN_DOMAINS)


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
        raddr = f"{dest_ip}:{dest_port}" if dest_ip and dest_port else dest_ip
        hostname = data.get("sni") or data.get("hostname") or data.get("query_name")

        if _is_known_benign(hostname):
            return

        key = (raddr, hostname, data.get("url"))
        if key in self._seen:
            return
        # flow_summary has no hostname/url, so it won't match the _seen key
        # above when a tls_connection/http_request for the same destination
        # already produced a finding. collapse it here instead.
        if event == "flow_summary" and raddr is not None and any(
            f.get("raddr") == raddr for f in self.findings
        ):
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
        })

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
