class NetworkFindingEngine:
    def __init__(self, root_pid, process_monitor):
        self.root_pid = root_pid
        self.procmon = process_monitor
        self.findings = []

    def ingest(self, evidence):
        if evidence["category"] != "network":
            return

        data = evidence["data"]
        pid = data.get("pid")

        if not pid:
            return

        # 🔒 FILTER UTAMA: PID attribution
        if not self.procmon.is_descendant(pid, self.root_pid):
            return

        self.findings.append({
            "pid": pid,
            "process": data.get("process"),
            "raddr": data.get("raddr"),
            "laddr": data.get("laddr"),
            "proto": data.get("proto"),
            "status": data.get("status"),
            "service": data.get("service"),
        })

    def analyze(self, emit):
        for f in self.findings:
            emit(
                category="network_behavior",
                event="malware_network_activity",
                data=f,
                confidence="medium" if f.get("service") else "low"
            )
