from collections import defaultdict

from network_watch import CAPTURE_CONNECTION_EVENTS


class PersistenceDetector:
    def __init__(self):
        # index evidence
        self.registry_exec_refs = []   # from registry_behavior
        self.process_execs = set()     # exe paths or names
        self.network_pids = set()      # pid with outbound network

    # ---------------------------------------------------------
    # INGEST EVIDENCE
    # ---------------------------------------------------------
    def ingest(self, category, event, data):
        # registry behavior
        if category == "registry_behavior" and event == "execution_reference_detected":
            self.registry_exec_refs.append(data)

        # process creation
        elif category == "process" and event == "process_create":
            name = data.get("name")
            cmd = " ".join(data.get("cmdline", []))
            if name:
                self.process_execs.add(name.lower())
            if cmd:
                self.process_execs.add(cmd.lower())

        # network activity
        elif category == "network_behavior" and event in CAPTURE_CONNECTION_EVENTS:
            pid = data.get("pid")
            if pid:
                self.network_pids.add(pid)

    # ---------------------------------------------------------
    # ANALYZE & EMIT
    # ---------------------------------------------------------
    def analyze(self, emit):
        for ref in self.registry_exec_refs:
            path = ref.get("path", "").lower()
            location = ref.get("location", "")

            executed = any(path in p for p in self.process_execs)
            networked = bool(self.network_pids)

            # RULE 2 — registry + process + network
            if executed and networked:
                emit(
                    category="persistence",
                    event="user_level_persistence_likely",
                    confidence="high",
                    derived_from=[
                        "registry_behavior:execution_reference_detected",
                        "process:process_create",
                        "network_behavior:tls_connection|http_request|flow_summary",
                    ],
                    data={
                        "pid": ref.get("pid"),
                        "path": ref.get("path"),
                        "location": location,
                        "note": (
                            "Executable referenced in registry was executed and outbound "
                            "network activity was observed during the analysis window. "
                            "pid is capture-derived, stamped with the analysis root PID, "
                            "not per-process attributed."
                        ),
                    },
                )

            # RULE 1 — registry + process
            elif executed:
                emit(
                    category="persistence",
                    event="potential_persistence_mechanism",
                    confidence="medium",
                    derived_from=[
                        "registry_behavior:execution_reference_detected",
                        "process:process_create",
                    ],
                    data={
                        "pid": ref.get("pid"),
                        "path": ref.get("path"),
                        "location": location,
                        "note": "Executable referenced in registry was executed during analysis window.",
                    },
                )

            # RULE 3 — registry only
            else:
                emit(
                    category="persistence",
                    event="suspicious_registry_persistence_artifact",
                    confidence="low",
                    derived_from=[
                        "registry_behavior:execution_reference_detected",
                    ],
                    data={
                        "pid": ref.get("pid"),
                        "path": ref.get("path"),
                        "location": location,
                        "note": "Registry execution reference observed without corresponding process execution.",
                    },
                )
