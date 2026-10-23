from collections import defaultdict
from datetime import datetime
import os
import re


class TimelineBuilder:
    SYSTEM_PATH_KEYWORDS = [
        r"\windows defender\definition updates",
        r"\windows\system32",
        r"\windows\winsxs",
        r"\_mei",
        r"api-ms-win-",
        r"vcruntime",
        r"ucrt"
    ]

    _UNRESOLVED_ATTRIBUTION_TIER = {"high": "medium", "medium": "low", "low": "low"}

    def __init__(self, evidences):
        self.evidences = evidences
        self.timeline = []
        self.iocs = defaultdict(list)
        self._seen_iocs = set()

    # --------------------------------------------------
    # BUILD TIMELINE
    # --------------------------------------------------
    def build(self):
        self.timeline = sorted(
            self.evidences,
            key=lambda e: e.get("timestamp", "")
        )
        return self.timeline

    def is_system_noise(self, path):
        if not path:
            return True
        p = path.lower()
        return any(k in p for k in self.SYSTEM_PATH_KEYWORDS)

    # --------------------------------------------------
    # IOC EXTRACTION
    # --------------------------------------------------
    def _add_ioc(self, category, value, confidence, source):
        key = (category, value, source)
        if key in self._seen_iocs:
            return
        self._seen_iocs.add(key)
        self.iocs[category].append({"value": value, "confidence": confidence, "source": source})

    def extract_iocs(self):
        # a hash is only useful attached to something already worth
        # looking at, cross-referenced by path, not dumped wholesale (a
        # real run hashes dozens of the sample's own runtime noise files
        # too). built as its own pass since the hash event for a path
        # can arrive before or after the event that flags that same
        # path; a single forward pass couldn't look an earlier flag's
        # hash up if the hash hadn't been seen yet.
        hashes_by_path = {}
        for ev in self.evidences:
            if ev.get("category") == "filesystem_behavior" and ev.get("event") == "file_content_hashed":
                data = ev.get("data", {})
                path, sha256 = data.get("path"), data.get("sha256")
                if path and sha256:
                    hashes_by_path[path] = sha256

        for ev in self.evidences:
            category = ev.get("category")
            event = ev.get("event")
            data = ev.get("data", {})

            # ---- Network IOC (STATIC)
            if event == "static_network_indicator":
                val = data.get("value")
                if val:
                    self._add_ioc("network", val, confidence="medium", source="static_indicator")

            # ---- persistence IOC.
            # "location" is the field registry_snapshot.py actually emits
            # (known_persistence_location/execution_reference_detected).
            # this used to read "key_path", a field no production code
            # emits, so registry IOCs never got populated.
            if category == "registry_behavior":
                key = data.get("location")
                if key:
                    self._add_ioc("registry", key, confidence="medium", source="registry_persistence")

            # ---- persistence_detector.py's own, separate signal: an
            # execution reference in the registry with no matching
            # process execution. distinct from registry_behavior above
            # (a different detector, a different question answered).
            if category == "persistence" and event == "suspicious_registry_persistence_artifact":
                path, location = data.get("path"), data.get("location")
                if path and location:
                    self._add_ioc(
                        "suspicious_persistence", f"{path} -> {location}",
                        confidence="medium", source="persistence_detector",
                    )

            # ---- process terminated: GhostRun's own kill-tree safety
            # net actually tearing down the sample's process tree is
            # real forensic context, not just an internal cleanup detail.
            if category == "process" and event == "process_terminate":
                name, pid = data.get("name"), data.get("pid")
                if name:
                    value = f"{name} (PID {pid})" if pid else name
                    self._add_ioc("process_terminated", value, confidence="low", source="process_lifecycle")

            if category == "filesystem_behavior":
                if event == "file_created":
                    path = data.get("path")
                    # a real dropper can use any extension; a whitelist
                    # of .exe/.dll/.ps1 misses exactly the files worth
                    # flagging (confirmed live against a .bin payload).
                    # the system-noise filter alone is the real bar.
                    if path and not self.is_system_noise(path):
                        sha256 = hashes_by_path.get(path)
                        value = f"{path} (sha256: {sha256})" if sha256 else path
                        # filesystem_watch.py can't resolve which process
                        # actually wrote a file (no equivalent to network's
                        # connection-table correlation), so a shared system
                        # root (WINDOWS_TEMP, PROGRAMDATA) only gets a
                        # capture-wide guess, never a resolved fact.
                        # confirmed live: an OS-created-then-deleted
                        # OProcSessId.dat got reported as a confident
                        # malware-dropped IOC purely because it landed
                        # under a root the sample's PID happened to be
                        # watching. caveat it the same way an unresolved
                        # network finding is caveated, instead of
                        # silently asserting attribution confidence has
                        # no room to downgrade (already the "low" floor).
                        if data.get("attribution_confidence") == "unknown":
                            value += (
                                " [unresolved attribution: observed during the run, "
                                "not confirmed to a specific malware process]"
                            )
                        self._add_ioc("file", value, confidence="low", source="heuristic")

                if event == "mass_extension_change":
                    ext = data.get("to_ext")
                    if ext:
                        self._add_ioc("extension", ext, confidence="low", source="heuristic")

                if event == "yara_match":
                    rule = data.get("rule")
                    path = data.get("path")
                    # same noise filter file_created already uses: a
                    # match inside the sample's own PyInstaller onefile
                    # extraction dir (_MEI<pid>) is its own legitimately-
                    # bundled runtime DLLs, not something it dropped
                    # (confirmed live: 125 of 126 real matches in one
                    # run were exactly this).
                    if rule and not (path and self.is_system_noise(path)):
                        sha256 = hashes_by_path.get(path) if path else None
                        if path and sha256:
                            value = f"{rule} ({path}, sha256: {sha256})"
                        elif path:
                            value = f"{rule} ({path})"
                        else:
                            value = rule
                        self._add_ioc("yara_match", value, confidence="high", source="yara_scan")

            # ---- Executed sample (Soft IOC)
            if category == "process" and event == "process_create":
                name = data.get("name")
                cmd = data.get("cmdline")
                if name:
                    self._add_ioc("Executed Malware", name, confidence="low", source="heuristic")
                if cmd:
                    self._add_ioc("Execution Command", " ".join(cmd), confidence="low", source="heuristic")

            # ---- Ransom note (Soft IOC)
            if category == "filesystem_behavior" and event == "file_created":
                p = data.get("path")
                if p:
                    fname = os.path.basename(p).lower()
                    # token-based match, not a raw substring check.
                    # a plain "read" substring would false-positive on normal
                    # filenames like api-ms-win-core-proces[read]s-l1-1-0.dll
                    # ("threads" contains "read").
                    # split on non-alnum separators and require a whole token
                    # to start with the keyword. still matches real note names
                    # (readme, read_me, decrypt_files, how-to-recover) without
                    # matching substrings buried inside unrelated words.
                    tokens = re.split(r"[^a-z0-9]+", fname)
                    if any(t.startswith(("read", "decrypt", "recover")) for t in tokens):
                        self._add_ioc("Ransom Note", p, confidence="medium", source="heuristic")

            # ---- Ransomware extension (Hard-ish IOC)
            if category == "filesystem_behavior" and event == "mass_extension_change":
                ext = data.get("to_ext")
                if ext:
                    self._add_ioc("Ransomware Extension", ext, confidence="medium", source="heuristic")

            # ---- mutex malware-family match.
            # confidence comes through as a top-level evidence field
            # (emit()'s **meta), not inside data, same as
            # network_behavior/malware_network_activity below.
            if category == "mutex_behavior" and event == "known_malware_mutex":
                family = data.get("family")
                mutex = data.get("mutex")
                if family:
                    value = f"{family} ({mutex})" if mutex else family
                    self._add_ioc(
                        "mutex_family", value,
                        confidence=ev.get("confidence", "medium"), source="mutex_signature",
                    )

            # ---- network finding.
            # pulled from the already-correlated, confidence-tiered
            # malware_network_activity signal, not the raw
            # ids_alert/tls_connection/http_request/flow_summary events
            # underneath it. that engine already dedupes and tiers those
            # into one signal, so pulling from the raw events too would
            # just duplicate and add noise.
            if category == "network_behavior" and event == "malware_network_activity":
                value = (
                    data.get("signature") or data.get("hostname")
                    or data.get("service") or data.get("raddr")
                )
                if value:
                    confidence = ev.get("confidence", "low")
                    # not confirmed to a specific malware process, only the
                    # capture-wide fallback tied it to the sample: one tier lower.
                    # absent/"resolved" keeps the tier.
                    if data.get("attribution_confidence") == "unknown":
                        confidence = self._UNRESOLVED_ATTRIBUTION_TIER.get(confidence, confidence)
                    self._add_ioc(
                        "network_finding", value,
                        confidence=confidence, source="network_behavior",
                    )

        return dict(self.iocs)

    # --------------------------------------------------
    # SUMMARY (OPTIONAL)
    # --------------------------------------------------
    def summary(self):
        return {
            "total_events": len(self.timeline),
            "categories": list(
                set(ev.get("category") for ev in self.timeline)
            ),
            "ioc_counts": {k: len(v) for k, v in self.iocs.items()},
        }
