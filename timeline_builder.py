from collections import defaultdict
from datetime import datetime
import os


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

    def __init__(self, evidences):
        self.evidences = evidences
        self.timeline = []
        self.iocs = defaultdict(set)

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
    def extract_iocs(self):
        for ev in self.evidences:
            category = ev.get("category")
            event = ev.get("event")
            data = ev.get("data", {})

            # ---- Network IOC (STATIC)
            if event == "static_network_indicator":
                val = data.get("value")
                if val:
                    self.iocs["network"].add(val)

            # ---- Persistence IOC
            if category == "registry_behavior":
                key = data.get("key_path")
                if key:
                    self.iocs["registry"].add(key)

            if category == "filesystem_behavior":
                if event == "file_created":
                    for path in data.get("examples", []):
                        if not path:
                            continue
                        if self.is_system_noise(path):
                            continue
                        if path.lower().endswith((".exe", ".dll", ".ps1")):
                            self.iocs["file"].add(path)

                if event == "mass_extension_change":
                    ext = data.get("to_ext")
                    if ext:
                        self.iocs["extension"].add(ext)

            # ---- Executed sample (Soft IOC)
            if category == "process" and event == "process_create":
                name = data.get("name")
                cmd = data.get("cmdline")
                if name:
                    self.iocs["Executed Malware"].add(name)
                if cmd:
                    self.iocs["Execution Command"].add(" ".join(cmd))

            # ---- Ransom note (Soft IOC)
            if category == "filesystem_behavior" and event == "file_created":
                for p in data.get("examples", []):
                    if not p:
                        continue
                    fname = os.path.basename(p).lower()
                    if "read" in fname or "decrypt" in fname or "recover" in fname:
                        self.iocs["Ransom Note"].add(p)

            # ---- Ransomware extension (Hard-ish IOC)
            if category == "filesystem_behavior" and event == "mass_extension_change":
                ext = data.get("to_ext")
                if ext:
                    self.iocs["Ransomware Extension"].add(ext)


        return {k: sorted(v) for k, v in self.iocs.items()}

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
