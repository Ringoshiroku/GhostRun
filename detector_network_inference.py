import re
import os


IP_REGEX = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


class NetworkInferenceDetector:
    """
    Infer failed or short-lived network attempts
    from static indicators + runtime behavior.
    """

    def __init__(self, sample_path):
        self.sample_path = sample_path
        self.static_ips = set()
        self.process_seen = False
        self.network_seen = False

        self._scan_static_ips()

    # --------------------------------------------------
    # STATIC ANALYSIS (LIGHTWEIGHT)
    # --------------------------------------------------
    def _scan_static_ips(self):
        if not self.sample_path or not os.path.exists(self.sample_path):
            return

        try:
            with open(self.sample_path, "rb") as f:
                data = f.read()
        except Exception:
            return

        try:
            text = data.decode(errors="ignore")
        except Exception:
            return

        for ip in IP_REGEX.findall(text):
            # simple sanity filter
            if not ip.startswith("127."):
                self.static_ips.add(ip)

    # --------------------------------------------------
    # INGEST RUNTIME EVIDENCE
    # --------------------------------------------------
    def ingest(self, category, event, data):
        if category == "process" and event == "process_create":
            self.process_seen = True

        elif category == "network":
            self.network_seen = True

    # --------------------------------------------------
    # ANALYZE
    # --------------------------------------------------
    def analyze(self, emit):
        # Only fire if:
        # - process ran
        # - no observable network
        # - but static network indicator exists
        if self.process_seen and not self.network_seen and self.static_ips:
            emit(
                category="behavior",
                event="possible_failed_network_attempt",
                confidence="medium",
                data={
                    "suspected_targets": sorted(self.static_ips),
                    "note": (
                        "Executable contains hardcoded network indicators but "
                        "no sustained socket-level network activity was observed. "
                        "This may indicate short-lived or failed connection attempts."
                    ),
                },
            )
