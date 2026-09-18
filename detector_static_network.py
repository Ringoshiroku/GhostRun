import re
import os


URL_REGEX = re.compile(
    rb"https?://[a-zA-Z0-9\.\-_:\/\?\=&%]+"
)

IP_REGEX = re.compile(
    rb"(?:\d{1,3}\.){3}\d{1,3}"
)


class StaticNetworkIndicatorDetector:
    """
    Extract static network indicators (URL / IP)
    from binary samples (for ransomware / hit-and-run malware).
    """

    def __init__(self, sample_path):
        self.sample_path = sample_path
        self.urls = set()
        self.ips = set()

        self._extract_static_indicators()

    def extract_unicode_strings(data, min_len=6):
        """
        Extract UTF-16LE strings from binary (for .NET samples).
        """
        result = []
        try:
            text = data.decode("utf-16le", errors="ignore")
            current = ""
            for ch in text:
                if ch.isprintable():
                    current += ch
                    if len(current) >= min_len:
                        result.append(current)
                else:
                    current = ""
        except Exception:
            pass
        return result


    # --------------------------------------------------
    # STATIC EXTRACTION
    # --------------------------------------------------
    def _extract_static_indicators(self):
        if not self.sample_path or not os.path.exists(self.sample_path):
            return

        try:
            with open(self.sample_path, "rb") as f:
                data = f.read()
        except Exception:
            return

        # --- ASCII scan (fallback) ---
        ascii_data = data.decode(errors="ignore")
        ascii_candidates = ascii_data.split("\x00")

        # --- Unicode (.NET) scan ---
        unicode_candidates = self.extract_unicode_strings(data)

        candidates = ascii_candidates + unicode_candidates

        for s in candidates:
            s = s.strip()

            if s.startswith("http://") or s.startswith("https://"):
                self.urls.add(s)

                # extract IP from URL if present
                m = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", s)
                if m:
                    self.ips.add(m.group())

            else:
                # standalone IP
                if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", s):
                    if not s.startswith(("0.", "1.", "4.", "11.", "127.")):
                        self.ips.add(s)


    # --------------------------------------------------
    # EMIT
    # --------------------------------------------------
    def analyze(self, emit):
        print("[DEBUG] Static URLs:", self.urls)
        print("[DEBUG] Static IPs:", self.ips)
        
        for url in sorted(self.urls):
            emit(
                category="behavior",
                event="static_network_indicator",
                confidence="high",
                data={
                    "type": "url",
                    "value": url,
                    "note": "Hardcoded network endpoint extracted from binary strings."
                }
            )

        for ip in sorted(self.ips):
            # Avoid double-reporting if IP already in URL
            if any(ip in u for u in self.urls):
                continue

            emit(
                category="behavior",
                event="static_network_indicator",
                confidence="medium",
                data={
                    "type": "ip",
                    "value": ip,
                    "note": "Hardcoded IP address extracted from binary strings."
                }
            )
