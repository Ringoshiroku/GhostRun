import re
import os

from rules_loader import load_rule_file


URL_REGEX = re.compile(
    r"https?://[a-zA-Z0-9\.\-_:\/\?\=&%]+"
)

IP_REGEX = re.compile(
    r"(?:\d{1,3}\.){3}\d{1,3}"
)

# label.label...tld shaped. On its own this is far too broad (matches
# .NET/Java namespace strings and filenames just as readily as real
# domains); same pattern and same reasoning as watson's ioc_strings.py,
# which this is ported from -- the TLD-membership check below is what
# actually distinguishes a domain from either of those.
_DOMAIN_LABEL = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
_DOMAIN_REGEX = re.compile(rf"\b(?:{_DOMAIN_LABEL}\.)+[a-zA-Z]{{2,24}}\b")

# A pragmatic floor, not an IANA-complete registry: common gTLDs plus
# ccTLDs actually seen in malware infrastructure and legitimate traffic.
# Case-sensitive on purpose: this set is all-lowercase, so a PascalCase
# match (a Go/.NET exported type name like *big.Int, *pkix.Name --
# structurally identical to a domain) never matches a real entry here,
# same mechanism watson's ioc_strings.py uses, no separate case check
# needed.
_KNOWN_TLDS = frozenset({
    "com", "net", "org", "info", "biz", "name", "pro", "mobi",
    "io", "co", "me", "tv", "cc", "ws", "app", "dev", "cloud",
    "online", "site", "xyz", "top", "club", "live", "link", "click",
    "work", "icu", "buzz", "monster", "fun", "space", "store", "tech",
    "shop", "vip", "win", "bid", "loan", "download", "stream",
    "gq", "ga", "cf", "ml", "tk",
    "gov", "edu", "mil", "int",
    "us", "uk", "ca", "au", "de", "fr", "jp", "cn", "ru", "in",
    "br", "it", "es", "nl", "se", "no", "dk", "fi", "pl", "tr",
    "ir", "kr", "mx", "za", "ch", "at", "be", "pt", "gr", "cz",
    "hu", "ro", "bg", "ua", "by", "kz", "su", "tw", "hk", "sg",
    "my", "id", "vn", "th", "ph", "nz", "ie", "is", "lu", "li",
    "sk", "si", "hr", "rs", "lt", "lv", "ee", "md", "ge", "am",
    "az", "uz", "pk", "bd", "lk", "np", "kh", "la", "mm", "mn",
    "ae", "sa", "il", "eg", "ng", "ke", "gh", "tz", "ug", "ma",
    "dz", "tn", "ly", "sc", "mu", "cy", "mt", "al", "mk", "ba",
})

# Go embeds an import path for every package it links in (including the
# standard library and any vendored dependency); those hosts are real,
# lowercase, real-TLD domains, just package hosts, not infrastructure a
# sample is beaconing to. Not an exhaustive registry, same list watson's
# ioc_strings.py uses.
_KNOWN_CODE_HOSTS = frozenset({
    "golang.org", "github.com", "gopkg.in", "google.golang.org", "k8s.io",
})


def _is_known_code_host(domain):
    return domain in _KNOWN_CODE_HOSTS or any(
        domain.endswith("." + host) for host in _KNOWN_CODE_HOSTS
    )


def _validate_benign_domain_entry(entry):
    if not isinstance(entry, str) or not entry.strip():
        return "entry must be a non-empty hostname string"
    return None


# same shared rule file network_finding_engine.py filters live connections
# against; a sample legitimately referencing a real benign domain (e.g. an
# update check-in URL) shouldn't be flagged here either.
KNOWN_BENIGN_DOMAINS = load_rule_file("benign_domains.yml", validate_entry=_validate_benign_domain_entry)


def _is_known_benign(domain):
    d = domain.lower()
    return any(sig in d for sig in KNOWN_BENIGN_DOMAINS)


class StaticNetworkIndicatorDetector:
    """
    Extract static network indicators (URL / IP)
    from binary samples (for ransomware / hit-and-run malware).
    """

    def __init__(self, sample_path):
        self.sample_path = sample_path
        self.urls = set()
        self.ips = set()
        self.domains = set()

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
            url_spans = []  # (start, end), so a domain match inside an
            # already-found url isn't also reported as its own bare domain

            # a url can appear anywhere in a candidate string, not just at
            # the start: the UTF-16 extraction path just accumulates any
            # printable run >= min_len, so a real url can end up stitched
            # together with surrounding text instead of cleanly isolated.
            for m in URL_REGEX.finditer(s):
                url = m.group()
                self.urls.add(url)
                url_spans.append((m.start(), m.end()))
                ip_in_url = IP_REGEX.search(url)
                if ip_in_url:
                    self.ips.add(ip_in_url.group())

            # standalone IP: fullmatch against the WHOLE candidate on
            # purpose, not a search -- a dotted-quad substring inside
            # unrelated text (a version string, part of a longer digit
            # run) is a known, real false-positive source a bare search
            # would reintroduce. only meaningful when the whole candidate
            # isn't itself a url (fullmatch already can't both match a url
            # pattern and an ip pattern on the same full string).
            if not url_spans and IP_REGEX.fullmatch(s):
                if not s.startswith(("0.", "1.", "4.", "11.", "127.")):
                    self.ips.add(s)

            # bare hostname, no url scheme: idiomatic native
            # WinHTTP/WinINet code passes host and path to separate API
            # calls (WinHttpConnect/WinHttpOpenRequest), so a native
            # sample never has a combined url string for this at all,
            # only the bare host -- confirmed live against a real native
            # test harness. ported from watson's ioc_strings.py: the
            # TLD-membership check (an all-lowercase set) is what
            # actually distinguishes a real domain from a .NET/Java
            # namespace string or a filename, which are structurally
            # identical otherwise. checked against the whole candidate
            # (not gated on url_spans being empty) so a genuinely
            # separate bare domain elsewhere in the same candidate string
            # still gets found; only a domain whose own span overlaps an
            # already-matched url is skipped, not the whole candidate.
            for m in _DOMAIN_REGEX.finditer(s):
                if any(not (m.end() <= us or m.start() >= ue) for us, ue in url_spans):
                    continue
                domain = m.group()
                tld = domain.rsplit(".", 1)[-1]
                if tld not in _KNOWN_TLDS:
                    continue
                if _is_known_code_host(domain) or _is_known_benign(domain):
                    continue
                self.domains.add(domain)


    # --------------------------------------------------
    # EMIT
    # --------------------------------------------------
    def analyze(self, emit):
        print("[DEBUG] Static URLs:", self.urls)
        print("[DEBUG] Static IPs:", self.ips)
        print("[DEBUG] Static Domains:", self.domains)

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

        for domain in sorted(self.domains):
            # same cross-candidate dedup as the IP case above
            if any(domain in u for u in self.urls):
                continue

            emit(
                category="behavior",
                event="static_network_indicator",
                confidence="medium",
                data={
                    "type": "domain",
                    "value": domain,
                    "note": "Hardcoded hostname extracted from binary strings (no URL scheme present)."
                }
            )
