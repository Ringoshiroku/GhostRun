import time
import psutil
import socket
import threading
import subprocess
import re


# =========================================================
# SERVICE INTELLIGENCE
# =========================================================

TELEGRAM_IP_RANGES = [
    ("149.154.0.0", "149.154.255.255"),
    ("91.108.0.0", "91.108.255.255"),
]

DISCORD_DOMAINS = [
    "discord.com",
    "discordapp.com",
    "discord.gg",
    "gateway.discord.gg",
]

DISCORD_IP_PREFIX = [
    "162.159.",   # Cloudflare
    "104.16.",
    "104.17.",
]


def ip_to_int(ip):
    try:
        return int.from_bytes(socket.inet_aton(ip), "big")
    except Exception:
        return None


def ip_in_range(ip, start, end):
    ip_i = ip_to_int(ip)
    if ip_i is None:
        return False
    return ip_to_int(start) <= ip_i <= ip_to_int(end)


# =========================================================
# DNS CACHE (WINDOWS)
# =========================================================

def load_dns_cache():
    """
    Parse `ipconfig /displaydns` output.
    Returns: { ip -> set(domains) }
    """
    cache = {}
    try:
        out = subprocess.check_output(
            ["ipconfig", "/displaydns"],
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )
    except Exception:
        return cache

    current_domain = None

    for line in out.splitlines():
        line = line.strip()

        if line.lower().startswith("record name"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                current_domain = parts[1].strip()

        elif "a (host) record" in line.lower() and current_domain:
            parts = line.split(":", 1)
            if len(parts) == 2:
                ip = parts[1].strip()
                cache.setdefault(ip, set()).add(current_domain)

    return cache


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# =========================================================
# NETWORK MONITOR (COMBINED)
# =========================================================

class NetworkMonitor(threading.Thread):
    def __init__(self, emit, interval=1):
        super().__init__(daemon=True)
        self.emit = emit
        self.interval = interval
        self.running = True
        self.seen = set()
        self.dns_cache = load_dns_cache()

    # -----------------------------------------------------
    # SERVICE INFERENCE
    # -----------------------------------------------------
    def infer_service(self, proc_name, remote_ip, remote_port):
        domain_hits = set()

        # DNS cache lookup
        if remote_ip in self.dns_cache:
            domain_hits |= self.dns_cache[remote_ip]

        # reverse DNS fallback
        rdns = reverse_dns(remote_ip)
        if rdns:
            domain_hits.add(rdns)

        # Telegram
        if remote_port == 443:
            for start, end in TELEGRAM_IP_RANGES:
                if ip_in_range(remote_ip, start, end):
                    return {
                        "service": "Telegram",
                        "confidence": "medium",
                        "domains": list(domain_hits),
                    }

        # Discord (domain-based)
        for d in domain_hits:
            for sig in DISCORD_DOMAINS:
                if sig in d.lower():
                    return {
                        "service": "Discord",
                        "confidence": "high",
                        "domains": list(domain_hits),
                    }

        # Discord (IP heuristic)
        for prefix in DISCORD_IP_PREFIX:
            if remote_ip.startswith(prefix) and remote_port == 443:
                return {
                    "service": "Discord",
                    "confidence": "medium",
                    "domains": list(domain_hits),
                }

        # Weak heuristic (process name)
        if proc_name and "discord" in proc_name.lower():
            return {
                "service": "Discord",
                "confidence": "low",
                "domains": list(domain_hits),
            }

        return None

    # -----------------------------------------------------
    # THREAD LOOP
    # -----------------------------------------------------
    def run(self):
        while self.running:
            try:
                conns = psutil.net_connections(kind="inet")
            except Exception:
                time.sleep(self.interval)
                continue

            for c in conns:
                if not c.raddr or not c.pid:
                    continue

                key = (c.pid, c.laddr, c.raddr, c.type)
                if key in self.seen:
                    continue

                self.seen.add(key)

                try:
                    proc = psutil.Process(c.pid)
                    proc_name = proc.name()
                except Exception:
                    proc_name = None

                laddr = f"{c.laddr.ip}:{c.laddr.port}"
                raddr = f"{c.raddr.ip}:{c.raddr.port}"

                proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"

                service_info = self.infer_service(
                    proc_name,
                    c.raddr.ip,
                    c.raddr.port,
                )

                data = {
                    "pid": c.pid,
                    "process": proc_name,
                    "laddr": laddr,
                    "raddr": raddr,
                    "proto": proto,
                    "status": c.status,
                }

                if service_info:
                    data.update(service_info)

                self.emit(
                    category="network",
                    event="connection",
                    data=data,
                )

            time.sleep(self.interval)

    def stop(self):
        self.running = False
