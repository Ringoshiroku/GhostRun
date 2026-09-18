import socket


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
