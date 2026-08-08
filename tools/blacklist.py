"""DNSBL / RBL blacklist checks for an IP."""

from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

from .dns_common import get_resolver, is_ip, normalize_domain, resolve_host_chain

DNSBLS = [
    ("zen.spamhaus.org", "Spamhaus ZEN"),
    ("bl.spamcop.net", "SpamCop"),
    ("b.barracudacentral.org", "Barracuda"),
    ("dnsbl.sorbs.net", "SORBS"),
    ("spam.dnsbl.anonmails.de", "Anonmails"),
    ("psbl.surriel.com", "PSBL"),
    ("dnsbl-1.uceprotect.net", "UCEProtect Level 1"),
]


def _reverse_octets(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def _check_one(ip: str, zone: str, name: str) -> dict:
    query = f"{_reverse_octets(ip)}.{zone}"
    try:
        answers = get_resolver().resolve(query, "A")
        codes = [r.to_text() for r in answers]
        listed = True
    except Exception:  # noqa: BLE001
        codes = []
        listed = False
    return {"zone": zone, "name": name, "listed": listed, "codes": codes, "query": query}


def check_blacklist(target: str) -> dict:
    target = (target or "").strip()
    if not target:
        return {"ok": False, "error": "Please enter an IP or domain"}

    if is_ip(target):
        ip = target
        host = None
    else:
        host = normalize_domain(target)
        resolved = resolve_host_chain(host)
        ips = [i for i in resolved.get("ips") or [] if ":" not in i]
        if not ips:
            return {"ok": False, "error": "Could not resolve an IPv4 address", "host": host}
        ip = ips[0]

    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            return {"ok": False, "error": "Only IPv4 blacklist checks are supported", "ip": ip}
    except ValueError:
        return {"ok": False, "error": "Invalid IP address", "ip": ip}

    results = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(_check_one, ip, z, n) for z, n in DNSBLS]
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: r["name"])
    listed_count = sum(1 for r in results if r["listed"])
    return {
        "ok": True,
        "ip": ip,
        "host": host,
        "listed_count": listed_count,
        "clean": listed_count == 0,
        "results": results,
    }
