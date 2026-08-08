"""SPF lookup tool."""

from __future__ import annotations

import re

from .dns_common import is_valid_domain, normalize_domain, query_records

INCLUDE_RE = re.compile(r"include:([^\s]+)", re.I)
REDIRECT_RE = re.compile(r"redirect=([^\s]+)", re.I)
IP_MECH_RE = re.compile(r"\b(ip4|ip6):([^\s]+)", re.I)


def _parse_spf(record: str) -> dict:
    mechanisms = record.split()
    includes = INCLUDE_RE.findall(record)
    redirects = REDIRECT_RE.findall(record)
    ips = [{"type": m.group(1).lower(), "value": m.group(2)} for m in IP_MECH_RE.finditer(record)]
    return {
        "raw": record,
        "mechanisms": mechanisms,
        "includes": includes,
        "redirects": redirects,
        "ips": ips,
        "has_all": any(m.endswith("all") for m in mechanisms),
    }


def lookup_spf(domain: str, follow: bool = True, max_lookups: int = 10) -> dict:
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"ok": False, "error": "Invalid domain name", "domain": domain}

    visited: set[str] = set()
    chain: list[dict] = []
    lookups = 0

    def walk(name: str, via: str) -> None:
        nonlocal lookups
        if name in visited or lookups >= max_lookups:
            return
        visited.add(name)
        lookups += 1

        txt = query_records(name, "TXT")
        spf_records = [
            r["data"].strip('"').replace('" "', "")
            for r in txt.get("records") or []
            if r["data"].strip('"').lower().startswith("v=spf1")
        ]

        entry = {
            "domain": name,
            "via": via,
            "ok": bool(spf_records),
            "error": None if spf_records else txt.get("error") or "No SPF record",
            "records": [_parse_spf(r) for r in spf_records],
        }
        chain.append(entry)

        if not follow or not spf_records:
            return

        parsed = entry["records"][0]
        for include in parsed["includes"]:
            walk(normalize_domain(include), f"include:{include}")
        for redirect in parsed["redirects"]:
            walk(normalize_domain(redirect), f"redirect={redirect}")

    walk(domain, "root")

    root = chain[0] if chain else None
    return {
        "ok": bool(root and root.get("ok")),
        "domain": domain,
        "error": None if root and root.get("ok") else (root or {}).get("error") or "No SPF record",
        "spf": root["records"][0] if root and root.get("records") else None,
        "chain": chain,
        "dns_lookups_used": lookups,
    }
