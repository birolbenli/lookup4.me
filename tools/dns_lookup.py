"""General DNS lookup for common record types."""

from __future__ import annotations

from .dns_common import is_valid_domain, normalize_domain, query_records

SUPPORTED_TYPES = ["A", "AAAA", "CNAME", "NS", "TXT", "SOA", "CAA", "MX", "SRV"]


def lookup_dns(domain: str, rdtype: str = "A") -> dict:
    domain = normalize_domain(domain)
    rdtype = (rdtype or "A").upper().strip()
    if rdtype not in SUPPORTED_TYPES:
        return {
            "ok": False,
            "error": f"Unsupported type. Use: {', '.join(SUPPORTED_TYPES)}",
            "domain": domain,
            "type": rdtype,
        }
    if not is_valid_domain(domain):
        return {"ok": False, "error": "Invalid domain name", "domain": domain, "type": rdtype}

    result = query_records(domain, rdtype)
    return {
        "ok": bool(result.get("records")),
        "domain": domain,
        "type": rdtype,
        "error": None if result.get("records") else result.get("error") or "No records",
        "records": result.get("records") or [],
    }


def lookup_ns(domain: str) -> dict:
    data = lookup_dns(domain, "NS")
    data["tool"] = "ns"
    return data


def lookup_caa(domain: str) -> dict:
    data = lookup_dns(domain, "CAA")
    data["tool"] = "caa"
    return data
