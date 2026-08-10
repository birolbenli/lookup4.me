"""External SOA record checker."""

from __future__ import annotations

from .dns_common import is_valid_domain, normalize_domain, query_records


def check_soa(domain: str) -> dict:
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"ok": False, "error": "Please enter a valid domain", "external_check": True}

    q = query_records(domain, "SOA")
    if not q.get("records"):
        return {
            "ok": False,
            "external_check": True,
            "domain": domain,
            "error": q.get("error") or "No SOA record",
        }

    raw = q["records"][0].get("data") or ""
    parts = raw.split()
    # mname rname serial refresh retry expire minimum
    parsed = {
        "raw": raw,
        "primary_ns": normalize_domain(parts[0]) if len(parts) > 0 else None,
        "responsible": parts[1].replace(".", "@", 1).rstrip(".") if len(parts) > 1 else None,
        "serial": parts[2] if len(parts) > 2 else None,
        "refresh": parts[3] if len(parts) > 3 else None,
        "retry": parts[4] if len(parts) > 4 else None,
        "expire": parts[5] if len(parts) > 5 else None,
        "minimum_ttl": parts[6] if len(parts) > 6 else None,
        "ttl": q["records"][0].get("ttl"),
    }
    findings = [{"severity": "info", "title": "SOA published", "detail": f"serial={parsed['serial']}"}]
    return {
        "ok": True,
        "external_check": True,
        "domain": domain,
        "score": 100,
        "soa": parsed,
        "findings": findings,
        "mode": "external_only",
    }
