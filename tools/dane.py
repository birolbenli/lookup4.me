"""External DANE/TLSA record checker (public DNS TLSA query)."""

from __future__ import annotations

from .dns_common import is_valid_domain, normalize_domain, query_records
from .mx import lookup_mx


USAGE = {
    "0": "PKIX-TA",
    "1": "PKIX-EE",
    "2": "DANE-TA",
    "3": "DANE-EE",
}
SELECTOR = {"0": "full cert", "1": "SubjectPublicKeyInfo"}
MATCHING = {"0": "exact", "1": "SHA-256", "2": "SHA-512"}


def _parse_tlsa(data: str) -> dict:
    parts = (data or "").split()
    if len(parts) < 4:
        return {"raw": data}
    usage, selector, matching, *rest = parts
    return {
        "raw": data,
        "usage": usage,
        "usage_label": USAGE.get(usage, usage),
        "selector": selector,
        "selector_label": SELECTOR.get(selector, selector),
        "matching_type": matching,
        "matching_label": MATCHING.get(matching, matching),
        "association": "".join(rest),
    }


def check_dane(domain: str, port: int = 25) -> dict:
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"ok": False, "error": "Please enter a valid domain", "external_check": True}

    mx = lookup_mx(domain)
    hosts = []
    for m in mx.get("records") or []:
        host = normalize_domain((m or {}).get("exchange") or "")
        if host:
            hosts.append(host)
    if not hosts:
        hosts = [domain]

    targets = []
    findings = []
    total_tlsa = 0
    for host in hosts[:8]:
        name = f"_{port}._tcp.{host}"
        q = query_records(name, "TLSA")
        records = [_parse_tlsa(r.get("data") or "") for r in (q.get("records") or [])]
        total_tlsa += len(records)
        targets.append(
            {
                "host": host,
                "name": name,
                "ok": bool(records),
                "error": q.get("error"),
                "records": records,
            }
        )

    score = 100
    if total_tlsa == 0:
        findings.append(
            {
                "severity": "high",
                "title": "No TLSA records found",
                "detail": f"Queried _{port}._tcp.<mx-host> for MX hosts (external DNS only).",
            }
        )
        score = 25
    else:
        findings.append(
            {
                "severity": "info",
                "title": f"{total_tlsa} TLSA record(s) published",
                "detail": "Full DANE validation (DNSSEC chain of trust) is not claimed by this external check.",
            }
        )

    return {
        "ok": True,
        "external_check": True,
        "domain": domain,
        "port": port,
        "score": score,
        "targets": targets,
        "findings": findings,
        "note": "This tool lists public TLSA records. Authoritative DNSSEC validation is out of scope for this check.",
        "mode": "external_only",
    }
