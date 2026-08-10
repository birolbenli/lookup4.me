"""External CNAME chain checker."""

from __future__ import annotations

from .dns_common import is_valid_domain, normalize_domain, resolve_host_chain


def check_cname(hostname: str) -> dict:
    hostname = normalize_domain(hostname)
    if not is_valid_domain(hostname):
        return {"ok": False, "error": "Please enter a valid hostname", "external_check": True}

    chain = resolve_host_chain(hostname)
    steps = chain.get("chain") or []
    cname_hops = [s for s in steps if s.get("type") == "CNAME"]
    broken = any(s.get("type") in {"UNRESOLVED", "LOOP"} for s in steps)
    findings = []
    score = 100
    if broken:
        findings.append({"severity": "critical", "title": "Broken or looping CNAME chain", "detail": ""})
        score = 20
    elif not cname_hops:
        findings.append(
            {
                "severity": "info",
                "title": "No CNAME for this name",
                "detail": "Name resolves directly (or has no CNAME).",
            }
        )
        score = 90
    else:
        findings.append(
            {
                "severity": "info",
                "title": f"CNAME chain length {len(cname_hops)}",
                "detail": f"Final IPs: {', '.join(chain.get('ips') or []) or '—'}",
            }
        )
        if len(cname_hops) > 3:
            findings.append({"severity": "medium", "title": "Long CNAME chain", "detail": "Prefer shorter chains"})
            score -= 15

    return {
        "ok": True,
        "external_check": True,
        "hostname": hostname,
        "score": score,
        "chain": steps,
        "final_ips": chain.get("ips") or [],
        "cname_count": len(cname_hops),
        "findings": findings,
        "mode": "external_only",
    }
