"""External TLS-RPT (_smtp._tls) checker."""

from __future__ import annotations

import re

from .dns_common import is_valid_domain, normalize_domain, query_records


def _txt_join(records: list[dict]) -> list[str]:
    out = []
    for r in records or []:
        data = (r.get("data") or "").strip().strip('"').replace('" "', "")
        if data:
            out.append(data)
    return out


def check_tlsrpt(domain: str) -> dict:
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"ok": False, "error": "Please enter a valid domain", "external_check": True}

    name = f"_smtp._tls.{domain}"
    dns = query_records(name, "TXT")
    records = _txt_join(dns.get("records") or [])
    findings = []
    score = 100
    parsed = []

    if not records:
        findings.append({"severity": "high", "title": "No TLS-RPT record", "detail": f"Missing TXT at {name}"})
        score = 20
    for raw in records:
        tags = {}
        for part in re.split(r"\s*;\s*", raw.strip().rstrip(";")):
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()
        version = tags.get("v", "")
        rua = tags.get("rua", "")
        item = {"raw": raw, "version": version, "rua": rua, "tags": tags}
        parsed.append(item)
        if version.upper() != "TLSRPTv1":
            findings.append({"severity": "high", "title": "Invalid TLS-RPT version", "detail": version or "—"})
            score -= 30
        if not rua:
            findings.append({"severity": "critical", "title": "Missing rua", "detail": raw})
            score -= 40
        else:
            for dest in rua.split(","):
                dest = dest.strip()
                if not (dest.startswith("mailto:") or dest.startswith("https://")):
                    findings.append(
                        {"severity": "medium", "title": "Unusual rua destination", "detail": dest}
                    )
                    score -= 10

    if records and not findings:
        findings.append({"severity": "info", "title": "TLS-RPT present", "detail": parsed[0].get("rua")})

    return {
        "ok": True,
        "external_check": True,
        "domain": domain,
        "score": max(0, min(100, score)),
        "dns_name": name,
        "records": parsed,
        "findings": findings,
        "mode": "external_only",
    }
