"""External BIMI checker (default._bimi + logo URL)."""

from __future__ import annotations

import re

from .dns_common import is_valid_domain, normalize_domain, query_records
from .http_fetch import fetch_url


def _txt_join(records: list[dict]) -> list[str]:
    out = []
    for r in records or []:
        data = (r.get("data") or "").strip().strip('"').replace('" "', "")
        if data:
            out.append(data)
    return out


def check_bimi(domain: str) -> dict:
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"ok": False, "error": "Please enter a valid domain", "external_check": True}

    name = f"default._bimi.{domain}"
    dns = query_records(name, "TXT")
    records = _txt_join(dns.get("records") or [])
    findings = []
    score = 100
    parsed = None
    logo = None
    vmc = None

    if not records:
        findings.append({"severity": "high", "title": "No BIMI record", "detail": f"Missing TXT at {name}"})
        score = 15
    else:
        raw = records[0]
        tags = {}
        for part in re.split(r"\s*;\s*", raw.strip().rstrip(";")):
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()
        version = tags.get("v", "")
        logo = tags.get("l") or tags.get("logo")
        vmc = tags.get("a")
        parsed = {"raw": raw, "version": version, "logo_url": logo, "authority_url": vmc, "tags": tags}
        if version.upper() != "BIMI1":
            findings.append({"severity": "high", "title": "Unexpected BIMI version", "detail": version or "—"})
            score -= 25
        if not logo:
            findings.append({"severity": "critical", "title": "Missing logo URL (l=)", "detail": ""})
            score -= 40
        else:
            logo_res = fetch_url(logo, timeout=10, max_body=256_000)
            ct = (logo_res.get("headers") or {}).get("Content-Type", "")
            logo_ok = logo_res.get("status_code") == 200
            parsed["logo_fetch"] = {
                "status_code": logo_res.get("status_code"),
                "content_type": ct,
                "ok": logo_ok,
                "error": logo_res.get("error"),
            }
            if not logo_ok:
                findings.append({"severity": "high", "title": "Logo URL not reachable", "detail": logo})
                score -= 25
            elif "svg" not in ct.lower() and not logo.lower().endswith(".svg"):
                findings.append(
                    {"severity": "medium", "title": "Logo may not be SVG", "detail": ct or logo}
                )
                score -= 10
        if not vmc:
            findings.append(
                {
                    "severity": "info",
                    "title": "No VMC/CMC authority URL (a=)",
                    "detail": "Some providers require a Verified Mark Certificate for inbox display.",
                }
            )
            score -= 5

    if records and score >= 80 and not any(f["severity"] in {"critical", "high"} for f in findings):
        findings.append({"severity": "info", "title": "BIMI record present", "detail": logo or ""})

    return {
        "ok": True,
        "external_check": True,
        "domain": domain,
        "score": max(0, min(100, score)),
        "dns_name": name,
        "record": parsed,
        "findings": findings,
        "mode": "external_only",
    }
