"""External MTA-STS checker (DNS TXT + HTTPS policy)."""

from __future__ import annotations

from .dns_common import is_valid_domain, normalize_domain, query_records
from .http_fetch import fetch_url


def _txt_join(records: list[dict]) -> list[str]:
    out = []
    for r in records or []:
        data = (r.get("data") or "").strip().strip('"').replace('" "', "")
        if data:
            out.append(data)
    return out


def _parse_policy(body: str) -> dict:
    fields: dict[str, str] = {}
    mx: list[str] = []
    for line in (body or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip().lower()
        val = val.strip()
        if key == "mx":
            mx.append(val)
        else:
            fields[key] = val
    return {"fields": fields, "mx": mx}


def check_mtasts(domain: str) -> dict:
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"ok": False, "error": "Please enter a valid domain", "external_check": True}

    dns_name = f"_mta-sts.{domain}"
    dns = query_records(dns_name, "TXT")
    txts = _txt_join(dns.get("records") or [])
    id_txt = next((t for t in txts if "v=STSv1" in t or "v=stsv1" in t.lower()), txts[0] if txts else None)

    policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    pol = fetch_url(policy_url, follow_redirects=True, timeout=10)
    parsed = _parse_policy(pol.get("body") or "") if pol.get("status_code") == 200 else {"fields": {}, "mx": []}
    fields = parsed["fields"]
    mode = (fields.get("mode") or "").lower()
    max_age = fields.get("max_age")
    version = fields.get("version") or ""

    findings = []
    score = 100
    if not id_txt:
        findings.append({"severity": "critical", "title": "Missing _mta-sts TXT", "detail": f"No TXT at {dns_name}"})
        score -= 40
    elif "v=STSv1" not in id_txt and "v=stsv1" not in id_txt.lower():
        findings.append({"severity": "high", "title": "Unexpected MTA-STS TXT", "detail": id_txt})
        score -= 20

    if pol.get("status_code") != 200:
        findings.append(
            {
                "severity": "critical",
                "title": "Policy file unreachable",
                "detail": f"{policy_url} → {pol.get('status_code') or pol.get('error')}",
            }
        )
        score -= 40
    else:
        if version.lower() != "stsv1":
            findings.append({"severity": "high", "title": "Policy version missing/invalid", "detail": version or "—"})
            score -= 15
        if mode not in {"enforce", "testing", "none"}:
            findings.append({"severity": "high", "title": "Invalid or missing mode", "detail": mode or "—"})
            score -= 20
        elif mode == "testing":
            findings.append({"severity": "medium", "title": "Mode is testing", "detail": "Not enforcing yet"})
            score -= 10
        elif mode == "none":
            findings.append({"severity": "high", "title": "Mode is none", "detail": "Policy disabled"})
            score -= 25
        if not max_age or not str(max_age).isdigit():
            findings.append({"severity": "medium", "title": "max_age missing/invalid", "detail": max_age or "—"})
            score -= 10
        if not parsed["mx"]:
            findings.append({"severity": "high", "title": "No mx: patterns in policy", "detail": ""})
            score -= 15

    if not findings:
        findings.append({"severity": "info", "title": "MTA-STS looks configured", "detail": f"mode={mode}"})

    score = max(0, min(100, score))
    return {
        "ok": True,
        "external_check": True,
        "domain": domain,
        "score": score,
        "dns": {"name": dns_name, "records": txts, "id_record": id_txt},
        "policy": {
            "url": policy_url,
            "status_code": pol.get("status_code"),
            "reachable": pol.get("status_code") == 200,
            "version": version,
            "mode": mode,
            "max_age": max_age,
            "mx": parsed["mx"],
            "raw": (pol.get("body") or "")[:2000],
            "error": pol.get("error"),
        },
        "findings": findings,
        "mode": "external_only",
    }
