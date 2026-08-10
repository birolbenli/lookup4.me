"""External security.txt checker."""

from __future__ import annotations

from .dns_common import is_valid_domain, normalize_domain
from .http_fetch import absolute_url, fetch_url


def check_security_txt(target: str) -> dict:
    raw = (target or "").strip()
    domain = normalize_domain(raw)
    if not domain and "://" not in raw:
        return {"ok": False, "error": "Please enter a domain or URL", "external_check": True}
    if not is_valid_domain(domain) and "://" not in raw:
        return {"ok": False, "error": "Please enter a valid domain", "external_check": True}

    base = absolute_url(raw if "://" in raw else domain)
    # Prefer well-known path on origin
    from urllib.parse import urlparse

    p = urlparse(base)
    origin = f"{p.scheme}://{p.netloc}"
    urls = [
        f"{origin}/.well-known/security.txt",
        f"{origin}/security.txt",
    ]
    chosen = None
    for u in urls:
        res = fetch_url(u, timeout=10, max_body=32_000)
        if res.get("status_code") == 200 and res.get("body"):
            chosen = res
            chosen["checked_url"] = u
            break
        if chosen is None:
            chosen = res
            chosen["checked_url"] = u

    body = (chosen or {}).get("body") or ""
    fields: dict[str, list[str]] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        k, v = line.split(":", 1)
        fields.setdefault(k.strip(), []).append(v.strip())

    findings = []
    score = 100
    if (chosen or {}).get("status_code") != 200:
        findings.append(
            {
                "severity": "high",
                "title": "security.txt not found",
                "detail": (chosen or {}).get("checked_url"),
            }
        )
        score = 10
    else:
        if "Contact" not in fields:
            findings.append({"severity": "critical", "title": "Missing Contact", "detail": ""})
            score -= 40
        if "Expires" not in fields:
            findings.append({"severity": "medium", "title": "Missing Expires", "detail": ""})
            score -= 15
        if "Canonical" not in fields:
            findings.append({"severity": "info", "title": "No Canonical field", "detail": ""})
            score -= 5
        if score >= 80:
            findings.append({"severity": "info", "title": "security.txt present", "detail": chosen.get("checked_url")})

    return {
        "ok": True,
        "external_check": True,
        "domain": domain,
        "score": max(0, min(100, score)),
        "url": (chosen or {}).get("checked_url"),
        "status_code": (chosen or {}).get("status_code"),
        "fields": fields,
        "raw": body[:4000],
        "findings": findings,
        "mode": "external_only",
    }
