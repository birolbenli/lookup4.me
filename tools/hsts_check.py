"""External HSTS header checker."""

from __future__ import annotations

import re

from .dns_common import normalize_domain
from .http_fetch import absolute_url, fetch_url


def check_hsts(target: str) -> dict:
    url = absolute_url(target or "")
    if not url:
        return {"ok": False, "error": "Please enter a URL or domain", "external_check": True}
    if url.startswith("http://"):
        # Still probe HTTPS equivalent for HSTS relevance
        https_url = "https://" + url[len("http://") :]
    else:
        https_url = url

    res = fetch_url(https_url, follow_redirects=True, timeout=10, max_body=2048)
    headers = {k.lower(): v for k, v in (res.get("headers") or {}).items()}
    hsts = headers.get("strict-transport-security")
    findings = []
    score = 100
    parsed = {"raw": hsts, "max_age": None, "include_subdomains": False, "preload": False}

    if res.get("status_code") is None and not res.get("ok"):
        return {
            "ok": False,
            "external_check": True,
            "url": https_url,
            "error": res.get("error") or "Request failed",
        }

    if not hsts:
        findings.append({"severity": "high", "title": "HSTS header missing", "detail": https_url})
        score = 25
    else:
        m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        parsed["max_age"] = int(m.group(1)) if m else None
        parsed["include_subdomains"] = "includesubdomains" in hsts.lower()
        parsed["preload"] = "preload" in hsts.lower()
        if parsed["max_age"] is None:
            findings.append({"severity": "critical", "title": "HSTS without max-age", "detail": hsts})
            score -= 40
        elif parsed["max_age"] < 31536000:
            findings.append(
                {
                    "severity": "medium",
                    "title": "max-age under 1 year",
                    "detail": str(parsed["max_age"]),
                }
            )
            score -= 15
        if not parsed["include_subdomains"]:
            findings.append({"severity": "info", "title": "includeSubDomains not set", "detail": ""})
            score -= 5
        if not parsed["preload"]:
            findings.append({"severity": "info", "title": "preload not set", "detail": ""})
            score -= 5
        if score >= 80:
            findings.append({"severity": "info", "title": "HSTS present", "detail": hsts})

    return {
        "ok": True,
        "external_check": True,
        "domain": normalize_domain(https_url),
        "url": https_url,
        "final_url": res.get("final_url"),
        "status_code": res.get("status_code"),
        "score": max(0, min(100, score)),
        "hsts": parsed,
        "findings": findings,
        "mode": "external_only",
    }
