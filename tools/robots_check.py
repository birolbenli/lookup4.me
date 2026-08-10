"""External robots.txt checker."""

from __future__ import annotations

from urllib.parse import urlparse

from .dns_common import is_valid_domain, normalize_domain
from .http_fetch import absolute_url, fetch_url


def check_robots(target: str) -> dict:
    raw = (target or "").strip()
    domain = normalize_domain(raw)
    if not is_valid_domain(domain) and "://" not in raw:
        return {"ok": False, "error": "Please enter a valid domain", "external_check": True}
    base = absolute_url(raw if "://" in raw else domain)
    origin = f"{urlparse(base).scheme}://{urlparse(base).netloc}"
    url = f"{origin}/robots.txt"
    res = fetch_url(url, timeout=10, max_body=64_000)
    body = res.get("body") or ""
    findings = []
    score = 100
    sitemaps = []
    agents = []
    for line in body.splitlines():
        low = line.strip()
        if not low or low.startswith("#"):
            continue
        if ":" not in low:
            continue
        k, v = low.split(":", 1)
        k = k.strip().lower()
        v = v.strip()
        if k == "sitemap":
            sitemaps.append(v)
        elif k == "user-agent":
            agents.append(v)

    if res.get("status_code") != 200:
        findings.append({"severity": "medium", "title": "robots.txt not found", "detail": url})
        score = 40
    else:
        if not agents:
            findings.append({"severity": "medium", "title": "No User-agent lines", "detail": ""})
            score -= 20
        if not sitemaps:
            findings.append({"severity": "info", "title": "No Sitemap directives", "detail": ""})
            score -= 5
        findings.append(
            {
                "severity": "info",
                "title": "robots.txt fetched",
                "detail": f"{len(agents)} user-agent block(s), {len(sitemaps)} sitemap(s)",
            }
        )

    return {
        "ok": True,
        "external_check": True,
        "domain": domain,
        "url": url,
        "status_code": res.get("status_code"),
        "score": max(0, min(100, score)),
        "user_agents": agents[:40],
        "sitemaps": sitemaps[:20],
        "raw": body[:6000],
        "findings": findings,
        "mode": "external_only",
    }
