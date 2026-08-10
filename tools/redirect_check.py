"""External HTTP redirect chain checker."""

from __future__ import annotations

from .http_fetch import absolute_url, follow_redirect_chain


def check_redirects(target: str) -> dict:
    url = absolute_url(target or "", default_scheme="http")
    if not url:
        return {"ok": False, "error": "Please enter a URL or domain", "external_check": True}

    # Probe both http and https start when bare domain
    starts = [url]
    if url.startswith("http://"):
        starts.append("https://" + url[len("http://") :])

    chains = []
    findings = []
    score = 100
    for start in starts[:2]:
        chain = follow_redirect_chain(start)
        chains.append(chain)
        hops = chain.get("hops") or []
        codes = [h.get("status_code") for h in hops]
        final = hops[-1] if hops else {}
        if start.startswith("http://"):
            https_end = str(chain.get("final_url") or "").startswith("https://")
            if https_end:
                findings.append(
                    {"severity": "info", "title": "HTTP upgrades to HTTPS", "detail": chain.get("final_url")}
                )
            else:
                findings.append(
                    {"severity": "high", "title": "HTTP does not land on HTTPS", "detail": chain.get("final_url")}
                )
                score -= 25
        if chain.get("hop_count", 0) > 3:
            findings.append(
                {"severity": "medium", "title": "Long redirect chain", "detail": f"{chain.get('hop_count')} hops"}
            )
            score -= 10
        if any(c in (302, 307) for c in codes[:-1]):
            findings.append(
                {
                    "severity": "info",
                    "title": "Temporary redirect in chain",
                    "detail": "Prefer 301/308 for permanent moves",
                }
            )
        if final.get("error") and final.get("status_code") is None:
            findings.append({"severity": "high", "title": "Chain failed", "detail": final.get("error")})
            score -= 30

    if not findings:
        findings.append({"severity": "info", "title": "Redirect chain inspected", "detail": ""})

    return {
        "ok": True,
        "external_check": True,
        "score": max(0, min(100, score)),
        "chains": chains,
        "findings": findings,
        "mode": "external_only",
    }
