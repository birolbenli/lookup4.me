"""External HTTP security headers analyzer."""

from __future__ import annotations

from .http_fetch import absolute_url, fetch_url

CHECKED = [
    ("strict-transport-security", "Strict-Transport-Security", 15),
    ("content-security-policy", "Content-Security-Policy", 15),
    ("x-content-type-options", "X-Content-Type-Options", 10),
    ("x-frame-options", "X-Frame-Options", 10),
    ("referrer-policy", "Referrer-Policy", 10),
    ("permissions-policy", "Permissions-Policy", 10),
    ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy", 8),
    ("cross-origin-embedder-policy", "Cross-Origin-Embedder-Policy", 7),
    ("cross-origin-resource-policy", "Cross-Origin-Resource-Policy", 5),
]


def check_sec_headers(target: str) -> dict:
    url = absolute_url(target or "")
    if not url:
        return {"ok": False, "error": "Please enter a URL or domain", "external_check": True}

    res = fetch_url(url, follow_redirects=True, timeout=10, max_body=2048)
    if res.get("status_code") is None and not res.get("ok"):
        return {"ok": False, "external_check": True, "url": url, "error": res.get("error") or "Request failed"}

    headers = {k.lower(): v for k, v in (res.get("headers") or {}).items()}
    rows = []
    score = 0
    findings = []
    for key, label, weight in CHECKED:
        val = headers.get(key)
        present = bool(val)
        if present:
            score += weight
            status = "pass"
        else:
            status = "fail"
            findings.append({"severity": "medium" if weight < 12 else "high", "title": f"Missing {label}", "detail": ""})
        rows.append({"header": label, "present": present, "value": val or "—", "status": status, "weight": weight})

    # x-content-type-options expected nosniff
    xcto = headers.get("x-content-type-options", "")
    if xcto and xcto.lower() != "nosniff":
        findings.append({"severity": "medium", "title": "X-Content-Type-Options unusual", "detail": xcto})
        score = max(0, score - 5)

    if score >= 70 and not findings:
        findings.append({"severity": "info", "title": "Strong header baseline", "detail": ""})

    return {
        "ok": True,
        "external_check": True,
        "url": url,
        "final_url": res.get("final_url"),
        "status_code": res.get("status_code"),
        "score": min(100, score),
        "headers": rows,
        "findings": findings,
        "mode": "external_only",
    }
