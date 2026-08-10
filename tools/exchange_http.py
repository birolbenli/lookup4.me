"""HTTP surface checks: redirect, HSTS, security headers, methods."""

from __future__ import annotations

from .exchange_endpoints import request


SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


def assess_http(host: str) -> dict:
    https_url = f"https://{host}/"
    http_url = f"http://{host}/"

    https = request(https_url, method="GET", follow_redirects=True)
    http = request(http_url, method="GET", follow_redirects=True)

    https_headers = dict(https.get("headers") or {})
    hsts = https_headers.get("strict-transport-security") or ""

    # Redirect to HTTPS?
    http_final = (http.get("final_url") or "").lower()
    http_to_https = http.get("reachable") and http_final.startswith("https://")

    present = {h: https_headers.get(h) for h in SECURITY_HEADERS if https_headers.get(h)}
    missing = [h for h in SECURITY_HEADERS if h not in present]

    # Safe method probe on HTTPS root
    options = request(https_url, method="OPTIONS", follow_redirects=False)
    trace = request(https_url, method="TRACE", follow_redirects=False)
    allow = (options.get("headers") or {}).get("allow") or (options.get("headers") or {}).get("public") or ""

    cookies_raw = https_headers.get("set-cookie") or ""
    cookie_flags = {
        "secure": "secure" in cookies_raw.lower(),
        "httponly": "httponly" in cookies_raw.lower(),
        "samesite": "samesite" in cookies_raw.lower(),
        "present": bool(cookies_raw),
    }

    return {
        "ok": bool(https.get("reachable")),
        "host": host,
        "https": {
            "reachable": https.get("reachable"),
            "status_code": https.get("status_code"),
            "final_url": https.get("final_url"),
        },
        "http": {
            "reachable": http.get("reachable"),
            "status_code": http.get("status_code"),
            "final_url": http.get("final_url"),
            "redirects_to_https": http_to_https,
        },
        "hsts": {
            "present": bool(hsts),
            "value": hsts[:200],
        },
        "security_headers": {
            "present": present,
            "missing": missing,
        },
        "methods": {
            "options_status": options.get("status_code"),
            "allow": allow[:200],
            "trace_status": trace.get("status_code"),
            "trace_enabled": trace.get("status_code") not in (None, 405, 501, 403, 404)
            and bool(trace.get("reachable")),
        },
        "cookies": cookie_flags,
    }
