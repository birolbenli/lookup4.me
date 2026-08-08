"""HTTP status and response header checker."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request

from .dns_common import normalize_domain


def check_http(url: str, timeout: float = 10.0) -> dict:
    raw = (url or "").strip()
    if not raw:
        return {"ok": False, "error": "Please enter a URL or domain"}

    if "://" not in raw:
        raw = "https://" + normalize_domain(raw)

    req = urllib.request.Request(
        raw,
        method="GET",
        headers={"User-Agent": "lookup4.me/1.0 (+https://lookup4.me)"},
    )
    context = ssl.create_default_context()

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            headers = {k: v for k, v in resp.headers.items()}
            return {
                "ok": True,
                "url": raw,
                "final_url": resp.geturl(),
                "status_code": resp.getcode(),
                "headers": headers,
            }
    except urllib.error.HTTPError as exc:
        headers = {k: v for k, v in (exc.headers.items() if exc.headers else [])}
        return {
            "ok": True,
            "url": raw,
            "final_url": exc.geturl() if hasattr(exc, "geturl") else raw,
            "status_code": exc.code,
            "headers": headers,
            "error": str(exc.reason),
        }
    except Exception as exc:  # noqa: BLE001
        # retry http if https failed for bare domains
        if raw.startswith("https://"):
            http_url = "http://" + raw[len("https://") :]
            try:
                req = urllib.request.Request(
                    http_url,
                    method="GET",
                    headers={"User-Agent": "lookup4.me/1.0"},
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    headers = {k: v for k, v in resp.headers.items()}
                    return {
                        "ok": True,
                        "url": http_url,
                        "final_url": resp.geturl(),
                        "status_code": resp.getcode(),
                        "headers": headers,
                        "note": "Fell back to HTTP",
                    }
            except Exception:  # noqa: BLE001
                pass
        return {"ok": False, "url": raw, "error": str(exc)}
