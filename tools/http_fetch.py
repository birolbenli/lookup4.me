"""Safe external HTTP helpers (no credentials, short timeouts)."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from typing import Any

UA = "tools.birolbenli.com/1.0 (+https://tools.birolbenli.com; external-check)"


def absolute_url(raw: str, default_scheme: str = "https") -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        return f"{default_scheme}://{raw.lstrip('/')}"
    return raw


def fetch_url(
    url: str,
    *,
    timeout: float = 10.0,
    follow_redirects: bool = True,
    method: str = "GET",
    max_body: int = 64_000,
) -> dict[str, Any]:
    url = absolute_url(url)
    if not url:
        return {"ok": False, "error": "Missing URL"}

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
            return None

    context = ssl.create_default_context()
    handlers: list[Any] = [urllib.request.HTTPSHandler(context=context)]
    if not follow_redirects:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(
        url,
        method=method,
        headers={"User-Agent": UA, "Accept": "*/*"},
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(max_body)
            headers = {k: v for k, v in resp.headers.items()}
            return {
                "ok": True,
                "url": url,
                "final_url": resp.geturl(),
                "status_code": resp.getcode(),
                "headers": headers,
                "body": body.decode("utf-8", errors="replace"),
                "redirected": resp.geturl() != url,
            }
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read(max_body)
        except Exception:  # noqa: BLE001
            pass
        headers = {k: v for k, v in (exc.headers.items() if exc.headers else [])}
        loc = headers.get("Location") or headers.get("location")
        return {
            "ok": True,
            "url": url,
            "final_url": getattr(exc, "url", None) or url,
            "status_code": exc.code,
            "headers": headers,
            "body": body.decode("utf-8", errors="replace"),
            "location": loc,
            "error": str(exc.reason),
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "url": url, "error": str(exc), "status_code": None, "headers": {}, "body": ""}


def follow_redirect_chain(url: str, *, max_hops: int = 10, timeout: float = 8.0) -> dict[str, Any]:
    url = absolute_url(url)
    hops: list[dict[str, Any]] = []
    current = url
    seen: set[str] = set()
    for _ in range(max_hops):
        if current in seen:
            hops.append({"url": current, "status_code": None, "error": "Redirect loop"})
            break
        seen.add(current)
        res = fetch_url(current, follow_redirects=False, timeout=timeout, max_body=2048)
        code = res.get("status_code")
        hop = {
            "url": current,
            "status_code": code,
            "error": res.get("error"),
        }
        hops.append(hop)
        if not res.get("ok") and code is None:
            break
        if code in (301, 302, 303, 307, 308):
            loc = res.get("location") or (res.get("headers") or {}).get("Location")
            if not loc:
                hop["error"] = "Redirect without Location"
                break
            if loc.startswith("/"):
                from urllib.parse import urljoin

                current = urljoin(current, loc)
            else:
                current = absolute_url(loc)
            hop["location"] = current
            continue
        break
    return {
        "ok": True,
        "start_url": url,
        "final_url": hops[-1]["url"] if hops else url,
        "hop_count": max(0, len(hops) - 1),
        "hops": hops,
        "external_check": True,
    }
