"""AAHC — Adam Akıllı Header Checker.

External disclosure scan: leaky/version headers, private IPs, weak cookies.
Optionally fills the first safe front-page form with random data and re-checks
the follow-up response (same-site only).
"""

from __future__ import annotations

import html.parser
import ipaddress
import random
import re
import secrets
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from typing import Any

from .dns_common import normalize_domain
from .http_fetch import UA, absolute_url

PRIVATE_IP_RE = re.compile(
    r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}|127(?:\.\d{1,3}){3})\b"
)

CAPTCHA_IMG_RE = re.compile(
    r"""<img[^>]+id=["']CaptchaImage["'][^>]*src=["']([^"']+)["']"""
    r"""|<img[^>]+src=["']([^"']*Captcha[^"']*)["']""",
    re.I,
)
MATH_CAPTCHA_RE = re.compile(
    r"(\d{1,3})\s*([+\-x×*÷/])\s*(\d{1,3})",
    re.I,
)

# Headers that commonly disclose stack / backend identity
DISCLOSURE_HEADERS: dict[str, str] = {
    "server": "high",
    "x-powered-by": "high",
    "x-aspnet-version": "high",
    "x-aspnetmvc-version": "high",
    "x-runtime": "medium",
    "x-version": "medium",
    "x-generator": "medium",
    "x-drupal-cache": "low",
    "x-drupal-dynamic-cache": "low",
    "x-varnish": "low",
    "via": "medium",
    "x-backend-server": "high",
    "x-served-by": "medium",
    "x-cache": "low",
    "x-cache-hits": "low",
    "x-host": "medium",
    "x-redirect-by": "low",
    "x-debug-token": "high",
    "x-debug-token-link": "high",
    "x-php-version": "high",
    "x-rack-cache": "low",
    "x-request-id": "low",
    "x-amzn-requestid": "low",
    "x-amz-cf-id": "low",
    "cf-ray": "low",
    "x-owa-version": "high",
    "x-feserver": "high",
    "x-beserver": "high",
    "x-sourcemap": "medium",
    "x-content-powered-by": "medium",
}

MISSING_SECURITY = [
    ("strict-transport-security", "Strict-Transport-Security", "medium"),
    ("content-security-policy", "Content-Security-Policy", "medium"),
    ("x-content-type-options", "X-Content-Type-Options", "low"),
    ("x-frame-options", "X-Frame-Options", "low"),
    ("referrer-policy", "Referrer-Policy", "low"),
]

SKIP_FORM_ATTR = re.compile(
    r"(login|signin|sign-in|log-in|auth|password|passwd|payment|checkout|card)", re.I
)
EMAIL_HINT = re.compile(r"(e-?mail|mail)", re.I)
PHONE_HINT = re.compile(r"(phone|tel|mobile|gsm)", re.I)
NAME_HINT = re.compile(r"(name|adsoyad|fullname|surname|first|last)", re.I)
URL_HINT = re.compile(r"(url|website|homepage|site)", re.I)


def _host_of(url: str) -> str:
    try:
        return normalize_domain(urllib.parse.urlparse(url).hostname or "")
    except Exception:  # noqa: BLE001
        return ""


def _same_site(a: str, b: str) -> bool:
    ha, hb = _host_of(a), _host_of(b)
    if not ha or not hb:
        return False
    if ha == hb:
        return True
    return ha.endswith("." + hb) or hb.endswith("." + ha)


_PUBLIC_HOST_CACHE: dict[str, tuple[bool, str]] = {}


def _url_is_public(url: str) -> tuple[bool, str]:
    """Block private/loopback/link-local/metadata targets."""
    import time

    parsed = urllib.parse.urlparse(absolute_url(url))
    if parsed.scheme not in {"http", "https"}:
        return False, "Only http/https URLs are allowed"
    host = (parsed.hostname or "").lower()
    if not host:
        return False, "Missing hostname"
    if host in {"localhost", "metadata.google.internal"}:
        return False, "Local/metadata hosts are blocked"

    cached = _PUBLIC_HOST_CACHE.get(host)
    if cached is not None:
        return cached

    last_exc: Exception | None = None
    infos: list[Any] = []
    # Docker embedded DNS occasionally returns EAI_AGAIN under load
    for attempt in range(4):
        try:
            infos = socket.getaddrinfo(host, None)
            last_exc = None
            break
        except socket.gaierror as exc:
            last_exc = exc
            if attempt < 3:
                time.sleep(0.12 * (attempt + 1))
    if last_exc is not None:
        result = (False, f"DNS failed: {last_exc}")
        # Do not cache failures — allow a later retry in the same process
        return result

    for info in infos:
        ip = info[4][0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        ):
            result = (False, f"Target resolves to non-public address ({ip})")
            _PUBLIC_HOST_CACHE[host] = result
            return result

    result = (True, "")
    _PUBLIC_HOST_CACHE[host] = result
    return result


def _request_bytes(
    url: str,
    *,
    cookie_jar: CookieJar | None,
    referer: str = "",
    timeout: float = 12.0,
    max_body: int = 500_000,
) -> dict[str, Any]:
    url = absolute_url(url)
    ok_public, reason = _url_is_public(url)
    if not ok_public:
        return {"ok": False, "error": reason, "data": b""}
    context = ssl.create_default_context()
    handlers: list[Any] = [urllib.request.HTTPSHandler(context=context)]
    if cookie_jar is not None:
        handlers.insert(0, urllib.request.HTTPCookieProcessor(cookie_jar))
    opener = urllib.request.build_opener(*handlers)
    hdrs = {"User-Agent": UA, "Accept": "image/*,*/*;q=0.8"}
    if referer:
        hdrs["Referer"] = referer
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return {
                "ok": True,
                "url": resp.geturl(),
                "status_code": resp.getcode(),
                "content_type": resp.headers.get("Content-Type", ""),
                "data": resp.read(max_body),
            }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "data": b""}


def _eval_math_captcha(text: str) -> str | None:
    """Parse OCR text like '61-5=?' / '2 + 27 = ?' into the numeric answer."""
    raw = (text or "").strip()
    if not raw:
        return None
    cleaned = (
        raw.replace("×", "*")
        .replace("x", "*")
        .replace("X", "*")
        .replace("÷", "/")
        .replace("—", "-")
        .replace("–", "-")
        .replace("=", " = ")
        .replace("?", " ")
    )
    cleaned = re.sub(r"[^0-9+\-*/.\s]", " ", cleaned)
    m = MATH_CAPTCHA_RE.search(cleaned)
    if not m:
        m = MATH_CAPTCHA_RE.search(re.sub(r"\s+", "", cleaned))
    if not m:
        return None
    a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
    if op == "+":
        return str(a + b)
    if op == "-":
        return str(a - b)
    if op in {"*", "x", "×"}:
        return str(a * b)
    if op in {"/", "÷"}:
        if b == 0 or a % b != 0:
            return None
        return str(a // b)
    return None


_DDDD_OCR = None


def _dddd_ocr():
    global _DDDD_OCR
    if _DDDD_OCR is None:
        import ddddocr  # type: ignore

        _DDDD_OCR = ddddocr.DdddOcr(show_ad=False)
    return _DDDD_OCR


def _captcha_blue_mask(img: Any) -> Any:
    """Mechsoft GIFs use saturated blue ink on white + speckles."""
    import numpy as np

    arr = np.array(img.convert("RGBA"))
    r = arr[:, :, 0].astype(int)
    b = arr[:, :, 2].astype(int)
    return ((b >= 230) & (r <= 60)).astype(np.uint8)


def _captcha_denoise_cc(mask: Any, min_count: int = 5) -> Any:
    import numpy as np

    h, w = mask.shape
    labels = np.zeros_like(mask, dtype=np.int32)
    lab = 0
    keep: set[int] = set()
    for y in range(h):
        for x in range(w):
            if not mask[y, x] or labels[y, x]:
                continue
            lab += 1
            stack = [(y, x)]
            labels[y, x] = lab
            count = 0
            while stack:
                cy, cx = stack.pop()
                count += 1
                for ny, nx in ((cy - 1, cx), (cy + 1, cx), (cy, cx - 1), (cy, cx + 1)):
                    if 0 <= ny < h and 0 <= nx < w and mask[ny, nx] and labels[ny, nx] == 0:
                        labels[ny, nx] = lab
                        stack.append((ny, nx))
            if count >= min_count:
                keep.add(lab)
    out = np.zeros_like(mask)
    for i in keep:
        out[labels == i] = 1
    return out


def _captcha_col_ranges(mask: Any) -> list[tuple[int, int]]:
    on = mask.sum(axis=0) > 0
    ranges: list[tuple[int, int]] = []
    start = None
    for i, v in enumerate(on):
        if v and start is None:
            start = i
        elif not v and start is not None:
            ranges.append((start, i - 1))
            start = None
    if start is not None:
        ranges.append((start, len(on) - 1))
    return ranges


def _captcha_glyph_h(mask: Any, x0: int, x1: int) -> tuple[int, float, int]:
    import numpy as np

    band = mask[:, x0 : x1 + 1]
    rows = band.sum(axis=1)
    ys = np.where(rows > 0)[0]
    if len(ys) == 0:
        return 0, 0.0, 0
    return int(ys[-1] - ys[0] + 1), float((ys[0] + ys[-1]) / 2), int(band.sum())


def _captcha_classify_op(mask: Any, x0: int, x1: int, img_h: int) -> str:
    """Classify + / - / = using ink concentration (noise-resistant)."""
    import numpy as np

    if x1 < x0:
        return "-"
    band = mask[:, max(0, x0) : x1 + 1]
    rows = band.sum(axis=1).astype(float)
    total = float(rows.sum())
    if total <= 0:
        return "-"
    peak = int(np.argmax(rows))
    near = float(rows[max(0, peak - 2) : peak + 3].sum())
    conc = near / total
    gh, cy, _ = _captcha_glyph_h(mask, x0, x1)
    mid = img_h / 2.0

    # Equals: two well-separated horizontal bands, each concentrated
    active = rows > max(1.0, total * 0.08)
    runs: list[tuple[int, int]] = []
    s = None
    for i, v in enumerate(active):
        if v and s is None:
            s = i
        elif not v and s is not None:
            runs.append((s, i - 1))
            s = None
    if s is not None:
        runs.append((s, len(active) - 1))
    if len(runs) >= 2:
        scored = sorted(
            ((float(rows[a : b + 1].sum()), a, b) for a, b in runs),
            reverse=True,
        )
        if len(scored) >= 2 and scored[1][0] >= total * 0.22:
            gap = abs(((scored[0][1] + scored[0][2]) / 2) - ((scored[1][1] + scored[1][2]) / 2))
            if gap >= max(4, int(0.08 * img_h)) and gh <= 0.55 * img_h:
                return "="

    # Plus: horizontal bar crossed by a vertical stem
    horiz = int((band[max(0, peak - 1) : peak + 2].sum(axis=0) > 0).sum())
    has_stem = False
    for c in range(band.shape[1]):
        ys = np.where(band[:, c] > 0)[0]
        if len(ys) == 0:
            continue
        if int(ys[0]) <= peak - 3 and int(ys[-1]) >= peak + 3:
            has_stem = True
            break
    if has_stem and horiz >= 3:
        return "+"

    # Minus: most ink in a thin horizontal band, no stem
    if conc >= 0.68 and not has_stem:
        return "-"
    if conc >= 0.85 and abs(cy - mid) <= 0.28 * img_h:
        return "-"

    # Tall cross without clear concentration
    upper = float(rows[: img_h // 2].sum())
    lower = float(rows[img_h // 2 :].sum())
    if gh >= 0.40 * img_h and upper > 0 and lower > 0:
        return "+"
    return "-"


def _captcha_ocr_digit(ocr: Any, mask: Any, x0: int, x1: int) -> str:
    import io

    import numpy as np
    from PIL import Image, ImageFilter, ImageOps  # type: ignore

    h, w = mask.shape
    pad = 2
    xa, xb = max(0, x0 - pad), min(w, x1 + pad + 1)
    crop_m = mask[:, xa:xb]
    im = Image.fromarray((crop_m * 255).astype(np.uint8))
    im = im.filter(ImageFilter.MaxFilter(3))  # solidify dotted stroke inside glyph only
    arr = np.array(im) > 0
    if not arr.any():
        return ""
    ys = np.where(arr.any(axis=1))[0]
    xs = np.where(arr.any(axis=0))[0]
    im = im.crop((int(xs[0]), int(ys[0]), int(xs[-1]) + 1, int(ys[-1]) + 1))
    inv = ImageOps.invert(im.convert("L"))
    inv = ImageOps.expand(inv, border=14, fill=255)
    inv = inv.resize(
        (max(56, inv.width * 5), max(56, inv.height * 5)),
        Image.Resampling.NEAREST,
    )
    buf = io.BytesIO()
    inv.save(buf, format="PNG")
    raw = (ocr.classification(buf.getvalue()) or "").strip()
    digs = re.sub(r"\D", "", raw)
    if not digs:
        return ""
    # Single-glyph crops should be one digit; wide merges keep all digits
    if (x1 - x0) < 28 and len(digs) > 1:
        return digs[0]
    return digs


def _ocr_math_captcha(image_bytes: bytes) -> dict[str, Any]:
    """Solve Mechsoft blue dotted math captchas (e.g. 61-5=?)."""
    try:
        import numpy as np
        from PIL import Image  # type: ignore
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"OCR dependencies missing: {exc}", "text": "", "answer": None}

    import io

    try:
        img = Image.open(io.BytesIO(image_bytes))
        if getattr(img, "n_frames", 1) > 1:
            img.seek(0)

        ocr = _dddd_ocr()
        # Quick path: raw GIF only if it is a clean a±b expression
        whole = (ocr.classification(image_bytes) or "").strip()
        whole_compact = re.sub(r"\s+", "", whole)
        m_raw = re.fullmatch(r"(\d{1,3})([+\-])(\d{1,3})", whole_compact)
        if m_raw:
            expr_raw = f"{m_raw.group(1)}{m_raw.group(2)}{m_raw.group(3)}"
            ans = _eval_math_captcha(expr_raw)
            if ans is not None:
                return {
                    "ok": True,
                    "text": expr_raw,
                    "answer": ans,
                    "error": None,
                    "engine": "ddddocr-raw",
                }

        mask = _captcha_denoise_cc(_captcha_blue_mask(img), min_count=5)
        h, w = mask.shape
        glyphs: list[dict[str, Any]] = []

        for x0, x1 in _captcha_col_ranges(mask):
            gh, _cy, count = _captcha_glyph_h(mask, x0, x1)
            bw = x1 - x0 + 1
            if count < 12 or bw < 2:
                continue
            if x0 >= int(w * 0.80):
                glyphs.append({"kind": "trail", "x0": x0, "x1": x1})
                continue
            # Tall narrow stroke is usually digit "1", not an operator
            # but a minus can be narrow with moderate height — use ink concentration.
            band = mask[:, x0 : x1 + 1]
            rows = band.sum(axis=1).astype(float)
            total = float(rows.sum()) or 1.0
            peak = int(rows.argmax())
            conc = float(rows[max(0, peak - 2) : peak + 3].sum()) / total
            dash_like = conc >= 0.62 and gh <= int(0.48 * h)
            tall_narrow = gh >= int(0.48 * h) and bw <= 18 and not dash_like
            short_op = gh <= max(9, int(0.32 * h)) or dash_like
            mid_narrow_op = bw <= 14 and gh <= int(0.38 * h) and not tall_narrow
            if (short_op or mid_narrow_op) and not tall_narrow:
                op = _captcha_classify_op(mask, x0, x1, h)
                glyphs.append({"kind": "op", "op": op, "x0": x0, "x1": x1, "h": gh, "bw": bw})
                continue
            dig = _captcha_ocr_digit(ocr, mask, x0, x1)
            if not dig and tall_narrow:
                dig = "1"
            glyphs.append({"kind": "digit", "digit": dig, "x0": x0, "x1": x1, "h": gh})

        left: list[str] = []
        right: list[str] = []
        op: str | None = None
        phase = "left"
        for g in glyphs:
            if g["kind"] == "trail":
                continue
            if g["kind"] == "op":
                if g["op"] == "=":
                    phase = "done"
                    continue
                if op is None and g["op"] in {"+", "-", "*", "/"}:
                    op = g["op"]
                    phase = "right"
                continue
            dig = g.get("digit") or ""
            if not dig:
                continue
            if phase == "left":
                left.append(dig)
            elif phase == "right":
                right.append(dig)

        # Fallback: split digit glyphs at the largest gap and classify that gap
        if op is None:
            digs = [g for g in glyphs if g["kind"] == "digit" and g.get("digit")]
            if len(digs) >= 2:
                best_i, best_gap = 0, -1
                for i in range(len(digs) - 1):
                    gap = digs[i + 1]["x0"] - digs[i]["x1"]
                    if gap > best_gap:
                        best_gap, best_i = gap, i
                left = [d["digit"] for d in digs[: best_i + 1]]
                right = [d["digit"] for d in digs[best_i + 1 :]]
                op = _captcha_classify_op(
                    mask, digs[best_i]["x1"] + 1, digs[best_i + 1]["x0"] - 1, h
                )

        expr = f"{''.join(left)}{op or '?'}{''.join(right)}"
        # Mechsoft DefaultCaptcha: only a±b with 1–2 digit operands
        if not re.fullmatch(r"\d{1,2}[+\-]\d{1,2}", expr):
            return {
                "ok": False,
                "error": "Could not parse math captcha from OCR",
                "text": whole or expr,
                "answer": None,
                "glyphs": [
                    {k: g.get(k) for k in ("kind", "digit", "op", "x0", "x1")} for g in glyphs
                ],
            }
        ans = _eval_math_captcha(expr)
        if ans is not None:
            return {
                "ok": True,
                "text": expr,
                "answer": ans,
                "error": None,
                "engine": "ddddocr-blue",
                "whole": whole,
            }
        return {
            "ok": False,
            "error": "Could not parse math captcha from OCR",
            "text": whole or expr,
            "answer": None,
            "glyphs": [
                {k: g.get(k) for k in ("kind", "digit", "op", "x0", "x1")} for g in glyphs
            ],
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "text": "", "answer": None}


def _form_captcha_rejected(page: dict[str, Any], action_url: str) -> bool:
    """True when wrong captcha bounces POST back to site root (Location: /)."""
    code = page.get("status_code")
    if code not in (301, 302, 303, 307, 308):
        return False
    loc = (
        page.get("location")
        or (page.get("headers") or {}).get("Location")
        or (page.get("headers") or {}).get("location")
        or ""
    )
    if not loc:
        return False
    next_url = urllib.parse.urljoin(action_url, loc)
    path = urllib.parse.urlparse(next_url).path or "/"
    return path in {"/", ""}


def _captcha_field_overrides(form: dict[str, Any], answer: str) -> dict[str, str]:
    overrides: dict[str, str] = {}
    for fname in ("CaptchaInputText", "captcha", "CaptchaCode", "captcha_code"):
        if any((f.get("name") or "") == fname for f in (form.get("fields") or [])):
            overrides[fname] = answer
    if overrides:
        return overrides
    for f in form.get("fields") or []:
        n = f.get("name") or ""
        # Never overwrite captcha instance id (CaptchaDeText)
        if n.lower() in {"captchadetext", "captcha_de_text"}:
            continue
        if "captcha" in n.lower() and (f.get("type") or "") in {"text", ""}:
            overrides[n] = answer
            break
    return overrides


def _find_captcha_image_url(html: str, page_url: str) -> str:
    m = CAPTCHA_IMG_RE.search(html or "")
    if not m:
        # Fallback: any DefaultCaptcha/Generate link
        m2 = re.search(r"""["'](/DefaultCaptcha/Generate\?t=[^"']+)["']""", html or "", re.I)
        if not m2:
            return ""
        return urllib.parse.urljoin(page_url, m2.group(1))
    src = m.group(1) or m.group(2) or ""
    return urllib.parse.urljoin(page_url, src) if src else ""


def _solve_page_captcha(
    html: str,
    page_url: str,
    cookie_jar: CookieJar,
) -> dict[str, Any]:
    img_url = _find_captcha_image_url(html, page_url)
    if not img_url:
        return {"ok": False, "error": "No captcha image found", "answer": None}
    fetched = _request_bytes(img_url, cookie_jar=cookie_jar, referer=page_url)
    if not fetched.get("ok") or not fetched.get("data"):
        return {
            "ok": False,
            "error": fetched.get("error") or "Captcha image fetch failed",
            "answer": None,
            "image_url": img_url,
        }
    ocr = _ocr_math_captcha(fetched["data"])
    ocr["image_url"] = img_url
    return ocr


def _request(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    cookie_jar: CookieJar | None,
    timeout: float = 12.0,
    max_body: int = 200_000,
    follow_redirects: bool = True,
) -> dict[str, Any]:
    url = absolute_url(url)
    ok_public, reason = _url_is_public(url)
    if not ok_public:
        return {"ok": False, "url": url, "error": reason, "status_code": None, "headers": {}, "body": ""}

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
            return None

    context = ssl.create_default_context()
    handlers: list[Any] = [urllib.request.HTTPSHandler(context=context)]
    if cookie_jar is not None:
        handlers.insert(0, urllib.request.HTTPCookieProcessor(cookie_jar))
    if not follow_redirects:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    hdrs = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    }
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, method=method.upper(), headers=hdrs)
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(max_body)
            return {
                "ok": True,
                "url": url,
                "final_url": resp.geturl(),
                "status_code": resp.getcode(),
                "headers": {k: v for k, v in resp.headers.items()},
                "body": body.decode("utf-8", errors="replace"),
            }
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read(max_body)
        except Exception:  # noqa: BLE001
            pass
        hdr = {k: v for k, v in (exc.headers.items() if exc.headers else [])}
        return {
            "ok": True,
            "url": url,
            "final_url": getattr(exc, "url", None) or url,
            "status_code": exc.code,
            "headers": hdr,
            "body": body.decode("utf-8", errors="replace"),
            "location": hdr.get("Location") or hdr.get("location"),
            "error": str(exc.reason),
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "url": url, "error": str(exc), "status_code": None, "headers": {}, "body": ""}


def _analyze_headers(headers: dict[str, str], *, page: str, body: str = "") -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lower = {k.lower(): v for k, v in (headers or {}).items()}

    for key, severity in DISCLOSURE_HEADERS.items():
        val = lower.get(key)
        if not val:
            continue
        findings.append(
            {
                "severity": severity,
                "title": f"Disclosure header: {key}",
                "detail": f"[{page}] {val[:240]}",
                "header": key,
                "value": val[:240],
                "page": page,
                "kind": "disclosure",
            }
        )

    cookie_vals = [v for k, v in headers.items() if k.lower() == "set-cookie"]
    for cval in cookie_vals:
        cl = cval.lower()
        issues = []
        if "httponly" not in cl:
            issues.append("missing HttpOnly")
        if "secure" not in cl:
            issues.append("missing Secure")
        if "samesite" not in cl:
            issues.append("missing SameSite")
        if issues:
            name = cval.split("=", 1)[0].strip()[:60]
            findings.append(
                {
                    "severity": "medium",
                    "title": f"Weak cookie flags: {name}",
                    "detail": f"[{page}] {', '.join(issues)} — {cval[:180]}",
                    "page": page,
                    "kind": "cookie",
                }
            )

    blob = " ".join(list(lower.values()) + [body[:8000]])
    seen_ip: set[str] = set()
    for match in PRIVATE_IP_RE.findall(blob):
        if match in seen_ip:
            continue
        seen_ip.add(match)
        findings.append(
            {
                "severity": "high",
                "title": "Private IP leaked",
                "detail": f"[{page}] {match}",
                "page": page,
                "kind": "private-ip",
            }
        )

    for key, label, severity in MISSING_SECURITY:
        if not lower.get(key):
            findings.append(
                {
                    "severity": severity,
                    "title": f"Missing {label}",
                    "detail": f"[{page}] Recommended hardening header is absent.",
                    "page": page,
                    "kind": "missing-security",
                }
            )
        elif key == "x-content-type-options" and lower.get(key, "").lower() != "nosniff":
            findings.append(
                {
                    "severity": "low",
                    "title": "X-Content-Type-Options unusual",
                    "detail": f"[{page}] {lower.get(key)}",
                    "page": page,
                    "kind": "missing-security",
                }
            )

    return findings


class _FormParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, Any]] = []
        self._cur: dict[str, Any] | None = None
        self._in_select = False
        self._select_name = ""
        self._select_options: list[str] = []
        self._textarea_name = ""
        self._textarea_buf = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {
                "action": ad.get("action", ""),
                "method": (ad.get("method") or "get").lower(),
                "id": ad.get("id", ""),
                "name": ad.get("name", ""),
                "fields": [],
                "has_password": False,
                "has_file": False,
                "submit_name": "",
                "submit_value": "",
            }
            return
        if not self._cur:
            return
        if tag == "input":
            itype = (ad.get("type") or "text").lower()
            name = ad.get("name") or ""
            if itype == "password":
                self._cur["has_password"] = True
            if itype == "file":
                self._cur["has_file"] = True
            if itype in {"submit", "image"} and name:
                self._cur["submit_name"] = name
                self._cur["submit_value"] = ad.get("value") or "Submit"
            if itype in {"button", "reset", "image"}:
                return
            if not name:
                return
            self._cur["fields"].append(
                {
                    "tag": "input",
                    "type": itype,
                    "name": name,
                    "value": ad.get("value", ""),
                    "checked": "checked" in ad,
                    "required": "required" in ad,
                }
            )
        elif tag == "select":
            self._in_select = True
            self._select_name = ad.get("name") or ""
            self._select_options = []
        elif tag == "option" and self._in_select:
            val = ad.get("value")
            self._select_options.append(val if val is not None else "")
        elif tag == "textarea":
            self._textarea_name = ad.get("name") or ""
            self._textarea_buf = ""

    def handle_data(self, data: str) -> None:
        if self._textarea_name:
            self._textarea_buf += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None
        elif tag == "select" and self._cur is not None and self._in_select:
            if self._select_name:
                opts = [o for o in self._select_options if o is not None]
                self._cur["fields"].append(
                    {
                        "tag": "select",
                        "type": "select",
                        "name": self._select_name,
                        "value": opts[0] if opts else "",
                        "options": opts,
                    }
                )
            self._in_select = False
            self._select_name = ""
            self._select_options = []
        elif tag == "textarea" and self._cur is not None and self._textarea_name:
            self._cur["fields"].append(
                {
                    "tag": "textarea",
                    "type": "textarea",
                    "name": self._textarea_name,
                    "value": self._textarea_buf.strip()[:200],
                }
            )
            self._textarea_name = ""
            self._textarea_buf = ""


def _parse_forms(html_text: str) -> list[dict[str, Any]]:
    parser = _FormParser()
    try:
        parser.feed(html_text or "")
        parser.close()
    except Exception:  # noqa: BLE001
        return []
    return parser.forms


def _random_value(field: dict[str, Any]) -> str | None:
    name = field.get("name") or ""
    itype = (field.get("type") or "text").lower()
    if itype == "hidden":
        return field.get("value") or ""
    if itype == "checkbox":
        return field.get("value") or "on"
    if itype == "radio":
        return field.get("value") or "1"
    if itype == "select":
        opts = [o for o in (field.get("options") or []) if str(o).strip() != ""]
        return opts[0] if opts else (field.get("value") or "1")
    if itype == "email" or EMAIL_HINT.search(name):
        return f"aahc-{secrets.token_hex(3)}@example.com"
    if itype == "tel" or PHONE_HINT.search(name):
        return f"+1555{random.randint(1000000, 9999999)}"
    if itype == "url" or URL_HINT.search(name):
        return "https://example.com"
    if itype == "number":
        return str(random.randint(1, 99))
    if itype == "date":
        return "2026-01-15"
    if itype == "password":
        return f"Aa1!{secrets.token_hex(4)}"
    if NAME_HINT.search(name):
        return random.choice(["Ada Test", "Can Demo", "Ece Sample"])
    if itype == "textarea":
        return "AAHC automated probe — please ignore."
    return f"aahc-{secrets.token_hex(2)}"


def _pick_form(forms: list[dict[str, Any]], page_url: str) -> dict[str, Any] | None:
    candidates: list[tuple[int, dict[str, Any]]] = []
    for form in forms:
        if form.get("has_file"):
            continue
        method = (form.get("method") or "get").lower()
        if method not in {"get", "post"}:
            continue
        action = form.get("action") or page_url
        abs_action = urllib.parse.urljoin(page_url, action)
        if abs_action.lower().startswith("javascript:"):
            continue
        if not _same_site(page_url, abs_action):
            continue
        blob = " ".join(
            [
                form.get("id") or "",
                form.get("name") or "",
                action,
                " ".join(f.get("name") or "" for f in form.get("fields") or []),
            ]
        )
        if SKIP_FORM_ATTR.search(blob) and form.get("has_password"):
            continue
        visible = [
            f
            for f in form.get("fields") or []
            if f.get("name") and (f.get("type") or "") not in {"hidden", "submit"}
        ]
        if not visible and not any((f.get("type") or "") == "hidden" for f in form.get("fields") or []):
            continue
        score = len(visible) * 2 + len(form.get("fields") or [])
        if form.get("has_password"):
            score -= 5
        candidates.append((score, form))
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


def _build_form_payload(
    form: dict[str, Any],
    *,
    overrides: dict[str, str] | None = None,
) -> dict[str, str]:
    data: dict[str, str] = {}
    radios_done: set[str] = set()
    overrides = overrides or {}
    for field in form.get("fields") or []:
        name = field.get("name") or ""
        if not name:
            continue
        if name in overrides:
            data[name] = overrides[name]
            continue
        itype = (field.get("type") or "").lower()
        if itype == "radio":
            if name in radios_done:
                continue
            radios_done.add(name)
            val = _random_value(field)
            if val is not None:
                data[name] = val
            continue
        if itype == "checkbox" and not field.get("checked") and random.random() < 0.35:
            continue
        val = _random_value(field)
        if val is not None:
            data[name] = val
    if form.get("submit_name") and form["submit_name"] not in data:
        data[form["submit_name"]] = form.get("submit_value") or "Submit"
    return data


def _score_from_findings(findings: list[dict[str, Any]]) -> int:
    score = 100
    for f in findings:
        kind = f.get("kind") or ""
        sev = f.get("severity") or "low"
        if kind == "disclosure":
            score -= {"high": 12, "medium": 8, "low": 3}.get(sev, 5)
        elif kind == "private-ip":
            score -= 15
        elif kind == "cookie":
            score -= 6
        elif kind == "missing-security":
            score -= {"high": 8, "medium": 5, "low": 2}.get(sev, 3)
        else:
            score -= 4
    return max(0, min(100, score))


def check_aahc(target: str) -> dict[str, Any]:
    _PUBLIC_HOST_CACHE.clear()
    url = absolute_url((target or "").strip())
    if not url:
        return {
            "ok": False,
            "error": "Please enter a website URL (e.g. https://example.com)",
            "external_check": True,
        }

    ok_public, reason = _url_is_public(url)
    if not ok_public:
        return {"ok": False, "error": reason, "url": url, "external_check": True}

    jar = CookieJar()
    steps: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []

    page1 = _request(url, cookie_jar=jar, follow_redirects=True)
    if page1.get("status_code") is None and not page1.get("ok"):
        return {
            "ok": False,
            "external_check": True,
            "url": url,
            "error": page1.get("error") or "Request failed",
        }

    page1_url = page1.get("final_url") or url
    f1 = _analyze_headers(page1.get("headers") or {}, page="Front page", body=page1.get("body") or "")
    all_findings.extend(f1)
    disc1 = [x for x in f1 if x.get("kind") == "disclosure"]
    steps.append(
        {
            "step": 1,
            "label": "Front page",
            "url": page1_url,
            "status_code": page1.get("status_code"),
            "disclosure_count": len(disc1),
            "finding_count": len(f1),
            "headers_sample": {
                k: v[:120] for k, v in list((page1.get("headers") or {}).items())[:12]
            },
        }
    )

    form_note = "No suitable same-site form found on the front page."
    form_meta: dict[str, Any] | None = None
    forms = _parse_forms(page1.get("body") or "")
    chosen = _pick_form(forms, page1_url)

    if chosen:
        action = urllib.parse.urljoin(page1_url, chosen.get("action") or page1_url)
        method = (chosen.get("method") or "get").lower()
        has_captcha = any(
            "captcha" in (f.get("name") or "").lower()
            for f in (chosen.get("fields") or [])
        )
        captcha_info: dict[str, Any] = {"present": has_captcha, "solved": False}
        parsed = urllib.parse.urlparse(page1_url)
        max_captcha_attempts = 12 if has_captcha else 1
        page2: dict[str, Any] = {}
        payload: dict[str, str] = {}
        form_html = page1.get("body") or ""
        form_chosen = chosen
        form_action = action
        attempts_used = 0

        for attempt in range(1, max_captcha_attempts + 1):
            attempts_used = attempt
            overrides: dict[str, str] = {}
            if has_captcha:
                if attempt > 1:
                    # Fresh tokens + captcha image (wrong answer invalidates session captcha)
                    refresh = _request(page1_url, cookie_jar=jar, follow_redirects=True)
                    if refresh.get("ok") or refresh.get("status_code"):
                        form_html = refresh.get("body") or form_html
                        forms_r = _parse_forms(form_html)
                        picked = _pick_form(forms_r, page1_url)
                        if picked:
                            form_chosen = picked
                            form_action = urllib.parse.urljoin(
                                page1_url, picked.get("action") or page1_url
                            )
                solved = _solve_page_captcha(form_html, page1_url, jar)
                captcha_info.update(
                    {
                        "solved": bool(solved.get("ok") and solved.get("answer")),
                        "ocr_text": (solved.get("text") or "")[:80],
                        "answer": solved.get("answer"),
                        "error": solved.get("error"),
                        "image_url": solved.get("image_url"),
                        "engine": solved.get("engine"),
                        "attempts": attempt,
                    }
                )
                if not captcha_info["solved"]:
                    # Never POST a random captcha value — refresh and retry OCR
                    captcha_info["error"] = solved.get("error") or "OCR parse failed"
                    continue
                overrides = _captcha_field_overrides(form_chosen, str(solved["answer"]))

            payload = _build_form_payload(form_chosen, overrides=overrides)
            # Important: do NOT follow redirects first — disclosure often sits on the
            # form action response (e.g. 302 from /Verification/GetObjectsByCode).
            if method == "get":
                q = urllib.parse.urlencode(payload)
                join = "&" if ("?" in form_action) else "?"
                step2_url = f"{form_action}{join}{q}" if payload else form_action
                page2 = _request(step2_url, cookie_jar=jar, follow_redirects=False)
            else:
                body = urllib.parse.urlencode(payload).encode("utf-8")
                page2 = _request(
                    form_action,
                    method="POST",
                    data=body,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Referer": page1_url,
                        "Origin": f"{parsed.scheme}://{parsed.netloc}",
                    },
                    cookie_jar=jar,
                    follow_redirects=False,
                )

            if page2.get("status_code") is None and not page2.get("ok"):
                break
            if has_captcha and _form_captcha_rejected(page2, form_action):
                captcha_info["rejected"] = True
                captcha_info["accepted"] = False
                captcha_info["error"] = (
                    f"Server rejected captcha answer (attempt {attempt}/{max_captcha_attempts})"
                )
                continue
            captcha_info["rejected"] = False
            captcha_info["accepted"] = True
            break

        form_meta = {
            "action": form_action,
            "method": method.upper(),
            "field_count": len(payload),
            "fields": list(payload.keys())[:20],
            "captcha_present": has_captcha,
            "captcha": captcha_info,
            "attempts": attempts_used,
        }
        action = form_action

        never_submitted = has_captcha and not page2.get("status_code") and not page2.get("ok")
        if never_submitted:
            form_note = (
                "Captcha present but could not be solved "
                f"({captcha_info.get('error') or 'unknown'}) after {attempts_used} attempt(s)."
            )
            steps.append(
                {
                    "step": 2,
                    "label": "Form action response",
                    "url": action,
                    "status_code": None,
                    "error": captcha_info.get("error") or "Captcha unsolved",
                    "form": form_meta,
                }
            )
        elif page2.get("status_code") is None and not page2.get("ok"):
            form_note = f"Form submit failed: {page2.get('error') or 'error'}"
            steps.append(
                {
                    "step": 2,
                    "label": "Form action response",
                    "url": action,
                    "status_code": None,
                    "error": page2.get("error"),
                    "form": form_meta,
                }
            )
        else:
            # Analyze the immediate form-action response (even 302/4xx)
            action_url = page2.get("final_url") or action
            f2 = _analyze_headers(
                page2.get("headers") or {},
                page=f"Form action ({urllib.parse.urlparse(action).path or '/'})",
                body=page2.get("body") or "",
            )
            all_findings.extend(f2)
            disc2 = [x for x in f2 if x.get("kind") == "disclosure"]
            loc = (
                page2.get("location")
                or (page2.get("headers") or {}).get("Location")
                or (page2.get("headers") or {}).get("location")
            )
            form_note = (
                f"Filled {len(payload)} field(s) via {method.upper()} to {action} "
                f"(status {page2.get('status_code')})."
            )
            if has_captcha and captcha_info.get("accepted"):
                form_note += (
                    f" Math captcha solved as {captcha_info.get('answer')}"
                    f" ({captcha_info.get('ocr_text')}; attempt {attempts_used})."
                )
            elif has_captcha:
                form_note += (
                    " Captcha present but could not be solved "
                    f"({captcha_info.get('error') or 'unknown'}) after {attempts_used} attempt(s)."
                )
            steps.append(
                {
                    "step": 2,
                    "label": "Form action response",
                    "url": action_url,
                    "status_code": page2.get("status_code"),
                    "disclosure_count": len(disc2),
                    "finding_count": len(f2),
                    "location": loc,
                    "form": form_meta,
                    "headers_sample": {
                        k: v[:120]
                        for k, v in list((page2.get("headers") or {}).items())[:12]
                    },
                }
            )

            # Optional same-site redirect hop (e.g. 302 → /)
            code = page2.get("status_code")
            if (
                code in (301, 302, 303, 307, 308)
                and loc
                and not (has_captcha and captcha_info.get("rejected") and not captcha_info.get("accepted"))
            ):
                next_url = urllib.parse.urljoin(action_url, loc)
                if _same_site(page1_url, next_url):
                    page3 = _request(next_url, cookie_jar=jar, follow_redirects=True)
                    if page3.get("status_code") is not None or page3.get("ok"):
                        final3 = page3.get("final_url") or next_url
                        if _same_site(page1_url, final3):
                            f3 = _analyze_headers(
                                page3.get("headers") or {},
                                page="After form redirect",
                                body=page3.get("body") or "",
                            )
                            all_findings.extend(f3)
                            disc3 = [x for x in f3 if x.get("kind") == "disclosure"]
                            steps.append(
                                {
                                    "step": 3,
                                    "label": "After form redirect",
                                    "url": final3,
                                    "status_code": page3.get("status_code"),
                                    "disclosure_count": len(disc3),
                                    "finding_count": len(f3),
                                    "headers_sample": {
                                        k: v[:120]
                                        for k, v in list((page3.get("headers") or {}).items())[:12]
                                    },
                                }
                            )
                else:
                    form_note += f" Redirect left the site ({next_url}); hop skipped."
    else:
        steps.append(
            {
                "step": 2,
                "label": "Form step skipped",
                "url": page1_url,
                "status_code": None,
                "note": form_note,
                "forms_seen": len(forms),
            }
        )

    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for f in all_findings:
        mark = f"{f.get('title')}|{f.get('detail')}"
        if mark in seen:
            continue
        seen.add(mark)
        deduped.append(f)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    deduped.sort(key=lambda x: order.get(str(x.get("severity")), 9))
    disclosure = [f for f in deduped if f.get("kind") == "disclosure"]
    score = _score_from_findings(deduped)

    return {
        "ok": True,
        "external_check": True,
        "tool": "AAHC",
        "title": "AAHC — Adam Akıllı Header Checker",
        "url": url,
        "final_url": page1_url,
        "status_code": page1.get("status_code"),
        "score": score,
        "summary": (
            f"{len(disclosure)} disclosure header(s) across {len(steps)} step(s). {form_note}"
        ),
        "form_note": form_note,
        "form": form_meta,
        "forms_seen": len(forms),
        "steps": steps,
        "findings": deduped,
        "headers": [
            {
                "header": f.get("header") or f.get("title"),
                "status": f.get("severity"),
                "value": f.get("detail") or f.get("value") or "—",
                "present": True,
            }
            for f in disclosure[:40]
        ],
        "guidance": [
            "Remove or generalize Server / X-Powered-By / framework version headers at the reverse proxy.",
            "Do not expose private RFC1918 addresses in Location, body, or custom headers.",
            "Set HttpOnly, Secure, and SameSite on session cookies.",
            "AAHC only submits one same-site form with random disposable values — "
            "only test sites you own or have permission to assess.",
        ],
        "mode": "external_only",
    }
