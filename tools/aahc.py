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


def _url_is_public(url: str) -> tuple[bool, str]:
    """Block private/loopback/link-local/metadata targets."""
    parsed = urllib.parse.urlparse(absolute_url(url))
    if parsed.scheme not in {"http", "https"}:
        return False, "Only http/https URLs are allowed"
    host = parsed.hostname or ""
    if not host:
        return False, "Missing hostname"
    if host.lower() in {"localhost", "metadata.google.internal"}:
        return False, "Local/metadata hosts are blocked"
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        return False, f"DNS failed: {exc}"
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
            return False, f"Target resolves to non-public address ({ip})"
    return True, ""


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


def _build_form_payload(form: dict[str, Any]) -> dict[str, str]:
    data: dict[str, str] = {}
    radios_done: set[str] = set()
    for field in form.get("fields") or []:
        name = field.get("name") or ""
        if not name:
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
    if form.get("submit_name"):
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
        payload = _build_form_payload(chosen)
        form_meta = {
            "action": action,
            "method": method.upper(),
            "field_count": len(payload),
            "fields": list(payload.keys())[:20],
        }
        if method == "get":
            q = urllib.parse.urlencode(payload)
            join = "&" if ("?" in action) else "?"
            step2_url = f"{action}{join}{q}" if payload else action
            page2 = _request(step2_url, cookie_jar=jar, follow_redirects=True)
        else:
            body = urllib.parse.urlencode(payload).encode("utf-8")
            parsed = urllib.parse.urlparse(page1_url)
            page2 = _request(
                action,
                method="POST",
                data=body,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": page1_url,
                    "Origin": f"{parsed.scheme}://{parsed.netloc}",
                },
                cookie_jar=jar,
                follow_redirects=True,
            )

        if page2.get("status_code") is None and not page2.get("ok"):
            form_note = f"Form submit failed: {page2.get('error') or 'error'}"
            steps.append(
                {
                    "step": 2,
                    "label": "After form submit",
                    "url": action,
                    "status_code": None,
                    "error": page2.get("error"),
                    "form": form_meta,
                }
            )
        else:
            final2 = page2.get("final_url") or action
            if not _same_site(page1_url, final2):
                form_note = (
                    f"Form redirected off-site ({final2}); skipped follow-up header analysis."
                )
                steps.append(
                    {
                        "step": 2,
                        "label": "After form submit (off-site — skipped)",
                        "url": final2,
                        "status_code": page2.get("status_code"),
                        "form": form_meta,
                    }
                )
            else:
                f2 = _analyze_headers(
                    page2.get("headers") or {},
                    page="After form",
                    body=page2.get("body") or "",
                )
                all_findings.extend(f2)
                disc2 = [x for x in f2 if x.get("kind") == "disclosure"]
                form_note = (
                    f"Filled {len(payload)} field(s) via {method.upper()} "
                    "and re-checked the next response."
                )
                steps.append(
                    {
                        "step": 2,
                        "label": "After form submit",
                        "url": final2,
                        "status_code": page2.get("status_code"),
                        "disclosure_count": len(disc2),
                        "finding_count": len(f2),
                        "form": form_meta,
                        "headers_sample": {
                            k: v[:120]
                            for k, v in list((page2.get("headers") or {}).items())[:12]
                        },
                    }
                )
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
