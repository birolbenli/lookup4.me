"""Lightweight User-Agent → OS / browser parsing (no heavy deps)."""

from __future__ import annotations

import re


def parse_ua(ua: str | None) -> dict:
    raw = (ua or "").strip()
    if not raw:
        return {"os": "Unknown", "browser": "Unknown", "device": "unknown", "ua": ""}

    os_name = "Unknown"
    if "Android" in raw:
        os_name = "Android"
    elif "iPhone" in raw or "iPad" in raw or "iOS" in raw:
        os_name = "iOS"
    elif "Windows NT 10" in raw or "Windows NT 11" in raw:
        os_name = "Windows 10/11"
    elif "Windows" in raw:
        os_name = "Windows"
    elif "Mac OS X" in raw or "Macintosh" in raw:
        os_name = "macOS"
    elif "CrOS" in raw:
        os_name = "ChromeOS"
    elif "Linux" in raw:
        os_name = "Linux"

    browser = "Unknown"
    patterns = [
        ("Edg/", "Edge"),
        ("OPR/", "Opera"),
        ("Opera", "Opera"),
        ("SamsungBrowser", "Samsung Internet"),
        ("Firefox/", "Firefox"),
        ("FxiOS/", "Firefox"),
        ("CriOS/", "Chrome"),
        ("Chrome/", "Chrome"),
        ("Safari/", "Safari"),
        ("MSIE", "IE"),
        ("Trident/", "IE"),
        ("curl/", "curl"),
        ("Wget/", "wget"),
        ("python-requests", "Python"),
        ("httpie", "HTTPie"),
    ]
    for needle, label in patterns:
        if needle in raw:
            browser = label
            break
    # Safari often includes Version/… Safari/ — Chrome already matched above.
    if browser == "Safari" and "Chrome/" in raw:
        browser = "Chrome"

    device = "desktop"
    if any(x in raw for x in ("Mobile", "Android", "iPhone")):
        device = "mobile"
    elif "iPad" in raw or "Tablet" in raw:
        device = "tablet"
    elif browser in {"curl", "wget", "Python", "HTTPie"}:
        device = "bot"

    # Short version hint
    ver = ""
    m = re.search(rf"{re.escape(browser)}/([\d.]+)", raw, flags=re.I)
    if not m and browser == "Edge":
        m = re.search(r"Edg/([\d.]+)", raw)
    if m:
        ver = m.group(1).split(".")[0]

    return {
        "os": os_name,
        "browser": f"{browser} {ver}".strip() if ver else browser,
        "device": device,
        "ua": raw[:400],
    }
