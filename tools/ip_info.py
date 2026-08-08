"""Client / target IP information helpers."""

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request

from .dns_common import is_ip, reverse_lookup


def client_ip_from_request(request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    return request.remote_addr or ""


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        )
    except ValueError:
        return False


def lookup_geo(ip: str) -> dict:
    """Best-effort geolocation via public API (ipwho.is)."""
    if not _is_public_ip(ip):
        return {
            "ok": False,
            "error": "Geolocation is only available for public IPs",
        }

    url = f"https://ipwho.is/{ip}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "tools.birolbenli.com/1.0", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
        return {"ok": False, "error": f"Geo lookup failed: {exc}"}

    if not data.get("success", True) and data.get("success") is False:
        return {"ok": False, "error": data.get("message") or "Geo lookup failed"}

    return {
        "ok": True,
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "region": data.get("region"),
        "city": data.get("city"),
        "postal": data.get("postal"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "timezone": (data.get("timezone") or {}).get("id")
        if isinstance(data.get("timezone"), dict)
        else data.get("timezone"),
        "org": data.get("connection", {}).get("org")
        if isinstance(data.get("connection"), dict)
        else data.get("org"),
        "isp": data.get("connection", {}).get("isp")
        if isinstance(data.get("connection"), dict)
        else data.get("isp"),
        "asn": data.get("connection", {}).get("asn")
        if isinstance(data.get("connection"), dict)
        else data.get("asn"),
    }


def lookup_ip_info(ip: str, request=None) -> dict:
    ip = (ip or "").strip()
    if not ip and request is not None:
        ip = client_ip_from_request(request)
    if not ip:
        return {"ok": False, "error": "No IP available"}
    if not is_ip(ip):
        return {"ok": False, "error": "Invalid IP address", "ip": ip}

    ptr = reverse_lookup(ip)
    geo = lookup_geo(ip)
    info = {
        "ok": True,
        "ip": ip,
        "ptr": ptr.get("hosts") or [],
        "ptr_ok": ptr.get("ok", False),
        "geo": geo,
    }
    if request is not None and ip == client_ip_from_request(request):
        info.update(
            {
                "user_agent": request.headers.get("User-Agent"),
                "language": request.headers.get("Accept-Language"),
                "forwarded": request.headers.get("X-Forwarded-For"),
                "via": request.headers.get("Via"),
                "host_header": request.headers.get("Host"),
            }
        )
    return info
