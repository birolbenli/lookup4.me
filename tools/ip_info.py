"""Client / target IP information helpers."""

from __future__ import annotations

from .dns_common import is_ip, reverse_lookup


def client_ip_from_request(request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    return request.remote_addr or ""


def lookup_ip_info(ip: str, request=None) -> dict:
    ip = (ip or "").strip()
    if not ip and request is not None:
        ip = client_ip_from_request(request)
    if not ip:
        return {"ok": False, "error": "No IP available"}
    if not is_ip(ip):
        return {"ok": False, "error": "Invalid IP address", "ip": ip}

    ptr = reverse_lookup(ip)
    info = {
        "ok": True,
        "ip": ip,
        "ptr": ptr.get("hosts") or [],
        "ptr_ok": ptr.get("ok", False),
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
