"""TCP port connectivity check."""

from __future__ import annotations

import socket
import time

from .dns_common import is_ip, normalize_domain, resolve_host_chain


def parse_host_port(value: str, default_port: int | None = None) -> tuple[str, int] | None:
    raw = (value or "").strip()
    if not raw:
        return None
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0]

    if raw.startswith("[") and "]" in raw:
        host, rest = raw[1:].split("]", 1)
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        if default_port:
            return host, default_port
        return None

    if raw.count(":") == 1:
        host, port_s = raw.rsplit(":", 1)
        if port_s.isdigit():
            return normalize_domain(host) if not is_ip(host) else host, int(port_s)

    if default_port:
        host = normalize_domain(raw) if not is_ip(raw) else raw
        return host, default_port
    return None


def check_port(target: str, port: int | None = None, timeout: float = 5.0) -> dict:
    if port is not None:
        host = normalize_domain(target) if not is_ip(target) else target.strip()
        parsed = (host, int(port))
    else:
        parsed = parse_host_port(target)
        if not parsed:
            return {
                "ok": False,
                "error": "Use host:port (example.com:443) or provide a port",
            }

    host, port_n = parsed
    if port_n < 1 or port_n > 65535:
        return {"ok": False, "error": "Port must be between 1 and 65535"}

    ips = [host] if is_ip(host) else resolve_host_chain(host).get("ips") or []
    if not ips:
        return {"ok": False, "host": host, "port": port_n, "error": "DNS resolution failed"}

    attempts = []
    for ip in ips[:3]:
        started = time.time()
        try:
            with socket.create_connection((ip, port_n), timeout=timeout):
                ms = int((time.time() - started) * 1000)
                attempts.append({"ip": ip, "ok": True, "latency_ms": ms})
                break
        except Exception as exc:  # noqa: BLE001
            ms = int((time.time() - started) * 1000)
            attempts.append({"ip": ip, "ok": False, "latency_ms": ms, "error": str(exc)})

    success = next((a for a in attempts if a.get("ok")), None)
    return {
        "ok": bool(success),
        "host": host,
        "port": port_n,
        "error": None if success else (attempts[-1].get("error") if attempts else "Closed"),
        "attempts": attempts,
        "open": bool(success),
    }
