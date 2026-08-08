"""Bulk SSL certificate checker."""

from __future__ import annotations

import datetime
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .dns_common import is_ip, normalize_domain, query_records


def parse_target(line: str) -> tuple[str, int] | None:
    raw = (line or "").strip()
    if not raw:
        return None

    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        port = parsed.port or 443
        if not host:
            return None
        return normalize_domain(host), port

    if raw.count(":") == 1 and not raw.startswith("["):
        host, port_str = raw.rsplit(":", 1)
        if port_str.isdigit() and host:
            return normalize_domain(host), int(port_str)

    host = normalize_domain(raw)
    if not host:
        return None
    return host, 443


def resolve_ip(host: str) -> str | None:
    if is_ip(host):
        return host
    a = query_records(host, "A")
    if a.get("records"):
        return a["records"][0]["data"]
    aaaa = query_records(host, "AAAA")
    if aaaa.get("records"):
        return aaaa["records"][0]["data"]
    return None


def get_ssl_info(hostname: str, port: int = 443) -> dict:
    ip = resolve_ip(hostname)
    if not ip:
        return {
            "domain": hostname,
            "port": port,
            "ip": None,
            "status": "error",
            "message": "DNS resolution failed",
        }

    try:
        sock = socket.create_connection((ip, port), timeout=10)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with context.wrap_socket(sock, server_hostname=hostname if not is_ip(hostname) else None) as ssock:
            cert_bin = ssock.getpeercert(binary_form=True)
            if not cert_bin:
                return {
                    "domain": hostname,
                    "port": port,
                    "ip": ip,
                    "status": "error",
                    "message": "No certificate returned",
                }

            cert = x509.load_der_x509_certificate(cert_bin, default_backend())
            expiry = cert.not_valid_after_utc.replace(tzinfo=None)
            days_left = (expiry - datetime.datetime.utcnow()).days

            issuer_cn = "Unknown"
            for attr in cert.issuer:
                if attr.oid._name == "commonName":
                    issuer_cn = attr.value
                    break

            subject_cn = "Unknown"
            for attr in cert.subject:
                if attr.oid._name == "commonName":
                    subject_cn = attr.value
                    break

            if days_left < 0:
                status = "expired"
            elif days_left <= 30:
                status = "warning"
            else:
                status = "valid"

            return {
                "domain": hostname,
                "port": port,
                "ip": ip,
                "status": status,
                "issuer": issuer_cn,
                "subject": subject_cn,
                "expiry_date": expiry.strftime("%Y-%m-%d"),
                "days_left": days_left,
                "serial_number": format(cert.serial_number, "x"),
                "version": str(cert.version.name),
                "message": None,
            }
    except socket.timeout:
        return {
            "domain": hostname,
            "port": port,
            "ip": ip,
            "status": "error",
            "message": "Connection timeout",
        }
    except ConnectionRefusedError:
        return {
            "domain": hostname,
            "port": port,
            "ip": ip,
            "status": "error",
            "message": "Connection refused",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "domain": hostname,
            "port": port,
            "ip": ip,
            "status": "error",
            "message": str(exc),
        }


def check_bulk(domains_text: str, max_domains: int = 10) -> dict:
    lines = [ln.strip() for ln in (domains_text or "").splitlines() if ln.strip()]
    if not lines:
        return {"ok": False, "error": "Please enter at least one domain", "results": []}
    if len(lines) > max_domains:
        return {
            "ok": False,
            "error": f"Maximum {max_domains} domains allowed at once",
            "results": [],
        }

    targets = []
    for line in lines:
        parsed = parse_target(line)
        if parsed and parsed[0]:
            targets.append(parsed)

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(10, len(targets) or 1)) as executor:
        futures = {
            executor.submit(get_ssl_info, host, port): (host, port) for host, port in targets
        }
        for future in as_completed(futures):
            results.append(future.result())

    # Keep input order
    order = {(h, p): i for i, (h, p) in enumerate(targets)}
    results.sort(key=lambda r: order.get((r["domain"], r["port"]), 999))

    summary = {
        "valid": sum(1 for r in results if r["status"] == "valid"),
        "warning": sum(1 for r in results if r["status"] == "warning"),
        "expired": sum(1 for r in results if r["status"] == "expired"),
        "error": sum(1 for r in results if r["status"] == "error"),
    }

    return {"ok": True, "count": len(results), "summary": summary, "results": results}
