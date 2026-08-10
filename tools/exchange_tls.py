"""TLS protocol and certificate assessment for Exchange external scan."""

from __future__ import annotations

import datetime
import socket
import ssl
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from .dns_common import is_ip
from .exchange_endpoints import public_ips
from .ssl_check import get_ssl_info

PROTOCOLS = [
    ("SSLv3", getattr(ssl, "PROTOCOL_SSLv3", None), False),  # may be unavailable
    ("TLSv1.0", getattr(ssl, "PROTOCOL_TLSv1", None), False),
    ("TLSv1.1", getattr(ssl, "PROTOCOL_TLSv1_1", None), False),
    ("TLSv1.2", getattr(ssl, "PROTOCOL_TLSv1_2", None), True),
    ("TLSv1.3", None, True),  # negotiated via CONTEXT with minimum/maximum
]


def _try_protocol(host: str, ip: str, port: int, label: str) -> dict:
    """Attempt a TLS handshake constrained to a protocol family."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Restrict versions when constants exist
        if label == "SSLv3":
            return {"protocol": label, "supported": False, "error": "SSLv3 not offered by client library"}
        if label == "TLSv1.0":
            if not hasattr(ssl, "TLSVersion"):
                return {"protocol": label, "supported": None, "error": "TLSVersion API unavailable"}
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
        elif label == "TLSv1.1":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        elif label == "TLSv1.2":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        elif label == "TLSv1.3":
            if not hasattr(ssl.TLSVersion, "TLSv1_3"):
                return {"protocol": label, "supported": None, "error": "TLS 1.3 not available"}
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        sock = socket.create_connection((ip, port), timeout=6)
        try:
            with ctx.wrap_socket(sock, server_hostname=None if is_ip(host) else host) as ssock:
                ver = ssock.version() or label
                cipher = ssock.cipher()
                return {
                    "protocol": label,
                    "supported": True,
                    "negotiated": ver,
                    "cipher": cipher[0] if cipher else None,
                }
        finally:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass
    except ssl.SSLError as exc:
        return {"protocol": label, "supported": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"protocol": label, "supported": False, "error": str(exc)}


def _cert_details(host: str, ip: str, port: int = 443) -> dict:
    try:
        sock = socket.create_connection((ip, port), timeout=8)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(sock, server_hostname=None if is_ip(host) else host) as ssock:
            cert_bin = ssock.getpeercert(binary_form=True)
            negotiated = ssock.version()
            cipher = ssock.cipher()
            if not cert_bin:
                return {"ok": False, "error": "No certificate"}
            cert = x509.load_der_x509_certificate(cert_bin, default_backend())
            not_before = cert.not_valid_before_utc.replace(tzinfo=None)
            not_after = cert.not_valid_after_utc.replace(tzinfo=None)
            now = datetime.datetime.utcnow()
            days_left = (not_after - now).days

            sans: list[str] = []
            try:
                ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                sans = [str(n) for n in ext.value.get_values_for_type(x509.DNSName)]
            except Exception:  # noqa: BLE001
                pass

            subject_cn = None
            for attr in cert.subject:
                if attr.oid._name == "commonName":
                    subject_cn = attr.value
                    break
            issuer_cn = None
            for attr in cert.issuer:
                if attr.oid._name == "commonName":
                    issuer_cn = attr.value
                    break

            host_l = host.lower()
            hostname_ok = False
            if is_ip(host):
                hostname_ok = True  # IP targets skip name match
            else:
                candidates = [s.lower() for s in sans]
                if subject_cn:
                    candidates.append(str(subject_cn).lower())
                for c in candidates:
                    if c == host_l:
                        hostname_ok = True
                        break
                    if c.startswith("*.") and host_l.endswith(c[1:]) and host_l.count(".") == c.count("."):
                        hostname_ok = True
                        break
                    if c.startswith("*.") and ".".join(host_l.split(".")[1:]) == c[2:]:
                        hostname_ok = True
                        break

            pub = cert.public_key()
            key_bits = None
            key_type = type(pub).__name__
            if isinstance(pub, rsa.RSAPublicKey):
                key_bits = pub.key_size
                key_type = "RSA"
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                key_bits = pub.key_size
                key_type = f"EC-{pub.curve.name}"
            elif isinstance(pub, dsa.DSAPublicKey):
                key_bits = pub.key_size
                key_type = "DSA"

            sig = cert.signature_hash_algorithm
            sig_name = sig.name if sig else "unknown"

            return {
                "ok": True,
                "negotiated_protocol": negotiated,
                "cipher": cipher[0] if cipher else None,
                "subject_cn": subject_cn,
                "issuer": issuer_cn,
                "not_before": not_before.strftime("%Y-%m-%d"),
                "not_after": not_after.strftime("%Y-%m-%d"),
                "days_left": days_left,
                "sans": sans[:20],
                "hostname_match": hostname_ok,
                "key_type": key_type,
                "key_bits": key_bits,
                "signature_hash": sig_name,
                "expired": days_left < 0,
            }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


def assess_tls(host: str, port: int = 443) -> dict[str, Any]:
    ips = public_ips(host)
    if not ips:
        return {
            "ok": False,
            "host": host,
            "error": "No public IP",
            "protocols": [],
            "certificate": None,
            "legacy": get_ssl_info(host, port),
        }

    ip = ips[0]
    protocols = []
    for label, _const, _ok in [
        ("SSLv3", None, False),
        ("TLSv1.0", None, False),
        ("TLSv1.1", None, False),
        ("TLSv1.2", None, True),
        ("TLSv1.3", None, True),
    ]:
        protocols.append(_try_protocol(host, ip, port, label))

    cert = _cert_details(host, ip, port)
    legacy = get_ssl_info(host, port)

    legacy_tls = [p for p in protocols if p.get("supported") and p["protocol"] in {"SSLv3", "TLSv1.0", "TLSv1.1"}]
    modern = [p for p in protocols if p.get("supported") and p["protocol"] in {"TLSv1.2", "TLSv1.3"}]

    return {
        "ok": bool(cert.get("ok") or legacy.get("status") in {"valid", "warning", "expired"}),
        "host": host,
        "ip": ip,
        "port": port,
        "protocols": protocols,
        "certificate": cert,
        "legacy_ssl": legacy,
        "summary": {
            "legacy_protocols": [p["protocol"] for p in legacy_tls],
            "modern_protocols": [p["protocol"] for p in modern],
            "tls13": any(p.get("supported") and p["protocol"] == "TLSv1.3" for p in protocols),
            "hostname_match": cert.get("hostname_match"),
            "days_left": cert.get("days_left") if cert.get("ok") else legacy.get("days_left"),
            "expired": bool(cert.get("expired") or legacy.get("status") == "expired"),
        },
    }
