"""SMTP connectivity test on port 25."""

from __future__ import annotations

import socket
import ssl
from typing import Any

from .dns_common import is_ip, is_valid_domain, normalize_domain, query_records, resolve_host_chain


def _read_reply(sock: socket.socket) -> str:
    chunks: list[bytes] = []
    sock.settimeout(10)
    while True:
        data = sock.recv(4096)
        if not data:
            break
        chunks.append(data)
        if b"\n" in data:
            # Multi-line SMTP replies end when 4th char is space
            text = b"".join(chunks).decode("utf-8", errors="replace")
            lines = text.splitlines()
            if lines and len(lines[-1]) >= 4 and lines[-1][3:4] == " ":
                break
            if lines and len(lines[-1]) >= 4 and lines[-1][3:4] != "-":
                break
    return b"".join(chunks).decode("utf-8", errors="replace").strip()


def _send_cmd(sock: socket.socket, command: str) -> str:
    sock.sendall((command + "\r\n").encode("ascii", errors="ignore"))
    return _read_reply(sock)


def _resolve_targets(host: str) -> list[dict[str, Any]]:
    host = normalize_domain(host)
    if is_ip(host):
        return [{"host": host, "ip": host, "source": "ip"}]

    if is_valid_domain(host):
        mx = query_records(host, "MX")
        if mx.get("records"):
            targets = []
            for item in mx["records"]:
                parts = item["data"].split(maxsplit=1)
                if len(parts) != 2:
                    continue
                preference, exchange = parts
                exchange = normalize_domain(exchange)
                resolved = resolve_host_chain(exchange)
                for ip in resolved["ips"] or []:
                    targets.append(
                        {
                            "host": exchange,
                            "ip": ip,
                            "preference": int(preference) if preference.isdigit() else 0,
                            "source": "mx",
                        }
                    )
            targets.sort(key=lambda t: t.get("preference", 0))
            if targets:
                return targets

        resolved = resolve_host_chain(host)
        return [
            {"host": host, "ip": ip, "source": "a"}
            for ip in resolved["ips"]
        ]

    return []


def test_smtp(host: str, port: int = 25, helo_name: str = "lookup4.me") -> dict:
    host = (host or "").strip()
    if not host:
        return {"ok": False, "error": "Please enter a domain or IP address"}

    targets = _resolve_targets(host)
    if not targets:
        return {"ok": False, "error": "Could not resolve host / MX records", "input": host}

    # Test first reachable preference / IP
    attempts: list[dict] = []
    for target in targets[:5]:
        attempt: dict[str, Any] = {
            "host": target["host"],
            "ip": target["ip"],
            "port": port,
            "source": target.get("source"),
            "preference": target.get("preference"),
        }
        try:
            sock = socket.create_connection((target["ip"], port), timeout=10)
            banner = _read_reply(sock)
            ehlo = _send_cmd(sock, f"EHLO {helo_name}")
            starttls_supported = "STARTTLS" in ehlo.upper()
            starttls_ok = None
            if starttls_supported:
                tls_reply = _send_cmd(sock, "STARTTLS")
                starttls_ok = tls_reply.startswith("220")
                if starttls_ok:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=target["host"])
                    ehlo_tls = _send_cmd(sock, f"EHLO {helo_name}")
                    attempt["ehlo_after_tls"] = ehlo_tls
            try:
                quit_reply = _send_cmd(sock, "QUIT")
            except Exception:  # noqa: BLE001
                quit_reply = ""
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass

            attempt.update(
                {
                    "ok": banner.startswith("220"),
                    "banner": banner,
                    "ehlo": ehlo,
                    "starttls_supported": starttls_supported,
                    "starttls_ok": starttls_ok,
                    "quit": quit_reply,
                }
            )
            attempts.append(attempt)
            if attempt["ok"]:
                break
        except socket.timeout:
            attempt.update({"ok": False, "error": "Connection timeout"})
            attempts.append(attempt)
        except ConnectionRefusedError:
            attempt.update({"ok": False, "error": "Connection refused"})
            attempts.append(attempt)
        except Exception as exc:  # noqa: BLE001
            attempt.update({"ok": False, "error": str(exc)})
            attempts.append(attempt)

    success = next((a for a in attempts if a.get("ok")), None)
    return {
        "ok": bool(success),
        "input": host,
        "port": port,
        "error": None if success else (attempts[-1].get("error") if attempts else "SMTP test failed"),
        "result": success,
        "attempts": attempts,
    }
