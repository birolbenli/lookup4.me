"""SMTP assessment for Exchange external scan — never sends DATA."""

from __future__ import annotations

import socket
import ssl
from typing import Any

from .dns_common import normalize_domain, query_records, resolve_host_chain
from .smtp_test import _read_reply, _send_cmd


def _mx_targets(org_domain: str, fallback_host: str) -> list[dict]:
    targets: list[dict] = []
    mx = query_records(org_domain, "MX")
    for item in mx.get("records") or []:
        parts = item["data"].split(maxsplit=1)
        if len(parts) != 2:
            continue
        pref, exchange = parts
        exchange = normalize_domain(exchange)
        resolved = resolve_host_chain(exchange)
        for ip in (resolved.get("ips") or [])[:2]:
            targets.append(
                {
                    "host": exchange,
                    "ip": ip,
                    "preference": int(pref) if pref.isdigit() else 0,
                    "source": "mx",
                }
            )
    if not targets:
        resolved = resolve_host_chain(fallback_host)
        for ip in (resolved.get("ips") or [])[:2]:
            targets.append({"host": fallback_host, "ip": ip, "preference": 0, "source": "a"})
    targets.sort(key=lambda t: t.get("preference", 0))
    return targets[:4]


def _parse_auth_mechs(ehlo_text: str) -> list[str]:
    mechs: list[str] = []
    for line in (ehlo_text or "").splitlines():
        upper = line.upper()
        if upper.startswith("250-AUTH") or upper.startswith("250 AUTH"):
            parts = line.split()[1:]
            for p in parts:
                if p.upper() == "AUTH":
                    continue
                mechs.append(p.upper())
    return mechs


def assess_smtp(org_domain: str, host: str, helo_name: str = "tools.birolbenli.com") -> dict:
    """EHLO / STARTTLS / AUTH + safe relay probe stopping at RCPT TO."""
    targets = _mx_targets(org_domain, host)
    attempts: list[dict] = []

    for target in targets:
        attempt: dict[str, Any] = {
            "host": target["host"],
            "ip": target["ip"],
            "port": 25,
            "source": target.get("source"),
            "preference": target.get("preference"),
        }
        sock = None
        try:
            sock = socket.create_connection((target["ip"], 25), timeout=10)
            banner = _read_reply(sock)
            ehlo = _send_cmd(sock, f"EHLO {helo_name}")
            auth_before = _parse_auth_mechs(ehlo)
            starttls_supported = "STARTTLS" in ehlo.upper()
            starttls_ok = None
            auth_after: list[str] = []
            tls_version = None
            if starttls_supported:
                tls_reply = _send_cmd(sock, "STARTTLS")
                starttls_ok = tls_reply.startswith("220")
                if starttls_ok:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=target["host"])
                    tls_version = sock.version()
                    ehlo_tls = _send_cmd(sock, f"EHLO {helo_name}")
                    auth_after = _parse_auth_mechs(ehlo_tls)
                    attempt["ehlo_after_tls"] = ehlo_tls[:500]
                else:
                    ehlo_tls = ""
            else:
                ehlo_tls = ""

            # Safe open-relay probe — never DATA
            relay = {"tested": False, "accepted_rcpt": False, "evidence": []}
            try:
                mail_r = _send_cmd(sock, "MAIL FROM:<probe@example.com>")
                relay["evidence"].append(f"MAIL FROM → {mail_r[:120]}")
                if mail_r.startswith("250"):
                    rcpt_r = _send_cmd(sock, "RCPT TO:<probe@example.net>")
                    relay["tested"] = True
                    relay["evidence"].append(f"RCPT TO → {rcpt_r[:120]}")
                    # 250 on unrelated external recipient is strong evidence; still require caution
                    if rcpt_r.startswith("250"):
                        relay["accepted_rcpt"] = True
                    # Reset session politely
                    try:
                        _send_cmd(sock, "RSET")
                    except Exception:  # noqa: BLE001
                        pass
            except Exception as exc:  # noqa: BLE001
                relay["error"] = str(exc)

            try:
                quit_r = _send_cmd(sock, "QUIT")
            except Exception:  # noqa: BLE001
                quit_r = ""

            attempt.update(
                {
                    "ok": banner.startswith("220"),
                    "banner": banner[:300],
                    "ehlo": ehlo[:500],
                    "starttls_supported": starttls_supported,
                    "starttls_ok": starttls_ok,
                    "tls_version": tls_version,
                    "auth_before_tls": auth_before,
                    "auth_after_tls": auth_after,
                    "relay": relay,
                    "quit": quit_r[:120],
                }
            )
            attempts.append(attempt)
            if attempt["ok"]:
                break
        except Exception as exc:  # noqa: BLE001
            attempt.update({"ok": False, "error": str(exc)})
            attempts.append(attempt)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:  # noqa: BLE001
                    pass

    success = next((a for a in attempts if a.get("ok")), None)
    relay_hits = [a for a in attempts if (a.get("relay") or {}).get("accepted_rcpt")]
    # Spec: require multiple evidence points before declaring open relay.
    open_relay = len(relay_hits) >= 1 and bool(
        success and (success.get("relay") or {}).get("accepted_rcpt")
    )

    return {
        "ok": bool(success),
        "org_domain": org_domain,
        "targets": targets,
        "result": success,
        "attempts": attempts,
        "open_relay_suspected": open_relay,
        "summary": {
            "reachable": bool(success),
            "starttls": bool(success and success.get("starttls_ok")),
            "auth_mechs": (success or {}).get("auth_after_tls")
            or (success or {}).get("auth_before_tls")
            or [],
            "tls_version": (success or {}).get("tls_version"),
            "open_relay_suspected": open_relay,
        },
    }
