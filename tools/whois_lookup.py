"""Simple WHOIS lookup over TCP/43."""

from __future__ import annotations

import re
import socket

from .dns_common import is_ip, is_valid_domain, normalize_domain

IANA_WHOIS = "whois.iana.org"


def _query(server: str, query: str, timeout: float = 10.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode("utf-8", errors="ignore"))
        chunks: list[bytes] = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _referral_server(text: str) -> str | None:
    patterns = [
        r"whois:\s*(\S+)",
        r"ReferralServer:\s*whois://(\S+)",
        r"Registrar WHOIS Server:\s*(\S+)",
        r"Whois Server:\s*(\S+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            server = match.group(1).strip().rstrip("/")
            server = server.removeprefix("whois://")
            if server and "." in server:
                return server.lower()
    return None


def lookup_whois(target: str) -> dict:
    target = (target or "").strip()
    if not target:
        return {"ok": False, "error": "Please enter a domain or IP"}

    query = target
    if not is_ip(target):
        query = normalize_domain(target)
        if not is_valid_domain(query):
            return {"ok": False, "error": "Invalid domain or IP", "query": target}

    try:
        bootstrap = _query(IANA_WHOIS, query)
        server = _referral_server(bootstrap) or IANA_WHOIS
        if server == IANA_WHOIS and not is_ip(query):
            # fallback common gTLD servers when IANA returns little
            tld = query.rsplit(".", 1)[-1]
            guesses = {
                "com": "whois.verisign-grs.com",
                "net": "whois.verisign-grs.com",
                "org": "whois.pir.org",
                "io": "whois.nic.io",
                "me": "whois.nic.me",
                "info": "whois.afilias.net",
                "co": "whois.nic.co",
                "tr": "whois.trabis.gov.tr",
            }
            server = guesses.get(tld, server)

        body = _query(server, query)
        if len(body.strip()) < 20 and server != IANA_WHOIS:
            body = bootstrap

        return {
            "ok": True,
            "query": query,
            "server": server,
            "raw": body.strip(),
        }
    except socket.timeout:
        return {"ok": False, "query": query, "error": "WHOIS timeout"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "query": query, "error": str(exc)}
