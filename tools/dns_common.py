"""Shared DNS helpers."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

import dns.exception
import dns.resolver
import dns.reversename

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\.?$"
)


def normalize_domain(value: str) -> str:
    domain = (value or "").strip().lower()
    domain = domain.removeprefix("http://").removeprefix("https://")
    domain = domain.split("/")[0].split(":")[0]
    return domain.rstrip(".")


def is_valid_domain(domain: str) -> bool:
    if not domain:
        return False
    return bool(DOMAIN_RE.match(domain + "." if not domain.endswith(".") else domain)) or bool(
        DOMAIN_RE.match(domain)
    )


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def get_resolver(nameservers: list[str] | None = None) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 8.0
    resolver.timeout = 5.0
    if nameservers:
        resolver.nameservers = nameservers
    return resolver


def query_records(name: str, rdtype: str) -> dict[str, Any]:
    resolver = get_resolver()
    try:
        answers = resolver.resolve(name, rdtype)
        records = []
        for rdata in answers:
            records.append(
                {
                    "data": rdata.to_text(),
                    "ttl": answers.rrset.ttl if answers.rrset else None,
                }
            )
        return {
            "ok": True,
            "name": name,
            "type": rdtype,
            "records": records,
        }
    except dns.resolver.NXDOMAIN:
        return {"ok": False, "name": name, "type": rdtype, "error": "NXDOMAIN", "records": []}
    except dns.resolver.NoAnswer:
        return {"ok": False, "name": name, "type": rdtype, "error": "NoAnswer", "records": []}
    except dns.resolver.NoNameservers:
        return {
            "ok": False,
            "name": name,
            "type": rdtype,
            "error": "NoNameservers",
            "records": [],
        }
    except dns.exception.Timeout:
        return {"ok": False, "name": name, "type": rdtype, "error": "Timeout", "records": []}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "name": name, "type": rdtype, "error": str(exc), "records": []}


def resolve_host_chain(hostname: str, max_depth: int = 12) -> dict[str, Any]:
    """Follow CNAME/host chain until an IP (or depth limit)."""
    hostname = normalize_domain(hostname)
    chain: list[dict[str, Any]] = []
    seen: set[str] = set()
    current = hostname

    for _ in range(max_depth):
        if current in seen:
            chain.append({"host": current, "type": "LOOP", "value": "CNAME loop detected"})
            break
        seen.add(current)

        if is_ip(current):
            chain.append({"host": current, "type": "IP", "value": current})
            break

        cname = query_records(current, "CNAME")
        if cname["ok"] and cname["records"]:
            target = normalize_domain(cname["records"][0]["data"])
            chain.append(
                {
                    "host": current,
                    "type": "CNAME",
                    "value": target,
                    "ttl": cname["records"][0].get("ttl"),
                }
            )
            current = target
            continue

        aaaa = query_records(current, "AAAA")
        a = query_records(current, "A")
        ips = [r["data"] for r in (a.get("records") or [])] + [
            r["data"] for r in (aaaa.get("records") or [])
        ]
        if ips:
            chain.append(
                {
                    "host": current,
                    "type": "A/AAAA",
                    "value": ips,
                    "ttl": (a.get("records") or aaaa.get("records") or [{}])[0].get("ttl"),
                }
            )
            break

        chain.append(
            {
                "host": current,
                "type": "UNRESOLVED",
                "value": a.get("error") or aaaa.get("error") or "No A/AAAA/CNAME",
            }
        )
        break

    leaf_ips: list[str] = []
    if chain:
        last = chain[-1]
        if last["type"] == "IP":
            leaf_ips = [last["value"]]
        elif last["type"] == "A/AAAA" and isinstance(last["value"], list):
            leaf_ips = last["value"]

    return {"hostname": hostname, "chain": chain, "ips": leaf_ips}


def reverse_lookup(ip: str) -> dict[str, Any]:
    ip = ip.strip()
    if not is_ip(ip):
        return {"ok": False, "error": "Invalid IP address", "ip": ip, "hosts": []}
    try:
        rev = dns.reversename.from_address(ip)
        answers = get_resolver().resolve(rev, "PTR")
        hosts = [normalize_domain(r.to_text()) for r in answers]
        return {"ok": True, "ip": ip, "hosts": hosts, "ptr_name": str(rev)}
    except dns.resolver.NXDOMAIN:
        return {"ok": False, "ip": ip, "error": "NXDOMAIN", "hosts": []}
    except dns.resolver.NoAnswer:
        return {"ok": False, "ip": ip, "error": "No PTR record", "hosts": []}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "ip": ip, "error": str(exc), "hosts": []}
