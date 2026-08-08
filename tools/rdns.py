"""Reverse DNS lookup tool."""

from __future__ import annotations

from .dns_common import is_ip, normalize_domain, reverse_lookup


def lookup_rdns(value: str) -> dict:
    value = (value or "").strip()
    if not value:
        return {"ok": False, "error": "Please enter an IP address"}

    # Allow accidental hostname paste: reject clearly
    if not is_ip(value):
        # maybe user pasted host — still reject for this tool
        cleaned = normalize_domain(value)
        if not is_ip(cleaned):
            return {"ok": False, "error": "Please enter a valid IPv4 or IPv6 address", "input": value}

    return reverse_lookup(value)
