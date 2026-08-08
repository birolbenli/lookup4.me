"""DMARC lookup tool."""

from __future__ import annotations

import re

from .dns_common import is_valid_domain, normalize_domain, query_records

TAG_RE = re.compile(r"([a-zA-Z0-9]+)\s*=\s*([^;]+)")


def _parse_dmarc(record: str) -> dict:
    tags = {}
    for match in TAG_RE.finditer(record):
        tags[match.group(1).lower()] = match.group(2).strip()
    return {
        "raw": record,
        "tags": tags,
        "policy": tags.get("p"),
        "subdomain_policy": tags.get("sp"),
        "percentage": tags.get("pct", "100"),
        "rua": tags.get("rua"),
        "ruf": tags.get("ruf"),
        "adkim": tags.get("adkim", "r"),
        "aspf": tags.get("aspf", "r"),
        "fo": tags.get("fo"),
        "rf": tags.get("rf"),
        "ri": tags.get("ri"),
    }


def lookup_dmarc(domain: str) -> dict:
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"ok": False, "error": "Invalid domain name", "domain": domain}

    name = f"_dmarc.{domain}"
    txt = query_records(name, "TXT")
    records = [
        r["data"].strip('"').replace('" "', "")
        for r in txt.get("records") or []
        if "v=dmarc1" in r["data"].lower()
    ]

    if not records:
        return {
            "ok": False,
            "domain": domain,
            "query": name,
            "error": txt.get("error") or "No DMARC record",
            "records": [],
        }

    parsed = [_parse_dmarc(r) for r in records]
    return {
        "ok": True,
        "domain": domain,
        "query": name,
        "records": parsed,
        "dmarc": parsed[0],
    }
