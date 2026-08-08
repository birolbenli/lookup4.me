"""MX lookup tool."""

from __future__ import annotations

from .dns_common import is_valid_domain, normalize_domain, query_records, resolve_host_chain


def lookup_mx(domain: str) -> dict:
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"ok": False, "error": "Invalid domain name", "domain": domain}

    result = query_records(domain, "MX")
    records = []
    for item in result.get("records") or []:
        # dnspython MX text: "10 mail.example.com."
        parts = item["data"].split(maxsplit=1)
        if len(parts) == 2:
            preference, exchange = parts
            exchange = normalize_domain(exchange)
        else:
            preference, exchange = "", normalize_domain(item["data"])

        host_resolution = resolve_host_chain(exchange)
        records.append(
            {
                "preference": int(preference) if preference.isdigit() else preference,
                "exchange": exchange,
                "ttl": item.get("ttl"),
                "ips": host_resolution["ips"],
                "chain": host_resolution["chain"],
            }
        )

    records.sort(key=lambda r: r["preference"] if isinstance(r["preference"], int) else 9999)

    return {
        "ok": bool(records) or result.get("ok"),
        "domain": domain,
        "error": None if records else result.get("error"),
        "records": records,
        "count": len(records),
    }
