"""DKIM lookup with common selector detection and host chain resolution."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from .dns_common import is_valid_domain, normalize_domain, query_records, resolve_host_chain

# Common selectors used by major providers + generic names (EasyDMARC-style detect-all)
COMMON_SELECTORS = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "k3",
    "s1",
    "s2",
    "s3",
    "dkim",
    "dkim1",
    "dkim2",
    "mail",
    "email",
    "smtp",
    "mx",
    "mandrill",
    "mailgun",
    "mta",
    "pm",
    "protonmail",
    "protonmail2",
    "protonmail3",
    "cm",
    "cmk1",
    "zendesk1",
    "zendesk2",
    "everlytickey1",
    "everlytickey2",
    "krs",
    "pic",
    "class",
    "hs1",
    "hs2",
    "s1024",
    "s2048",
    "scph0920",
    "scph0321",
    "sm",
    "sm1",
    "sm2",
    "sig1",
    "sig2",
    "litesrv",
    "mxvault",
    "key1",
    "key2",
    "mailchimp",
    "mc",
    "ctct1",
    "ctct2",
    "amazonses",
    "yandex",
    "yahoo",
    "outlook",
    "office365",
    "o365",
    "sendgrid",
    "sg",
    "postmark",
    "pmta",
    "shopify",
    "bigcommerce",
    "hubspot",
    "hs1-100",
    "ming",
    "turbo",
    "mailjet",
    "mj1",
    "mj2",
    "brevo",
    "sendinblue",
]


def _extract_hosts_from_dkim(record: str) -> list[str]:
    hosts = []
    for part in record.split(";"):
        part = part.strip()
        if part.lower().startswith("p=") or not part:
            continue
        # n= notes can contain free text; skip IP-looking noise carefully
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if key in {"n", "t", "h", "k", "v", "g", "p"}:
            continue
        # Some records put service hosts in notes rarely; mainly resolve if value looks like hostname
        if key in {"s"} and "." in value and not value.startswith("http"):
            hosts.append(normalize_domain(value))
    return hosts


def _parse_dkim(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        tags[key.strip().lower()] = value.strip()

    public_key = tags.get("p", "")
    return {
        "raw": record,
        "tags": tags,
        "version": tags.get("v", "DKIM1"),
        "key_type": tags.get("k", "rsa"),
        "hash": tags.get("h"),
        "service": tags.get("s"),
        "notes": tags.get("n"),
        "flags": tags.get("t"),
        "public_key": public_key,
        "public_key_length": len(public_key),
        "revoked": public_key == "",
    }


def _check_selector(domain: str, selector: str) -> dict | None:
    name = f"{selector}._domainkey.{domain}"
    txt = query_records(name, "TXT")
    cname = query_records(name, "CNAME")

    records_raw = []
    for r in txt.get("records") or []:
        data = r["data"].strip('"').replace('" "', "")
        if "v=dkim1" in data.lower() or "p=" in data.lower():
            records_raw.append(data)

    if not records_raw and not (cname.get("ok") and cname.get("records")):
        return None

    host_resolutions = []
    if cname.get("ok") and cname.get("records"):
        for item in cname["records"]:
            target = normalize_domain(item["data"])
            host_resolutions.append(resolve_host_chain(target))

    # Also resolve any hostname-like values found in DKIM tags (rare)
    for raw in records_raw:
        for host in _extract_hosts_from_dkim(raw):
            host_resolutions.append(resolve_host_chain(host))

    # If CNAME pointed elsewhere, also try TXT at the end of chain hostname
    if not records_raw and host_resolutions:
        leaf_host = None
        for step in host_resolutions[0]["chain"]:
            if step["type"] in {"CNAME", "A/AAAA", "UNRESOLVED"}:
                leaf_host = step["host"]
        if leaf_host:
            leaf_txt = query_records(leaf_host, "TXT")
            for r in leaf_txt.get("records") or []:
                data = r["data"].strip('"').replace('" "', "")
                if "v=dkim1" in data.lower() or "p=" in data.lower():
                    records_raw.append(data)

    return {
        "selector": selector,
        "name": name,
        "found": True,
        "cname": [normalize_domain(r["data"]) for r in cname.get("records") or []],
        "records": [_parse_dkim(r) for r in records_raw],
        "host_resolutions": host_resolutions,
    }


def lookup_dkim(domain: str, selectors: list[str] | None = None) -> dict:
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return {"ok": False, "error": "Invalid domain name", "domain": domain}

    to_check = selectors or COMMON_SELECTORS
    # Preserve order, unique
    seen: set[str] = set()
    unique = []
    for s in to_check:
        s = s.strip().lower()
        if s and s not in seen:
            seen.add(s)
            unique.append(s)

    found: list[dict] = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_check_selector, domain, s): s for s in unique}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    found.sort(key=lambda x: x["selector"])

    return {
        "ok": bool(found),
        "domain": domain,
        "selectors_checked": len(unique),
        "selectors_found": len(found),
        "error": None if found else "No DKIM selectors found among common list",
        "results": found,
    }
