"""Public mail-domain security checks for Exchange assessment."""

from __future__ import annotations

from .dns_common import normalize_domain, query_records
from .dkim import COMMON_SELECTORS, lookup_dkim
from .dmarc import lookup_dmarc
from .exchange_endpoints import request
from .spf import lookup_spf


def _txt_join(records: list[dict]) -> list[str]:
    out = []
    for r in records or []:
        data = (r.get("data") or "").strip().strip('"').replace('" "', "")
        if data:
            out.append(data)
    return out


def assess_mail_domain(org: str) -> dict:
    org = normalize_domain(org)
    spf = lookup_spf(org, follow=True, max_lookups=8)
    dmarc = lookup_dmarc(org)

    # DKIM — only known/common selectors (no brute force beyond COMMON_SELECTORS list)
    dkim = lookup_dkim(org, selectors=COMMON_SELECTORS[:40])
    found_selectors = [s.get("selector") for s in (dkim.get("results") or []) if s.get("found")]

    # MTA-STS DNS + policy
    mta_sts_dns = query_records(f"_mta-sts.{org}", "TXT")
    mta_sts_txt = _txt_join(mta_sts_dns.get("records") or [])
    policy = None
    policy_url = f"https://mta-sts.{org}/.well-known/mta-sts.txt"
    if mta_sts_txt:
        pol_res = request(policy_url, method="GET", follow_redirects=True)
        if pol_res.get("reachable") and pol_res.get("status_code") == 200:
            policy = {
                "url": policy_url,
                "body": (pol_res.get("body_preview") or "")[:500],
                "status_code": pol_res.get("status_code"),
            }

    tlsrpt = query_records(f"_smtp._tls.{org}", "TXT")
    tlsrpt_txt = _txt_join(tlsrpt.get("records") or [])

    caa = query_records(org, "CAA")
    caa_records = [r.get("data") for r in (caa.get("records") or []) if r.get("data")]

    mx = query_records(org, "MX")
    mx_hosts = []
    for r in mx.get("records") or []:
        parts = (r.get("data") or "").split(maxsplit=1)
        if len(parts) == 2:
            mx_hosts.append({"preference": parts[0], "host": normalize_domain(parts[1])})

    spf_count = 0
    if spf.get("spf"):
        spf_count = 1
    # Multiple SPF at root is bad
    root_txt = query_records(org, "TXT")
    spf_all = [t for t in _txt_join(root_txt.get("records") or []) if t.lower().startswith("v=spf1")]
    spf_count = len(spf_all)

    dmarc_policy = None
    if dmarc.get("ok") and dmarc.get("dmarc"):
        dmarc_policy = (dmarc["dmarc"].get("policy") or dmarc["dmarc"].get("p") or "").lower()
    elif dmarc.get("parsed"):
        dmarc_policy = (dmarc["parsed"].get("p") or "").lower()

    return {
        "ok": True,
        "domain": org,
        "spf": {
            "ok": bool(spf.get("ok")),
            "count": spf_count,
            "record": (spf.get("spf") or {}).get("raw") if isinstance(spf.get("spf"), dict) else None,
            "error": spf.get("error"),
        },
        "dmarc": {
            "ok": bool(dmarc.get("ok")),
            "policy": dmarc_policy,
            "error": dmarc.get("error"),
            "raw": (dmarc.get("record") or dmarc.get("raw")),
        },
        "dkim": {
            "ok": bool(found_selectors),
            "selectors_found": found_selectors[:15],
            "note": "Only common/discoverable selectors were queried (no brute force).",
        },
        "mta_sts": {
            "dns_txt": mta_sts_txt,
            "policy": policy,
            "present": bool(mta_sts_txt),
        },
        "tls_rpt": {
            "records": tlsrpt_txt,
            "present": bool(tlsrpt_txt),
        },
        "caa": {
            "records": caa_records[:10],
            "present": bool(caa_records),
        },
        "mx": mx_hosts[:10],
        "dnssec": {
            "status": "NOT_OBSERVABLE",
            "note": "Authoritative DNSSEC validation is not performed by this scanner.",
        },
        "dane": {
            "status": "NOT_OBSERVABLE",
            "note": "TLSA/DANE lookup requires DNSSEC-aware resolution; not confirmed here.",
        },
    }
