#!/usr/bin/env python3
"""Build Turkish gettext catalog from the legacy snapshot (one-time) or refresh .mo.

Usage:
  python scripts/build_translations.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from babel.messages.catalog import Catalog
from babel.messages.mofile import write_mo
from babel.messages.pofile import read_po, write_po

TR_PO = ROOT / "translations" / "tr" / "LC_MESSAGES" / "messages.po"
TR_MO = ROOT / "translations" / "tr" / "LC_MESSAGES" / "messages.mo"

# English tool strings (msgids) → legacy Turkish values keyed by slug field
TOOL_MSGIDS = {
    "mx": {
        "name": "MX Lookup",
        "desc": "Find mail exchangers and resolve their IPs.",
    },
    "spf": {
        "name": "SPF Lookup",
        "desc": "Inspect SPF records and included policies.",
    },
    "dkim": {
        "name": "DKIM Lookup",
        "desc": "Detect common DKIM selectors and follow host chains.",
    },
    "dmarc": {
        "name": "DMARC Lookup",
        "desc": "Check DMARC policy, rua/ruf and alignment tags.",
    },
    "headers": {
        "name": "Email Header Analyzer",
        "desc": "Paste raw headers/source and get a clear, educational report.",
        "placeholder": "Paste full email source or headers here…",
    },
    "mailtest": {
        "name": "Mail Tester",
        "desc": "Get a random inbox, send a message, and see a deliverability score.",
    },
    "dns": {
        "name": "DNS Lookup",
        "desc": "Query A, AAAA, CNAME, NS, TXT, SOA, CAA, MX and SRV.",
    },
    "ns": {
        "name": "NS Lookup",
        "desc": "List authoritative nameservers for a domain.",
    },
    "caa": {
        "name": "CAA Lookup",
        "desc": "See which CAs are allowed to issue certificates.",
    },
    "whois": {
        "name": "WHOIS",
        "desc": "Query domain or IP registration data.",
    },
    "ssl": {
        "name": "SSL Checker",
        "desc": "Check up to 10 certificates at once in a table.",
    },
    "http": {
        "name": "Raw HTTP Headers",
        "desc": "Fetch status code and all response headers (unscored).",
    },
    "port": {
        "name": "Port Check",
        "desc": "Test if a TCP port is open on a host.",
    },
    "rdns": {
        "name": "Reverse DNS",
        "desc": "Resolve PTR records for an IP address.",
    },
    "blacklist": {
        "name": "Blacklist Check",
        "desc": "Check an IP against common DNSBL / RBL lists.",
    },
    "smtp": {
        "name": "SMTP Test",
        "desc": "Test SMTP banner, EHLO and STARTTLS on port 25.",
    },
    "exchange": {
        "name": "Microsoft Exchange Server HC",
        "desc": "External-only Exchange security assessment: TLS, auth, VDirs, SMTP, mail domain, hybrid signals.",
        "placeholder": "mail.example.com",
    },
    "autodiscover": {
        "name": "Exchange Autodiscover",
        "desc": "Check Autodiscover DNS (A/CNAME + SRV) and HTTPS endpoints — including accepted domains that SRV to a primary org.",
        "placeholder": "btcturkhisse.com / btcturk.com",
    },
    "ip": {
        "name": "IP Lookup",
        "desc": "See your public IP (curl-friendly) or inspect another IP.",
        "placeholder": "leave empty for your IP",
    },
    "mtasts": {
        "name": "MTA-STS Checker",
        "desc": "Check _mta-sts DNS and the HTTPS policy file (mode, max_age, mx).",
    },
    "tlsrpt": {
        "name": "TLS-RPT Checker",
        "desc": "Validate _smtp._tls reporting records and rua destinations.",
    },
    "bimi": {
        "name": "BIMI Checker",
        "desc": "Inspect default._bimi TXT, logo URL reachability, and VMC hints.",
    },
    "dane": {
        "name": "DANE / TLSA Checker",
        "desc": "List public TLSA records for MX hosts (external DNS only).",
    },
    "soa": {
        "name": "SOA Checker",
        "desc": "Parse SOA serial, refresh, retry, expire, and minimum TTL.",
    },
    "cname": {
        "name": "CNAME Checker",
        "desc": "Follow CNAME chains to the final destination and detect loops.",
    },
    "securitytxt": {
        "name": "security.txt Checker",
        "desc": "Fetch /.well-known/security.txt and validate Contact / Expires fields.",
    },
    "hsts": {
        "name": "HSTS Checker",
        "desc": "Inspect Strict-Transport-Security max-age, includeSubDomains, preload.",
    },
    "robots": {
        "name": "robots.txt Checker",
        "desc": "Fetch robots.txt and summarize User-agent and Sitemap lines.",
    },
    "redirect": {
        "name": "Redirect Checker",
        "desc": "Trace HTTP redirect chains (301/302/307/308) to the final URL.",
    },
    "secheaders": {
        "name": "HTTP Security Headers",
        "desc": "Score HSTS, CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP.",
    },
    "spfgen": {
        "name": "Create SPF record",
        "desc": "Build a starter SPF TXT to publish — not a live lookup.",
    },
    "dmarcgen": {
        "name": "Create DMARC record",
        "desc": "Build a starter _dmarc policy — not a live lookup.",
    },
    "mtastsgen": {
        "name": "Create MTA-STS policy",
        "desc": "Build starter DNS + policy file text — not a live check.",
    },
    "tlsrptgen": {
        "name": "Create TLS-RPT record",
        "desc": "Build a starter _smtp._tls record — not a live check.",
    },
    "caagen": {
        "name": "Create CAA records",
        "desc": "Build starter CAA issue/iodef records — not a live lookup.",
    },
    "securitytxtgen": {
        "name": "Create security.txt",
        "desc": "Build RFC 9116 security.txt text — not a live fetch.",
    },
}


def _add(catalog: Catalog, msgid: str, msgstr: str) -> None:
    if not msgid:
        return
    if msgid in catalog:
        # Prefer non-empty translation if we see the string again
        existing = catalog[msgid]
        if existing.string or not msgstr:
            return
    catalog.add(msgid, msgstr or None)


def build_from_legacy() -> Catalog:
    from email_report_messages import EMAIL_REPORT_TR
    from scripts.legacy_i18n_snapshot import JS_TR, TOOLS_TR, TR

    catalog = Catalog(
        locale="tr",
        project="lookup4.me",
        version="1.0",
        copyright_holder="Birol Benli",
        msgid_bugs_address="birolbenli@gmail.com",
        creation_date=datetime.now(timezone.utc),
        charset="utf-8",
    )
    for msgid, msgstr in TR.items():
        _add(catalog, msgid, msgstr)
    for msgid, msgstr in JS_TR.items():
        _add(catalog, msgid, msgstr)
    for msgid, msgstr in EMAIL_REPORT_TR.items():
        _add(catalog, msgid, msgstr)
    for slug, tr_fields in TOOLS_TR.items():
        en_fields = TOOL_MSGIDS.get(slug) or {}
        for key, tr_val in tr_fields.items():
            en_val = en_fields.get(key)
            if en_val:
                _add(catalog, en_val, tr_val)
    return catalog


def merge_catalog(base: Catalog, extra: Catalog) -> None:
    for message in extra:
        if not message.id:
            continue
        if message.id not in base:
            base.add(message.id, message.string)
        elif message.string and not (base[message.id].string or "").strip():
            base[message.id].string = message.string


def main() -> int:
    TR_PO.parent.mkdir(parents=True, exist_ok=True)
    legacy = build_from_legacy()

    if TR_PO.is_file():
        with TR_PO.open("rb") as fh:
            catalog = read_po(fh)
        merge_catalog(catalog, legacy)
        # Prefer email-report TR overrides when both exist
        from email_report_messages import EMAIL_REPORT_TR

        for msgid, msgstr in EMAIL_REPORT_TR.items():
            if msgid in catalog:
                catalog[msgid].string = msgstr
            else:
                catalog.add(msgid, msgstr)
    else:
        catalog = legacy

    with TR_PO.open("wb") as fh:
        write_po(fh, catalog, width=100)
    with TR_MO.open("wb") as fh:
        write_mo(fh, catalog)

    print(f"Wrote {TR_PO.relative_to(ROOT)} ({len(catalog)} messages)")
    print(f"Wrote {TR_MO.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
