"""Record / file generators (guidance only — external publish still required)."""

from __future__ import annotations

from .dns_common import is_valid_domain, normalize_domain


def _need_domain(domain: str):
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return None, {"ok": False, "error": "Please enter a valid domain", "external_check": True}
    return domain, None


def generate_spf(domain: str) -> dict:
    domain, err = _need_domain(domain)
    if err:
        return err
    value = "v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all"
    return {
        "ok": True,
        "external_check": True,
        "generator": True,
        "domain": domain,
        "title": "Suggested SPF record",
        "records": [
            {
                "type": "TXT",
                "name": domain,
                "value": value,
                "note": "Edit includes for your providers. Prefer a single SPF TXT at the apex.",
            }
        ],
        "guidance": [
            "Publish exactly one SPF TXT on the root domain.",
            "Stay under 10 DNS lookups (include/a/mx/redirect).",
            "Use -all when ready to enforce; ~all while testing.",
        ],
    }


def generate_dmarc(domain: str) -> dict:
    domain, err = _need_domain(domain)
    if err:
        return err
    value = f"v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}; fo=1; adkim=s; aspf=s"
    return {
        "ok": True,
        "external_check": True,
        "generator": True,
        "domain": domain,
        "title": "Suggested DMARC record",
        "records": [
            {
                "type": "TXT",
                "name": f"_dmarc.{domain}",
                "value": value,
                "note": "Start with p=none + rua, then move to quarantine/reject.",
            }
        ],
        "guidance": [
            "Ensure SPF and DKIM pass before p=reject.",
            "Monitor rua aggregate reports.",
        ],
    }


def generate_mtasts(domain: str) -> dict:
    domain, err = _need_domain(domain)
    if err:
        return err
    dns = "v=STSv1; id=20260101"
    policy = (
        "version: STSv1\n"
        "mode: testing\n"
        f"mx: *.{domain}\n"
        "max_age: 604800\n"
    )
    return {
        "ok": True,
        "external_check": True,
        "generator": True,
        "domain": domain,
        "title": "Suggested MTA-STS configuration",
        "records": [
            {"type": "TXT", "name": f"_mta-sts.{domain}", "value": dns, "note": "Bump id when policy changes."},
            {
                "type": "HTTPS",
                "name": f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                "value": policy,
                "note": "Serve over valid HTTPS. Adjust mx: patterns to match your MX hosts.",
            },
        ],
        "guidance": [
            "Use mode: testing first, then enforce.",
            "Also publish TLS-RPT for reporting.",
        ],
    }


def generate_tlsrpt(domain: str) -> dict:
    domain, err = _need_domain(domain)
    if err:
        return err
    value = f"v=TLSRPTv1; rua=mailto:tlsrpt@{domain}"
    return {
        "ok": True,
        "external_check": True,
        "generator": True,
        "domain": domain,
        "title": "Suggested TLS-RPT record",
        "records": [
            {
                "type": "TXT",
                "name": f"_smtp._tls.{domain}",
                "value": value,
                "note": "rua may be mailto: or https: endpoints.",
            }
        ],
        "guidance": ["Pair with MTA-STS for actionable SMTP TLS reporting."],
    }


def generate_caa(domain: str) -> dict:
    domain, err = _need_domain(domain)
    if err:
        return err
    return {
        "ok": True,
        "external_check": True,
        "generator": True,
        "domain": domain,
        "title": "Suggested CAA records",
        "records": [
            {"type": "CAA", "name": domain, "value": '0 issue "letsencrypt.org"', "note": "Allow Let's Encrypt"},
            {
                "type": "CAA",
                "name": domain,
                "value": f'0 iodef "mailto:caa@{domain}"',
                "note": "Optional incident reporting",
            },
        ],
        "guidance": ["Add every CA you actually use (issue / issuewild)."],
    }


def generate_security_txt(domain: str) -> dict:
    domain, err = _need_domain(domain)
    if err:
        return err
    body = (
        f"Contact: mailto:security@{domain}\n"
        f"Expires: 2027-01-01T00:00:00.000Z\n"
        f"Canonical: https://{domain}/.well-known/security.txt\n"
        f"Preferred-Languages: en, tr\n"
        f"Policy: https://{domain}/security-policy\n"
    )
    return {
        "ok": True,
        "external_check": True,
        "generator": True,
        "domain": domain,
        "title": "Suggested security.txt",
        "records": [
            {
                "type": "HTTPS",
                "name": f"https://{domain}/.well-known/security.txt",
                "value": body,
                "note": "RFC 9116 — keep Expires updated.",
            }
        ],
        "guidance": ["Serve over HTTPS. Prefer /.well-known/security.txt."],
    }
