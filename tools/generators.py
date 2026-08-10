"""Record / file generators: inspect existing public config, then improve or create."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from .dns_common import is_valid_domain, normalize_domain, query_records
from .dmarc import lookup_dmarc
from .mtasts import check_mtasts
from .security_txt import check_security_txt
from .spf import lookup_spf
from .tlsrpt import check_tlsrpt


def _need_domain(domain: str):
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return None, {"ok": False, "error": "Please enter a valid domain", "external_check": True}
    return domain, None


def _txt_join(records: list[dict]) -> list[str]:
    out = []
    for r in records or []:
        data = (r.get("data") or "").strip().strip('"').replace('" "', "")
        if data:
            out.append(data)
    return out


def _base(domain: str, title: str, *, mode: str, existing, records, changes, explanations, guidance=None):
    return {
        "ok": True,
        "external_check": True,
        "generator": True,
        "domain": domain,
        "title": title,
        "mode": mode,  # created | improved
        "existing": existing,
        "records": records,
        "changes": changes,
        "explanations": explanations,
        "guidance": guidance or [
            "Review the proposed value before publishing.",
            "This is an external check — nothing is written to your DNS/host automatically.",
        ],
    }


def generate_spf(domain: str) -> dict:
    domain, err = _need_domain(domain)
    if err:
        return err

    current = lookup_spf(domain, follow=False)
    existing_raw = (current.get("spf") or {}).get("raw") if current.get("ok") else None
    existing = {
        "found": bool(existing_raw),
        "summary": existing_raw or "No SPF TXT on the apex domain.",
        "records": [{"type": "TXT", "name": domain, "value": existing_raw}] if existing_raw else [],
    }

    changes = []
    parts = ["v=spf1"]

    if existing_raw:
        # Keep provider includes / ip4 / ip6 / a / mx (except all / v=)
        tokens = existing_raw.split()
        kept = []
        for tok in tokens[1:]:  # skip v=spf1
            low = tok.lower()
            if low.endswith("all"):
                continue
            if low.startswith("redirect="):
                # Prefer explicit includes over redirect for clarity when improving
                kept.append(tok)
                continue
            kept.append(tok)
        if kept:
            parts.extend(kept)
            changes.append(
                {
                    "item": "Existing mechanisms",
                    "action": "kept",
                    "detail": " ".join(kept),
                    "why": "Preserves your current sending sources (include/ip4/ip6/a/mx).",
                }
            )
        else:
            parts.extend(["include:_spf.google.com", "include:spf.protection.outlook.com"])
            changes.append(
                {
                    "item": "include mechanisms",
                    "action": "added",
                    "detail": "include:_spf.google.com include:spf.protection.outlook.com",
                    "why": "Existing SPF had no usable mechanisms; common Google/Microsoft includes were suggested as a starting point — edit to match your providers.",
                }
            )

        old_all = next((t for t in tokens if t.lower().endswith("all")), None)
        if not old_all:
            parts.append("~all")
            changes.append(
                {
                    "item": "~all",
                    "action": "added",
                    "detail": "~all",
                    "why": "Soft-fail for mail that does not match SPF. Safer first step than -all while you monitor.",
                }
            )
        elif old_all.lower() in {"?all", "+all"}:
            parts.append("~all")
            changes.append(
                {
                    "item": "all",
                    "action": "improved",
                    "detail": f"{old_all} → ~all",
                    "why": "?all/+all are weak. ~all soft-fails unauthorized senders; move to -all when ready.",
                }
            )
        elif old_all.lower() == "~all":
            parts.append("~all")
            changes.append(
                {
                    "item": "~all",
                    "action": "kept",
                    "detail": "~all",
                    "why": "Soft-fail kept. Switch to -all after confirming legitimate mail passes SPF/DKIM.",
                }
            )
        else:
            parts.append(old_all)
            changes.append(
                {
                    "item": old_all,
                    "action": "kept",
                    "detail": old_all,
                    "why": "Hard-fail (-all) already enforces SPF for non-matching senders.",
                }
            )
        mode = "improved"
        title = "Improved SPF record (based on current DNS)"
    else:
        parts.extend(["include:_spf.google.com", "include:spf.protection.outlook.com", "~all"])
        changes = [
            {
                "item": "v=spf1",
                "action": "added",
                "detail": "v=spf1",
                "why": "Declares this TXT as an SPF policy (RFC 7208).",
            },
            {
                "item": "include:_spf.google.com",
                "action": "added",
                "detail": "include:_spf.google.com",
                "why": "Allows Google Workspace / Gmail sending infrastructure. Remove if unused.",
            },
            {
                "item": "include:spf.protection.outlook.com",
                "action": "added",
                "detail": "include:spf.protection.outlook.com",
                "why": "Allows Microsoft 365 / Exchange Online. Remove if unused.",
            },
            {
                "item": "~all",
                "action": "added",
                "detail": "~all",
                "why": "Soft-fail everything else. Tighten to -all after validation.",
            },
        ]
        mode = "created"
        title = "New SPF record (none found)"

    value = " ".join(parts)
    if existing_raw and value == existing_raw:
        changes.append(
            {
                "item": "Record",
                "action": "unchanged",
                "detail": value,
                "why": "Current SPF already looks reasonable; no structural change suggested.",
            }
        )

    explanations = [
        {"token": "v=spf1", "meaning": "SPF version marker — required."},
        {"token": "include:…", "meaning": "Trust another domain’s SPF (counts toward the 10-lookup limit)."},
        {"token": "ip4:/ip6:", "meaning": "Allow a specific sending IP or CIDR."},
        {"token": "a / mx", "meaning": "Allow the domain’s A/AAAA or MX hosts to send."},
        {"token": "~all", "meaning": "Soft-fail non-matching mail (mark, don’t hard reject)."},
        {"token": "-all", "meaning": "Fail non-matching mail (stronger; use when confident)."},
    ]

    return _base(
        domain,
        title,
        mode=mode,
        existing=existing,
        records=[
            {
                "type": "TXT",
                "name": domain,
                "value": value,
                "note": "Publish a single SPF TXT at the apex. Stay under 10 DNS lookups.",
            }
        ],
        changes=changes,
        explanations=explanations,
        guidance=[
            "Keep only includes for providers you actually use.",
            "Never publish two SPF TXT records on the same name.",
            "External check only — you must update DNS yourself.",
        ],
    )


def generate_dmarc(domain: str) -> dict:
    domain, err = _need_domain(domain)
    if err:
        return err

    current = lookup_dmarc(domain)
    dmarc = current.get("dmarc") if current.get("ok") else None
    existing_raw = (dmarc or {}).get("raw")
    existing = {
        "found": bool(existing_raw),
        "summary": existing_raw or "No DMARC TXT at _dmarc." + domain,
        "records": (
            [{"type": "TXT", "name": f"_dmarc.{domain}", "value": existing_raw}] if existing_raw else []
        ),
    }

    tags = dict((dmarc or {}).get("tags") or {})
    changes = []

    if existing_raw:
        mode = "improved"
        title = "Improved DMARC record (based on current DNS)"
        if "v" not in tags:
            tags["v"] = "DMARC1"
            changes.append(
                {
                    "item": "v=DMARC1",
                    "action": "added",
                    "why": "Required DMARC version tag.",
                }
            )
        p = (tags.get("p") or "none").lower()
        if p == "none":
            tags["p"] = "quarantine"
            changes.append(
                {
                    "item": "p",
                    "action": "improved",
                    "detail": "none → quarantine",
                    "why": "Moves from monitor-only to quarantine of failing messages. Use p=reject when ready.",
                }
            )
        else:
            changes.append(
                {
                    "item": "p",
                    "action": "kept",
                    "detail": tags.get("p"),
                    "why": "Existing policy kept.",
                }
            )
        if not tags.get("rua"):
            tags["rua"] = f"mailto:dmarc@{domain}"
            changes.append(
                {
                    "item": "rua",
                    "action": "added",
                    "detail": tags["rua"],
                    "why": "Aggregate reports so you can see spoofing/authentication failures.",
                }
            )
        else:
            changes.append(
                {
                    "item": "rua",
                    "action": "kept",
                    "detail": tags.get("rua"),
                    "why": "Reporting address already present.",
                }
            )
        if not tags.get("fo"):
            tags["fo"] = "1"
            changes.append(
                {
                    "item": "fo=1",
                    "action": "added",
                    "why": "Request failure reports when either SPF or DKIM fails (useful with ruf).",
                }
            )
        if (tags.get("adkim") or "r").lower() != "s":
            old = tags.get("adkim", "r")
            tags["adkim"] = "s"
            changes.append(
                {
                    "item": "adkim",
                    "action": "improved",
                    "detail": f"{old} → s",
                    "why": "Strict DKIM identifier alignment (org domain must match).",
                }
            )
        if (tags.get("aspf") or "r").lower() != "s":
            old = tags.get("aspf", "r")
            tags["aspf"] = "s"
            changes.append(
                {
                    "item": "aspf",
                    "action": "improved",
                    "detail": f"{old} → s",
                    "why": "Strict SPF identifier alignment.",
                }
            )
    else:
        mode = "created"
        title = "New DMARC record (none found)"
        tags = {
            "v": "DMARC1",
            "p": "none",
            "rua": f"mailto:dmarc@{domain}",
            "fo": "1",
            "adkim": "s",
            "aspf": "s",
        }
        changes = [
            {"item": "v=DMARC1", "action": "added", "why": "Required DMARC version."},
            {
                "item": "p=none",
                "action": "added",
                "why": "Monitor mode first — receivers report but do not quarantine/reject yet.",
            },
            {
                "item": "rua",
                "action": "added",
                "detail": tags["rua"],
                "why": "Where aggregate XML reports are sent.",
            },
            {"item": "fo=1", "action": "added", "why": "Richer failure reporting options."},
            {"item": "adkim=s / aspf=s", "action": "added", "why": "Strict alignment for DKIM and SPF."},
        ]

    # Stable tag order
    order = ["v", "p", "sp", "pct", "rua", "ruf", "fo", "adkim", "aspf", "ri", "rf"]
    parts = []
    for key in order:
        if key in tags and tags[key] is not None and str(tags[key]) != "":
            parts.append(f"{key}={tags[key]}")
    for key, val in tags.items():
        if key not in order and val is not None and str(val) != "":
            parts.append(f"{key}={val}")
    value = "; ".join(parts)

    explanations = [
        {"token": "p=", "meaning": "Policy for the organizational domain: none | quarantine | reject."},
        {"token": "sp=", "meaning": "Policy for subdomains (optional)."},
        {"token": "rua=", "meaning": "Aggregate report mailbox or HTTPS endpoint."},
        {"token": "ruf=", "meaning": "Forensic/failure reports (optional; privacy-sensitive)."},
        {"token": "adkim=/aspf=", "meaning": "Alignment mode: r=relaxed, s=strict."},
        {"token": "pct=", "meaning": "Percentage of mail the policy applies to (rollout)."},
    ]

    return _base(
        domain,
        title,
        mode=mode,
        existing=existing,
        records=[
            {
                "type": "TXT",
                "name": f"_dmarc.{domain}",
                "value": value,
                "note": "Publish at _dmarc.<domain>. Move p=none → quarantine → reject as reports look clean.",
            }
        ],
        changes=changes,
        explanations=explanations,
    )


def generate_mtasts(domain: str) -> dict:
    domain, err = _need_domain(domain)
    if err:
        return err

    cur = check_mtasts(domain)
    dns_recs = (cur.get("dns") or {}).get("records") or []
    id_rec = (cur.get("dns") or {}).get("id_record")
    pol = cur.get("policy") or {}
    has_dns = bool(dns_recs)
    has_pol = bool(pol.get("reachable") and pol.get("raw"))

    existing = {
        "found": has_dns or has_pol,
        "summary": (
            (id_rec or (dns_recs[0] if dns_recs else "No _mta-sts TXT"))
            + (" | policy OK" if has_pol else " | policy missing/unreachable")
        ),
        "records": [],
    }
    if id_rec or dns_recs:
        existing["records"].append(
            {"type": "TXT", "name": f"_mta-sts.{domain}", "value": id_rec or dns_recs[0]}
        )
    if has_pol:
        existing["records"].append(
            {
                "type": "HTTPS",
                "name": pol.get("url") or f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                "value": pol.get("raw") or "",
            }
        )

    # MX patterns from live MX
    mx_q = query_records(domain, "MX")
    mx_hosts = []
    for r in mx_q.get("records") or []:
        parts = (r.get("data") or "").split(maxsplit=1)
        if len(parts) == 2:
            mx_hosts.append(normalize_domain(parts[1]))
    mx_lines = [f"mx: {h}" for h in mx_hosts[:8]] or [f"mx: *.{domain}"]

    changes = []
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    dns_value = f"v=STSv1; id={today}"

    mode_val = (pol.get("mode") or "").lower()
    if has_pol and mode_val == "enforce":
        new_mode = "enforce"
        changes.append({"item": "mode", "action": "kept", "detail": "enforce", "why": "Already enforcing."})
    elif has_pol and mode_val == "testing":
        new_mode = "testing"
        changes.append(
            {
                "item": "mode",
                "action": "kept",
                "detail": "testing",
                "why": "Kept testing. Switch to enforce after TLS-RPT looks clean.",
            }
        )
    elif has_pol and mode_val == "none":
        new_mode = "testing"
        changes.append(
            {
                "item": "mode",
                "action": "improved",
                "detail": "none → testing",
                "why": "Re-enables reporting path toward enforcement.",
            }
        )
    else:
        new_mode = "testing"
        changes.append(
            {
                "item": "mode",
                "action": "added",
                "detail": "testing",
                "why": "Safe first policy mode while you validate MX coverage.",
            }
        )

    max_age = pol.get("max_age") if str(pol.get("max_age") or "").isdigit() else None
    if not max_age or int(max_age) < 86400:
        new_max = "604800"
        changes.append(
            {
                "item": "max_age",
                "action": "improved" if max_age else "added",
                "detail": f"{max_age or '—'} → {new_max}",
                "why": "Cache policy for 7 days (604800s). Too-low values cause churn.",
            }
        )
    else:
        new_max = str(max_age)
        changes.append({"item": "max_age", "action": "kept", "detail": new_max, "why": "Existing max_age kept."})

    if mx_hosts:
        changes.append(
            {
                "item": "mx patterns",
                "action": "improved" if has_pol else "added",
                "detail": ", ".join(mx_hosts[:8]),
                "why": "Derived from your live MX records so the policy matches real mail hosts.",
            }
        )
    else:
        changes.append(
            {
                "item": "mx patterns",
                "action": "added",
                "detail": f"*.{domain}",
                "why": "No MX found; wildcard pattern suggested — replace with exact MX hostnames.",
            }
        )

    if has_dns:
        changes.append(
            {
                "item": "id",
                "action": "improved",
                "detail": f"id={today}",
                "why": "Bump id whenever the policy file changes so senders refresh.",
            }
        )
    else:
        changes.append(
            {
                "item": "_mta-sts TXT",
                "action": "added",
                "detail": dns_value,
                "why": "DNS discovery record pointing receivers at your MTA-STS policy host.",
            }
        )

    policy = "version: STSv1\n" f"mode: {new_mode}\n" + "\n".join(mx_lines) + f"\nmax_age: {new_max}\n"
    mode = "improved" if (has_dns or has_pol) else "created"
    title = (
        "Improved MTA-STS configuration (based on current DNS/HTTPS)"
        if mode == "improved"
        else "New MTA-STS configuration (none found)"
    )

    explanations = [
        {"token": "v=STSv1 / version", "meaning": "MTA-STS version (RFC 8461)."},
        {"token": "id=", "meaning": "Policy version id in DNS — change when policy content changes."},
        {"token": "mode", "meaning": "testing = report only; enforce = require TLS to listed MX; none = disable."},
        {"token": "mx:", "meaning": "Which MX hostnames the policy applies to (patterns allowed)."},
        {"token": "max_age", "meaning": "How long senders may cache the policy (seconds)."},
    ]

    return _base(
        domain,
        title,
        mode=mode,
        existing=existing,
        records=[
            {
                "type": "TXT",
                "name": f"_mta-sts.{domain}",
                "value": dns_value,
                "note": "DNS discovery record.",
            },
            {
                "type": "HTTPS",
                "name": f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                "value": policy,
                "note": "Serve over a valid HTTPS certificate for mta-sts.<domain>.",
            },
        ],
        changes=changes,
        explanations=explanations,
        guidance=[
            "Publish TLS-RPT alongside MTA-STS.",
            "Move mode testing → enforce after reviewing reports.",
        ],
    )


def generate_tlsrpt(domain: str) -> dict:
    domain, err = _need_domain(domain)
    if err:
        return err

    cur = check_tlsrpt(domain)
    records = cur.get("records") or []
    existing_raw = records[0]["raw"] if records else None
    existing = {
        "found": bool(existing_raw),
        "summary": existing_raw or f"No TXT at _smtp._tls.{domain}",
        "records": (
            [{"type": "TXT", "name": f"_smtp._tls.{domain}", "value": existing_raw}] if existing_raw else []
        ),
    }

    changes = []
    if existing_raw:
        tags = dict(records[0].get("tags") or {})
        mode = "improved"
        title = "Improved TLS-RPT record (based on current DNS)"
        if (tags.get("v") or "").upper() != "TLSRPTV1":
            tags["v"] = "TLSRPTv1"
            changes.append(
                {
                    "item": "v",
                    "action": "improved",
                    "detail": "TLSRPTv1",
                    "why": "Correct version string required by RFC 8460.",
                }
            )
        else:
            tags["v"] = "TLSRPTv1"
            changes.append({"item": "v=TLSRPTv1", "action": "kept", "why": "Version already correct."})
        rua = tags.get("rua") or ""
        if not rua:
            tags["rua"] = f"mailto:tlsrpt@{domain}"
            changes.append(
                {
                    "item": "rua",
                    "action": "added",
                    "detail": tags["rua"],
                    "why": "Without rua, TLS failure reports have nowhere to go.",
                }
            )
        else:
            # validate destinations
            bad = [
                d.strip()
                for d in rua.split(",")
                if d.strip() and not (d.strip().startswith("mailto:") or d.strip().startswith("https://"))
            ]
            if bad:
                tags["rua"] = f"mailto:tlsrpt@{domain}"
                changes.append(
                    {
                        "item": "rua",
                        "action": "improved",
                        "detail": f"invalid → {tags['rua']}",
                        "why": "rua must be mailto: or https: URIs.",
                    }
                )
            else:
                changes.append(
                    {"item": "rua", "action": "kept", "detail": rua, "why": "Reporting destination kept."}
                )
        value = f"v={tags.get('v', 'TLSRPTv1')}; rua={tags.get('rua')}"
    else:
        mode = "created"
        title = "New TLS-RPT record (none found)"
        value = f"v=TLSRPTv1; rua=mailto:tlsrpt@{domain}"
        changes = [
            {"item": "v=TLSRPTv1", "action": "added", "why": "TLS-RPT version marker."},
            {
                "item": "rua",
                "action": "added",
                "detail": f"mailto:tlsrpt@{domain}",
                "why": "Mailbox (or https URL) that receives SMTP TLS reporting JSON.",
            },
        ]

    explanations = [
        {"token": "v=TLSRPTv1", "meaning": "Identifies a TLS reporting policy (RFC 8460)."},
        {
            "token": "rua=",
            "meaning": "Report URI(s): mailto:address or https://endpoint (comma-separated).",
        },
    ]

    return _base(
        domain,
        title,
        mode=mode,
        existing=existing,
        records=[
            {
                "type": "TXT",
                "name": f"_smtp._tls.{domain}",
                "value": value,
                "note": "Works best together with MTA-STS.",
            }
        ],
        changes=changes,
        explanations=explanations,
    )


def generate_caa(domain: str) -> dict:
    domain, err = _need_domain(domain)
    if err:
        return err

    q = query_records(domain, "CAA")
    existing_vals = [r.get("data") for r in (q.get("records") or []) if r.get("data")]
    existing = {
        "found": bool(existing_vals),
        "summary": "; ".join(existing_vals[:6]) if existing_vals else "No CAA records",
        "records": [{"type": "CAA", "name": domain, "value": v} for v in existing_vals],
    }

    changes = []
    proposed = []
    issuers = []
    has_iodef = False
    for val in existing_vals:
        low = val.lower()
        if "iodef" in low:
            has_iodef = True
            proposed.append(val)
        elif "issuewild" in low or re.search(r"\bissue\b", low):
            issuers.append(val)
            proposed.append(val)

    if existing_vals:
        mode = "improved"
        title = "Improved CAA set (based on current DNS)"
        if issuers:
            changes.append(
                {
                    "item": "issue / issuewild",
                    "action": "kept",
                    "detail": ", ".join(issuers[:8]),
                    "why": "Existing CA allow-list preserved.",
                }
            )
        else:
            proposed.insert(0, '0 issue "letsencrypt.org"')
            changes.append(
                {
                    "item": 'issue "letsencrypt.org"',
                    "action": "added",
                    "why": "No issue tag found; Let's Encrypt suggested as a common baseline — add your real CAs.",
                }
            )
        if not has_iodef:
            iodef = f'0 iodef "mailto:caa@{domain}"'
            proposed.append(iodef)
            changes.append(
                {
                    "item": "iodef",
                    "action": "added",
                    "detail": iodef,
                    "why": "Tells CAs where to report unauthorized issuance attempts.",
                }
            )
        else:
            changes.append({"item": "iodef", "action": "kept", "why": "Incident contact already present."})
    else:
        mode = "created"
        title = "New CAA records (none found)"
        proposed = [
            '0 issue "letsencrypt.org"',
            f'0 iodef "mailto:caa@{domain}"',
        ]
        changes = [
            {
                "item": 'issue "letsencrypt.org"',
                "action": "added",
                "why": "Only this CA may issue certificates for the domain (adjust to your CA).",
            },
            {
                "item": "iodef",
                "action": "added",
                "why": "Reporting mailbox for CAA/unauthorized issuance notices.",
            },
        ]

    explanations = [
        {"token": "issue", "meaning": "CAs allowed to issue for the domain."},
        {"token": "issuewild", "meaning": "CAs allowed to issue wildcard certificates."},
        {"token": "iodef", "meaning": "Where to send violation/issuance reports (mailto or URL)."},
        {"token": "0 flag", "meaning": "Issuer critical flag (0 = non-critical)."},
    ]

    return _base(
        domain,
        title,
        mode=mode,
        existing=existing,
        records=[{"type": "CAA", "name": domain, "value": v} for v in proposed],
        changes=changes,
        explanations=explanations,
        guidance=["List every CA you use. Missing a CA will block certificate issuance."],
    )


def generate_security_txt(domain: str) -> dict:
    domain, err = _need_domain(domain)
    if err:
        return err

    cur = check_security_txt(domain)
    fields = cur.get("fields") or {}
    raw = cur.get("raw") or ""
    found = cur.get("status_code") == 200 and bool(raw.strip())
    existing = {
        "found": found,
        "summary": (cur.get("url") + " found") if found else "No security.txt found",
        "records": (
            [{"type": "HTTPS", "name": cur.get("url") or "", "value": raw[:4000]}] if found else []
        ),
    }

    changes = []
    # Normalize to first value per field
    contact = (fields.get("Contact") or [None])[0]
    expires = (fields.get("Expires") or [None])[0]
    canonical = (fields.get("Canonical") or [None])[0]
    policy = (fields.get("Policy") or [None])[0]
    langs = (fields.get("Preferred-Languages") or [None])[0]

    if found:
        mode = "improved"
        title = "Improved security.txt (based on current file)"
        if not contact:
            contact = f"mailto:security@{domain}"
            changes.append(
                {
                    "item": "Contact",
                    "action": "added",
                    "detail": contact,
                    "why": "Required by RFC 9116 — how researchers reach you.",
                }
            )
        else:
            changes.append(
                {"item": "Contact", "action": "kept", "detail": contact, "why": "Existing contact kept."}
            )
        # Expires: refresh if missing or soon
        need_exp = True
        if expires:
            try:
                exp_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                if exp_dt > datetime.now(timezone.utc) + timedelta(days=30):
                    need_exp = False
                    changes.append(
                        {
                            "item": "Expires",
                            "action": "kept",
                            "detail": expires,
                            "why": "Expiry is still far enough in the future.",
                        }
                    )
            except ValueError:
                pass
        if need_exp:
            expires = (datetime.now(timezone.utc) + timedelta(days=365)).strftime(
                "%Y-%m-%dT00:00:00.000Z"
            )
            changes.append(
                {
                    "item": "Expires",
                    "action": "improved" if fields.get("Expires") else "added",
                    "detail": expires,
                    "why": "Fresh 1-year expiry so the file stays valid.",
                }
            )
        if not canonical:
            canonical = f"https://{domain}/.well-known/security.txt"
            changes.append(
                {
                    "item": "Canonical",
                    "action": "added",
                    "detail": canonical,
                    "why": "Points to the authoritative copy of this file.",
                }
            )
        else:
            changes.append({"item": "Canonical", "action": "kept", "detail": canonical, "why": "Kept."})
        if not langs:
            langs = "en, tr"
            changes.append(
                {
                    "item": "Preferred-Languages",
                    "action": "added",
                    "detail": langs,
                    "why": "Languages you can handle for security reports.",
                }
            )
        if not policy:
            policy = f"https://{domain}/security-policy"
            changes.append(
                {
                    "item": "Policy",
                    "action": "added",
                    "detail": policy,
                    "why": "Optional link to your vulnerability disclosure policy — create the page or remove.",
                }
            )
    else:
        mode = "created"
        title = "New security.txt (none found)"
        contact = f"mailto:security@{domain}"
        expires = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%dT00:00:00.000Z")
        canonical = f"https://{domain}/.well-known/security.txt"
        langs = "en, tr"
        policy = f"https://{domain}/security-policy"
        changes = [
            {"item": "Contact", "action": "added", "detail": contact, "why": "Required contact for reports."},
            {"item": "Expires", "action": "added", "detail": expires, "why": "File validity end date."},
            {"item": "Canonical", "action": "added", "detail": canonical, "why": "Canonical HTTPS location."},
            {
                "item": "Preferred-Languages",
                "action": "added",
                "detail": langs,
                "why": "Preferred languages for communication.",
            },
            {
                "item": "Policy",
                "action": "added",
                "detail": policy,
                "why": "Link to disclosure policy (optional but recommended).",
            },
        ]

    body = (
        f"Contact: {contact}\n"
        f"Expires: {expires}\n"
        f"Canonical: {canonical}\n"
        f"Preferred-Languages: {langs}\n"
        f"Policy: {policy}\n"
    )

    explanations = [
        {"token": "Contact", "meaning": "mailto: or https: URL for security reports (required)."},
        {"token": "Expires", "meaning": "ISO-8601 datetime after which the file should be ignored."},
        {"token": "Canonical", "meaning": "Authoritative URL(s) for this security.txt."},
        {"token": "Policy", "meaning": "URL of your vulnerability disclosure policy."},
        {"token": "Preferred-Languages", "meaning": "Languages you accept for reports."},
    ]

    return _base(
        domain,
        title,
        mode=mode,
        existing=existing,
        records=[
            {
                "type": "HTTPS",
                "name": f"https://{domain}/.well-known/security.txt",
                "value": body,
                "note": "Serve over HTTPS at /.well-known/security.txt",
            }
        ],
        changes=changes,
        explanations=explanations,
    )
