"""Rich email header / message analysis with educational findings."""

from __future__ import annotations

import email
import email.policy
import hashlib
import re
from email.message import Message
from email.utils import parseaddr, parsedate_to_datetime
from typing import Any

from .blacklist import check_blacklist
from .dns_common import is_ip, normalize_domain, reverse_lookup
from .dmarc import lookup_dmarc
from .spf import lookup_spf

AUTH_RE = re.compile(
    r"(spf|dkim|dmarc)\s*=\s*([a-z]+)",
    re.I,
)
RECEIVED_IP_RE = re.compile(
    r"\b(?:from|by)\s+[^\s]+.*?\[([0-9a-fA-F\.:]+)\]|\((\[?[0-9a-fA-F\.:]+\]?)\)",
)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _status_rank(status: str) -> int:
    return {"pass": 0, "info": 1, "warn": 2, "fail": 3, "neutral": 1}.get(status, 1)


def _finding(
    fid: str,
    title: str,
    status: str,
    summary: str,
    *,
    detail: str = "",
    edu: str = "",
    recommendation: str = "",
) -> dict[str, Any]:
    return {
        "id": fid,
        "title": title,
        "status": status,
        "summary": summary,
        "detail": detail,
        "edu": edu,
        "recommendation": recommendation,
    }


def _get(msg: Message, name: str) -> str:
    values = msg.get_all(name, [])
    if not values:
        return ""
    if len(values) == 1:
        return str(values[0])
    return "\n".join(str(v) for v in values)


def _domain_of(addr: str) -> str:
    _, email_addr = parseaddr(addr or "")
    if "@" not in email_addr:
        return ""
    return normalize_domain(email_addr.split("@", 1)[1])


def _parse_auth_results(text: str) -> dict[str, str]:
    results = {}
    for match in AUTH_RE.finditer(text or ""):
        results[match.group(1).lower()] = match.group(2).lower()
    return results


def _extract_ips_from_received(received_headers: list[str]) -> list[str]:
    ips: list[str] = []
    for header in received_headers:
        for match in IPV4_RE.findall(header):
            if match.startswith("127.") or match.startswith("10.") or match.startswith("192.168."):
                continue
            if match not in ips and is_ip(match):
                ips.append(match)
    return ips


def _body_stats(msg: Message) -> dict[str, Any]:
    text_parts = []
    html_parts = []
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition", "")).lower()
            filename = part.get_filename()
            if filename or "attachment" in disp:
                attachments.append(
                    {
                        "filename": filename or "unnamed",
                        "type": ctype,
                        "size": len(part.get_payload(decode=True) or b""),
                    }
                )
                continue
            if ctype == "text/plain":
                try:
                    text_parts.append(part.get_content())
                except Exception:  # noqa: BLE001
                    payload = part.get_payload(decode=True) or b""
                    text_parts.append(payload.decode("utf-8", errors="replace"))
            elif ctype == "text/html":
                try:
                    html_parts.append(part.get_content())
                except Exception:  # noqa: BLE001
                    payload = part.get_payload(decode=True) or b""
                    html_parts.append(payload.decode("utf-8", errors="replace"))
    else:
        ctype = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:  # noqa: BLE001
            content = (msg.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
        if ctype == "text/html":
            html_parts.append(str(content))
        else:
            text_parts.append(str(content))

    text = "\n".join(text_parts)
    html = "\n".join(html_parts)
    links = re.findall(r"https?://[^\s\"'<>]+", text + "\n" + html, flags=re.I)
    return {
        "has_text": bool(text.strip()),
        "has_html": bool(html.strip()),
        "text_len": len(text),
        "html_len": len(html),
        "links": links[:30],
        "link_count": len(links),
        "attachments": attachments,
    }


def _verify_dkim(raw: bytes) -> dict[str, Any]:
    try:
        import dkim  # type: ignore
    except Exception:  # noqa: BLE001
        return {"checked": False, "pass": None, "error": "dkimpy not installed"}

    try:
        ok = bool(dkim.verify(raw))
        return {"checked": True, "pass": ok, "error": None if ok else "Signature did not verify"}
    except Exception as exc:  # noqa: BLE001
        return {"checked": True, "pass": False, "error": str(exc)}


def analyze_email(
    raw_text: str,
    *,
    peer_ip: str | None = None,
    envelope_from: str | None = None,
    mode: str = "headers",
) -> dict[str, Any]:
    raw_text = (raw_text or "").strip()
    if not raw_text:
        return {"ok": False, "error": "Paste a full email source or headers first."}

    # Ensure there is a header/body split for the parser
    if "\n\n" not in raw_text.replace("\r\n", "\n"):
        raw_text = raw_text + "\n\n"

    raw_bytes = raw_text.encode("utf-8", errors="replace")
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)

    from_header = _get(msg, "From")
    to_header = _get(msg, "To")
    subject = _get(msg, "Subject")
    date_hdr = _get(msg, "Date")
    message_id = _get(msg, "Message-ID")
    return_path = _get(msg, "Return-Path") or (envelope_from or "")
    reply_to = _get(msg, "Reply-To")
    auth_results = _get(msg, "Authentication-Results")
    received = msg.get_all("Received", []) or []
    dkim_sig = _get(msg, "DKIM-Signature")
    list_unsub = _get(msg, "List-Unsubscribe")
    x_mailer = _get(msg, "X-Mailer") or _get(msg, "User-Agent")

    from_domain = _domain_of(from_header)
    return_domain = _domain_of(return_path) if return_path else ""
    reply_domain = _domain_of(reply_to) if reply_to else ""

    auth = _parse_auth_results(auth_results)
    received_ips = _extract_ips_from_received([str(r) for r in received])
    sending_ip = peer_ip or (received_ips[0] if received_ips else "")

    body = _body_stats(msg)
    dkim_verify = _verify_dkim(raw_bytes) if (dkim_sig or mode == "mailtest") else {
        "checked": False,
        "pass": None,
        "error": None,
    }

    findings: list[dict[str, Any]] = []

    # Identity overview
    findings.append(
        _finding(
            "identity",
            "Message identity",
            "info",
            f"From {parseaddr(from_header)[1] or 'unknown'} · Subject: {subject or '(none)'}",
            detail=f"To: {to_header or '—'} · Date: {date_hdr or '—'} · Message-ID: {message_id or '—'}",
            edu="These fields are what recipients and filters see first. A clear From name and stable Message-ID help trust and threading.",
        )
    )

    # Return-Path / alignment
    if return_domain and from_domain:
        aligned = return_domain == from_domain or from_domain.endswith("." + return_domain) or return_domain.endswith(
            "." + from_domain
        )
        findings.append(
            _finding(
                "return-path",
                "Return-Path alignment",
                "pass" if aligned else "warn",
                "Envelope sender domain matches From domain."
                if aligned
                else "Envelope sender domain differs from From domain.",
                detail=f"Return-Path/envelope: {return_path or '—'} · From domain: {from_domain}",
                edu="Return-Path is where bounces go. Large differences from the From domain can look like spoofing, even when forwarding is legitimate.",
                recommendation=""
                if aligned
                else "Use a From domain that aligns with your bounce/envelope domain, or authenticate with DKIM/DMARC properly for the From domain.",
            )
        )
    elif not return_path:
        findings.append(
            _finding(
                "return-path",
                "Return-Path",
                "warn",
                "No Return-Path / envelope sender found in the source.",
                edu="SMTP envelope sender (MAIL FROM) becomes Return-Path. Missing values make bounce handling and SPF evaluation harder to reason about.",
                recommendation="Ensure your mail server sets a valid envelope sender.",
            )
        )

    # Reply-To mismatch
    if reply_to and reply_domain and from_domain and reply_domain != from_domain:
        findings.append(
            _finding(
                "reply-to",
                "Reply-To mismatch",
                "warn",
                "Reply-To domain differs from From domain.",
                detail=f"Reply-To: {reply_to}",
                edu="Reply-To pointing elsewhere is common for ticket systems, but spammers also abuse it to harvest replies.",
                recommendation="If intentional, keep branding clear in the message body. If not, remove Reply-To.",
            )
        )

    # Authentication-Results
    if auth_results:
        for proto in ("spf", "dkim", "dmarc"):
            result = auth.get(proto)
            if not result:
                continue
            status = "pass" if result in {"pass", "bestguesspass"} else ("warn" if result in {"neutral", "none", "policy"} else "fail")
            if result == "none" and proto == "dmarc":
                status = "warn"
            findings.append(
                _finding(
                    f"auth-{proto}",
                    f"Authentication-Results · {proto.upper()}",
                    status,
                    f"{proto.upper()} reported as “{result}” by the receiving server.",
                    detail=auth_results[:1200],
                    edu={
                        "spf": "SPF lists which servers may send mail for a domain.",
                        "dkim": "DKIM cryptographically signs the message so it cannot be altered unnoticed.",
                        "dmarc": "DMARC ties SPF/DKIM to the From domain and tells receivers what to do on failure.",
                    }[proto],
                    recommendation=(
                        ""
                        if status == "pass"
                        else f"Investigate why {proto.upper()} is “{result}”. Fix DNS records or signing configuration for the sending domain."
                    ),
                )
            )
    else:
        findings.append(
            _finding(
                "auth-results",
                "Authentication-Results",
                "info",
                "No Authentication-Results header present in this source.",
                edu="This header is usually added by the receiving mail system (Gmail, Outlook, your MX). If you pasted only outgoing headers, it may be absent.",
            )
        )

    # DKIM signature presence + crypto verify
    if dkim_sig:
        status = "pass" if dkim_verify.get("pass") else ("warn" if not dkim_verify.get("checked") else "fail")
        summary = "DKIM signature present and verified." if dkim_verify.get("pass") else (
            "DKIM signature present (local crypto verify skipped)."
            if not dkim_verify.get("checked")
            else "DKIM signature present but verification failed."
        )
        findings.append(
            _finding(
                "dkim-sig",
                "DKIM signature",
                status,
                summary,
                detail=dkim_verify.get("error") or dkim_sig[:500],
                edu="A valid DKIM signature strongly improves deliverability and is required for solid DMARC alignment.",
                recommendation=""
                if status == "pass"
                else "Check selector DNS record, private key config, and that middleboxes are not rewriting signed headers/body.",
            )
        )
    else:
        findings.append(
            _finding(
                "dkim-sig",
                "DKIM signature",
                "fail",
                "No DKIM-Signature header found.",
                edu="Without DKIM, many filters trust the message less and DMARC often cannot pass via DKIM alignment.",
                recommendation="Enable DKIM signing on your MTA or ESP, then publish the selector TXT record.",
            )
        )

    # Live SPF / DMARC DNS for From domain
    if from_domain:
        spf = lookup_spf(from_domain, follow=True)
        if spf.get("ok"):
            findings.append(
                _finding(
                    "spf-dns",
                    "SPF record (From domain)",
                    "pass",
                    f"SPF record found for {from_domain}.",
                    detail=(spf.get("spf") or {}).get("raw", ""),
                    edu="SPF alone is not enough, but a correct SPF record is a baseline for mailbox providers.",
                )
            )
        else:
            findings.append(
                _finding(
                    "spf-dns",
                    "SPF record (From domain)",
                    "fail",
                    f"No SPF record found for {from_domain}.",
                    edu="Domains without SPF are easier to spoof and often score worse in spam filters.",
                    recommendation=f'Publish a TXT record on {from_domain} such as: v=spf1 include:your-esp.com ~all',
                )
            )

        dmarc = lookup_dmarc(from_domain)
        if dmarc.get("ok"):
            policy = (dmarc.get("dmarc") or {}).get("policy") or "none"
            status = "pass" if policy in {"quarantine", "reject"} else "warn"
            findings.append(
                _finding(
                    "dmarc-dns",
                    "DMARC policy",
                    status,
                    f"DMARC policy is p={policy}.",
                    detail=(dmarc.get("dmarc") or {}).get("raw", ""),
                    edu="p=none monitors only. p=quarantine or p=reject actively protect the domain from spoofing.",
                    recommendation=""
                    if status == "pass"
                    else "After monitoring reports, raise DMARC policy to quarantine, then reject.",
                )
            )
        else:
            findings.append(
                _finding(
                    "dmarc-dns",
                    "DMARC policy",
                    "fail",
                    f"No DMARC record for {from_domain}.",
                    recommendation=f"Publish _dmarc.{from_domain} TXT: v=DMARC1; p=none; rua=mailto:dmarc@{from_domain}",
                    edu="DMARC tells receivers how to handle unauthenticated mail using your domain in From.",
                )
            )

    # Sending IP / rDNS / blacklist
    if sending_ip:
        ptr = reverse_lookup(sending_ip)
        ptr_hosts = ptr.get("hosts") or []
        findings.append(
            _finding(
                "rdns",
                "Sending IP reverse DNS",
                "pass" if ptr_hosts else "warn",
                f"PTR found: {', '.join(ptr_hosts)}" if ptr_hosts else f"No PTR for {sending_ip}.",
                detail=f"IP: {sending_ip}",
                edu="Mailbox providers expect sending IPs to have valid reverse DNS that looks like a mail host.",
                recommendation=""
                if ptr_hosts
                else "Ask your provider to set a PTR such as mail.yourdomain.com for this IP.",
            )
        )
        bl = check_blacklist(sending_ip)
        if bl.get("ok"):
            findings.append(
                _finding(
                    "blacklist",
                    "Blacklist reputation",
                    "pass" if bl.get("clean") else "fail",
                    "IP is clean on checked DNSBLs."
                    if bl.get("clean")
                    else f"Listed on {bl.get('listed_count')} DNSBL(s).",
                    detail=", ".join(
                        f"{r['name']}" for r in (bl.get("results") or []) if r.get("listed")
                    ),
                    edu="DNSBL listings are a common reason for spam-folder or reject decisions.",
                    recommendation=""
                    if bl.get("clean")
                    else "Request delisting after fixing the root cause (compromise, open relay, bad content).",
                )
            )
    else:
        findings.append(
            _finding(
                "sending-ip",
                "Sending IP",
                "info",
                "Could not confidently detect the sending IP from headers alone.",
                edu="Received headers vary by server. For full IP reputation checks, use Mail Tester with a live delivery.",
            )
        )

    # Message-ID
    if message_id and "@" in message_id:
        findings.append(
            _finding(
                "message-id",
                "Message-ID",
                "pass",
                "Message-ID looks well-formed.",
                detail=message_id,
                edu="A unique Message-ID helps clients thread conversations and avoid duplicate detection quirks.",
            )
        )
    else:
        findings.append(
            _finding(
                "message-id",
                "Message-ID",
                "warn",
                "Message-ID missing or unusual.",
                recommendation="Configure your MTA/app to generate RFC-compliant Message-ID values.",
                edu="Missing Message-IDs are uncommon for healthy mail streams.",
            )
        )

    # Date parse
    if date_hdr:
        try:
            parsedate_to_datetime(date_hdr)
            findings.append(
                _finding(
                    "date",
                    "Date header",
                    "pass",
                    "Date header parsed successfully.",
                    detail=date_hdr,
                    edu="Invalid dates can look automated or malformed to filters and clients.",
                )
            )
        except Exception:  # noqa: BLE001
            findings.append(
                _finding(
                    "date",
                    "Date header",
                    "warn",
                    "Date header could not be parsed.",
                    detail=date_hdr,
                    recommendation="Use RFC 5322 date formatting from your mail library.",
                )
            )

    # List-Unsubscribe
    if list_unsub:
        findings.append(
            _finding(
                "list-unsubscribe",
                "List-Unsubscribe",
                "pass",
                "List-Unsubscribe header present.",
                detail=list_unsub[:500],
                edu="Bulk/marketing mail should include one-click unsubscribe headers for better inbox placement.",
            )
        )
    elif body.get("link_count", 0) > 3:
        findings.append(
            _finding(
                "list-unsubscribe",
                "List-Unsubscribe",
                "warn",
                "Many links found but no List-Unsubscribe header.",
                edu="Providers increasingly expect unsubscribe headers on campaign mail.",
                recommendation="Add List-Unsubscribe and List-Unsubscribe-Post headers for marketing messages.",
            )
        )

    # Content
    if mode == "mailtest" or body["has_html"] or body["has_text"]:
        if body["has_html"] and not body["has_text"]:
            findings.append(
                _finding(
                    "content-alt",
                    "Plain-text alternative",
                    "warn",
                    "HTML body found without a text/plain alternative.",
                    edu="Multipart messages with both text and HTML are more accessible and look less spammy.",
                    recommendation="Send multipart/alternative with both text/plain and text/html parts.",
                )
            )
        elif body["has_text"] and body["has_html"]:
            findings.append(
                _finding(
                    "content-alt",
                    "Plain-text alternative",
                    "pass",
                    "Both text and HTML parts are present.",
                    edu="Good MIME structure helps deliverability and accessibility.",
                )
            )

        if body["link_count"] > 15:
            findings.append(
                _finding(
                    "content-links",
                    "Link volume",
                    "warn",
                    f"Detected {body['link_count']} links in the message.",
                    edu="Very link-heavy messages, especially with short/redirect URLs, often score worse.",
                    recommendation="Reduce tracking redirects and keep a smaller set of clear destination links.",
                )
            )

        if body["attachments"]:
            risky = [
                a
                for a in body["attachments"]
                if str(a.get("filename", "")).lower().endswith(
                    (".exe", ".js", ".bat", ".cmd", ".scr", ".zip", ".html")
                )
            ]
            findings.append(
                _finding(
                    "attachments",
                    "Attachments",
                    "fail" if risky else "info",
                    f"{len(body['attachments'])} attachment(s) found"
                    + (" including risky types." if risky else "."),
                    detail=", ".join(a["filename"] for a in body["attachments"][:10]),
                    edu="Executable or nested archive attachments are major spam/malware signals.",
                    recommendation="Avoid executable attachments; host files on HTTPS instead.",
                )
            )

    if x_mailer:
        findings.append(
            _finding(
                "mailer",
                "Mailer fingerprint",
                "info",
                f"Client/mailer: {x_mailer}",
                edu="Not bad by itself — just useful context when debugging a stream.",
            )
        )

    # Received chain summary
    chain = []
    for idx, item in enumerate(received[:12]):
        chain.append({"hop": idx + 1, "value": str(item)})

    findings.sort(key=lambda f: _status_rank(f["status"]))

    counts = {
        "pass": sum(1 for f in findings if f["status"] == "pass"),
        "warn": sum(1 for f in findings if f["status"] == "warn"),
        "fail": sum(1 for f in findings if f["status"] == "fail"),
        "info": sum(1 for f in findings if f["status"] == "info"),
    }

    score = _score_from_findings(findings, dkim_verify, auth)

    recommendations = [
        f["recommendation"]
        for f in findings
        if f.get("recommendation") and f["status"] in {"fail", "warn"}
    ]

    return {
        "ok": True,
        "mode": mode,
        "score": score,
        "score_label": _score_label(score),
        "counts": counts,
        "findings": findings,
        "recommendations": recommendations,
        "meta": {
            "from": from_header,
            "to": to_header,
            "subject": subject,
            "date": date_hdr,
            "message_id": message_id,
            "return_path": return_path,
            "from_domain": from_domain,
            "sending_ip": sending_ip,
            "auth_results": auth,
            "dkim_verify": dkim_verify,
            "x_mailer": x_mailer,
        },
        "received_chain": chain,
        "body": {
            "has_text": body["has_text"],
            "has_html": body["has_html"],
            "link_count": body["link_count"],
            "attachments": body["attachments"],
            "links": body["links"][:10],
        },
        "fingerprint": hashlib.sha256(raw_bytes).hexdigest()[:16],
    }


def _score_from_findings(findings: list[dict], dkim_verify: dict, auth: dict) -> float:
    score = 10.0
    for f in findings:
        if f["status"] == "fail":
            score -= 1.6
        elif f["status"] == "warn":
            score -= 0.7
    if dkim_verify.get("pass") is True:
        score += 0.4
    if auth.get("dmarc") == "pass":
        score += 0.3
    return round(max(0.0, min(10.0, score)), 1)


def _score_label(score: float) -> str:
    if score >= 9:
        return "Excellent"
    if score >= 7:
        return "Good"
    if score >= 5:
        return "Fair"
    if score >= 3:
        return "Poor"
    return "Critical"
