"""Rich email header / message analysis with educational findings."""

from __future__ import annotations

import email
import email.policy
import hashlib
import re
from email.message import Message
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
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


def _normalize_mailbox(addr: str) -> str:
    """Lowercase mailbox address without display name / angle brackets."""
    raw = (addr or "").strip()
    if not raw:
        return ""
    _, email_addr = parseaddr(raw)
    email_addr = (email_addr or raw).strip().strip("<>").strip().lower()
    return email_addr if "@" in email_addr else ""


def _addrs_from_headers(msg: Message, *names: str) -> set[str]:
    out: set[str] = set()
    for name in names:
        for value in msg.get_all(name, []) or []:
            for _, addr in getaddresses([str(value)]):
                norm = _normalize_mailbox(addr)
                if norm:
                    out.add(norm)
    return out


def _detect_recipient_channel(
    msg: Message,
    received_headers: list[str],
) -> dict[str, Any]:
    """
    Infer whether the mailbox that received this copy was addressed via To, Cc, or Bcc.

    Uses Delivered-To / X-Original-To / Received "for=" (envelope RCPT) when present.
    Bcc is normally stripped from headers, so delivery to an address absent from To/Cc
    is reported as likely Bcc.
    """
    to_addrs = _addrs_from_headers(msg, "To")
    cc_addrs = _addrs_from_headers(msg, "Cc")
    bcc_addrs = _addrs_from_headers(msg, "Bcc")  # rare on received mail

    delivered = ""
    evidence = ""
    for hdr in (
        "Delivered-To",
        "X-Original-To",
        "X-Envelope-To",
        "Envelope-To",
        "X-RCPT-To",
        "Apparently-To",
    ):
        val = _get(msg, hdr)
        if not val:
            continue
        # Prefer the first address-looking token
        cand = _normalize_mailbox(val.split("\n", 1)[0])
        if not cand:
            for _, addr in getaddresses([val]):
                cand = _normalize_mailbox(addr)
                if cand:
                    break
        if cand:
            delivered = cand
            evidence = hdr
            break

    if not delivered:
        for raw in received_headers:
            hop = _parse_received_hop(str(raw))
            cand = _normalize_mailbox(hop.get("for") or "")
            if cand:
                delivered = cand
                evidence = "Received for="
                break

    if not delivered:
        return {
            "role": "unknown",
            "label": "Recipient channel unknown",
            "summary": "Could not determine whether this mailbox was in To, Cc, or Bcc.",
            "detail": (
                "No Delivered-To / X-Original-To / Received for= address was found. "
                "Paste headers from the receiving mailbox (not only the sent copy)."
            ),
            "mailbox": "",
            "evidence": "",
            "in_to": False,
            "in_cc": False,
            "in_bcc_header": False,
        }

    in_to = delivered in to_addrs
    in_cc = delivered in cc_addrs
    in_bcc_header = delivered in bcc_addrs

    if in_to:
        role = "to"
        label = "Received via To"
        summary = "This copy was addressed in To."
    elif in_cc:
        role = "cc"
        label = "Received via Cc"
        summary = "This copy was addressed in Cc."
    elif in_bcc_header:
        role = "bcc"
        label = "Received via Bcc"
        summary = "This copy was addressed in Bcc."
    else:
        role = "bcc"
        label = "Likely received via Bcc"
        summary = (
            "Delivered mailbox is not listed in To or Cc — "
            "Bcc (or a rewritten envelope recipient) is the usual explanation."
        )

    detail_bits = [
        f"Mailbox: {delivered}",
        f"Evidence: {evidence}",
        f"In To: {'yes' if in_to else 'no'}",
        f"In Cc: {'yes' if in_cc else 'no'}",
    ]
    if bcc_addrs:
        detail_bits.append(f"In Bcc header: {'yes' if in_bcc_header else 'no'}")

    return {
        "role": role,
        "label": label,
        "summary": summary,
        "detail": " · ".join(detail_bits),
        "mailbox": delivered,
        "evidence": evidence,
        "in_to": in_to,
        "in_cc": in_cc,
        "in_bcc_header": in_bcc_header,
    }


def _is_private_ip(ip: str) -> bool:
    ip = (ip or "").strip().strip("[]")
    if not is_ip(ip):
        return False
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".", 2)[1])
        except (ValueError, IndexError):
            return False
        return 16 <= second <= 31
    if ip.lower().startswith("fc") or ip.lower().startswith("fd") or ip.lower() == "::1":
        return True
    return False


def _org_domain(addr_or_domain: str) -> str:
    """Registrable-ish org label: last two labels for normal domains."""
    domain = _domain_of(addr_or_domain) if "@" in (addr_or_domain or "") else normalize_domain(addr_or_domain or "")
    if not domain:
        return ""
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _detect_internal_mail(
    msg: Message,
    *,
    from_domain: str,
    received_headers: list[str],
) -> dict[str, Any]:
    """
    Detect on-prem / corporate internal delivery (typical Exchange headers).

    Internal mail often has no DKIM — that is normal and should not be scored as a failure.
    """
    signals: list[str] = []
    header_map = {k.lower(): str(v) for k, v in msg.items()}

    auth_as = header_map.get("x-ms-exchange-organization-authas", "")
    if re.search(r"\binternal\b", auth_as, re.I):
        signals.append(f"X-MS-Exchange-Organization-AuthAs: {auth_as.strip()[:80]}")

    auth_mech = header_map.get("x-ms-exchange-organization-authmechanism", "")
    # Common Exchange internal submission mechanisms (03/04/06 etc.) when paired with AuthAs
    if auth_mech.strip() and re.search(r"\binternal\b", auth_as, re.I):
        signals.append(f"X-MS-Exchange-Organization-AuthMechanism: {auth_mech.strip()[:40]}")

    direction = header_map.get("x-ms-exchange-organization-messagedirectionality", "")
    if direction.strip().lower() == "originating" and re.search(r"\binternal\b", auth_as, re.I):
        signals.append("MessageDirectionality: Originating")

    ms_org_headers = [
        k
        for k in header_map
        if k.startswith("x-ms-exchange-organization-") or k.startswith("x-ms-exchange-crosstenant-")
    ]

    to_orgs = {_org_domain(a) for a in _addrs_from_headers(msg, "To", "Cc") if _org_domain(a)}
    from_org = _org_domain(from_domain)
    same_org = bool(from_org and to_orgs and all(o == from_org for o in to_orgs))

    public_ips: list[str] = []
    private_ips: list[str] = []
    for raw in received_headers:
        for match in IPV4_RE.findall(str(raw)):
            if _is_private_ip(match):
                if match not in private_ips:
                    private_ips.append(match)
            elif is_ip(match) and match not in public_ips:
                public_ips.append(match)

    # Soft path: same org + Exchange org headers + no public Received IPs
    if same_org and ms_org_headers and not public_ips:
        signals.append(
            f"Same-org From/To ({from_org}) with Exchange organization headers "
            f"and no public Received IPs"
        )

    # Soft path: Thread-Index + Exchange headers + same org (Outlook internal)
    if same_org and header_map.get("thread-index") and len(ms_org_headers) >= 2 and not public_ips:
        signals.append("Outlook Thread-Index with Exchange organization headers (same org)")

    # Deduplicate while preserving order
    seen: set[str] = set()
    uniq: list[str] = []
    for s in signals:
        if s not in seen:
            seen.add(s)
            uniq.append(s)

    is_internal = bool(uniq)
    return {
        "is_internal": is_internal,
        "signals": uniq[:6],
        "label": "Internal / corporate mail path" if is_internal else "",
        "summary": (
            "Headers look like internal corporate delivery (often Exchange). "
            "Internet auth checks such as DKIM may be absent by design."
            if is_internal
            else ""
        ),
        "same_org": same_org,
        "from_org": from_org,
    }


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


def _clean_host(value: str) -> str:
    value = (value or "").strip().strip("<>").strip("\"'")
    value = value.rstrip(".")
    if value.lower() in {"unknown", "localhost", "local"}:
        return value
    return value


def _parse_received_hop(raw: str) -> dict[str, Any]:
    """Parse one Received header into from/by/ip/protocol/time pieces."""
    text = " ".join(str(raw).split())
    from_host = ""
    helo = ""
    by_host = ""
    protocol = ""
    for_addr = ""
    when = ""
    ip = ""

    # Split timestamp after last semicolon
    if ";" in text:
        body, when = text.rsplit(";", 1)
        when = when.strip()
    else:
        body = text

    from_m = re.search(
        r"\bfrom\s+([^\s\(\);]+)(?:\s+\(([^)]*)\))?",
        body,
        re.I,
    )
    if from_m:
        from_host = _clean_host(from_m.group(1))
        paren = from_m.group(2) or ""
        # HELO/name and/or IP inside parentheses
        helo_m = re.search(r"helo\s*=\s*([^\s;]+)", paren, re.I)
        if helo_m:
            helo = _clean_host(helo_m.group(1))
        # First hostname token in paren often differs from IP
        name_m = re.match(r"([A-Za-z0-9._-]+)", paren.strip())
        if name_m and not is_ip(name_m.group(1)):
            helo = helo or _clean_host(name_m.group(1))
        ip_m = re.search(r"\[([0-9a-fA-F\.:]+)\]", paren)
        if not ip_m:
            ip_m = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", paren)
        if ip_m:
            candidate = ip_m.group(1).strip("[]")
            if is_ip(candidate):
                ip = candidate

    by_m = re.search(r"\bby\s+([^\s\(\);]+)", body, re.I)
    if by_m:
        by_host = _clean_host(by_m.group(1))

    with_m = re.search(r"\bwith\s+([A-Za-z0-9._+-]+)", body, re.I)
    if with_m:
        protocol = with_m.group(1)

    for_m = re.search(r"\bfor\s+(<[^>]+>|[^\s;]+)", body, re.I)
    if for_m:
        for_addr = for_m.group(1).strip()

    if not ip:
        for match in IPV4_RE.findall(body):
            if is_ip(match):
                ip = match
                break

    label = from_host or helo or by_host or ip or "hop"
    role = "relay"
    return {
        "raw": text[:800],
        "from": from_host,
        "helo": helo,
        "by": by_host,
        "ip": ip,
        "protocol": protocol,
        "for": for_addr,
        "time": when,
        "label": label,
        "role": role,
    }


def _build_delivery_flow(
    received_headers: list[str],
    *,
    from_header: str,
    to_header: str,
    peer_ip: str | None = None,
) -> dict[str, Any]:
    """
    Build chronological delivery path (origin → destination).
    Received headers are newest-first; we reverse for left-to-right flow.
    """
    hops = [_parse_received_hop(str(h)) for h in received_headers[:16]]
    hops.reverse()  # oldest first

    nodes: list[dict[str, Any]] = []
    from_addr = parseaddr(from_header)[1] or from_header or "sender"
    to_addr = parseaddr(to_header)[1] or to_header or "recipient"

    # Origin mailbox node
    nodes.append(
        {
            "kind": "mailbox",
            "role": "origin",
            "title": "Sender",
            "subtitle": from_addr,
            "detail": _domain_of(from_header) or "",
            "ip": "",
            "protocol": "",
            "time": "",
        }
    )

    for idx, hop in enumerate(hops):
        # Prefer the "from" side as the transferring host for this hop
        host = hop["from"] or hop["helo"] or hop["by"] or hop["ip"] or f"hop-{idx + 1}"
        title = host
        subtitle_parts = []
        if hop["ip"] and hop["ip"] != host:
            subtitle_parts.append(hop["ip"])
        if hop["protocol"]:
            subtitle_parts.append(hop["protocol"])
        if hop["by"] and hop["by"] != host:
            subtitle_parts.append(f"→ {hop['by']}")

        role = "origin-mta" if idx == 0 else ("inbox-mta" if idx == len(hops) - 1 else "relay")
        nodes.append(
            {
                "kind": "server",
                "role": role,
                "title": title,
                "subtitle": " · ".join(subtitle_parts) if subtitle_parts else (hop["by"] or "mail server"),
                "detail": hop["time"],
                "ip": hop["ip"],
                "protocol": hop["protocol"],
                "time": hop["time"],
                "by": hop["by"],
                "from": hop["from"],
                "for": hop["for"],
            }
        )

    # If we have peer_ip and first server has no IP, annotate
    if peer_ip and len(nodes) > 1 and not nodes[1].get("ip"):
        nodes[1]["ip"] = peer_ip
        if nodes[1]["subtitle"] == "mail server":
            nodes[1]["subtitle"] = peer_ip

    nodes.append(
        {
            "kind": "mailbox",
            "role": "destination",
            "title": "Recipient",
            "subtitle": to_addr,
            "detail": _domain_of(to_header) or "",
            "ip": "",
            "protocol": "",
            "time": "",
        }
    )

    # Compact summary line
    path_labels = []
    for node in nodes:
        if node["role"] == "origin":
            path_labels.append(node["subtitle"])
        elif node["role"] == "destination":
            path_labels.append(node["subtitle"])
        else:
            path_labels.append(node["title"])

    return {
        "nodes": nodes,
        "hop_count": len(hops),
        "summary": " → ".join(path_labels),
        "hops": hops,
    }


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
    cc_header = _get(msg, "Cc")
    bcc_header = _get(msg, "Bcc")
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
    received_list = [str(r) for r in received]
    received_ips = _extract_ips_from_received(received_list)
    sending_ip = peer_ip or (received_ips[0] if received_ips else "")
    recipient_channel = _detect_recipient_channel(msg, received_list)
    internal_mail = _detect_internal_mail(
        msg, from_domain=from_domain, received_headers=received_list
    )
    is_internal = bool(internal_mail.get("is_internal"))

    body = _body_stats(msg)
    dkim_verify = _verify_dkim(raw_bytes) if (dkim_sig or mode == "mailtest") else {
        "checked": False,
        "pass": None,
        "error": None,
    }

    findings: list[dict[str, Any]] = []

    # Identity overview
    identity_bits = [f"To: {to_header or '—'}"]
    if cc_header:
        identity_bits.append(f"Cc: {cc_header}")
    if bcc_header:
        identity_bits.append(f"Bcc: {bcc_header}")
    identity_bits.append(f"Date: {date_hdr or '—'}")
    identity_bits.append(f"Message-ID: {message_id or '—'}")
    findings.append(
        _finding(
            "identity",
            "Message identity",
            "info",
            f"From {parseaddr(from_header)[1] or 'unknown'} · Subject: {subject or '(none)'}",
            detail=" · ".join(identity_bits),
            edu="These fields are what recipients and filters see first. A clear From name and stable Message-ID help trust and threading.",
        )
    )

    findings.append(
        _finding(
            "recipient-channel",
            "Recipient channel (To / Cc / Bcc)",
            "info",
            recipient_channel["summary"],
            detail=recipient_channel.get("detail") or "",
            edu=(
                "To and Cc are visible to all recipients. Bcc hides other addresses and is usually "
                "stripped from headers — if the delivered mailbox is not in To or Cc, this copy was "
                "likely received via Bcc (or an envelope rewrite)."
            ),
        )
    )

    if is_internal:
        findings.append(
            _finding(
                "internal-mail",
                "Internal / corporate mail path",
                "info",
                internal_mail["summary"],
                detail=" · ".join(internal_mail.get("signals") or []),
                edu=(
                    "Internal Exchange (or similar) submission often skips public DKIM/SPF because "
                    "the message never leaves the organization. Treat missing internet auth as context, "
                    "not as a deliverability failure."
                ),
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
            # Internal mail: missing/soft internet auth is expected — keep as info
            if is_internal and result in {"none", "neutral", "temperror"}:
                status = "info"
            findings.append(
                _finding(
                    f"auth-{proto}",
                    f"Authentication-Results · {proto.upper()}",
                    status,
                    (
                        f"{proto.upper()} reported as none — expected on many internal paths."
                        if is_internal and status == "info" and result == "none"
                        else (
                            f"{proto.upper()} soft result “{result}” — common on internal paths."
                            if is_internal and status == "info"
                            else f"{proto.upper()} reported as “{result}” by the receiving server."
                        )
                    ),
                    detail=auth_results[:1200],
                    edu={
                        "spf": "SPF lists which servers may send mail for a domain.",
                        "dkim": "DKIM cryptographically signs the message so it cannot be altered unnoticed.",
                        "dmarc": "DMARC ties SPF/DKIM to the From domain and tells receivers what to do on failure.",
                    }[proto],
                    recommendation=(
                        ""
                        if status in {"pass", "info"}
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
    elif is_internal:
        findings.append(
            _finding(
                "dkim-sig",
                "DKIM signature",
                "info",
                "No DKIM-Signature header — normal for many internal / corporate messages.",
                detail="; ".join(internal_mail.get("signals") or [])[:500],
                edu=(
                    "Internal Exchange submission usually does not add DKIM. This is informational, "
                    "not a public deliverability failure. DKIM still matters for internet-bound mail."
                ),
                recommendation="",
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

    # Received chain + visual delivery flow (origin → destination)
    chain = []
    for idx, item in enumerate(received_list[:16]):
        chain.append({"hop": idx + 1, "value": item})

    delivery_flow = _build_delivery_flow(
        received_list,
        from_header=from_header,
        to_header=to_header,
        peer_ip=peer_ip or sending_ip,
    )

    if delivery_flow["hop_count"]:
        findings.append(
            _finding(
                "delivery-path",
                "Delivery path",
                "info",
                f"{delivery_flow['hop_count']} server hop(s) from sender to recipient.",
                detail=delivery_flow.get("summary", ""),
                edu="Each Received header is a stamp added by a mail server. Reading them bottom-to-top shows the journey from the sending server to the inbox.",
            )
        )

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
            "cc": cc_header,
            "bcc": bcc_header,
            "subject": subject,
            "date": date_hdr,
            "message_id": message_id,
            "return_path": return_path,
            "from_domain": from_domain,
            "sending_ip": sending_ip,
            "auth_results": auth,
            "dkim_verify": dkim_verify,
            "x_mailer": x_mailer,
            "recipient_channel": recipient_channel,
            "internal_mail": internal_mail,
        },
        "received_chain": chain,
        "delivery_flow": delivery_flow,
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
