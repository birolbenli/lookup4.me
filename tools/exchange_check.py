"""Microsoft Exchange External Security Assessment v2 — orchestrator."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from .dns_common import is_ip, normalize_domain
from .exchange_endpoints import (
    hosts_to_probe,
    org_domain,
    probe_all_endpoints,
    public_ips,
)
from .exchange_findings import (
    ADMIN_SURFACE,
    HYBRID_EXPECTED_PUBLIC,
    finding,
    not_observable_section,
    ui_severity,
    weighted_score,
)
from .exchange_http import assess_http
from .exchange_mail_domain import assess_mail_domain
from .exchange_ms_refs import EXCHANGE_SU_BASELINE, MS_REFS
from .exchange_smtp_assess import assess_smtp
from .exchange_tls import assess_tls


def _headers_report(endpoints: list[dict]) -> dict:
    items: list[dict] = []
    seen: set[str] = set()
    for e in endpoints:
        if not e.get("reachable"):
            continue
        for h in e.get("leaky_headers") or []:
            name = (h.get("header") or "").lower()
            val = h.get("value") or ""
            key = f"{e.get('host')}|{name}|{val[:60]}"
            if key in seen:
                continue
            seen.add(key)
            if name == "private-ip" or "private" in name:
                risk, note = "critical", "Internal IP"
            elif name in {
                "x-feserver",
                "x-beserver",
                "x-calculatedbetarget",
                "x-calculatedfetarget",
                "x-diaginfo",
            }:
                risk, note = "warning", "Internal hostname"
            elif name in {"x-owa-version", "x-aspnet-version", "x-owa-diagnostics"}:
                risk, note = "warning", "Version"
            elif name == "server":
                risk, note = "warning", "Server banner"
            elif name == "location":
                risk, note = "critical", "Internal redirect"
            else:
                risk, note = "info", "Header"
            items.append(
                {
                    "host": e.get("host"),
                    "vd": e.get("name"),
                    "url": e.get("url"),
                    "header": name,
                    "value": val[:160],
                    "risk": risk,
                    "note": note,
                }
            )
    order = {"critical": 0, "warning": 1, "info": 2}
    items.sort(key=lambda r: (order.get(r["risk"], 9), r.get("header") or ""))
    critical = sum(1 for i in items if i["risk"] == "critical")
    warning = sum(1 for i in items if i["risk"] == "warning")
    return {
        "items": items[:50],
        "critical": critical,
        "warning": warning,
        "risk_count": critical + warning,
    }


def _auth_audit(endpoints: list[dict]) -> dict:
    probed = [e for e in endpoints if e.get("reachable")]
    ntlm_eps = [e for e in probed if e.get("auth", {}).get("ntlm")]
    oauth_eps = [e for e in probed if e.get("auth", {}).get("oauth")]
    hma_eps = [e for e in probed if e.get("auth", {}).get("hma_challenge")]
    basic_eps = [e for e in probed if e.get("auth", {}).get("basic")]
    negotiate_eps = [
        e for e in probed if "Negotiate" in (e.get("auth", {}).get("schemes") or [])
    ]
    entra_eps = [e for e in probed if e.get("auth", {}).get("entra_oauth")]
    bearer_probed = [e for e in probed if (e.get("bearer_probe") or {}).get("used")]
    idp = [e for e in probed if e.get("idp_redirect")]

    oauth_found = bool(oauth_eps)
    if oauth_found:
        oauth_status = "detected"
        oauth_confidence = "medium" if hma_eps else "low"
        oauth_summary = (
            f"OAuth 2.0/Bearer challenge on {len(oauth_eps)} endpoint(s)"
            + (f" ({len(hma_eps)} with Entra/client_id hints)." if hma_eps else ".")
        )
    else:
        oauth_status = "inconclusive"
        oauth_confidence = "low"
        oauth_summary = (
            "No Bearer challenge after anonymous + dummy Bearer probes on EWS/EAS/MAPI. "
            "This is inconclusive (LB/WAF may strip headers). It does not prove HMA/OAuth is missing."
        )

    return {
        "method": (
            "Unauthenticated HTTPS GET on each VD; plus Authorization: Bearer invalidtoken "
            "on EWS / ActiveSync / MAPI to elicit HMA WWW-Authenticate."
        ),
        "endpoints_probed": len(probed),
        "bearer_probe_endpoints": len(bearer_probed),
        "limits": [
            "External probes cannot verify server-to-server hybrid OAuth (Teams free/busy trust).",
            "Confirm with Get-AuthServer, Get-IntraOrganizationConnector, Get-OrganizationConfig, Test-OAuthConnectivity.",
            "Never disable legacy auth / NTLM based only on a failed external Bearer probe.",
        ],
        "ntlm": {
            "checked": True,
            "found": bool(ntlm_eps),
            "status": "detected" if ntlm_eps else "not_detected",
            "summary": (
                f"NTLM/Negotiate on {len(ntlm_eps)} endpoint(s)."
                if ntlm_eps
                else "NTLM/Negotiate not advertised."
            ),
            "endpoints": [
                {"url": e["url"], "name": e.get("name"), "schemes": e.get("auth", {}).get("schemes") or []}
                for e in ntlm_eps
            ],
        },
        "oauth2": {
            "checked": True,
            "found": oauth_found,
            "status": oauth_status,
            "confidence": oauth_confidence,
            "summary": oauth_summary,
            "entra_hint": bool(entra_eps),
            "hma_challenge": bool(hma_eps),
            "endpoints": [
                {
                    "url": e["url"],
                    "name": e.get("name"),
                    "authorization_uri": e.get("auth", {}).get("authorization_uri") or "",
                    "client_id": e.get("auth", {}).get("client_id") or "",
                    "entra": bool(e.get("auth", {}).get("entra_oauth")),
                    "hma_challenge": bool(e.get("auth", {}).get("hma_challenge")),
                }
                for e in oauth_eps
            ],
        },
        "basic": {
            "checked": True,
            "found": bool(basic_eps),
            "status": "detected" if basic_eps else "not_detected",
            "summary": (
                f"Basic auth on {len(basic_eps)} endpoint(s)."
                if basic_eps
                else "Basic auth not advertised."
            ),
            "endpoints": [{"url": e["url"], "name": e.get("name")} for e in basic_eps],
        },
        "negotiate": {
            "checked": True,
            "found": bool(negotiate_eps),
            "status": "detected" if negotiate_eps else "not_detected",
            "summary": (
                f"Negotiate on {len(negotiate_eps)} endpoint(s)."
                if negotiate_eps
                else "Negotiate not advertised."
            ),
            "endpoints": [{"url": e["url"], "name": e.get("name")} for e in negotiate_eps],
        },
        "idp_redirects": {
            "found": bool(idp),
            "count": len(idp),
            "endpoints": [e["url"] for e in idp[:8]],
        },
    }


def _passive_fingerprint(endpoints: list[dict]) -> dict:
    versions = []
    for e in endpoints:
        for h in e.get("leaky_headers") or []:
            if (h.get("header") or "").lower() == "x-owa-version":
                versions.append(h.get("value") or "")
    versions = sorted({v for v in versions if v})
    hint = None
    confidence = "low"
    if versions:
        hint = versions[0]
        confidence = "low"
    return {
        "x_owa_versions": versions[:5],
        "build_hint": hint,
        "confidence": confidence,
        "su_baseline": EXCHANGE_SU_BASELINE,
        "note": (
            "Exact Exchange build/SU cannot be asserted from one HTTP header. "
            "CVE mapping requires reliable version evidence; otherwise treat as "
            "potentially affected / not confirmed."
        ),
        "cve_claim": "not_confirmed",
    }


def _hybrid_signals(endpoints: list[dict], hosts: list[dict], auth_audit: dict, fingerprint: dict) -> dict:
    signals = []
    if auth_audit.get("ntlm", {}).get("found"):
        signals.append("legacy_windows_auth")
    if any(e.get("id") in HYBRID_EXPECTED_PUBLIC and e.get("reachable") for e in endpoints):
        signals.append("hybrid_capable_endpoints_public")
    if auth_audit.get("oauth2", {}).get("found"):
        signals.append("bearer_challenge_observed")
    if auth_audit.get("idp_redirects", {}).get("found"):
        signals.append("entra_idp_redirect")
    if any(h.get("role") == "autodiscover" and h.get("resolves") for h in hosts):
        signals.append("autodiscover_dns")
    if fingerprint.get("build_hint"):
        signals.append("owa_version_header")

    likely = bool(
        "legacy_windows_auth" in signals
        or ("hybrid_capable_endpoints_public" in signals and "autodiscover_dns" in signals)
        or "bearer_challenge_observed" in signals
    )
    return {
        "likely": likely,
        "confidence": "low" if likely else "low",
        "signals": signals,
        "summary": (
            "External signals suggest internet-facing Exchange (on-prem or classic hybrid)."
            if likely
            else "Hybrid vs cloud not clear from this probe alone."
        ),
        "guidance": [
            "Classic Hybrid may require public EWS/MRSProxy/Autodiscover — do not flag solely for being public.",
            "Hybrid Agent / Dedicated Hybrid App cannot be confirmed externally.",
            "OAuth/Bearer observed externally is a signal, not proof of complete HMA correctness.",
        ],
        "never_claim": [
            "Hybrid Agent confirmed",
            "Dedicated Hybrid App confirmed",
            "Auth Certificate valid",
            "Extended Protection enabled",
        ],
    }


def _build_findings(
    *,
    host: str,
    endpoints: list[dict],
    auth_audit: dict,
    tls: dict,
    http: dict,
    smtp: dict,
    mail: dict,
    headers_report: dict,
    hybrid: dict,
    fingerprint: dict,
    hosts: list[dict],
) -> list[dict]:
    findings: list[dict] = []

    # --- Auth ---
    ntlm = auth_audit.get("ntlm") or {}
    if ntlm.get("found"):
        findings.append(
            finding(
                id="AUTH-NTLM-EXPOSED",
                title="NTLM / Negotiate exposed on the internet",
                status="WARN",
                severity="medium",
                confidence="high",
                target=host,
                observed=ntlm.get("summary") or "",
                expected="Prefer Modern Auth / HMA; reduce internet NTLM where topology allows.",
                why="NTLM on the public internet is a common relay/brute target.",
                remediation="Use HMA + Authentication Policies to block legacy auth (not by blindly disabling NTLM on VDirs required for hybrid).",
                ref_keys=("block_legacy", "hma", "M9"),
                category="legacy_auth",
                endpoints=[e["url"] for e in ntlm.get("endpoints") or []][:8],
            )
        )
    else:
        findings.append(
            finding(
                id="AUTH-NTLM-ABSENT",
                title="NTLM / Negotiate not detected",
                status="PASS",
                severity="info",
                confidence="medium",
                target=host,
                observed=ntlm.get("summary") or "",
                expected="No internet NTLM challenge (or not advertised).",
                why="Reduces classic NTLM relay surface.",
                remediation="Still prefer Authentication Policies for hybrid users.",
                ref_keys=("block_legacy",),
                category="legacy_auth",
            )
        )

    oauth = auth_audit.get("oauth2") or {}
    if oauth.get("found"):
        findings.append(
            finding(
                id="AUTH-OAUTH-DETECTED",
                title="OAuth 2.0 / Bearer detected",
                status="PASS",
                severity="info",
                confidence=oauth.get("confidence") or "medium",
                target=host,
                observed=oauth.get("summary") or "",
                expected="Bearer challenge with Entra authorization_uri on modern endpoints.",
                why="External Bearer is a modern-auth signal (not full HMA proof).",
                remediation="Verify server-side HMA completeness separately.",
                ref_keys=("hma", "M12"),
                category="modern_auth",
                endpoints=[e["url"] for e in oauth.get("endpoints") or []][:8],
            )
        )
    else:
        findings.append(
            finding(
                id="AUTH-OAUTH-INCONCLUSIVE",
                title="OAuth 2.0 / Bearer inconclusive",
                status="INFO",
                severity="info",
                confidence="low",
                target=host,
                observed=oauth.get("summary") or "",
                expected="Optional external Bearer challenge; absence is not proof HMA is off.",
                why="Anonymous probes and LB/WAF may hide Bearer; S2S OAuth is not visible externally.",
                scope_limitation="Cannot confirm VDir OAuthAuthentication or S2S hybrid OAuth.",
                remediation=(
                    "Verify server-side: Get-WebServicesVirtualDirectory OAuthAuthentication, "
                    "Get-OrganizationConfig OAuth2ClientProfileEnabled, Get-AuthServer, "
                    "Test-OAuthConnectivity. Do not disable NTLM/legacy auth based only on this probe."
                ),
                ref_keys=("hma", "M12"),
                category="modern_auth",
            )
        )

    basic = auth_audit.get("basic") or {}
    if basic.get("found"):
        findings.append(
            finding(
                id="AUTH-BASIC-EXPOSED",
                title="HTTP Basic auth advertised",
                status="FAIL",
                severity="high",
                confidence="high",
                target=host,
                observed=basic.get("summary") or "",
                expected="Basic auth disabled on internet-facing Exchange VDirs where possible.",
                why="Basic auth sends credentials in a reusable form and is frequently abused.",
                remediation="Disable Basic on VDirs where possible.",
                ref_keys=("M9", "disable_basic"),
                category="legacy_auth",
                endpoints=[e["url"] for e in basic.get("endpoints") or []][:8],
            )
        )

    # --- Exchange web / topology-aware ---
    hc_open = [e for e in endpoints if e.get("healthcheck") and e["healthcheck"].get("healthy")]
    if hc_open:
        findings.append(
            finding(
                id="EX-HEALTHCHECK-PUBLIC",
                title="Exchange healthcheck URLs are publicly reachable",
                status="WARN",
                severity="medium",
                confidence="high",
                target=host,
                observed="Public healthchecks fingerprint Exchange.",
                expected="Healthchecks limited to LB/monitoring IPs.",
                why="Public healthchecks fingerprint Exchange and aid reconnaissance.",
                remediation="Allow only LB/monitoring IPs.",
                ref_keys=("publish",),
                category="exposure",
                endpoints=[e["healthcheck"]["url"] for e in hc_open if e.get("healthcheck")][:8],
            )
        )

    open_admin = [
        e
        for e in endpoints
        if e.get("id") in ADMIN_SURFACE and e.get("exposure") in {"open", "auth_required"}
    ]
    if open_admin:
        findings.append(
            finding(
                id="EX-ADMIN-SURFACE",
                title="Admin surfaces (ECP / PowerShell) reachable",
                status="WARN",
                severity="high",
                confidence="high",
                target=host,
                observed="ECP/PowerShell should stay internal.",
                expected="Admin surfaces not published to the internet.",
                why="Admin panels increase brute-force and exploit surface.",
                remediation="Publish only OWA/EWS/Autodiscover/MAPI as needed.",
                ref_keys=("vd_defaults", "publish"),
                category="exposure",
                endpoints=[e["url"] for e in open_admin[:8]],
            )
        )

    # Public EWS — informational for hybrid, not automatic FAIL
    ews_pub = [
        e
        for e in endpoints
        if e.get("id") in {"ews", "ews_asmx", "mrsproxy"}
        and e.get("exposure") in {"open", "auth_required"}
    ]
    if ews_pub:
        findings.append(
            finding(
                id="EX-EWS-PUBLIC",
                title="EWS / MRSProxy reachable externally",
                status="INFO",
                severity="info",
                confidence="medium",
                target=host,
                observed=f"{len(ews_pub)} EWS-related endpoint(s) reachable.",
                expected="May be required for classic hybrid / Teams; Hybrid Agent topologies differ.",
                why="Public EWS is not universally bad; topology-dependent.",
                scope_limitation="Cannot confirm Hybrid Agent or classic hybrid necessity.",
                remediation="Keep available if hybrid needs it; remove public NTLM where possible; do not disable blindly.",
                ref_keys=("M11", "M5", "teams_ews"),
                category="hybrid",
                endpoints=[e["url"] for e in ews_pub[:6]],
            )
        )

    open_owa = [
        e for e in endpoints if e.get("id") in {"owa", "owa_auth"} and e.get("exposure") in {"open", "auth_required", "error"}
    ]
    if open_owa:
        findings.append(
            finding(
                id="EX-OWA-PUBLIC",
                title="OWA reachable externally",
                status="INFO",
                severity="info",
                confidence="high",
                target=host,
                observed="OWA is published.",
                expected="Common — use Modern Auth / MFA.",
                why="Expected for many deployments; strengthen with MFA/Conditional Access.",
                remediation="Prefer HMA + Conditional Access.",
                ref_keys=("hma", "vd_defaults"),
                category="exposure",
                endpoints=[e["url"] for e in open_owa[:4]],
            )
        )

    # --- TLS ---
    summary = tls.get("summary") or {}
    cert = tls.get("certificate") or {}
    legacy_protos = summary.get("legacy_protocols") or []
    if "SSLv3" in legacy_protos:
        findings.append(
            finding(
                id="TLS-SSLV3",
                title="SSLv3 supported",
                status="FAIL",
                severity="critical",
                confidence="high",
                target=host,
                observed="SSLv3 handshake succeeded.",
                expected="SSLv3 disabled.",
                why="SSLv3 is obsolete and broken.",
                remediation="Disable SSLv3; follow Exchange TLS best practices.",
                ref_keys=("M7", "tls"),
                category="tls",
            )
        )
    if any(p in legacy_protos for p in ("TLSv1.0", "TLSv1.1")):
        findings.append(
            finding(
                id="TLS-LEGACY",
                title="Legacy TLS 1.0/1.1 supported",
                status="FAIL",
                severity="high",
                confidence="high",
                target=host,
                observed=", ".join(legacy_protos),
                expected="TLS 1.2+ only for Exchange HTTPS.",
                why="Legacy TLS weakens transport security.",
                remediation="Disable TLS 1.0/1.1 per Microsoft Exchange TLS guidance.",
                ref_keys=("M7",),
                category="tls",
            )
        )
    if summary.get("expired") or (isinstance(summary.get("days_left"), int) and summary["days_left"] < 0):
        findings.append(
            finding(
                id="TLS-CERT-EXPIRED",
                title="TLS certificate expired",
                status="FAIL",
                severity="high",
                confidence="high",
                target=host,
                observed=f"days_left={summary.get('days_left')}",
                expected="Valid, unexpired certificate matching hostname.",
                why="Expired certificates break clients and enable MITM warnings.",
                remediation="Renew immediately.",
                ref_keys=("M7",),
                category="tls",
            )
        )
    elif isinstance(summary.get("days_left"), int) and summary["days_left"] <= 30:
        findings.append(
            finding(
                id="TLS-CERT-EXPIRING",
                title="TLS certificate expires soon",
                status="WARN",
                severity="medium",
                confidence="high",
                target=host,
                observed=f"{summary.get('days_left')} day(s) left.",
                expected="Certificate validity > 30 days.",
                why="Upcoming expiry causes outages.",
                remediation="Renew before expiry.",
                ref_keys=("M7",),
                category="tls",
            )
        )
    elif cert.get("ok") or (tls.get("legacy_ssl") or {}).get("status") == "valid":
        findings.append(
            finding(
                id="TLS-CERT-VALID",
                title="TLS certificate valid",
                status="PASS",
                severity="info",
                confidence="high",
                target=host,
                observed=f"{summary.get('days_left')} day(s) left · {cert.get('issuer') or (tls.get('legacy_ssl') or {}).get('issuer')}.",
                expected="Valid certificate.",
                why="Healthy TLS baseline.",
                remediation="Keep auto-renewal.",
                ref_keys=("M7",),
                category="tls",
            )
        )

    if cert.get("ok") and cert.get("hostname_match") is False:
        findings.append(
            finding(
                id="TLS-HOSTNAME-MISMATCH",
                title="TLS certificate hostname mismatch",
                status="FAIL",
                severity="high",
                confidence="high",
                target=host,
                observed=f"CN/SAN does not clearly match {host}. SANs={cert.get('sans')}",
                expected="Certificate SAN includes the published hostname.",
                why="Clients reject mismatched names; may indicate wrong cert or interception.",
                remediation="Issue a certificate covering all published names.",
                ref_keys=("M7",),
                category="tls",
            )
        )

    if summary.get("tls13") is False and any(
        p.get("supported") and p.get("protocol") == "TLSv1.2" for p in (tls.get("protocols") or [])
    ):
        findings.append(
            finding(
                id="TLS-NO-1-3",
                title="TLS 1.3 not negotiated",
                status="INFO",
                severity="info",
                confidence="medium",
                target=host,
                observed="TLS 1.3 handshake not successful; TLS 1.2 may still be fine.",
                expected="TLS 1.3 optional; TLS 1.2 minimum.",
                why="Absence of TLS 1.3 is informational, not automatically a failure.",
                remediation="Enable TLS 1.3 when platform supports it.",
                ref_keys=("M7",),
                category="tls",
            )
        )

    # --- HTTP ---
    if http.get("ok"):
        if not (http.get("hsts") or {}).get("present"):
            findings.append(
                finding(
                    id="HTTP-NO-HSTS",
                    title="HSTS not present",
                    status="WARN",
                    severity="medium",
                    confidence="high",
                    target=host,
                    observed="Strict-Transport-Security header missing on HTTPS root.",
                    expected="HSTS enabled for Exchange HTTPS.",
                    why="Without HSTS, clients may be downgraded to HTTP.",
                    remediation="Configure HSTS per Microsoft Exchange guidance.",
                    ref_keys=("M8", "hsts"),
                    category="http",
                )
            )
        else:
            findings.append(
                finding(
                    id="HTTP-HSTS-OK",
                    title="HSTS present",
                    status="PASS",
                    severity="info",
                    confidence="high",
                    target=host,
                    observed=(http.get("hsts") or {}).get("value") or "HSTS set",
                    expected="HSTS present.",
                    why="Helps prevent SSL stripping.",
                    remediation="Keep max-age appropriate for production.",
                    ref_keys=("M8",),
                    category="http",
                )
            )

        http_block = http.get("http") or {}
        if http_block.get("reachable") and not http_block.get("redirects_to_https"):
            findings.append(
                finding(
                    id="HTTP-NO-REDIRECT",
                    title="HTTP does not redirect to HTTPS",
                    status="WARN",
                    severity="medium",
                    confidence="medium",
                    target=host,
                    observed=f"HTTP final URL: {http_block.get('final_url')}",
                    expected="Port 80 redirects to HTTPS.",
                    why="Cleartext HTTP enables interception.",
                    remediation="Redirect HTTP to HTTPS at the load balancer or IIS.",
                    ref_keys=("M8",),
                    category="http",
                )
            )

        if (http.get("methods") or {}).get("trace_enabled"):
            findings.append(
                finding(
                    id="HTTP-TRACE",
                    title="HTTP TRACE appears enabled",
                    status="WARN",
                    severity="low",
                    confidence="medium",
                    target=host,
                    observed=f"TRACE status={(http.get('methods') or {}).get('trace_status')}",
                    expected="TRACE disabled.",
                    why="TRACE can assist cross-site tracing attacks.",
                    remediation="Disable TRACE at IIS/load balancer.",
                    ref_keys=("publish",),
                    category="http",
                )
            )

    # --- SMTP ---
    smtp_sum = smtp.get("summary") or {}
    if smtp.get("open_relay_suspected"):
        findings.append(
            finding(
                id="SMTP-OPEN-RELAY",
                title="Possible open relay (RCPT accepted)",
                status="FAIL",
                severity="critical",
                confidence="medium",
                target=org_domain(host),
                observed="RCPT TO for unrelated external recipient returned 250 (DATA not sent).",
                expected="Reject unauthorized relay recipients.",
                why="Open relays are abused for spam and malware.",
                scope_limitation="Stopped before DATA; treat as suspected until confirmed operationally.",
                remediation="Fix receive connectors / relay permissions immediately.",
                ref_keys=("publish",),
                category="smtp",
            )
        )
    if smtp_sum.get("reachable") and not smtp_sum.get("starttls"):
        findings.append(
            finding(
                id="SMTP-NO-STARTTLS",
                title="SMTP STARTTLS missing or failed",
                status="FAIL",
                severity="high",
                confidence="high",
                target=org_domain(host),
                observed="STARTTLS not successful on tested MX/host.",
                expected="STARTTLS available and working on port 25.",
                why="Cleartext SMTP exposes credentials and message content.",
                remediation="Enable and prefer STARTTLS on receive connectors.",
                ref_keys=("M7",),
                category="smtp",
            )
        )
    elif smtp_sum.get("reachable") and smtp_sum.get("starttls"):
        findings.append(
            finding(
                id="SMTP-STARTTLS-OK",
                title="SMTP STARTTLS available",
                status="PASS",
                severity="info",
                confidence="high",
                target=org_domain(host),
                observed=f"TLS={smtp_sum.get('tls_version')}",
                expected="STARTTLS works.",
                why="Encrypted SMTP submission/relay path.",
                remediation="Keep strong TLS on SMTP.",
                ref_keys=("M7",),
                category="smtp",
            )
        )
    elif not smtp_sum.get("reachable"):
        findings.append(
            finding(
                id="SMTP-UNREACHABLE",
                title="SMTP port 25 not reachable from scanner",
                status="INFO",
                severity="info",
                confidence="medium",
                target=org_domain(host),
                observed=smtp.get("attempts", [{}])[-1].get("error") if smtp.get("attempts") else "unreachable",
                expected="Optional — many hosts filter port 25.",
                why="May be intentional firewall policy.",
                remediation="Ensure MX path accepts mail from the internet if this host should receive mail.",
                ref_keys=("publish",),
                category="smtp",
            )
        )

    # --- Mail domain ---
    spf = mail.get("spf") or {}
    if not spf.get("ok"):
        findings.append(
            finding(
                id="MAIL-SPF-MISSING",
                title="SPF missing or invalid",
                status="WARN",
                severity="medium",
                confidence="high",
                target=mail.get("domain") or org_domain(host),
                observed=spf.get("error") or "No SPF",
                expected="Single valid v=spf1 record.",
                why="Missing SPF weakens spoofing defenses.",
                remediation="Publish one SPF record covering legitimate senders.",
                ref_keys=("publish",),
                category="mail_domain",
            )
        )
    elif spf.get("count", 0) > 1:
        findings.append(
            finding(
                id="MAIL-SPF-MULTIPLE",
                title="Multiple SPF records",
                status="FAIL",
                severity="medium",
                confidence="high",
                target=mail.get("domain") or org_domain(host),
                observed=f"{spf.get('count')} SPF TXT records at apex.",
                expected="Exactly one SPF record.",
                why="Multiple SPF records are invalid per RFC.",
                remediation="Merge into a single v=spf1 record.",
                ref_keys=("publish",),
                category="mail_domain",
            )
        )

    dmarc = mail.get("dmarc") or {}
    if not dmarc.get("ok"):
        findings.append(
            finding(
                id="MAIL-DMARC-MISSING",
                title="DMARC missing",
                status="WARN",
                severity="medium",
                confidence="high",
                target=mail.get("domain") or org_domain(host),
                observed=dmarc.get("error") or "No DMARC",
                expected="DMARC with an explicit policy.",
                why="DMARC enables spoof reporting and enforcement.",
                remediation="Publish _dmarc TXT; move toward p=quarantine/reject.",
                ref_keys=("publish",),
                category="mail_domain",
            )
        )
    elif (dmarc.get("policy") or "").lower() in {"none", "n"}:
        findings.append(
            finding(
                id="MAIL-DMARC-NONE",
                title="DMARC policy is none",
                status="INFO",
                severity="low",
                confidence="high",
                target=mail.get("domain") or org_domain(host),
                observed=f"p={dmarc.get('policy')}",
                expected="Eventually p=quarantine or p=reject.",
                why="Monitoring-only DMARC does not block spoofing.",
                remediation="Raise policy after reviewing aggregate reports.",
                ref_keys=("publish",),
                category="mail_domain",
            )
        )

    if not (mail.get("mta_sts") or {}).get("present"):
        findings.append(
            finding(
                id="MAIL-MTASTS-MISSING",
                title="MTA-STS not published",
                status="INFO",
                severity="low",
                confidence="high",
                target=mail.get("domain") or org_domain(host),
                observed="No _mta-sts TXT.",
                expected="Optional but recommended for SMTP STS.",
                why="MTA-STS helps enforce TLS for inbound SMTP.",
                remediation="Publish MTA-STS DNS + policy file when ready.",
                ref_keys=("publish",),
                category="mail_domain",
            )
        )

    # --- Disclosure ---
    if headers_report.get("risk_count"):
        findings.append(
            finding(
                id="DISC-HEADERS",
                title="Sensitive data in HTTP headers",
                status="FAIL" if headers_report.get("critical") else "WARN",
                severity="high" if headers_report.get("critical") else "medium",
                confidence="high",
                target=host,
                observed=f"{headers_report['risk_count']} leak(s): hostname, version, and/or internal IP.",
                expected="No internal hostnames/IPs/version banners on public responses.",
                why="Aids attackers in mapping internal topology and version.",
                remediation="Strip X-FEServer/version at proxy; hide private IPs.",
                ref_keys=("publish",),
                category="disclosure",
                endpoints=[
                    f"{r['header']}: {r['value']}" for r in (headers_report.get("items") or [])[:6]
                ],
            )
        )

    if fingerprint.get("build_hint"):
        findings.append(
            finding(
                id="DISC-FINGERPRINT",
                title="Passive Exchange version hint",
                status="INFO",
                severity="low",
                confidence="low",
                target=host,
                observed=f"x-owa-version≈{fingerprint.get('build_hint')}",
                expected="Minimize version disclosure; do not treat as confirmed build.",
                why="Passive fingerprint only — not a confirmed SU/CVE claim.",
                scope_limitation="Exact build/SU not reliably knowable from external HTTP alone.",
                remediation=(
                    f"Compare against current SU baseline {EXCHANGE_SU_BASELINE.get('build')} "
                    f"({EXCHANGE_SU_BASELINE.get('label')}) using internal HealthChecker / build inventory."
                ),
                ref_keys=("M1", "M2", "M13"),
                category="fingerprint",
            )
        )

    unresolved = [h for h in hosts if not h.get("ips")]
    if unresolved:
        findings.append(
            finding(
                id="DNS-UNRESOLVED",
                title="Some related hostnames did not resolve",
                status="INFO",
                severity="info",
                confidence="high",
                target=host,
                observed=", ".join(h["host"] for h in unresolved),
                expected="OK if unused (e.g. download.*).",
                why="Incomplete DNS may be intentional.",
                remediation="Match Autodiscover to your design.",
                ref_keys=("vd_defaults",),
                category="dns",
                endpoints=[h["host"] for h in unresolved],
            )
        )

    # Sort: FAIL/critical first using ui severity
    order = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    findings.sort(key=lambda f: order.get(ui_severity(f), 9))
    return findings


def check_exchange(host: str) -> dict:
    started = time.time()
    scanned_at = datetime.now(timezone.utc).isoformat()

    raw = (host or "").strip()
    if not raw:
        return {"ok": False, "error": "Please enter an Exchange hostname (e.g. mail.example.com)"}

    if "://" in raw:
        raw = urlparse(raw).hostname or raw
    host = normalize_domain(raw.replace("\\", "/").split("/")[0])
    if not host or ("." not in host and not is_ip(host)):
        return {"ok": False, "error": "Enter a valid hostname such as mail.example.com"}

    primary_ips = public_ips(host)
    if not primary_ips:
        return {
            "ok": False,
            "error": "Hostname must resolve to a public IP address (private/local targets are blocked).",
            "host": host,
        }

    org = org_domain(host)
    host_rows = []
    for item in hosts_to_probe(host):
        ips = public_ips(item["host"])
        host_rows.append({**item, "ips": ips, "resolves": bool(ips)})

    # Core probes
    endpoints = probe_all_endpoints(host_rows)
    auth_audit = _auth_audit(endpoints)
    headers_report = _headers_report(endpoints)
    tls = assess_tls(host)
    http = assess_http(host)
    smtp = assess_smtp(org, host)
    mail = assess_mail_domain(org)
    fingerprint = _passive_fingerprint(endpoints)
    hybrid = _hybrid_signals(endpoints, host_rows, auth_audit, fingerprint)

    findings = _build_findings(
        host=host,
        endpoints=endpoints,
        auth_audit=auth_audit,
        tls=tls,
        http=http,
        smtp=smtp,
        mail=mail,
        headers_report=headers_report,
        hybrid=hybrid,
        fingerprint=fingerprint,
        hosts=host_rows,
    )

    summary = weighted_score(findings)

    # Shared frontends
    ip_map: dict[str, list[str]] = {}
    for h in host_rows:
        for ip in h.get("ips") or []:
            ip_map.setdefault(ip, []).append(h["host"])
    shared_frontends = [{"ip": ip, "hosts": hs} for ip, hs in ip_map.items() if len(hs) > 1]

    duration_ms = int((time.time() - started) * 1000)
    coverage = {
        "dns_hosts": len(host_rows),
        "endpoints": len(endpoints),
        "tls": bool(tls.get("ok")),
        "http": bool(http.get("ok")),
        "smtp": bool((smtp.get("summary") or {}).get("reachable")),
        "mail_domain": bool(mail.get("ok")),
        "auth_probed": (auth_audit.get("endpoints_probed") or 0),
    }

    # Legacy ssl key for older UI bits
    legacy_ssl = tls.get("legacy_ssl") or {}
    if tls.get("certificate", {}).get("ok"):
        c = tls["certificate"]
        legacy_ssl = {
            **legacy_ssl,
            "domain": host,
            "status": "expired" if c.get("expired") else ("warning" if (c.get("days_left") or 99) <= 30 else "valid"),
            "days_left": c.get("days_left"),
            "expiry_date": c.get("not_after"),
            "issuer": c.get("issuer"),
            "subject": c.get("subject_cn"),
        }

    # For legacy UI that expects severity critical|warning|info|ok on findings
    for f in findings:
        f["severity"] = f.get("ui_severity") or ui_severity(f)

    return {
        "ok": True,
        "assessment_version": "2.0",
        "mode": "external_only",
        "tool": "Microsoft Exchange Server HC",
        "host": host,
        "org_domain": org,
        "scanned_at": scanned_at,
        "duration_ms": duration_ms,
        "hosts": host_rows,
        "shared_frontends": shared_frontends,
        "ssl": legacy_ssl,
        "tls_detail": tls,
        "http_detail": http,
        "endpoints": endpoints,
        "auth_audit": auth_audit,
        "smtp_assess": smtp,
        "mail_domain": mail,
        "fingerprint": fingerprint,
        "posture": {"hybrid": hybrid, "teams": {
            "relevant": True,
            "summary": "Teams often needs Exchange (EWS/Autodiscover). Public EWS is topology-dependent.",
            "guidance": hybrid.get("guidance") or [],
            "ews_status": (
                "EWS reachable."
                if any(e.get("id") in {"ews", "ews_asmx"} and e.get("reachable") for e in endpoints)
                else "EWS not reachable externally."
            ),
            "ntlm_on_ews": any(
                e.get("id") in {"ews", "ews_asmx"} and e.get("auth", {}).get("ntlm") for e in endpoints
            ),
            "oauth_on_ews": any(
                e.get("id") in {"ews", "ews_asmx"} and e.get("auth", {}).get("oauth") for e in endpoints
            ),
        }},
        "headers_report": headers_report,
        "not_observable": not_observable_section(),
        "findings": findings,
        "summary": summary,
        "coverage": coverage,
        "microsoft_refs": [MS_REFS[k] for k in ("M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10", "M11", "M12", "M13")],
        "counts": {
            "reachable": sum(1 for e in endpoints if e.get("reachable")),
            "ntlm": sum(1 for e in endpoints if e.get("auth", {}).get("ntlm")),
            "oauth": sum(1 for e in endpoints if e.get("auth", {}).get("oauth")),
            "basic": sum(1 for e in endpoints if e.get("auth", {}).get("basic")),
            "healthcheck_open": sum(
                1 for e in endpoints if e.get("healthcheck") and e["healthcheck"].get("healthy")
            ),
            "header_leaks": headers_report.get("risk_count") or 0,
        },
        "executive_summary": {
            "headline": f"{summary.get('grade')} · {summary.get('score')}/100 · {summary.get('label')}",
            "mode": "External-only assessment — no Exchange login, agent, or PowerShell.",
            "top_issues": [
                f.get("title")
                for f in findings
                if f.get("status") in {"FAIL", "WARN"}
            ][:5],
        },
    }
