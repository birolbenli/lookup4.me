"""Versioned Microsoft reference database for Exchange external assessment (spec v2)."""

from __future__ import annotations

MS_REFS: dict[str, dict] = {
    "M1": {
        "id": "M1",
        "title": "Exchange Server build numbers and release dates",
        "url": "https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates",
    },
    "M2": {
        "id": "M2",
        "title": "Released: July 2026 Exchange Server Security Updates",
        "url": "https://techcommunity.microsoft.com/blog/exchange/released-july-2026-exchange-server-security-updates/4534146",
    },
    "M3": {
        "id": "M3",
        "title": "Exchange Server Security Changes for Hybrid Deployments",
        "url": "https://techcommunity.microsoft.com/blog/exchange/exchange-server-security-changes-for-hybrid-deployments/4396833",
    },
    "M4": {
        "id": "M4",
        "title": "Deploy dedicated Exchange hybrid app",
        "url": "https://learn.microsoft.com/en-us/exchange/hybrid-deployment/deploy-dedicated-hybrid-app",
    },
    "M5": {
        "id": "M5",
        "title": "Microsoft Hybrid Agent",
        "url": "https://learn.microsoft.com/en-us/exchange/hybrid-deployment/hybrid-agent",
    },
    "M6": {
        "id": "M6",
        "title": "Exchange Server support for Windows Extended Protection",
        "url": "https://learn.microsoft.com/en-us/exchange/plan-and-deploy/post-installation-tasks/security-best-practices/exchange-extended-protection",
    },
    "M7": {
        "id": "M7",
        "title": "Exchange Server TLS configuration best practices",
        "url": "https://learn.microsoft.com/en-us/exchange/plan-and-deploy/post-installation-tasks/security-best-practices/exchange-tls-configuration",
    },
    "M8": {
        "id": "M8",
        "title": "Configure HTTP Strict Transport Security (HSTS) in Exchange Server",
        "url": "https://learn.microsoft.com/en-us/exchange/plan-and-deploy/post-installation-tasks/security-best-practices/configure-http-strict-transport-security-in-exchange-server",
    },
    "M9": {
        "id": "M9",
        "title": "Disable Basic authentication on Exchange Server virtual directories",
        "url": "https://learn.microsoft.com/en-us/exchange/plan-and-deploy/post-installation-tasks/disable-basic-authentication-on-exchange-server-virtual-directories",
    },
    "M10": {
        "id": "M10",
        "title": "MAPI over HTTP in Exchange Server",
        "url": "https://learn.microsoft.com/en-us/exchange/clients/mapi-over-http/mapi-over-http",
    },
    "M11": {
        "id": "M11",
        "title": "Hybrid Configuration wizard options",
        "url": "https://learn.microsoft.com/en-us/exchange/hybrid-configuration-wizard-options",
    },
    "M12": {
        "id": "M12",
        "title": "Configure OAuth authentication between Exchange and Exchange Online",
        "url": "https://learn.microsoft.com/en-us/exchange/configure-oauth-authentication-between-exchange-and-exchange-online-organizations-exchange-2013-help",
    },
    "M13": {
        "id": "M13",
        "title": "Exchange Server HealthChecker (CSS-Exchange) — internal/authenticated reference only",
        "url": "https://github.com/microsoft/CSS-Exchange/tree/main/Diagnostics/HealthChecker",
    },
    "CVE-2026-62911": {
        "id": "CVE-2026-62911",
        "title": "CVE-2026-62911 — Exchange Server elevation of privilege (Aug 2026)",
        "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62911",
    },
    "M2b": {
        "id": "M2b",
        "title": "Released: August 2026 Exchange Server Security Updates",
        "url": "https://techcommunity.microsoft.com/blog/exchange/released-august-2026-exchange-server-security-updates/4543951",
    },
}

# Convenience aliases used by finding code
MS_REFS.update(
    {
        "hma": {
            "id": "hma",
            "title": "Configure Exchange Server for Hybrid Modern Authentication",
            "url": "https://learn.microsoft.com/en-us/microsoft-365/enterprise/configure-exchange-server-for-hybrid-modern-authentication",
        },
        "block_legacy": {
            "id": "block_legacy",
            "title": "Use authentication policies to block legacy auth (hybrid)",
            "url": "https://learn.microsoft.com/en-us/exchange/hybrid-deployment/block-legacy-auth-2019-hybrid",
        },
        "disable_basic": MS_REFS["M9"],
        "vd_defaults": {
            "id": "vd_defaults",
            "title": "Default settings for Exchange virtual directories",
            "url": "https://learn.microsoft.com/en-us/exchange/clients/default-virtual-directory-settings",
        },
        "teams_ews": {
            "id": "teams_ews",
            "title": "How Exchange and Microsoft Teams interact",
            "url": "https://learn.microsoft.com/en-us/microsoftteams/exchange-teams-interact",
        },
        "publish": {
            "id": "publish",
            "title": "Client access services (publishing Exchange)",
            "url": "https://learn.microsoft.com/en-us/exchange/architecture/client-access",
        },
        "tls": MS_REFS["M7"],
        "hsts": MS_REFS["M8"],
        "hybrid_agent": MS_REFS["M5"],
        "dedicated_hybrid_app": MS_REFS["M4"],
        "extended_protection": MS_REFS["M6"],
    }
)

EXCHANGE_SU_BASELINE = {
    "as_of": "2026-08-11",
    "product": "Exchange Server SE",
    "label": "RTM Aug26SU (CVE-2026-62911)",
    "build": "15.2.2562.45",
    "refs": [MS_REFS["M1"], MS_REFS["M2b"], MS_REFS["CVE-2026-62911"]],
}


def refs(*keys: str) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for k in keys:
        item = MS_REFS.get(k)
        if not item:
            continue
        uid = item.get("url") or item.get("id") or k
        if uid in seen:
            continue
        seen.add(uid)
        out.append(dict(item))
    return out


NOT_OBSERVABLE_CATALOG: list[dict] = [
    {
        "id": "NO-HYBRID-AGENT",
        "title": "Microsoft Hybrid Agent presence / health",
        "detail": "Hybrid Agent is an on-premises connector; not confirmable from URL-only scanning.",
        "refs": refs("hybrid_agent", "M5"),
    },
    {
        "id": "NO-DEDICATED-HYBRID-APP",
        "title": "Dedicated Exchange hybrid app (Entra)",
        "detail": "Dedicated Hybrid App is an Entra-side object and cannot be confirmed externally.",
        "refs": refs("dedicated_hybrid_app", "M4", "M3"),
    },
    {
        "id": "NO-AUTH-CERT",
        "title": "Exchange Auth Certificate / Get-AuthConfig",
        "detail": "Auth certificate thumbprint and validity require Exchange Management Shell.",
        "refs": refs("M12", "hma"),
    },
    {
        "id": "NO-EXTENDED-PROTECTION",
        "title": "Windows Extended Protection state",
        "detail": "Extended Protection configuration is not visible to anonymous HTTP probes.",
        "refs": refs("extended_protection", "M6"),
    },
    {
        "id": "NO-VDIR-OAUTH-FLAG",
        "title": "Virtual directory OAuthAuthentication flag",
        "detail": "Server-side VDir OAuthAuthentication / OAuth2ClientProfileEnabled cannot be read externally.",
        "refs": refs("hma", "M12"),
    },
    {
        "id": "NO-S2S-OAUTH",
        "title": "Server-to-server hybrid OAuth (Teams free/busy)",
        "detail": "S2S token trust and Test-OAuthConnectivity are not observable from anonymous external HTTP.",
        "refs": refs("M12", "teams_ews"),
    },
]
