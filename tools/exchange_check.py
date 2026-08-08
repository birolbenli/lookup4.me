"""Exchange Server virtual directory / health / exposure scanner."""

from __future__ import annotations

import ipaddress
import re
import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from .dns_common import is_ip, normalize_domain, query_records
from .ssl_check import get_ssl_info

UA = "tools.birolbenli.com/1.0 (+https://tools.birolbenli.com; Exchange HC)"
TIMEOUT = 8.0

MS_REFS = {
    "hma": {
        "title": "Configure Exchange Server for Hybrid Modern Authentication",
        "url": "https://learn.microsoft.com/en-us/microsoft-365/enterprise/configure-exchange-server-for-hybrid-modern-authentication",
    },
    "block_legacy": {
        "title": "Use authentication policies to block legacy auth (hybrid)",
        "url": "https://learn.microsoft.com/en-us/exchange/hybrid-deployment/block-legacy-auth-2019-hybrid",
    },
    "disable_basic": {
        "title": "Disable Basic authentication on Exchange virtual directories",
        "url": "https://learn.microsoft.com/en-us/exchange/plan-and-deploy/post-installation-tasks/disable-basic-authentication-on-exchange-server-virtual-directories",
    },
    "legacy_blog": {
        "title": "Disabling Legacy Authentication in Exchange Server 2019",
        "url": "https://techcommunity.microsoft.com/blog/exchange/disabling-legacy-authentication-in-exchange-server-2019/712048",
    },
    "vd_defaults": {
        "title": "Default settings for Exchange virtual directories",
        "url": "https://learn.microsoft.com/en-us/exchange/clients/default-virtual-directory-settings",
    },
    "teams_ews": {
        "title": "How Exchange and Microsoft Teams interact",
        "url": "https://learn.microsoft.com/en-us/microsoftteams/exchange-teams-interact",
    },
    "publish": {
        "title": "Client access services (publishing Exchange)",
        "url": "https://learn.microsoft.com/en-us/exchange/architecture/client-access",
    },
}

# Common Exchange virtual directories and optional healthcheck paths.
VDIRS = [
    {
        "id": "owa",
        "name": "OWA",
        "path": "/owa/",
        "healthcheck": "/owa/healthcheck.htm",
    },
    {
        "id": "ecp",
        "name": "ECP",
        "path": "/ecp/",
        "healthcheck": "/ecp/healthcheck.htm",
    },
    {
        "id": "ews",
        "name": "EWS",
        "path": "/EWS/Exchange.asmx",
        "healthcheck": "/EWS/healthcheck.htm",
    },
    {
        "id": "eas",
        "name": "ActiveSync",
        "path": "/Microsoft-Server-ActiveSync",
        "healthcheck": "/Microsoft-Server-ActiveSync/healthcheck.htm",
    },
    {
        "id": "autodiscover",
        "name": "Autodiscover",
        "path": "/Autodiscover/Autodiscover.xml",
        "healthcheck": "/Autodiscover/healthcheck.htm",
    },
    {
        "id": "mapi",
        "name": "MAPI",
        "path": "/mapi/emsmdb",
        "healthcheck": "/mapi/healthcheck.htm",
    },
    {
        "id": "oab",
        "name": "OAB",
        "path": "/OAB/",
        "healthcheck": None,
    },
    {
        "id": "powershell",
        "name": "PowerShell",
        "path": "/PowerShell/",
        "healthcheck": "/PowerShell/healthcheck.htm",
    },
    {
        "id": "rpc",
        "name": "RPC",
        "path": "/rpc/rpcproxy.dll",
        "healthcheck": "/rpc/healthcheck.htm",
    },
]

LEAKY_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-owa-version",
    "x-feserver",
    "x-beserver",
    "x-calculatedbetarget",
    "x-calculatedfetarget",
    "x-ms-diagnostics",
    "x-diaginfo",
    "x-backendhttpstatus",
    "x-routerecovery",
    "x-owa-diagnostics",
    "request-id",
)

PRIVATE_IP_RE = re.compile(
    r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}|127(?:\.\d{1,3}){3})\b"
)

# Left-most labels that are service hosts, not the org domain.
SERVICE_LABELS = {
    "mail",
    "posta",
    "owa",
    "webmail",
    "exchange",
    "outlook",
    "smtp",
    "mx",
    "autodiscover",
    "download",
    "eas",
    "ews",
    "ecp",
}


def _org_domain(host: str) -> str:
    """Org domain for Autodiscover: mail.izto.org.tr → izto.org.tr (not org.tr)."""
    host = normalize_domain(host)
    parts = host.split(".")
    if len(parts) < 2:
        return host
    # download.mail.example.com → strip download + mail
    if parts[0] == "download" and len(parts) > 2 and parts[1] in SERVICE_LABELS - {"download", "autodiscover"}:
        return ".".join(parts[2:])
    if parts[0] in SERVICE_LABELS:
        return ".".join(parts[1:])
    return host


def _hosts_to_probe(host: str) -> list[dict]:
    """primary + autodiscover.<org> + download.<primary>.

    Example: mail.izto.org.tr →
      mail.izto.org.tr, autodiscover.izto.org.tr, download.mail.izto.org.tr
    """
    host = normalize_domain(host)
    org = _org_domain(host)
    parts = host.split(".")

    if parts[0] == "download" and len(parts) > 2:
        rest = ".".join(parts[1:])
        primary = rest if not rest.startswith("autodiscover.") else f"mail.{org}"
    elif parts[0] == "autodiscover":
        primary = f"mail.{org}"
    elif parts[0] not in SERVICE_LABELS:
        # Bare org (izto.org.tr) → assume mail.<org> + download.mail.<org>
        primary = f"mail.{org}"
    else:
        primary = host

    hosts = [
        {"role": "primary", "host": primary, "org_domain": org},
        {"role": "autodiscover", "host": f"autodiscover.{org}", "org_domain": org},
        {"role": "download", "host": f"download.{primary}", "org_domain": org},
    ]
    # Keep the typed name if it is not already one of the three.
    if host not in {h["host"] for h in hosts}:
        hosts.insert(0, {"role": "input", "host": host, "org_domain": org})

    seen: set[str] = set()
    out = []
    for item in hosts:
        h = item["host"]
        if not h or h in seen or h.startswith("download.autodiscover."):
            continue
        seen.add(h)
        out.append(item)
    return out


def _public_ips(host: str) -> list[str]:
    ips: list[str] = []
    if is_ip(host):
        ips.append(host)
    else:
        for rtype in ("A", "AAAA"):
            ans = query_records(host, rtype)
            for rec in ans.get("records") or []:
                data = rec.get("data")
                if data:
                    ips.append(data)
    public = []
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
            continue
        public.append(ip)
    return public


def _parse_auth(www_authenticate: str | None) -> dict:
    raw = www_authenticate or ""
    lower = raw.lower()
    schemes = []
    if "ntlm" in lower:
        schemes.append("NTLM")
    if "negotiate" in lower:
        schemes.append("Negotiate")
    if "basic" in lower:
        schemes.append("Basic")
    if "bearer" in lower:
        schemes.append("Bearer")
    oauth = "Bearer" in schemes or "oauth" in lower
    # Negotiate often includes NTLM fallback on Windows; treat as legacy Windows auth exposure.
    ntlm = "NTLM" in schemes or "Negotiate" in schemes
    auth_uri = ""
    m = re.search(r'authorization_uri="([^"]+)"', raw, flags=re.I)
    if m:
        auth_uri = m.group(1)
    entra = "login.microsoftonline.com" in auth_uri.lower() or "login.windows.net" in auth_uri.lower()
    return {
        "raw": raw,
        "schemes": schemes,
        "ntlm": ntlm,
        "oauth": oauth,
        "basic": "Basic" in schemes,
        "authorization_uri": auth_uri,
        "entra_oauth": entra,
        "checked": True,
        "www_authenticate_present": bool(raw.strip()),
    }


def _request(url: str, method: str = "GET") -> dict:
    req = urllib.request.Request(url, method=method, headers={"User-Agent": UA, "Accept": "*/*"})
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=context) as resp:
            body = resp.read(4096)
            headers = {k: v for k, v in resp.headers.items()}
            return {
                "reachable": True,
                "url": url,
                "final_url": resp.geturl(),
                "status_code": resp.getcode(),
                "headers": headers,
                "body_preview": body.decode("utf-8", errors="replace"),
            }
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(4096)
        except Exception:  # noqa: BLE001
            body = b""
        headers = {k: v for k, v in (exc.headers.items() if exc.headers else [])}
        return {
            "reachable": True,
            "url": url,
            "final_url": getattr(exc, "url", None) or url,
            "status_code": exc.code,
            "headers": headers,
            "body_preview": body.decode("utf-8", errors="replace") if body else "",
            "error": str(exc.reason),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "reachable": False,
            "url": url,
            "status_code": None,
            "headers": {},
            "error": str(exc),
        }


def _classify_exposure(status: int | None, auth: dict) -> str:
    if status is None:
        return "closed"
    if status in (401, 403):
        return "auth_required"
    if 200 <= status < 400:
        return "open"
    if status in (301, 302, 303, 307, 308):
        return "redirect"
    return "error"


def _probe_vdir(host: str, vdir: dict) -> dict:
    base = f"https://{host}"
    path_url = base + vdir["path"]
    path_res = _request(path_url, method="GET")
    headers = {k.lower(): v for k, v in (path_res.get("headers") or {}).items()}
    auth = _parse_auth(headers.get("www-authenticate"))
    status = path_res.get("status_code")
    exposure = _classify_exposure(status, auth)

    health = None
    if vdir.get("healthcheck"):
        health_url = base + vdir["healthcheck"]
        health_res = _request(health_url, method="GET")
        h_status = health_res.get("status_code")
        body = (health_res.get("body_preview") or "").strip()
        # Classic Exchange healthcheck returns HTTP 200 with a tiny "200 OK" body.
        healthy = bool(
            health_res.get("reachable")
            and h_status == 200
            and (
                body.upper().startswith("200")
                or body.upper() in {"OK", "200 OK"}
                or (len(body) <= 32 and "html" not in body.lower())
            )
        )
        health = {
            "url": health_url,
            "reachable": health_res.get("reachable"),
            "status_code": h_status,
            "healthy": healthy,
            "body_preview": body[:80],
            "error": health_res.get("error"),
            "headers": {k.lower(): v for k, v in (health_res.get("headers") or {}).items()},
            "recommendation": (
                "Public healthcheck — restrict to LB/monitoring IPs."
                if healthy
                else None
            ),
        }

    header_sources = [headers]
    if health and health.get("headers"):
        header_sources.append(health["headers"])

    leak_hits = []
    seen_hdr: set[str] = set()
    for src in header_sources:
        for key in LEAKY_HEADERS:
            if key not in src:
                continue
            mark = f"{key}|{src[key][:80]}"
            if mark in seen_hdr:
                continue
            seen_hdr.add(mark)
            leak_hits.append({"header": key, "value": src[key][:180]})
        # Location / redirect targets with internal IPs
        loc = src.get("location") or ""
        if loc and PRIVATE_IP_RE.search(loc):
            mark = f"location|{loc[:80]}"
            if mark not in seen_hdr:
                seen_hdr.add(mark)
                leak_hits.append({"header": "location", "value": loc[:180]})

    private_hits = []
    blob = " ".join(
        [
            path_res.get("final_url") or "",
            path_res.get("body_preview") or "",
            " ".join(headers.values()),
            " ".join((health or {}).get("headers", {}).values()) if health else "",
        ]
    )
    for match in PRIVATE_IP_RE.findall(blob):
        if match not in private_hits:
            private_hits.append(match)
            mark = f"private-ip|{match}"
            if mark not in seen_hdr:
                seen_hdr.add(mark)
                leak_hits.append({"header": "private-ip", "value": match})

    severity = "info"
    if exposure == "open" and auth["ntlm"]:
        severity = "critical"
    elif auth["ntlm"] or (health and health.get("healthy")):
        severity = "warning"
    elif exposure in ("open", "auth_required") and auth["basic"]:
        severity = "warning"
    elif exposure == "open":
        severity = "warning"

    return {
        "id": vdir["id"],
        "name": vdir["name"],
        "host": host,
        "url": path_url,
        "reachable": path_res.get("reachable"),
        "status_code": status,
        "final_url": path_res.get("final_url"),
        "exposure": exposure,
        "auth": auth,
        "healthcheck": health,
        "leaky_headers": leak_hits,
        "private_ips": private_hits,
        "severity": severity,
        "error": path_res.get("error"),
    }


def _headers_report(endpoints: list[dict]) -> dict:
    """Aggregate risky response headers (server name, version, internal IP)."""
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
            if name == "private-ip" or PRIVATE_IP_RE.search(val):
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
            elif name == "x-powered-by":
                risk, note = "info", "Stack hint"
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
    """Explicit statement of what was checked for NTLM / OAuth 2.0 / Basic."""
    probed = [e for e in endpoints if e.get("reachable")]
    ntlm_eps = [e for e in probed if e.get("auth", {}).get("ntlm")]
    oauth_eps = [e for e in probed if e.get("auth", {}).get("oauth")]
    basic_eps = [e for e in probed if e.get("auth", {}).get("basic")]
    negotiate_eps = [
        e for e in probed if "Negotiate" in (e.get("auth", {}).get("schemes") or [])
    ]
    entra_eps = [e for e in probed if e.get("auth", {}).get("entra_oauth")]
    no_challenge = [
        e
        for e in probed
        if e.get("exposure") in {"open", "auth_required", "error"}
        and not e.get("auth", {}).get("www_authenticate_present")
    ]

    def _status(found: bool, found_label: str, missing_label: str) -> dict:
        return {
            "checked": True,
            "found": found,
            "status": "detected" if found else "not_detected",
            "summary": found_label if found else missing_label,
        }

    return {
        "method": "Unauthenticated HTTPS GET → parse WWW-Authenticate on each reachable VD.",
        "endpoints_probed": len(probed),
        "ntlm": {
            **_status(
                bool(ntlm_eps),
                f"NTLM/Negotiate on {len(ntlm_eps)} endpoint(s).",
                "NTLM/Negotiate not advertised.",
            ),
            "endpoints": [
                {
                    "url": e["url"],
                    "name": e.get("name"),
                    "schemes": e.get("auth", {}).get("schemes") or [],
                }
                for e in ntlm_eps
            ],
            "microsoft": "Use HMA + Authentication Policies to block legacy auth (not by disabling NTLM on VDirs).",
            "refs": [MS_REFS["block_legacy"], MS_REFS["hma"]],
        },
        "oauth2": {
            **_status(
                bool(oauth_eps),
                f"OAuth 2.0/Bearer on {len(oauth_eps)} endpoint(s).",
                "OAuth 2.0/Bearer not advertised.",
            ),
            "entra_hint": bool(entra_eps),
            "endpoints": [
                {
                    "url": e["url"],
                    "name": e.get("name"),
                    "authorization_uri": e.get("auth", {}).get("authorization_uri") or "",
                    "entra": bool(e.get("auth", {}).get("entra_oauth")),
                }
                for e in oauth_eps
            ],
            "microsoft": "Enable Hybrid Modern Authentication (Entra ID OAuth) for hybrid/Teams.",
            "refs": [MS_REFS["hma"]],
        },
        "basic": {
            **_status(
                bool(basic_eps),
                f"Basic auth on {len(basic_eps)} endpoint(s).",
                "Basic auth not advertised.",
            ),
            "endpoints": [{"url": e["url"], "name": e.get("name")} for e in basic_eps],
            "microsoft": "Disable Basic auth on Exchange VDirs where possible.",
            "refs": [MS_REFS["disable_basic"]],
        },
        "negotiate": {
            **_status(
                bool(negotiate_eps),
                f"Negotiate on {len(negotiate_eps)} endpoint(s).",
                "Negotiate not advertised.",
            ),
            "endpoints": [{"url": e["url"], "name": e.get("name")} for e in negotiate_eps],
        },
        "no_www_authenticate": {
            "count": len(no_challenge),
            "note": "No WWW-Authenticate may still mean forms/cookie auth — not proof of Modern Auth.",
            "endpoints": [e["url"] for e in no_challenge[:8]],
        },
    }


def _posture(endpoints: list[dict], hosts: list[dict], auth_audit: dict) -> dict:
    """Hybrid / Teams oriented interpretation based on remote signals + Microsoft guidance."""
    signals = []
    autodiscover_host = next((h for h in hosts if h.get("role") == "autodiscover"), None)
    download_host = next((h for h in hosts if h.get("role") == "download"), None)
    ews = [e for e in endpoints if e.get("id") == "ews" and e.get("reachable")]
    mapi = [e for e in endpoints if e.get("id") == "mapi" and e.get("reachable")]
    owa = [e for e in endpoints if e.get("id") == "owa" and e.get("reachable")]

    leak_blob = " ".join(
        f"{h.get('header','')}:{h.get('value','')}"
        for e in endpoints
        for h in (e.get("leaky_headers") or [])
    ).lower()
    if "outlook.com" in leak_blob or "prod.outlook.com" in leak_blob:
        signals.append("cloud_frontend_headers")
    if any(e.get("auth", {}).get("entra_oauth") for e in endpoints):
        signals.append("entra_oauth_challenge")
    if auth_audit.get("ntlm", {}).get("found"):
        signals.append("legacy_windows_auth")
    if autodiscover_host and autodiscover_host.get("resolves"):
        signals.append("autodiscover_dns")
    if download_host and download_host.get("resolves"):
        signals.append("download_dns")
    if ews:
        signals.append("ews_published")
    if mapi:
        signals.append("mapi_published")

    likely_hybrid = bool(
        signals.count("legacy_windows_auth")
        or (signals.count("ews_published") and signals.count("autodiscover_dns"))
        or signals.count("entra_oauth_challenge")
    )
    likely_onprem_publish = bool(auth_audit.get("ntlm", {}).get("found") or owa or ews)

    hybrid = {
        "likely": likely_hybrid or likely_onprem_publish,
        "signals": signals,
        "summary": (
            "Looks like internet-facing Exchange (on-prem or hybrid)."
            if likely_hybrid or likely_onprem_publish
            else "Hybrid vs cloud not clear from this probe alone."
        ),
        "guidance": [
            "Enable HMA (Entra OAuth) for hybrid clients.",
            "Then BlockLegacyAuth* via Authentication Policies (Ex2019 CU2+).",
            "Keep ECP / remote PowerShell off the public internet.",
        ],
        "refs": [MS_REFS["hma"], MS_REFS["block_legacy"]],
    }

    teams = {
        "relevant": True,
        "summary": (
            "Teams needs Exchange (often EWS/Autodiscover). Keep them available, but not with public NTLM."
        ),
        "guidance": [
            "Do not blindly disable EWS if Teams calendar is required.",
            "Remove internet NTLM on EWS; prefer HMA / Modern Auth.",
            "Keep ECP/PowerShell internal; use MFA / Conditional Access.",
        ],
        "refs": [MS_REFS["teams_ews"], MS_REFS["hma"]],
        "ews_status": "EWS reachable." if ews else "EWS not reachable externally.",
        "ntlm_on_ews": any(e.get("auth", {}).get("ntlm") for e in ews),
        "oauth_on_ews": any(e.get("auth", {}).get("oauth") for e in ews),
    }

    return {"hybrid": hybrid, "teams": teams}


def _security_findings(
    endpoints: list[dict],
    ssl_info: dict,
    hosts: list[dict],
    auth_audit: dict,
) -> list[dict]:
    findings: list[dict] = []

    ntlm = auth_audit.get("ntlm") or {}
    if ntlm.get("found"):
        findings.append(
            {
                "severity": "critical",
                "title": "NTLM / Negotiate exposed on the internet",
                "detail": ntlm.get("summary"),
                "guidance": "Block legacy auth (HMA + Authentication Policies).",
                "endpoints": [e["url"] for e in ntlm.get("endpoints") or []][:8],
                "refs": ntlm.get("refs") or [],
                "context": "legacy_auth",
            }
        )
    else:
        findings.append(
            {
                "severity": "ok",
                "title": "NTLM / Negotiate not detected",
                "detail": ntlm.get("summary"),
                "guidance": "Still prefer Authentication Policies for hybrid users.",
                "endpoints": [],
                "refs": [MS_REFS["block_legacy"]],
                "context": "legacy_auth",
            }
        )

    oauth = auth_audit.get("oauth2") or {}
    if oauth.get("found"):
        findings.append(
            {
                "severity": "ok",
                "title": "OAuth 2.0 / Bearer detected",
                "detail": oauth.get("summary")
                + (" Entra ID issuer." if oauth.get("entra_hint") else ""),
                "guidance": oauth.get("microsoft"),
                "endpoints": [e["url"] for e in oauth.get("endpoints") or []][:8],
                "refs": oauth.get("refs") or [],
                "context": "modern_auth",
            }
        )
    else:
        findings.append(
            {
                "severity": "warning",
                "title": "OAuth 2.0 / Bearer not detected",
                "detail": "No Bearer challenge on probed VDs. Hybrid usually needs HMA.",
                "guidance": "Enable HMA, then block legacy auth.",
                "endpoints": [],
                "refs": [MS_REFS["hma"], MS_REFS["block_legacy"]],
                "context": "modern_auth",
            }
        )

    basic = auth_audit.get("basic") or {}
    if basic.get("found"):
        findings.append(
            {
                "severity": "warning",
                "title": "HTTP Basic auth advertised",
                "detail": basic.get("summary"),
                "guidance": "Disable Basic on VDirs where possible.",
                "endpoints": [e["url"] for e in basic.get("endpoints") or []][:8],
                "refs": basic.get("refs") or [],
                "context": "legacy_auth",
            }
        )

    hc_open = [e for e in endpoints if e.get("healthcheck") and e["healthcheck"].get("healthy")]
    if hc_open:
        findings.append(
            {
                "severity": "warning",
                "title": "Exchange healthcheck URLs are publicly reachable",
                "detail": "Public healthchecks fingerprint Exchange.",
                "guidance": "Allow only LB/monitoring IPs.",
                "endpoints": [e["healthcheck"]["url"] for e in hc_open if e.get("healthcheck")][:8],
                "refs": [MS_REFS["publish"]],
                "context": "exposure",
            }
        )

    open_admin = [
        e
        for e in endpoints
        if e.get("id") in {"ecp", "powershell"} and e.get("exposure") in {"open", "auth_required"}
    ]
    open_owa = [
        e for e in endpoints if e.get("id") == "owa" and e.get("exposure") in {"open", "auth_required", "error"}
    ]
    if open_admin:
        findings.append(
            {
                "severity": "warning",
                "title": "Admin surfaces (ECP / PowerShell) reachable",
                "detail": "ECP/PowerShell should stay internal.",
                "guidance": "Publish only OWA/EWS/Autodiscover/MAPI as needed.",
                "endpoints": [e["url"] for e in open_admin[:8]],
                "refs": [MS_REFS["vd_defaults"], MS_REFS["publish"]],
                "context": "exposure",
            }
        )
    if open_owa:
        findings.append(
            {
                "severity": "info",
                "title": "OWA reachable externally",
                "detail": "Common — use Modern Auth / MFA.",
                "guidance": "Prefer HMA + Conditional Access.",
                "endpoints": [e["url"] for e in open_owa[:4]],
                "refs": [MS_REFS["hma"], MS_REFS["vd_defaults"]],
                "context": "exposure",
            }
        )

    # Header/IP leaks are reported via headers_report (+ summary finding in check_exchange).

    if ssl_info:
        days = ssl_info.get("days_left")
        status = ssl_info.get("status")
        if status == "expired" or (isinstance(days, int) and days < 0):
            findings.append(
                {
                    "severity": "critical",
                    "title": "TLS certificate expired",
                    "detail": f"{ssl_info.get('domain')} expired.",
                    "guidance": "Renew immediately.",
                    "endpoints": [],
                    "refs": [],
                    "context": "tls",
                }
            )
        elif isinstance(days, int) and days <= 30:
            findings.append(
                {
                    "severity": "warning",
                    "title": "TLS certificate expires soon",
                    "detail": f"{ssl_info.get('domain')}: {days} day(s) left.",
                    "guidance": "Renew before expiry.",
                    "endpoints": [],
                    "refs": [],
                    "context": "tls",
                }
            )
        elif status == "valid":
            findings.append(
                {
                    "severity": "ok",
                    "title": "TLS certificate valid",
                    "detail": f"{days} day(s) left · {ssl_info.get('issuer')}.",
                    "guidance": "Keep auto-renewal.",
                    "endpoints": [],
                    "refs": [],
                    "context": "tls",
                }
            )

    unresolved = [h for h in hosts if not h.get("ips")]
    if unresolved:
        findings.append(
            {
                "severity": "info",
                "title": "Some related hostnames did not resolve",
                "detail": "OK if unused (e.g. download.*).",
                "guidance": "Match Autodiscover to your design.",
                "endpoints": [h["host"] for h in unresolved],
                "refs": [MS_REFS["vd_defaults"]],
                "context": "dns",
            }
        )

    order = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    return findings


def _score(findings: list[dict], endpoints: list[dict]) -> dict:
    score = 100
    for f in findings:
        sev = f["severity"]
        if sev == "critical":
            score -= 25
        elif sev == "warning":
            score -= 12
        elif sev == "info":
            score -= 2
    # Bonus small penalty for each publicly reachable VD
    exposed = sum(1 for e in endpoints if e.get("exposure") in {"open", "auth_required"})
    score -= min(20, exposed * 2)
    score = max(0, min(100, score))
    if score >= 85:
        grade = "A"
        label = "Good"
    elif score >= 70:
        grade = "B"
        label = "Fair"
    elif score >= 50:
        grade = "C"
        label = "Needs work"
    else:
        grade = "D"
        label = "High risk"
    return {"score": score, "grade": grade, "label": label}


def check_exchange(host: str) -> dict:
    raw = (host or "").strip()
    if not raw:
        return {"ok": False, "error": "Please enter an Exchange hostname (e.g. mail.example.com)"}

    if "://" in raw:
        raw = urlparse(raw).hostname or raw
    host = normalize_domain(raw.replace("\\", "/").split("/")[0])
    if not host or "." not in host and not is_ip(host):
        return {"ok": False, "error": "Enter a valid hostname such as mail.example.com"}

    # SSRF guard: require at least one public IP for the primary host
    primary_ips = _public_ips(host)
    if not primary_ips:
        return {
            "ok": False,
            "error": "Hostname must resolve to a public IP address (private/local targets are blocked).",
            "host": host,
        }

    host_rows = []
    for item in _hosts_to_probe(host):
        ips = _public_ips(item["host"])
        host_rows.append({**item, "ips": ips, "resolves": bool(ips)})

    ssl_info = get_ssl_info(host, 443)

    # Same VD set on every resolving namespace (they often front the same Exchange).
    jobs = []
    for h in host_rows:
        if not h["resolves"]:
            continue
        for v in VDIRS:
            jobs.append((h["host"], v))

    endpoints: list[dict] = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futs = {pool.submit(_probe_vdir, h, v): (h, v) for h, v in jobs}
        for fut in as_completed(futs):
            try:
                endpoints.append(fut.result())
            except Exception as exc:  # noqa: BLE001
                h, v = futs[fut]
                endpoints.append(
                    {
                        "id": v["id"],
                        "name": v["name"],
                        "host": h,
                        "url": f"https://{h}{v['path']}",
                        "reachable": False,
                        "exposure": "closed",
                        "severity": "info",
                        "auth": {
                            "schemes": [],
                            "ntlm": False,
                            "oauth": False,
                            "basic": False,
                            "checked": False,
                            "www_authenticate_present": False,
                        },
                        "error": str(exc),
                    }
                )

    # Stable sort: primary host first, then by name
    role_rank = {h["host"]: i for i, h in enumerate(host_rows)}
    endpoints.sort(key=lambda e: (role_rank.get(e.get("host"), 99), e.get("name") or ""))

    auth_audit = _auth_audit(endpoints)
    posture = _posture(endpoints, host_rows, auth_audit)
    findings = _security_findings(endpoints, ssl_info, host_rows, auth_audit)
    headers_report = _headers_report(endpoints)
    if headers_report.get("risk_count"):
        findings.append(
            {
                "severity": "critical" if headers_report.get("critical") else "warning",
                "title": "Sensitive data in HTTP headers",
                "detail": f"{headers_report['risk_count']} leak(s): hostname, version, and/or internal IP.",
                "guidance": "Strip X-FEServer/version at proxy; hide private IPs.",
                "endpoints": [
                    f"{r['header']}: {r['value']}" for r in (headers_report.get("items") or [])[:6]
                ],
                "refs": [],
                "context": "headers",
            }
        )
        findings.sort(key=lambda f: {"critical": 0, "warning": 1, "info": 2, "ok": 3}.get(f["severity"], 9))
    summary = _score(findings, endpoints)

    # Same-IP hint across namespaces
    ip_map: dict[str, list[str]] = {}
    for h in host_rows:
        for ip in h.get("ips") or []:
            ip_map.setdefault(ip, []).append(h["host"])
    shared_frontends = [
        {"ip": ip, "hosts": hs} for ip, hs in ip_map.items() if len(hs) > 1
    ]

    return {
        "ok": True,
        "host": host,
        "org_domain": _org_domain(host),
        "tool": "Microsoft Exchange Server HC",
        "hosts": host_rows,
        "shared_frontends": shared_frontends,
        "ssl": ssl_info,
        "endpoints": endpoints,
        "auth_audit": auth_audit,
        "posture": posture,
        "headers_report": headers_report,
        "findings": findings,
        "summary": summary,
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
    }
