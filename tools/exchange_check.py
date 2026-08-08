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

UA = "tools.birolbenli.com/1.0 (+https://tools.birolbenli.com; Exchange VD check)"
TIMEOUT = 8.0

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
    "www-authenticate",
)

PRIVATE_IP_RE = re.compile(
    r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}|127(?:\.\d{1,3}){3})\b"
)


def _parent_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3:
        return ".".join(parts[-2:])
    return host


def _hosts_to_probe(host: str) -> list[dict]:
    host = normalize_domain(host)
    parent = _parent_domain(host)
    hosts = [
        {"role": "primary", "host": host},
        {"role": "autodiscover", "host": f"autodiscover.{parent}"},
        {"role": "download", "host": f"download.{host}"},
    ]
    # Avoid duplicate when input is already autodiscover.*
    seen = set()
    out = []
    for item in hosts:
        h = item["host"]
        if h in seen:
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
    ntlm = "NTLM" in schemes or "Negotiate" in schemes
    return {
        "raw": raw,
        "schemes": schemes,
        "ntlm": ntlm,
        "oauth": oauth,
        "basic": "Basic" in schemes,
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
        healthy = bool(
            health_res.get("reachable")
            and h_status == 200
            and ("200" in body or body.upper().startswith("OK") or len(body) < 40)
        )
        health = {
            "url": health_url,
            "reachable": health_res.get("reachable"),
            "status_code": h_status,
            "healthy": healthy,
            "body_preview": body[:80],
            "error": health_res.get("error"),
            "recommendation": (
                "Healthcheck is publicly reachable. Restrict it to internal networks / load balancer probes only."
                if healthy or (health_res.get("reachable") and h_status and h_status < 500)
                else None
            ),
        }

    leak_hits = []
    for key in LEAKY_HEADERS:
        if key in headers and key != "www-authenticate":
            leak_hits.append({"header": key, "value": headers[key][:180]})

    private_hits = []
    blob = " ".join([path_res.get("final_url") or "", path_res.get("body_preview") or "", " ".join(headers.values())])
    for match in PRIVATE_IP_RE.findall(blob):
        if match not in private_hits:
            private_hits.append(match)

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


def _security_findings(endpoints: list[dict], ssl_info: dict, hosts: list[dict]) -> list[dict]:
    findings: list[dict] = []

    ntlm_eps = [e for e in endpoints if e.get("auth", {}).get("ntlm") and e.get("reachable")]
    if ntlm_eps:
        findings.append(
            {
                "severity": "critical",
                "title": "NTLM / Negotiate exposed on the internet",
                "detail": (
                    f"{len(ntlm_eps)} endpoint(s) advertise NTLM or Negotiate. "
                    "Prefer Modern Auth (OAuth 2.0) and block NTLM at the edge."
                ),
                "endpoints": [e["url"] for e in ntlm_eps[:8]],
            }
        )

    basic_eps = [e for e in endpoints if e.get("auth", {}).get("basic") and e.get("reachable")]
    if basic_eps:
        findings.append(
            {
                "severity": "warning",
                "title": "HTTP Basic authentication advertised",
                "detail": "Basic auth over the internet increases credential-theft risk. Disable where possible.",
                "endpoints": [e["url"] for e in basic_eps[:8]],
            }
        )

    oauth_eps = [e for e in endpoints if e.get("auth", {}).get("oauth")]
    if oauth_eps and not ntlm_eps:
        findings.append(
            {
                "severity": "ok",
                "title": "OAuth / Bearer challenge observed",
                "detail": "At least one endpoint advertises Bearer/OAuth-style authentication.",
                "endpoints": [e["url"] for e in oauth_eps[:5]],
            }
        )

    hc_open = [
        e
        for e in endpoints
        if e.get("healthcheck")
        and (e["healthcheck"].get("healthy") or (e["healthcheck"].get("status_code") in (200, 401, 403)))
    ]
    if hc_open:
        findings.append(
            {
                "severity": "warning",
                "title": "Exchange healthcheck URLs are publicly reachable",
                "detail": (
                    "Healthcheck pages help attackers fingerprint Exchange. "
                    "Allow only from load balancers / monitoring networks."
                ),
                "endpoints": [e["healthcheck"]["url"] for e in hc_open if e.get("healthcheck")][:8],
            }
        )

    open_admin = [
        e
        for e in endpoints
        if e.get("id") in {"ecp", "powershell", "owa"} and e.get("exposure") in {"open", "auth_required"}
    ]
    if open_admin:
        findings.append(
            {
                "severity": "warning",
                "title": "Admin / mailbox web surfaces reachable from the internet",
                "detail": (
                    "ECP/PowerShell should usually stay internal. OWA may be intentional — "
                    "confirm MFA/Modern Auth and publish only what you need."
                ),
                "endpoints": [e["url"] for e in open_admin[:8]],
            }
        )

    leak_eps = [e for e in endpoints if e.get("leaky_headers")]
    if leak_eps:
        samples = []
        for e in leak_eps[:5]:
            for h in e["leaky_headers"][:2]:
                samples.append(f"{h['header']}: {h['value']}")
        findings.append(
            {
                "severity": "warning",
                "title": "Response headers may leak server identity",
                "detail": "Headers such as X-FEServer / X-OWA-Version / Server can reveal internal names and versions.",
                "endpoints": samples[:8],
            }
        )

    priv = sorted({ip for e in endpoints for ip in (e.get("private_ips") or [])})
    if priv:
        findings.append(
            {
                "severity": "critical",
                "title": "Private / internal IP addresses visible externally",
                "detail": "Internal addresses appeared in redirects, bodies, or headers.",
                "endpoints": priv,
            }
        )

    if ssl_info:
        days = ssl_info.get("days_left")
        status = ssl_info.get("status")
        if status == "expired" or (isinstance(days, int) and days < 0):
            findings.append(
                {
                    "severity": "critical",
                    "title": "TLS certificate expired",
                    "detail": f"Certificate for {ssl_info.get('domain')} is expired.",
                    "endpoints": [],
                }
            )
        elif isinstance(days, int) and days <= 30:
            findings.append(
                {
                    "severity": "warning",
                    "title": "TLS certificate expires soon",
                    "detail":                     f"{ssl_info.get('domain')} expires in {days} day(s) "
                    f"(not after {ssl_info.get('expiry_date')}).",
                    "endpoints": [],
                }
            )
        elif status in {"ok", "valid", "warning"} or isinstance(days, int):
            findings.append(
                {
                    "severity": "ok" if status == "valid" else "warning",
                    "title": "TLS certificate looks valid remotely"
                    if status == "valid"
                    else "TLS certificate checked",
                    "detail": (
                        f"{ssl_info.get('domain')}: {days} day(s) left, issuer {ssl_info.get('issuer')}."
                        if days is not None
                        else str(ssl_info.get("message") or "Checked")
                    ),
                    "endpoints": [],
                }
            )

    unresolved = [h for h in hosts if not h.get("ips")]
    if unresolved:
        findings.append(
            {
                "severity": "info",
                "title": "Some related hostnames did not resolve",
                "detail": "Missing DNS is fine if you do not use that name (e.g. download.* / autodiscover.*).",
                "endpoints": [h["host"] for h in unresolved],
            }
        )

    if not findings:
        findings.append(
            {
                "severity": "info",
                "title": "Limited public Exchange footprint detected",
                "detail": "Few or no classic virtual directories answered. Confirm the hostname fronts Exchange.",
                "endpoints": [],
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

    # Probe VDirs on hosts that resolve (primary always; others if DNS exists)
    jobs = []
    for h in host_rows:
        if not h["resolves"]:
            continue
        # Autodiscover host: mainly autodiscover path; download host: OAB-focused but scan key set
        if h["role"] == "autodiscover":
            vdirs = [v for v in VDIRS if v["id"] in {"autodiscover", "owa"}]
        elif h["role"] == "download":
            vdirs = [v for v in VDIRS if v["id"] in {"oab", "owa"}]
        else:
            vdirs = VDIRS
        for v in vdirs:
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
                        "auth": {"schemes": [], "ntlm": False, "oauth": False, "basic": False},
                        "error": str(exc),
                    }
                )

    # Stable sort: primary host first, then by name
    role_rank = {h["host"]: i for i, h in enumerate(host_rows)}
    endpoints.sort(key=lambda e: (role_rank.get(e.get("host"), 99), e.get("name") or ""))

    findings = _security_findings(endpoints, ssl_info, host_rows)
    summary = _score(findings, endpoints)

    return {
        "ok": True,
        "host": host,
        "hosts": host_rows,
        "ssl": ssl_info,
        "endpoints": endpoints,
        "findings": findings,
        "summary": summary,
        "counts": {
            "reachable": sum(1 for e in endpoints if e.get("reachable")),
            "ntlm": sum(1 for e in endpoints if e.get("auth", {}).get("ntlm")),
            "oauth": sum(1 for e in endpoints if e.get("auth", {}).get("oauth")),
            "healthcheck_open": sum(
                1
                for e in endpoints
                if e.get("healthcheck")
                and (e["healthcheck"].get("healthy") or e["healthcheck"].get("status_code") == 200)
            ),
        },
    }
