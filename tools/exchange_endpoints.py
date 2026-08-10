"""Exchange endpoint registry and safe external probes (spec v2)."""

from __future__ import annotations

import ipaddress
import re
import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from .dns_common import is_ip, normalize_domain, query_records

UA = "tools.birolbenli.com/1.0 (+https://tools.birolbenli.com; Exchange External Assessment)"
TIMEOUT = 8.0
MAX_REDIRECTS = 4
MAX_BODY = 4096

BEARER_PROBE_VDIRS = {"ews", "ews_asmx", "eas", "mapi", "mapi_emsmdb"}

VDIRS = [
    {"id": "owa", "name": "OWA", "path": "/owa/", "healthcheck": "/owa/healthcheck.htm"},
    {"id": "owa_auth", "name": "OWA auth", "path": "/owa/auth/logon.aspx", "healthcheck": None},
    {"id": "ecp", "name": "ECP", "path": "/ecp/", "healthcheck": "/ecp/healthcheck.htm"},
    {"id": "ecp_default", "name": "ECP default.aspx", "path": "/ecp/default.aspx", "healthcheck": None},
    {"id": "ews", "name": "EWS", "path": "/EWS/", "healthcheck": "/EWS/healthcheck.htm"},
    {"id": "ews_asmx", "name": "EWS Exchange.asmx", "path": "/EWS/Exchange.asmx", "healthcheck": None},
    {"id": "mrsproxy", "name": "MRSProxy", "path": "/EWS/mrsproxy.svc", "healthcheck": None},
    {"id": "eas", "name": "ActiveSync", "path": "/Microsoft-Server-ActiveSync", "healthcheck": "/Microsoft-Server-ActiveSync/healthcheck.htm"},
    {"id": "autodiscover", "name": "Autodiscover XML", "path": "/Autodiscover/Autodiscover.xml", "healthcheck": "/Autodiscover/healthcheck.htm"},
    {"id": "autodiscover_svc", "name": "Autodiscover.svc", "path": "/autodiscover/autodiscover.svc", "healthcheck": None},
    {"id": "mapi", "name": "MAPI", "path": "/mapi/", "healthcheck": "/mapi/healthcheck.htm"},
    {"id": "mapi_emsmdb", "name": "MAPI emsmdb", "path": "/mapi/emsmdb", "healthcheck": None},
    {"id": "mapi_nspi", "name": "MAPI nspi", "path": "/mapi/nspi", "healthcheck": None},
    {"id": "oab", "name": "OAB", "path": "/OAB/", "healthcheck": None},
    {"id": "powershell", "name": "PowerShell", "path": "/PowerShell/", "healthcheck": "/PowerShell/healthcheck.htm"},
    {"id": "rpc", "name": "RPC", "path": "/rpc/", "healthcheck": "/rpc/healthcheck.htm"},
    {"id": "rpcproxy", "name": "rpcproxy.dll", "path": "/rpc/rpcproxy.dll", "healthcheck": None},
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

SERVICE_LABELS = {
    "mail", "posta", "owa", "webmail", "exchange", "outlook", "smtp", "mx",
    "autodiscover", "download", "eas", "ews", "ecp",
}


def org_domain(host: str) -> str:
    host = normalize_domain(host)
    parts = host.split(".")
    if len(parts) < 2:
        return host
    if parts[0] == "download" and len(parts) > 2 and parts[1] in SERVICE_LABELS - {"download", "autodiscover"}:
        return ".".join(parts[2:])
    if parts[0] in SERVICE_LABELS:
        return ".".join(parts[1:])
    return host


def hosts_to_probe(host: str) -> list[dict]:
    host = normalize_domain(host)
    org = org_domain(host)
    parts = host.split(".")

    if parts[0] == "download" and len(parts) > 2:
        rest = ".".join(parts[1:])
        primary = rest if not rest.startswith("autodiscover.") else f"mail.{org}"
    elif parts[0] == "autodiscover":
        primary = f"mail.{org}"
    elif parts[0] not in SERVICE_LABELS:
        primary = f"mail.{org}"
    else:
        primary = host

    hosts = [
        {"role": "primary", "host": primary, "org_domain": org},
        {"role": "autodiscover", "host": f"autodiscover.{org}", "org_domain": org},
        {"role": "download", "host": f"download.{primary}", "org_domain": org},
    ]
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


def public_ips(host: str) -> list[str]:
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


def parse_auth(www_authenticate: str | None) -> dict:
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
    auth_uri = ""
    m = re.search(r'authorization_uri="([^"]+)"', raw, flags=re.I)
    if m:
        auth_uri = m.group(1)
    client_id = ""
    m2 = re.search(r'client_id="([^"]+)"', raw, flags=re.I)
    if m2:
        client_id = m2.group(1)
    entra = "login.microsoftonline.com" in auth_uri.lower() or "login.windows.net" in auth_uri.lower()
    hma_challenge = bool(oauth and (entra or client_id))
    return {
        "raw": raw[:800],
        "schemes": schemes,
        "ntlm": ntlm,
        "oauth": oauth,
        "basic": "Basic" in schemes,
        "authorization_uri": auth_uri,
        "client_id": client_id,
        "entra_oauth": entra,
        "hma_challenge": hma_challenge,
        "checked": True,
        "www_authenticate_present": bool(raw.strip()),
    }


def merge_auth(primary: dict, extra: dict | None) -> dict:
    if not extra:
        return primary
    schemes = []
    for s in (primary.get("schemes") or []) + (extra.get("schemes") or []):
        if s not in schemes:
            schemes.append(s)
    raw_parts = [p for p in (primary.get("raw") or "", extra.get("raw") or "") if p]
    auth_uri = primary.get("authorization_uri") or extra.get("authorization_uri") or ""
    client_id = primary.get("client_id") or extra.get("client_id") or ""
    oauth = "Bearer" in schemes or bool(primary.get("oauth") or extra.get("oauth"))
    ntlm = "NTLM" in schemes or "Negotiate" in schemes
    entra = bool(primary.get("entra_oauth") or extra.get("entra_oauth"))
    hma = bool(primary.get("hma_challenge") or extra.get("hma_challenge") or (oauth and (entra or client_id)))
    return {
        "raw": ", ".join(raw_parts)[:800],
        "schemes": schemes,
        "ntlm": ntlm,
        "oauth": oauth,
        "basic": "Basic" in schemes,
        "authorization_uri": auth_uri,
        "client_id": client_id,
        "entra_oauth": entra,
        "hma_challenge": hma,
        "checked": True,
        "www_authenticate_present": bool(("".join(raw_parts)).strip()),
        "bearer_probe_used": True,
        "bearer_probe_oauth": bool(extra.get("oauth")),
        "anonymous_oauth": bool(primary.get("oauth")),
    }


def request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    *,
    follow_redirects: bool = True,
) -> dict:
    hdrs = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    chain: list[dict] = []
    current = url
    context = ssl.create_default_context()

    for _ in range(MAX_REDIRECTS + 1):
        req = urllib.request.Request(current, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=context) as resp:
                body = resp.read(MAX_BODY)
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                entry = {
                    "url": current,
                    "status_code": resp.getcode(),
                    "headers": resp_headers,
                    "final_url": resp.geturl(),
                }
                chain.append(entry)
                result = {
                    "reachable": True,
                    "url": url,
                    "final_url": resp.geturl(),
                    "status_code": resp.getcode(),
                    "headers": resp_headers,
                    "body_preview": body.decode("utf-8", errors="replace"),
                    "redirect_chain": chain,
                }
                return result
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(MAX_BODY)
            except Exception:  # noqa: BLE001
                body = b""
            resp_headers = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
            entry = {
                "url": current,
                "status_code": exc.code,
                "headers": resp_headers,
                "final_url": getattr(exc, "url", None) or current,
            }
            chain.append(entry)
            if follow_redirects and exc.code in {301, 302, 303, 307, 308}:
                loc = resp_headers.get("location") or ""
                if not loc:
                    break
                if loc.startswith("/"):
                    parsed = urlparse(current)
                    loc = f"{parsed.scheme}://{parsed.netloc}{loc}"
                current = loc
                continue
            return {
                "reachable": True,
                "url": url,
                "final_url": getattr(exc, "url", None) or current,
                "status_code": exc.code,
                "headers": resp_headers,
                "body_preview": body.decode("utf-8", errors="replace") if body else "",
                "error": str(exc.reason),
                "redirect_chain": chain,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "reachable": False,
                "url": url,
                "status_code": None,
                "headers": {},
                "error": str(exc),
                "redirect_chain": chain,
            }
    return {
        "reachable": True,
        "url": url,
        "final_url": current,
        "status_code": chain[-1]["status_code"] if chain else None,
        "headers": chain[-1]["headers"] if chain else {},
        "body_preview": "",
        "error": "Too many redirects",
        "redirect_chain": chain,
    }


def classify_exposure(status: int | None) -> str:
    if status is None:
        return "closed"
    if status in (401, 403):
        return "auth_required"
    if 200 <= status < 400:
        return "open"
    if status in (301, 302, 303, 307, 308):
        return "redirect"
    return "error"


def probe_vdir(host: str, vdir: dict) -> dict:
    base = f"https://{host}"
    path_url = base + vdir["path"]
    path_res = request(path_url, method="GET")
    headers = dict(path_res.get("headers") or {})
    auth = parse_auth(headers.get("www-authenticate"))
    bearer_probe = None

    if vdir.get("id") in BEARER_PROBE_VDIRS and path_res.get("reachable"):
        bearer_res = request(
            path_url,
            method="GET",
            headers={"Authorization": "Bearer invalidtoken"},
            follow_redirects=False,
        )
        b_headers = dict(bearer_res.get("headers") or {})
        bearer_auth = parse_auth(b_headers.get("www-authenticate"))
        bearer_probe = {
            "used": True,
            "status_code": bearer_res.get("status_code"),
            "oauth": bool(bearer_auth.get("oauth")),
            "hma_challenge": bool(bearer_auth.get("hma_challenge")),
            "www_authenticate_present": bool(bearer_auth.get("www_authenticate_present")),
            "authorization_uri": bearer_auth.get("authorization_uri") or "",
            "client_id": bearer_auth.get("client_id") or "",
            "raw": (bearer_auth.get("raw") or "")[:400],
        }
        auth = merge_auth(auth, bearer_auth)
        if bearer_auth.get("www_authenticate_present"):
            headers = {**headers, **b_headers}

    # Identity provider redirect signal
    chain = path_res.get("redirect_chain") or []
    idp_redirect = False
    for step in chain:
        fu = (step.get("final_url") or step.get("url") or "").lower()
        loc = (step.get("headers") or {}).get("location", "").lower()
        if "login.microsoftonline.com" in fu or "login.microsoftonline.com" in loc:
            idp_redirect = True
            break

    status = path_res.get("status_code")
    exposure = classify_exposure(status)

    health = None
    if vdir.get("healthcheck"):
        health_url = base + vdir["healthcheck"]
        health_res = request(health_url, method="GET", follow_redirects=False)
        h_status = health_res.get("status_code")
        body = (health_res.get("body_preview") or "").strip()
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
            "headers": dict(health_res.get("headers") or {}),
            "recommendation": (
                "Public healthcheck — restrict to LB/monitoring IPs." if healthy else None
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
        "redirect_chain": [
            {"url": s.get("url"), "status_code": s.get("status_code")} for s in chain[:6]
        ],
        "idp_redirect": idp_redirect,
        "exposure": exposure,
        "auth": auth,
        "bearer_probe": bearer_probe,
        "healthcheck": health,
        "leaky_headers": leak_hits,
        "private_ips": private_hits,
        "severity": severity,
        "error": path_res.get("error"),
        "cookies": headers.get("set-cookie", "")[:300],
    }


def probe_all_endpoints(host_rows: list[dict]) -> list[dict]:
    jobs = []
    for h in host_rows:
        if not h.get("resolves"):
            continue
        for v in VDIRS:
            jobs.append((h["host"], v))

    endpoints: list[dict] = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futs = {pool.submit(probe_vdir, h, v): (h, v) for h, v in jobs}
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
                            "hma_challenge": False,
                            "client_id": "",
                            "authorization_uri": "",
                            "entra_oauth": False,
                        },
                        "bearer_probe": None,
                        "error": str(exc),
                    }
                )
    role_rank = {h["host"]: i for i, h in enumerate(host_rows)}
    endpoints.sort(key=lambda e: (role_rank.get(e.get("host"), 99), e.get("name") or ""))
    return endpoints
