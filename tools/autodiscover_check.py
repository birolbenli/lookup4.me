"""Exchange Autodiscover DNS + HTTPS discovery (external-only).

Covers the common multi-domain pattern:
- Primary org (e.g. example.com) hosts Autodiscover on autodiscover.<primary>
- Accepted domains (e.g. alias.example.com) publish SRV _autodiscover._tcp
  (and/or CNAME) pointing at the primary Autodiscover host
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urlparse

from .dns_common import is_valid_domain, normalize_domain, query_records, resolve_host_chain
from .http_fetch import fetch_url, follow_redirect_chain

UA_PATH = "/Autodiscover/Autodiscover.xml"
HC_PATH = "/Autodiscover/healthcheck.htm"


def _parse_input(raw: str) -> tuple[str, str | None]:
    """domain[, primary] — separators: space, slash, comma, newline."""
    text = (raw or "").strip()
    if not text:
        return "", None
    parts = [normalize_domain(p) for p in re.split(r"[\s,/|]+", text) if p.strip()]
    domain = parts[0] if parts else ""
    primary = parts[1] if len(parts) > 1 else None
    if primary and primary == domain:
        primary = None
    return domain, primary


def _parse_srv(data: str) -> dict[str, Any] | None:
    parts = (data or "").split()
    if len(parts) < 4:
        return None
    try:
        return {
            "priority": int(parts[0]),
            "weight": int(parts[1]),
            "port": int(parts[2]),
            "target": normalize_domain(parts[3]),
            "raw": data.strip(),
        }
    except ValueError:
        return None


def _org_of(host: str) -> str:
    host = normalize_domain(host)
    parts = host.split(".")
    if len(parts) >= 3 and parts[0] in {"autodiscover", "mail", "owa", "outlook", "exchange", "eas", "ews"}:
        return ".".join(parts[1:])
    if len(parts) >= 2:
        return ".".join(parts[-2:]) if len(parts) > 2 else host
    return host


def _probe_https(url: str, *, timeout: float = 8.0) -> dict[str, Any]:
    res = fetch_url(url, follow_redirects=True, timeout=timeout, max_body=4096)
    code = res.get("status_code")
    headers = {k.lower(): v for k, v in (res.get("headers") or {}).items()}
    body = (res.get("body") or "")[:2000]
    www = headers.get("www-authenticate") or ""
    signals: list[str] = []
    if code in (401, 403):
        signals.append("auth_challenge")
    if "ntlm" in www.lower() or "negotiate" in www.lower() or "basic" in www.lower():
        signals.append("www_authenticate")
    if any(h in headers for h in ("x-feserver", "x-calculatedbetarget", "x-owa-version", "request-id")):
        signals.append("exchange_headers")
    if "autodiscover" in body.lower() or "microsoft" in body.lower()[:400]:
        signals.append("exchange_body")
    # Unauthenticated Autodiscover often answers 401 — that still means the endpoint exists.
    reachable = isinstance(code, int) and code < 500
    exchange_like = bool(signals) or code in (401, 403)
    return {
        "url": url,
        "final_url": res.get("final_url") or url,
        "status_code": code,
        "reachable": reachable,
        "exchange_like": exchange_like,
        "signals": signals,
        "www_authenticate": www[:160] if www else None,
        "error": res.get("error"),
        "redirected": res.get("redirected"),
    }


def _dns_autodiscover_host(domain: str) -> dict[str, Any]:
    name = f"autodiscover.{domain}"
    cname = query_records(name, "CNAME")
    a = query_records(name, "A")
    aaaa = query_records(name, "AAAA")
    chain = resolve_host_chain(name)
    steps = chain.get("chain") or []
    cname_vals = [normalize_domain(r["data"]) for r in (cname.get("records") or [])]
    a_vals = [r["data"] for r in (a.get("records") or [])]
    aaaa_vals = [r["data"] for r in (aaaa.get("records") or [])]
    resolves = bool(a_vals or aaaa_vals or cname_vals or chain.get("ips"))
    final_host = name
    for step in steps:
        if step.get("type") == "CNAME" and isinstance(step.get("value"), str):
            final_host = normalize_domain(step["value"])
        elif step.get("type") in {"A/AAAA", "IP"}:
            break
    return {
        "name": name,
        "cname": cname_vals,
        "a": a_vals,
        "aaaa": aaaa_vals,
        "resolves": resolves,
        "chain": steps,
        "final_host": final_host,
        "ips": chain.get("ips") or [],
    }


def _dns_srv(domain: str) -> dict[str, Any]:
    name = f"_autodiscover._tcp.{domain}"
    q = query_records(name, "SRV")
    records = []
    for r in q.get("records") or []:
        parsed = _parse_srv(r.get("data") or "")
        if parsed:
            parsed["ttl"] = r.get("ttl")
            records.append(parsed)
    records.sort(key=lambda x: (x.get("priority", 0), -x.get("weight", 0)))
    return {
        "name": name,
        "present": bool(records),
        "error": q.get("error") if not records else None,
        "records": records,
    }


def _build_probe_urls(domain: str, srv: dict[str, Any], host_dns: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()

    def add(u: str) -> None:
        u = u.rstrip("/")
        if u not in seen:
            seen.add(u)
            urls.append(u)

    if host_dns.get("resolves"):
        add(f"https://autodiscover.{domain}{UA_PATH}")
    add(f"https://{domain}{UA_PATH}")
    for rec in srv.get("records") or []:
        target = rec.get("target")
        port = int(rec.get("port") or 443)
        if not target:
            continue
        if port == 443:
            add(f"https://{target}{UA_PATH}")
        else:
            add(f"https://{target}:{port}{UA_PATH}")
    # If CNAME/A resolves to a different host, probe that hostname too
    final = host_dns.get("final_host")
    if (
        host_dns.get("resolves")
        and final
        and final not in {f"autodiscover.{domain}", domain}
        and not _looks_ip(final)
    ):
        add(f"https://{final}{UA_PATH}")
    return urls


def _looks_ip(value: str) -> bool:
    from .dns_common import is_ip

    return is_ip(value)


def check_autodiscover(query: str) -> dict[str, Any]:
    domain, primary = _parse_input(query)
    if not is_valid_domain(domain):
        return {"ok": False, "error": "Please enter a valid domain", "external_check": True}
    if primary and not is_valid_domain(primary):
        return {
            "ok": False,
            "error": "Primary domain looks invalid — use: domain / primary-domain",
            "external_check": True,
        }

    host_dns = _dns_autodiscover_host(domain)
    srv = _dns_srv(domain)

    primary_dns = None
    if primary:
        primary_dns = {
            "domain": primary,
            "autodiscover": _dns_autodiscover_host(primary),
            "srv": _dns_srv(primary),
        }

    probe_urls = _build_probe_urls(domain, srv, host_dns)
    probes: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(6, max(1, len(probe_urls)))) as pool:
        futs = {pool.submit(_probe_https, u): u for u in probe_urls}
        for fut in as_completed(futs):
            try:
                probes.append(fut.result())
            except Exception as exc:  # noqa: BLE001
                probes.append(
                    {
                        "url": futs[fut],
                        "reachable": False,
                        "exchange_like": False,
                        "status_code": None,
                        "error": str(exc),
                        "signals": [],
                    }
                )
    # Stable order matching probe_urls
    by_url = {p["url"]: p for p in probes}
    probes = [by_url[u] for u in probe_urls if u in by_url]

    # Legacy HTTP redirect method (Outlook still tries this)
    http_redirect = follow_redirect_chain(
        f"http://autodiscover.{domain}{UA_PATH}", max_hops=5, timeout=6.0
    )
    http_final = http_redirect.get("final_url") or ""
    http_https = http_final.lower().startswith("https://")
    http_useful = http_https and any(
        (h.get("status_code") or 0) in (301, 302, 303, 307, 308) for h in (http_redirect.get("hops") or [])
    )

    # Optional healthcheck on best Exchange-like host
    best = next((p for p in probes if p.get("exchange_like")), None) or next(
        (p for p in probes if p.get("reachable")), None
    )
    health = None
    if best and best.get("final_url"):
        parsed = urlparse(best["final_url"])
        if parsed.hostname:
            hc_url = f"https://{parsed.hostname}{HC_PATH}"
            hc = fetch_url(hc_url, follow_redirects=True, timeout=6.0, max_body=512)
            health = {
                "url": hc_url,
                "status_code": hc.get("status_code"),
                "ok": hc.get("status_code") == 200,
                "body_snippet": ((hc.get("body") or "")[:80]).strip(),
            }

    working_methods: list[str] = []
    if host_dns.get("resolves"):
        working_methods.append("autodiscover_dns")
    if srv.get("present"):
        working_methods.append("srv")
    if any(p.get("exchange_like") for p in probes):
        working_methods.append("https_endpoint")
    if http_useful:
        working_methods.append("http_redirect")

    # Where does discovery ultimately point?
    targets: list[str] = []
    for rec in srv.get("records") or []:
        if rec.get("target"):
            targets.append(rec["target"])
    for c in host_dns.get("cname") or []:
        targets.append(c)
    if host_dns.get("resolves") and host_dns.get("final_host"):
        targets.append(host_dns["final_host"])
    for p in probes:
        if p.get("exchange_like") and p.get("final_url"):
            host = urlparse(p["final_url"]).hostname
            if host:
                targets.append(normalize_domain(host))

    target_orgs = sorted({_org_of(t) for t in targets if t and not _looks_ip(t)})
    points_elsewhere = any(o != domain for o in target_orgs)
    matches_primary = bool(primary and any(o == primary or o.endswith("." + primary) for o in target_orgs))

    # Preferred method label
    if srv.get("present") and (not host_dns.get("resolves") or points_elsewhere):
        method = "srv"
    elif host_dns.get("cname"):
        method = "cname"
    elif host_dns.get("resolves"):
        method = "autodiscover_host"
    elif any(p.get("exchange_like") for p in probes):
        method = "https_only"
    elif http_useful:
        method = "http_redirect"
    else:
        method = "none"

    findings: list[dict[str, str]] = []
    score = 100

    if method == "none" and not working_methods:
        findings.append(
            {
                "severity": "critical",
                "title": "No Autodiscover discovery path found",
                "detail": (
                    f"No A/CNAME for autodiscover.{domain}, no SRV at "
                    f"_autodiscover._tcp.{domain}, and HTTPS endpoints did not look like Exchange."
                ),
            }
        )
        score -= 55
    else:
        if "https_endpoint" in working_methods:
            findings.append(
                {
                    "severity": "info",
                    "title": "HTTPS Autodiscover endpoint responds",
                    "detail": best["url"] if best else "Endpoint answered with Exchange-like signals (often HTTP 401).",
                }
            )
        if srv.get("present"):
            top = srv["records"][0]
            detail = f"{srv['name']} → {top['target']}:{top['port']} (prio {top['priority']})"
            if points_elsewhere:
                findings.append(
                    {
                        "severity": "info",
                        "title": "SRV points Autodiscover to another domain",
                        "detail": (
                            f"{detail}. Common for accepted/alias domains that share the primary "
                            f"org Autodiscover"
                            + (f" ({primary})." if matches_primary else ".")
                        ),
                    }
                )
            else:
                findings.append(
                    {
                        "severity": "info",
                        "title": "SRV Autodiscover record present",
                        "detail": detail,
                    }
                )
            if int(top.get("port") or 443) != 443:
                findings.append(
                    {
                        "severity": "medium",
                        "title": "SRV port is not 443",
                        "detail": f"Port {top.get('port')} — Outlook expects HTTPS on 443 in most deployments.",
                    }
                )
                score -= 10
        if host_dns.get("resolves"):
            cname = ", ".join(host_dns.get("cname") or []) or None
            ips = ", ".join(host_dns.get("ips") or host_dns.get("a") or []) or "—"
            findings.append(
                {
                    "severity": "info",
                    "title": f"autodiscover.{domain} resolves",
                    "detail": (f"CNAME → {cname}; " if cname else "") + f"IPs: {ips}",
                }
            )
        elif not srv.get("present"):
            findings.append(
                {
                    "severity": "high",
                    "title": f"autodiscover.{domain} does not resolve",
                    "detail": "No A/AAAA/CNAME. Without SRV, clients may fail Autodiscover for this domain.",
                }
            )
            score -= 25

        if points_elsewhere and not srv.get("present") and host_dns.get("cname"):
            findings.append(
                {
                    "severity": "info",
                    "title": "CNAME delegates Autodiscover to another host",
                    "detail": ", ".join(host_dns.get("cname") or []),
                }
            )

        if primary:
            if matches_primary:
                findings.append(
                    {
                        "severity": "info",
                        "title": "Aligned with primary domain",
                        "detail": f"Discovery targets look related to {primary}.",
                    }
                )
            elif points_elsewhere:
                findings.append(
                    {
                        "severity": "medium",
                        "title": "Does not clearly point at the stated primary",
                        "detail": f"Expected ties to {primary}; saw org hints: {', '.join(target_orgs) or '—'}.",
                    }
                )
                score -= 10
            elif primary_dns and not (primary_dns["autodiscover"].get("resolves") or primary_dns["srv"].get("present")):
                findings.append(
                    {
                        "severity": "medium",
                        "title": "Primary domain also lacks Autodiscover DNS",
                        "detail": f"Checked autodiscover.{primary} and _autodiscover._tcp.{primary}.",
                    }
                )
                score -= 10

        if http_useful and "https_endpoint" not in working_methods and not srv.get("present"):
            findings.append(
                {
                    "severity": "medium",
                    "title": "Only legacy HTTP redirect method found",
                    "detail": f"http://autodiscover.{domain}/… redirects to {http_final}. Prefer HTTPS DNS or SRV.",
                }
            )
            score -= 15
        elif http_useful:
            findings.append(
                {
                    "severity": "info",
                    "title": "HTTP redirect method also works",
                    "detail": f"→ {http_final}",
                }
            )

        if not any(p.get("exchange_like") for p in probes) and (host_dns.get("resolves") or srv.get("present")):
            findings.append(
                {
                    "severity": "high",
                    "title": "DNS present but HTTPS Autodiscover did not look healthy",
                    "detail": "Records exist, yet probes did not return Exchange-like auth/headers. Check firewall, TLS, or publishing.",
                }
            )
            score -= 20

    if health and health.get("ok"):
        findings.append(
            {
                "severity": "info",
                "title": "Autodiscover healthcheck reachable",
                "detail": health["url"],
            }
        )
    elif health and best and best.get("exchange_like"):
        findings.append(
            {
                "severity": "low",
                "title": "healthcheck.htm not publicly OK",
                "detail": f"{health['url']} → {health.get('status_code') or health.get('error') or '—'}",
            }
        )

    # DNS table for UI
    records: list[dict[str, str]] = []
    if host_dns.get("cname"):
        for c in host_dns["cname"]:
            records.append(
                {
                    "type": "CNAME",
                    "name": host_dns["name"],
                    "value": c,
                    "note": "Autodiscover hostname",
                }
            )
    for ip in host_dns.get("a") or []:
        records.append({"type": "A", "name": host_dns["name"], "value": ip, "note": ""})
    for ip in host_dns.get("aaaa") or []:
        records.append({"type": "AAAA", "name": host_dns["name"], "value": ip, "note": ""})
    if not host_dns.get("resolves"):
        records.append(
            {
                "type": "—",
                "name": host_dns["name"],
                "value": "(no A/AAAA/CNAME)",
                "note": host_dns.get("error") or "",
            }
        )
    if srv.get("present"):
        for rec in srv["records"]:
            records.append(
                {
                    "type": "SRV",
                    "name": srv["name"],
                    "value": rec.get("raw") or f"{rec['priority']} {rec['weight']} {rec['port']} {rec['target']}",
                    "note": "Outlook DNS SRV discovery",
                }
            )
    else:
        records.append(
            {
                "type": "SRV",
                "name": srv["name"],
                "value": "(not found)",
                "note": srv.get("error") or "NoAnswer/NXDOMAIN",
            }
        )

    summary_bits = []
    if method == "srv" and srv.get("records"):
        top = srv["records"][0]
        summary_bits.append(f"SRV → {top['target']}:{top['port']}")
    elif host_dns.get("cname"):
        summary_bits.append(f"CNAME → {host_dns['cname'][0]}")
    elif host_dns.get("resolves"):
        summary_bits.append(f"autodiscover.{domain} resolves")
    if points_elsewhere:
        summary_bits.append(f"delegates to {', '.join(target_orgs)}")
    summary = "; ".join(summary_bits) if summary_bits else "No working Autodiscover path"

    guidance = [
        "Outlook order (simplified, external): HTTPS autodiscover.<domain>, HTTPS <domain>, HTTP redirect, then SRV _autodiscover._tcp.<domain>.",
        "Accepted domains often skip a full Autodiscover site and only publish SRV (or CNAME) to the primary org Autodiscover host.",
        "Optional input: domain / primary — e.g. alias.example.com / example.com — to verify SRV/CNAME alignment.",
        "HTTP 401 on Autodiscover.xml is normal without credentials; it still means the endpoint is published.",
    ]

    score = max(0, min(100, score))
    return {
        "ok": True,
        "external_check": True,
        "domain": domain,
        "primary_hint": primary,
        "score": score,
        "method": method,
        "summary": summary,
        "title": f"Autodiscover for {domain}",
        "note": summary,
        "working_methods": working_methods,
        "discovery": {
            "points_elsewhere": points_elsewhere,
            "matches_primary": matches_primary,
            "target_orgs": target_orgs,
            "targets": sorted(set(targets)),
        },
        "dns": {"autodiscover": host_dns, "srv": srv, "primary": primary_dns},
        "records": records,
        "probes": probes,
        "http_redirect": {
            "used": http_useful,
            "final_url": http_final,
            "hops": http_redirect.get("hops") or [],
        },
        "healthcheck": health,
        "findings": findings,
        "guidance": guidance,
        "mode": "external_only",
    }
