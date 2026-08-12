"""tools.birolbenli.com — DNS, email & SSL lookup tools."""

from __future__ import annotations

import logging
import os
import threading
from urllib.parse import unquote

from flask import Flask, Response, g, jsonify, redirect, render_template, request

from i18n import COOKIE as LANG_COOKIE
from i18n import SUPPORTED as LANG_SUPPORTED
from i18n import _, get_lang, init_babel, js_bundle, localize_tools
from tools.admin_auth import (
    begin_setup,
    change_password,
    confirm_authenticator,
    confirm_setup,
    flask_secret_key,
    is_setup_complete,
    login as admin_password_login,
    login_otp,
    password_configured,
    profile_info,
    reset_authenticator,
    update_username,
    validate_preauth,
    validate_session,
)
from tools.admin_store import (
    add_ip,
    cleanup_old_logs,
    country_visit_stats,
    init_admin_store,
    is_blacklisted,
    list_ips,
    log_query,
    log_visit,
    overview_stats,
    recent_queries,
    recent_visits,
    remove_ip,
    tool_stats,
    top_ips,
    top_visitors,
)
from tools.blacklist import check_blacklist
from tools.dkim import lookup_dkim
from tools.dmarc import lookup_dmarc
from tools.dns_lookup import SUPPORTED_TYPES, lookup_caa, lookup_dns, lookup_ns
from tools.email_analyze import analyze_email
from tools.exchange_check import check_exchange
from tools.autodiscover_check import check_autodiscover
from tools.feedback import (
    delete_feedback,
    feedback_unread_count,
    get_feedback,
    init_feedback,
    list_feedback,
    mark_feedback_read,
    submit_feedback,
)
from tools.system_stats import start_metrics_sampler, system_snapshot
from tools.http_check import check_http
from tools.ip_info import client_ip_from_request, lookup_ip_info
from tools.mail_store import create_test, get_test, init_mail_store, list_tests
from tools.mx import lookup_mx
from tools.port_check import check_port
from tools.rdns import lookup_rdns
from tools.smtp_receiver import start_smtp_receiver
from tools.smtp_test import test_smtp
from tools.spf import lookup_spf
from tools.ssl_check import check_bulk
from tools.mtasts import check_mtasts
from tools.tlsrpt import check_tlsrpt
from tools.bimi import check_bimi
from tools.dane import check_dane
from tools.soa_check import check_soa
from tools.cname_check import check_cname
from tools.security_txt import check_security_txt
from tools.hsts_check import check_hsts
from tools.robots_check import check_robots
from tools.redirect_check import check_redirects
from tools.sec_headers import check_sec_headers
from tools.generators import (
    generate_caa,
    generate_dmarc,
    generate_mtasts,
    generate_security_txt,
    generate_spf,
    generate_tlsrpt,
)
from tools.concurrency import HEAVY_SLUGS, release_heavy, try_acquire_heavy
from tools.rate_limit import (
    BUCKET_MAILTEST,
    BUCKET_TOOLS,
    consume as consume_rate,
    init_rate_limit,
    limit_for as rate_limit_for,
    peek as peek_rate,
    tool_bucket,
)
from tools.stats import bump, get_counts, init_stats, total_count
from tools.visitors import get_country_counts, init_visitors, track_visitor, visitor_total
from tools.whois_lookup import lookup_whois

logging.basicConfig(level=logging.INFO)

ADMIN_COOKIE = "admin_session"
ADMIN_PREAUTH_COOKIE = "admin_preauth"

app = Flask(__name__)
app.secret_key = flask_secret_key()
app.config["BUYMEACOFFEE_URL"] = os.environ.get(
    "BUYMEACOFFEE_URL", "https://buymeacoffee.com/birolbenli"
)
app.config["LINKEDIN_URL"] = os.environ.get(
    "LINKEDIN_URL", "https://tr.linkedin.com/in/birolbenli"
)
app.config["MAILTEST_DOMAIN"] = os.environ.get(
    "MAILTEST_DOMAIN", "tools.birolbenli.com"
)
init_babel(app)

TOOLS = [
    {
        "slug": "mx",
        "name": "MX Lookup",
        "desc": "Find mail exchangers and resolve their IPs.",
        "field": "domain",
        "placeholder": "example.com",
        "example": "gmail.com",
        "input": "text",
    },
    {
        "slug": "spf",
        "name": "SPF Lookup",
        "desc": "Inspect SPF records and included policies.",
        "field": "domain",
        "placeholder": "example.com",
        "example": "google.com",
        "input": "text",
    },
    {
        "slug": "dkim",
        "name": "DKIM Lookup",
        "desc": "Detect common DKIM selectors and follow host chains.",
        "field": "domain",
        "placeholder": "example.com",
        "example": "github.com",
        "input": "text",
    },
    {
        "slug": "dmarc",
        "name": "DMARC Lookup",
        "desc": "Check DMARC policy, rua/ruf and alignment tags.",
        "field": "domain",
        "placeholder": "example.com",
        "example": "microsoft.com",
        "input": "text",
    },
    {
        "slug": "headers",
        "name": "Email Header Analyzer",
        "desc": "Paste raw headers/source and get a clear, educational report.",
        "field": "raw",
        "placeholder": "Paste full email source or headers here…",
        "example": "",
        "input": "special",
        "template": "headers.html",
    },
    {
        "slug": "mailtest",
        "name": "Mail Tester",
        "desc": "Get a random inbox, send a message, and see a deliverability score.",
        "field": "id",
        "placeholder": "",
        "example": "",
        "input": "special",
        "template": "mailtest.html",
        "optional": True,
    },
    {
        "slug": "dns",
        "name": "DNS Lookup",
        "desc": "Query A, AAAA, CNAME, NS, TXT, SOA, CAA, MX and SRV.",
        "field": "domain",
        "placeholder": "example.com",
        "example": "cloudflare.com",
        "input": "text",
        "extra": "type",
    },
    {
        "slug": "ns",
        "name": "NS Lookup",
        "desc": "List authoritative nameservers for a domain.",
        "field": "domain",
        "placeholder": "example.com",
        "example": "wikipedia.org",
        "input": "text",
    },
    {
        "slug": "caa",
        "name": "CAA Lookup",
        "desc": "See which CAs are allowed to issue certificates.",
        "field": "domain",
        "placeholder": "example.com",
        "example": "google.com",
        "input": "text",
    },
    {
        "slug": "whois",
        "name": "WHOIS",
        "desc": "Query domain or IP registration data.",
        "field": "query",
        "placeholder": "example.com",
        "example": "github.com",
        "input": "text",
    },
    {
        "slug": "ssl",
        "name": "SSL Checker",
        "desc": "Check up to 10 certificates at once in a table.",
        "field": "domains",
        "placeholder": "example.com\nexample.org:8443",
        "example": "google.com,github.com",
        "input": "textarea",
    },
    {
        "slug": "http",
        "name": "Raw HTTP Headers",
        "desc": "Fetch status code and all response headers (unscored).",
        "field": "url",
        "placeholder": "https://example.com",
        "example": "https://example.com",
        "input": "text",
    },
    {
        "slug": "port",
        "name": "Port Check",
        "desc": "Test if a TCP port is open on a host.",
        "field": "target",
        "placeholder": "example.com:443",
        "example": "1.1.1.1:443",
        "input": "text",
    },
    {
        "slug": "rdns",
        "name": "Reverse DNS",
        "desc": "Resolve PTR records for an IP address.",
        "field": "ip",
        "placeholder": "8.8.8.8",
        "example": "1.1.1.1",
        "input": "text",
    },
    {
        "slug": "blacklist",
        "name": "Blacklist Check",
        "desc": "Check an IP against common DNSBL / RBL lists.",
        "field": "target",
        "placeholder": "1.2.3.4 or mail.example.com",
        "example": "8.8.8.8",
        "input": "text",
    },
    {
        "slug": "smtp",
        "name": "SMTP Test",
        "desc": "Test SMTP banner, EHLO and STARTTLS on port 25.",
        "field": "host",
        "placeholder": "mx.example.com",
        "example": "gmail-smtp-in.l.google.com",
        "input": "text",
    },
    {
        "slug": "exchange",
        "name": "Microsoft Exchange Server HC",
        "desc": "External-only Exchange security assessment: TLS, auth, VDirs, SMTP, mail domain, hybrid signals.",
        "field": "host",
        "placeholder": "mail.example.com",
        "example": "outlook.office365.com",
        "input": "text",
    },
    {
        "slug": "autodiscover",
        "name": "Exchange Autodiscover",
        "desc": "Check Autodiscover DNS (A/CNAME + SRV) and HTTPS endpoints — including accepted domains that SRV to a primary org.",
        "field": "domain",
        "placeholder": "btcturkhisse.com / btcturk.com",
        "example": "btcturkhisse.com/btcturk.com",
        "input": "text",
    },
    {
        "slug": "ip",
        "name": "IP Lookup",
        "desc": "See your public IP (curl-friendly) or inspect another IP.",
        "field": "ip",
        "placeholder": "leave empty for your IP",
        "example": "",
        "input": "text",
        "optional": True,
    },
    # Wave-1 expansion (external-only)
    {
        "slug": "mtasts",
        "name": "MTA-STS Checker",
        "desc": "Check _mta-sts DNS and the HTTPS policy file (mode, max_age, mx).",
        "field": "domain",
        "placeholder": "example.com",
        "example": "google.com",
        "input": "text",
    },
    {
        "slug": "tlsrpt",
        "name": "TLS-RPT Checker",
        "desc": "Validate _smtp._tls reporting records and rua destinations.",
        "field": "domain",
        "placeholder": "example.com",
        "example": "google.com",
        "input": "text",
    },
    {
        "slug": "bimi",
        "name": "BIMI Checker",
        "desc": "Inspect default._bimi TXT, logo URL reachability, and VMC hints.",
        "field": "domain",
        "placeholder": "example.com",
        "example": "paypal.com",
        "input": "text",
    },
    {
        "slug": "dane",
        "name": "DANE / TLSA Checker",
        "desc": "List public TLSA records for MX hosts (external DNS only).",
        "field": "domain",
        "placeholder": "example.com",
        "example": "nic.cz",
        "input": "text",
    },
    {
        "slug": "soa",
        "name": "SOA Checker",
        "desc": "Parse SOA serial, refresh, retry, expire, and minimum TTL.",
        "field": "domain",
        "placeholder": "example.com",
        "example": "cloudflare.com",
        "input": "text",
    },
    {
        "slug": "cname",
        "name": "CNAME Checker",
        "desc": "Follow CNAME chains to the final destination and detect loops.",
        "field": "domain",
        "placeholder": "www.example.com",
        "example": "www.github.com",
        "input": "text",
    },
    {
        "slug": "securitytxt",
        "name": "security.txt Checker",
        "desc": "Fetch /.well-known/security.txt and validate Contact / Expires fields.",
        "field": "domain",
        "placeholder": "example.com",
        "example": "google.com",
        "input": "text",
    },
    {
        "slug": "hsts",
        "name": "HSTS Checker",
        "desc": "Inspect Strict-Transport-Security max-age, includeSubDomains, preload.",
        "field": "url",
        "placeholder": "https://example.com",
        "example": "https://example.com",
        "input": "text",
    },
    {
        "slug": "robots",
        "name": "robots.txt Checker",
        "desc": "Fetch robots.txt and summarize User-agent and Sitemap lines.",
        "field": "domain",
        "placeholder": "example.com",
        "example": "example.com",
        "input": "text",
    },
    {
        "slug": "redirect",
        "name": "Redirect Checker",
        "desc": "Trace HTTP redirect chains (301/302/307/308) to the final URL.",
        "field": "url",
        "placeholder": "http://example.com",
        "example": "http://github.com",
        "input": "text",
    },
    {
        "slug": "secheaders",
        "name": "HTTP Security Headers",
        "desc": "Score HSTS, CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP.",
        "field": "url",
        "placeholder": "https://example.com",
        "example": "https://example.com",
        "input": "text",
    },
    {
        "slug": "spfgen",
        "name": "Create SPF record",
        "desc": "Build a starter SPF TXT to publish — not a live lookup.",
        "field": "domain",
        "placeholder": "example.com",
        "example": "example.com",
        "input": "text",
        "button": "Generate",
        "badge": "Generator",
    },
    {
        "slug": "dmarcgen",
        "name": "Create DMARC record",
        "desc": "Build a starter _dmarc policy — not a live lookup.",
        "field": "domain",
        "placeholder": "example.com",
        "example": "example.com",
        "input": "text",
        "button": "Generate",
        "badge": "Generator",
    },
    {
        "slug": "mtastsgen",
        "name": "Create MTA-STS policy",
        "desc": "Build starter DNS + policy file text — not a live check.",
        "field": "domain",
        "placeholder": "example.com",
        "example": "example.com",
        "input": "text",
        "button": "Generate",
        "badge": "Generator",
    },
    {
        "slug": "tlsrptgen",
        "name": "Create TLS-RPT record",
        "desc": "Build a starter _smtp._tls record — not a live check.",
        "field": "domain",
        "placeholder": "example.com",
        "example": "example.com",
        "input": "text",
        "button": "Generate",
        "badge": "Generator",
    },
    {
        "slug": "caagen",
        "name": "Create CAA records",
        "desc": "Build starter CAA issue/iodef records — not a live lookup.",
        "field": "domain",
        "placeholder": "example.com",
        "example": "example.com",
        "input": "text",
        "button": "Generate",
        "badge": "Generator",
    },
    {
        "slug": "securitytxtgen",
        "name": "Create security.txt",
        "desc": "Build RFC 9116 security.txt text — not a live fetch.",
        "field": "domain",
        "placeholder": "example.com",
        "example": "example.com",
        "input": "text",
        "button": "Generate",
        "badge": "Generator",
    },
]

# Homepage sections — featured first, then thematic groups.
HOMEPAGE_GROUPS = [
    {
        "id": "featured",
        "featured": True,
        "title": "Featured tools",
        "blurb": "Exchange exposure, deliverability, security headers, and bulk SSL — start here.",
        "slugs": ["exchange", "mailtest", "secheaders", "ssl", "headers", "mtasts"],
    },
    {
        "id": "domain-security",
        "featured": False,
        "title": "Domain security",
        "blurb": "Public security.txt and related domain-facing checks.",
        # Featured tools are listed once above; omit them from later groups.
        "slugs": ["securitytxt", "whois"],
    },
    {
        "id": "email-auth",
        "featured": False,
        "title": "Email authentication",
        "blurb": "SPF, DKIM, DMARC, TLS-RPT, BIMI, and DANE/TLSA.",
        "slugs": ["mx", "spf", "dkim", "dmarc", "tlsrpt", "bimi", "dane"],
    },
    {
        "id": "smtp-mail",
        "featured": False,
        "title": "SMTP & mail server",
        "blurb": "Live SMTP probes and blacklist checks.",
        "slugs": ["smtp", "blacklist"],
    },
    {
        "id": "exchange",
        "featured": False,
        "title": "Microsoft Exchange",
        "blurb": "External-only Exchange health, Autodiscover, endpoints, TLS, and hybrid signals.",
        "slugs": ["autodiscover"],
    },
    {
        "id": "dns",
        "featured": False,
        "title": "DNS & domain",
        "blurb": "Records, nameservers, SOA, CNAME chains, CAA, and reverse DNS.",
        "slugs": ["dns", "ns", "soa", "cname", "caa", "rdns"],
    },
    {
        "id": "ssl-tls",
        "featured": False,
        "title": "SSL / TLS",
        "blurb": "HSTS and related TLS surface checks.",
        "slugs": ["hsts"],
    },
    {
        "id": "web-security",
        "featured": False,
        "title": "Web security",
        "blurb": "Redirects, robots.txt, and raw HTTP headers.",
        "slugs": ["redirect", "robots", "http"],
    },
    {
        "id": "network",
        "featured": False,
        "title": "IP & network",
        "blurb": "Ports and public IP identity.",
        "slugs": ["port", "ip"],
    },
    {
        "id": "generators",
        "featured": False,
        "title": "Generator tools",
        "blurb": "Starter records and files — review before publishing.",
        "slugs": ["spfgen", "dmarcgen", "mtastsgen", "tlsrptgen", "caagen", "securitytxtgen"],
    },
]


def homepage_tool_groups(tools_list: list[dict]) -> list[dict]:
    by_slug = {t["slug"]: t for t in tools_list}
    used: set[str] = set()
    groups: list[dict] = []
    for g in HOMEPAGE_GROUPS:
        items = []
        for slug in g["slugs"]:
            if slug in used:
                continue
            tool = by_slug.get(slug)
            if not tool:
                continue
            items.append(tool)
            used.add(slug)
        if items:
            groups.append(
                {
                    "id": g["id"],
                    "featured": bool(g.get("featured")),
                    "title": _(g["title"]),
                    "blurb": _(g["blurb"]) if g.get("blurb") else "",
                    "tools": items,
                }
            )
    leftover = [t for t in tools_list if t["slug"] not in used]
    if leftover:
        groups.append(
            {
                "id": "more",
                "featured": False,
                "title": _("More tools"),
                "blurb": "",
                "tools": leftover,
            }
        )
    return groups


def get_tool(slug: str) -> dict | None:
    return next((t for t in TOOLS if t["slug"] == slug), None)


def _is_https_request() -> bool:
    if request.is_secure:
        return True
    proto = (request.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
    return proto == "https"


def _blacklist_redirect():
    """Send blocked clients away — do not serve any site content."""
    return redirect("https://www.google.com/", code=302)


@app.before_request
def _ensure_runtime():
    g.set_lang_cookie = (request.args.get("lang") or "").lower() in LANG_SUPPORTED
    init_stats()
    init_mail_store()
    init_feedback()
    init_visitors()
    init_rate_limit()
    init_admin_store()

    path = request.path or "/"
    ip = client_ip_from_request(request)
    remote = (request.remote_addr or "").strip()

    # Local healthchecks stay on HTTP (Docker / Apache probes).
    local_health = path == "/health" and remote in {"127.0.0.1", "::1"}

    # Blacklisted IPs never see the site (admin/static included).
    if not local_health and is_blacklisted(ip):
        return _blacklist_redirect()

    # Force HTTPS (behind reverse proxy via X-Forwarded-Proto).
    force_https = os.environ.get("FORCE_HTTPS", "1").strip() not in {"0", "false", "no"}
    if force_https and not local_health and not _is_https_request():
        https_url = request.url.replace("http://", "https://", 1)
        return redirect(https_url, code=301)

    return None


def _should_track_visitor() -> bool:
    if request.method != "GET":
        return False
    path = request.path or "/"
    if path.startswith("/static") or path.startswith("/api/") or path == "/health":
        return False
    if path.startswith("/admin"):
        return False
    if path.endswith(".json"):
        return False
    if wants_plain():
        return False
    return True


def _log_visit_bg(ip: str, path: str, ua: str) -> None:
    try:
        track_visitor(ip)
        from tools.ip_info import lookup_geo

        geo = lookup_geo(ip) if ip else {}
        log_visit(
            ip=ip,
            path=path,
            user_agent=ua,
            country_code=(geo.get("country_code") or "") if geo.get("ok") else "",
            country_name=(geo.get("country") or "") if geo.get("ok") else "",
            city=(geo.get("city") or "") if geo.get("ok") else "",
            isp=(geo.get("isp") or geo.get("org") or "") if geo.get("ok") else "",
        )
    except Exception:  # noqa: BLE001
        logging.exception("visit log failed")


@app.after_request
def _after_request(response):
    if getattr(g, "set_lang_cookie", False):
        response.set_cookie(
            LANG_COOKIE,
            get_lang(),
            max_age=60 * 60 * 24 * 365,
            samesite="Lax",
        )
    ctype = (response.content_type or "").lower()
    if "text/html" in ctype:
        # Avoid stale homepage/tool lists after deploys
        response.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
        response.headers["Pragma"] = "no-cache"
    if _should_track_visitor() and "text/html" in ctype and response.status_code < 400:
        ip = client_ip_from_request(request)
        ua = request.headers.get("User-Agent", "")
        path = request.path or "/"
        threading.Thread(
            target=_log_visit_bg, args=(ip, path, ua), daemon=True
        ).start()
    return response


@app.context_processor
def inject_globals():
    tools = localize_tools(TOOLS)
    return {
        "_": _,
        "tools": tools,
        "buymeacoffee_url": app.config["BUYMEACOFFEE_URL"],
        "linkedin_url": app.config["LINKEDIN_URL"],
        "site_name": "tools.birolbenli.com",
        "total_queries": total_count(),
        "dns_types": SUPPORTED_TYPES,
        "mailtest_domain": app.config["MAILTEST_DOMAIN"],
        "visitor_ip": client_ip_from_request(request),
        "lang": get_lang(),
        "js_i18n": js_bundle(),
        "rate_limit_mailtest": rate_limit_for(BUCKET_MAILTEST),
        "rate_limit_tools": rate_limit_for(BUCKET_TOOLS),
    }


def _rate_limit_response(info: dict, as_json: bool = True):
    headers = {
        "X-RateLimit-Limit": str(info.get("limit", 0)),
        "X-RateLimit-Remaining": str(info.get("remaining", 0)),
        "X-RateLimit-Reset": str(info.get("reset_at") or ""),
    }
    limit = info.get("limit") or 0
    bucket = info.get("bucket") or ""
    tool_name = None
    if bucket == BUCKET_MAILTEST:
        error = _(
            "Daily Mail Tester limit reached ({limit}/day per IP). Try again after UTC midnight.",
            limit=limit,
        )
    elif isinstance(bucket, str) and bucket.startswith("tool:"):
        slug = bucket.split(":", 1)[1]
        tool = get_tool(slug)
        tool_name = (tool or {}).get("name") or slug
        error = _(
            "Daily {tool} limit reached ({limit}/day per IP). Try again after UTC midnight.",
            tool=tool_name,
            limit=limit,
        )
    else:
        error = _(
            "Daily tool limit reached ({limit}/day per IP). Try again after UTC midnight.",
            limit=limit,
        )
    payload = {
        "ok": False,
        "error": error,
        "code": "rate_limited",
        "limit": info.get("limit"),
        "used": info.get("used"),
        "remaining": info.get("remaining"),
        "reset_at": info.get("reset_at"),
        "bucket": info.get("bucket"),
        "tool": tool_name,
    }
    if as_json:
        return jsonify(payload), 429, headers
    return Response(error + "\n", status=429, mimetype="text/plain", headers=headers)


def _consume_or_reject(bucket: str, as_json: bool = True):
    ip = client_ip_from_request(request)
    info = consume_rate(ip, bucket)
    if not info.get("allowed"):
        return _rate_limit_response(info, as_json=as_json)
    return None


def wants_plain() -> bool:
    ua = (request.headers.get("User-Agent") or "").lower()
    accept = (request.headers.get("Accept") or "").lower()
    if request.args.get("format") == "text":
        return True
    if "curl/" in ua or "wget/" in ua or "httpie" in ua:
        return True
    if "application/json" in accept:
        return False
    if "text/plain" in accept and "text/html" not in accept:
        return True
    return False


def run_tool(slug: str, query: str = "", extra: dict | None = None) -> dict:
    extra = extra or {}
    query = unquote((query or "").strip())
    tool = get_tool(slug)
    if not tool:
        return {"ok": False, "error": "Unknown tool"}

    if slug == "mx":
        result = lookup_mx(query)
    elif slug == "spf":
        result = lookup_spf(query)
    elif slug == "dkim":
        result = lookup_dkim(query)
    elif slug == "dmarc":
        result = lookup_dmarc(query)
    elif slug == "headers":
        result = analyze_email(query, mode="headers")
    elif slug == "dns":
        result = lookup_dns(query, extra.get("type") or request.args.get("type") or "A")
    elif slug == "ns":
        result = lookup_ns(query)
    elif slug == "caa":
        result = lookup_caa(query)
    elif slug == "whois":
        result = lookup_whois(query)
    elif slug == "ssl":
        domains = query.replace(",", "\n")
        result = check_bulk(domains, max_domains=10)
    elif slug == "http":
        result = check_http(query)
    elif slug == "port":
        result = check_port(query)
    elif slug == "rdns":
        result = lookup_rdns(query)
    elif slug == "blacklist":
        result = check_blacklist(query)
    elif slug == "smtp":
        result = test_smtp(query)
    elif slug == "exchange":
        result = check_exchange(query)
    elif slug == "autodiscover":
        result = check_autodiscover(query)
    elif slug == "ip":
        result = lookup_ip_info(query, request=request)
    elif slug == "mtasts":
        result = check_mtasts(query)
    elif slug == "tlsrpt":
        result = check_tlsrpt(query)
    elif slug == "bimi":
        result = check_bimi(query)
    elif slug == "dane":
        result = check_dane(query)
    elif slug == "soa":
        result = check_soa(query)
    elif slug == "cname":
        result = check_cname(query)
    elif slug == "securitytxt":
        result = check_security_txt(query)
    elif slug == "hsts":
        result = check_hsts(query)
    elif slug == "robots":
        result = check_robots(query)
    elif slug == "redirect":
        result = check_redirects(query)
    elif slug == "secheaders":
        result = check_sec_headers(query)
    elif slug == "spfgen":
        result = generate_spf(query)
    elif slug == "dmarcgen":
        result = generate_dmarc(query)
    elif slug == "mtastsgen":
        result = generate_mtasts(query)
    elif slug == "tlsrptgen":
        result = generate_tlsrpt(query)
    elif slug == "caagen":
        result = generate_caa(query)
    elif slug == "securitytxtgen":
        result = generate_security_txt(query)
    else:
        result = {"ok": False, "error": "Unknown tool"}

    bump(slug)
    try:
        log_query(
            ip=client_ip_from_request(request),
            tool=slug,
            query=query,
            ok=bool(result.get("ok", True)) if isinstance(result, dict) else True,
            user_agent=request.headers.get("User-Agent", ""),
        )
    except Exception:  # noqa: BLE001
        logging.exception("query log failed")
    return result


def _admin_authed() -> bool:
    return validate_session(request.cookies.get(ADMIN_COOKIE))


def _require_admin():
    if not _admin_authed():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    return None


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "tools.birolbenli.com"})


@app.get("/")
def index():
    return render_template("index.html", tool_groups=homepage_tool_groups(localize_tools(TOOLS)))


@app.get("/api/visitors/geo")
def api_visitors_geo():
    countries = get_country_counts()
    return jsonify(
        {
            "ok": True,
            "total": visitor_total(),
            "queries": total_count(),
            "countries": countries,
        }
    )


@app.get("/about")
def about():
    return render_template("about.html", counts=get_counts())


@app.get("/privacy")
def privacy():
    return render_template("privacy.html")


@app.get("/feedback")
@app.get("/report")
def feedback_page():
    from tools.feedback_dkim import ensure_dkim_keys

    ensure_dkim_keys()
    return render_template("feedback.html")


@app.post("/api/feedback")
def api_feedback():
    data = request.get_json(silent=True) or {}
    result = submit_feedback(
        kind=data.get("kind") or request.form.get("kind", ""),
        title=data.get("title") or request.form.get("title", ""),
        message=data.get("message") or request.form.get("message", ""),
        contact_email=data.get("contact_email") or request.form.get("contact_email", ""),
        page_url=data.get("page_url") or request.form.get("page_url", ""),
        honeypot=data.get("website") or request.form.get("website", ""),
        ip=client_ip_from_request(request),
        user_agent=request.headers.get("User-Agent", ""),
    )
    if result.get("ok"):
        bump("feedback")
    status = 200 if result.get("ok") else 400
    return jsonify(result), status


@app.get("/ip")
@app.get("/ip/")
def my_ip_plain():
    ip = client_ip_from_request(request)
    bump("ip")
    if request.args.get("format") == "json" or request.path.endswith(".json"):
        return jsonify(lookup_ip_info(ip, request=request))
    return Response(ip + "\n", mimetype="text/plain")


@app.get("/ip.json")
def my_ip_json():
    ip = client_ip_from_request(request)
    bump("ip")
    return jsonify(lookup_ip_info(ip, request=request))


@app.get("/ua")
def my_ua():
    ua = request.headers.get("User-Agent", "")
    bump("ip")
    return Response(ua + "\n", mimetype="text/plain")


@app.get("/tools/<slug>")
@app.get("/tools/<slug>/<path:query>")
def tool_page(slug: str, query: str | None = None):
    tool = get_tool(slug)
    if not tool:
        return render_template("404.html"), 404

    query = unquote(query) if query else ""
    dns_type = request.args.get("type", "A")

    if query and wants_plain() and slug in {"ip", "rdns"}:
        blocked = _consume_or_reject(tool_bucket(slug), as_json=False)
        if blocked:
            return blocked
        result = run_tool(slug, query)
        if slug == "ip":
            return Response((result.get("ip") or "") + "\n", mimetype="text/plain")
        hosts = result.get("hosts") or []
        return Response("\n".join(hosts) + ("\n" if hosts else ""), mimetype="text/plain")

    if query and request.args.get("format") == "json" and slug not in {"mailtest"}:
        blocked = _consume_or_reject(tool_bucket(slug), as_json=True)
        if blocked:
            return blocked
        held = try_acquire_heavy(slug)
        if slug in HEAVY_SLUGS and not held:
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": _(
                            "Server is busy with other external checks. Please try again in a moment."
                        ),
                        "code": "busy",
                    }
                ),
                503,
            )
        try:
            return jsonify(run_tool(slug, query, {"type": dns_type}))
        finally:
            if held:
                release_heavy()

    template = tool.get("template") or "tool.html"
    localized = next((t for t in localize_tools(TOOLS) if t["slug"] == slug), tool)
    return render_template(
        template,
        tool=localized,
        auto_query=query,
        dns_type=dns_type,
        test_id=query if slug == "mailtest" else "",
    )


@app.post("/api/<slug>")
def api_tool(slug: str):
    tool = get_tool(slug)
    if not tool:
        return jsonify({"ok": False, "error": "Unknown tool"}), 404

    if slug == "mailtest":
        return jsonify({"ok": False, "error": "Use /api/mailtest/create"}), 400

    data = request.get_json(silent=True) or {}
    field = tool["field"]
    query = data.get(field)
    if query is None:
        query = data.get("query") or data.get("domain") or data.get("host") or data.get("raw") or ""
    if isinstance(query, list):
        query = "\n".join(str(x) for x in query)

    if not str(query).strip() and not tool.get("optional"):
        return jsonify({"ok": False, "error": "Missing query"}), 400

    blocked = _consume_or_reject(tool_bucket(slug), as_json=True)
    if blocked:
        return blocked

    held = try_acquire_heavy(slug)
    if slug in HEAVY_SLUGS and not held:
        return (
            jsonify(
                {
                    "ok": False,
                    "error": _(
                        "Server is busy with other external checks. Please try again in a moment."
                    ),
                    "code": "busy",
                }
            ),
            503,
        )

    extra = {"type": data.get("type") or "A"}
    try:
        return jsonify(run_tool(slug, str(query), extra))
    finally:
        if held:
            release_heavy()


@app.post("/api/mailtest/create")
def api_mailtest_create():
    blocked = _consume_or_reject(BUCKET_MAILTEST, as_json=True)
    if blocked:
        return blocked
    domain = app.config["MAILTEST_DOMAIN"]
    result = create_test(domain)
    bump("mailtest")
    if isinstance(result, dict):
        usage = peek_rate(client_ip_from_request(request), BUCKET_MAILTEST)
        result["rate_limit"] = {
            "limit": usage.get("limit"),
            "used": usage.get("used"),
            "remaining": usage.get("remaining"),
            "reset_at": usage.get("reset_at"),
        }
        try:
            log_query(
                ip=client_ip_from_request(request),
                tool="mailtest",
                query=result.get("address") or "create",
                ok=True,
                user_agent=request.headers.get("User-Agent", ""),
            )
        except Exception:  # noqa: BLE001
            logging.exception("mailtest log failed")
    return jsonify(result)


def _set_admin_cookie(resp, token: str, *, preauth: bool = False):
    name = ADMIN_PREAUTH_COOKIE if preauth else ADMIN_COOKIE
    max_age = 60 * 15 if preauth else 60 * 60 * 12
    resp.set_cookie(
        name,
        token,
        httponly=True,
        samesite="Lax",
        secure=_is_https_request(),
        max_age=max_age,
    )
    return resp


def _clear_preauth(resp):
    resp.delete_cookie(ADMIN_PREAUTH_COOKIE)
    return resp


def _require_preauth():
    if not validate_preauth(request.cookies.get(ADMIN_PREAUTH_COOKIE)):
        return jsonify({"ok": False, "error": "Login with username/password first"}), 401
    return None


@app.get("/admin")
@app.get("/admin/")
def admin_page():
    return render_template(
        "admin.html",
        setup_complete=is_setup_complete(),
        password_configured=password_configured(),
        site_name="tools.birolbenli.com",
    )


@app.post("/admin/api/login")
def admin_login():
    data = request.get_json(silent=True) or {}
    result = admin_password_login(
        data.get("username") or "",
        data.get("password") or "",
        data.get("otp") or "",
    )
    if not result.get("ok"):
        return jsonify(result), 401

    if result.get("need_setup"):
        resp = jsonify(
            {
                "ok": True,
                "need_setup": True,
                "setup": result.get("setup"),
            }
        )
        _set_admin_cookie(resp, result["preauth"], preauth=True)
        return resp

    if result.get("need_otp"):
        resp = jsonify({"ok": True, "need_otp": True})
        _set_admin_cookie(resp, result["preauth"], preauth=True)
        return resp

    resp = jsonify({"ok": True})
    _clear_preauth(resp)
    _set_admin_cookie(resp, result["token"], preauth=False)
    return resp


@app.post("/admin/api/login/otp")
def admin_login_otp():
    denied = _require_preauth()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    result = login_otp(data.get("otp") or "")
    if not result.get("ok"):
        return jsonify(result), 401
    resp = jsonify({"ok": True})
    _clear_preauth(resp)
    _set_admin_cookie(resp, result["token"], preauth=False)
    return resp


@app.get("/admin/api/setup")
def admin_setup_info():
    denied = _require_preauth()
    if denied:
        return denied
    if is_setup_complete():
        return jsonify({"ok": False, "error": "Already configured"}), 400
    return jsonify(begin_setup())


@app.post("/admin/api/setup/confirm")
def admin_setup_confirm():
    denied = _require_preauth()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    result = confirm_setup(data.get("code") or "")
    if not result.get("ok"):
        return jsonify(result), 400
    resp = jsonify({"ok": True})
    _clear_preauth(resp)
    _set_admin_cookie(resp, result["token"], preauth=False)
    return resp


@app.post("/admin/api/logout")
def admin_logout():
    resp = jsonify({"ok": True})
    resp.delete_cookie(ADMIN_COOKIE)
    resp.delete_cookie(ADMIN_PREAUTH_COOKIE)
    return resp


@app.get("/admin/api/profile")
def admin_profile_get():
    denied = _require_admin()
    if denied:
        return denied
    return jsonify(profile_info())


@app.post("/admin/api/profile/username")
def admin_profile_username():
    denied = _require_admin()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    result = update_username(
        data.get("username") or "",
        data.get("current_password") or "",
    )
    if not result.get("ok"):
        return jsonify(result), 400
    return jsonify(result)


@app.post("/admin/api/profile/password")
def admin_profile_password():
    denied = _require_admin()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    new_password = data.get("new_password") or ""
    confirm = data.get("confirm_password") or ""
    if new_password != confirm:
        return jsonify({"ok": False, "error": "Password confirmation does not match"}), 400
    result = change_password(
        data.get("current_password") or "",
        new_password,
        data.get("otp") or "",
    )
    if not result.get("ok"):
        return jsonify(result), 400
    return jsonify(result)


@app.post("/admin/api/profile/totp/reset")
def admin_profile_totp_reset():
    denied = _require_admin()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    result = reset_authenticator(
        data.get("current_password") or "",
        data.get("otp") or "",
    )
    if not result.get("ok"):
        return jsonify(result), 400
    return jsonify(result)


@app.post("/admin/api/profile/totp/confirm")
def admin_profile_totp_confirm():
    denied = _require_admin()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    result = confirm_authenticator(data.get("code") or "")
    if not result.get("ok"):
        return jsonify(result), 400
    return jsonify({"ok": True, "totp_active": True})


@app.get("/admin/api/overview")
def admin_overview():
    denied = _require_admin()
    if denied:
        return denied
    try:
        cleanup_old_logs()
    except Exception:  # noqa: BLE001
        pass
    stats = overview_stats()
    try:
        stats["inbox_unread"] = feedback_unread_count()
    except Exception:  # noqa: BLE001
        stats["inbox_unread"] = 0
    return jsonify({"ok": True, "stats": stats})


@app.get("/admin/api/system")
def admin_system():
    denied = _require_admin()
    if denied:
        return denied
    return jsonify(system_snapshot(with_history=True))


@app.get("/admin/api/inbox")
def admin_inbox_list():
    denied = _require_admin()
    if denied:
        return denied
    unread = (request.args.get("unread") or "").strip() in {"1", "true", "yes"}
    items = list_feedback(150, unread_only=unread)
    return jsonify(
        {
            "ok": True,
            "items": items,
            "unread": feedback_unread_count(),
        }
    )


@app.get("/admin/api/inbox/<int:item_id>")
def admin_inbox_get(item_id: int):
    denied = _require_admin()
    if denied:
        return denied
    item = get_feedback(item_id)
    if not item:
        return jsonify({"ok": False, "error": "Not found"}), 404
    if not item.get("is_read"):
        mark_feedback_read(item_id, True)
        item["is_read"] = True
    return jsonify({"ok": True, "item": item, "unread": feedback_unread_count()})


@app.post("/admin/api/inbox/<int:item_id>/read")
def admin_inbox_read(item_id: int):
    denied = _require_admin()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    is_read = data.get("is_read", True)
    if not mark_feedback_read(item_id, bool(is_read)):
        return jsonify({"ok": False, "error": "Not found"}), 404
    return jsonify({"ok": True, "unread": feedback_unread_count()})


@app.delete("/admin/api/inbox/<int:item_id>")
def admin_inbox_delete(item_id: int):
    denied = _require_admin()
    if denied:
        return denied
    if not delete_feedback(item_id):
        return jsonify({"ok": False, "error": "Not found"}), 404
    return jsonify({"ok": True, "unread": feedback_unread_count()})


@app.get("/admin/api/top-ips")
def admin_top_ips():
    denied = _require_admin()
    if denied:
        return denied
    return jsonify({"ok": True, "items": top_ips(40, 7)})


@app.get("/admin/api/lists")
def admin_lists_get():
    denied = _require_admin()
    if denied:
        return denied
    return jsonify({"ok": True, "items": list_ips()})


@app.post("/admin/api/lists")
def admin_lists_add():
    denied = _require_admin()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    result = add_ip(data.get("ip") or "", data.get("list_type") or "", data.get("note") or "")
    status = 200 if result.get("ok") else 400
    return jsonify(result), status


@app.delete("/admin/api/lists")
def admin_lists_del():
    denied = _require_admin()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    return jsonify(remove_ip(data.get("ip") or "", data.get("list_type") or ""))


@app.get("/admin/api/queries")
def admin_queries():
    denied = _require_admin()
    if denied:
        return denied
    tool = (request.args.get("tool") or "").strip() or None
    ip = (request.args.get("ip") or "").strip() or None
    return jsonify({"ok": True, "items": recent_queries(150, tool=tool, ip=ip)})


@app.get("/admin/api/tool-stats")
def admin_tool_stats():
    denied = _require_admin()
    if denied:
        return denied
    return jsonify({"ok": True, **tool_stats(14)})


@app.get("/admin/api/mail")
def admin_mail():
    denied = _require_admin()
    if denied:
        return denied
    return jsonify({"ok": True, "items": list_tests(150)})


@app.get("/admin/api/visitors")
def admin_visitors():
    denied = _require_admin()
    if denied:
        return denied
    return jsonify(
        {
            "ok": True,
            "countries": country_visit_stats(30),
            "top": top_visitors(50, 7),
            "recent": recent_visits(120),
            "legacy_countries": get_country_counts(),
        }
    )


@app.get("/api/mailtest/<test_id>")
def api_mailtest_status(test_id: str):
    test = get_test(test_id)
    if not test:
        return jsonify({"ok": False, "error": "Test not found"}), 404
    return jsonify(test)


@app.errorhandler(404)
def not_found(_err):
    return render_template("404.html"), 404


# Start SMTP sink once per process (gunicorn workers=1)
start_smtp_receiver()
start_metrics_sampler()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=True)
