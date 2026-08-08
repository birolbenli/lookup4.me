"""tools.birolbenli.com — DNS, email & SSL lookup tools."""

from __future__ import annotations

import logging
import os
import threading
from urllib.parse import unquote

from flask import Flask, Response, g, jsonify, render_template, request

from i18n import COOKIE as LANG_COOKIE
from i18n import _, detect_lang, get_lang, js_bundle, localize_tools
from tools.blacklist import check_blacklist
from tools.dkim import lookup_dkim
from tools.dmarc import lookup_dmarc
from tools.dns_lookup import SUPPORTED_TYPES, lookup_caa, lookup_dns, lookup_ns
from tools.email_analyze import analyze_email
from tools.exchange_check import check_exchange
from tools.feedback import init_feedback, submit_feedback
from tools.http_check import check_http
from tools.ip_info import client_ip_from_request, lookup_ip_info
from tools.mail_store import create_test, get_test, init_mail_store
from tools.mx import lookup_mx
from tools.port_check import check_port
from tools.rdns import lookup_rdns
from tools.smtp_receiver import start_smtp_receiver
from tools.smtp_test import test_smtp
from tools.spf import lookup_spf
from tools.ssl_check import check_bulk
from tools.stats import bump, get_counts, init_stats, total_count
from tools.visitors import get_country_counts, init_visitors, track_visitor, visitor_total
from tools.whois_lookup import lookup_whois

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.config["BUYMEACOFFEE_URL"] = os.environ.get(
    "BUYMEACOFFEE_URL", "https://buymeacoffee.com/birolbenli"
)
app.config["LINKEDIN_URL"] = os.environ.get(
    "LINKEDIN_URL", "https://tr.linkedin.com/in/birolbenli"
)
app.config["MAILTEST_DOMAIN"] = os.environ.get(
    "MAILTEST_DOMAIN", "tools.birolbenli.com"
)

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
        "name": "HTTP Headers",
        "desc": "Fetch status code and response headers.",
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
        "desc": "External Exchange health check: VDirs, NTLM vs OAuth 2.0, hybrid/Teams guidance, TLS.",
        "field": "host",
        "placeholder": "mail.example.com",
        "example": "outlook.office365.com",
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
]


def get_tool(slug: str) -> dict | None:
    return next((t for t in TOOLS if t["slug"] == slug), None)


@app.before_request
def _ensure_runtime():
    g.lang = detect_lang()
    g.set_lang_cookie = request.args.get("lang") in {"en", "tr"}
    init_stats()
    init_mail_store()
    init_feedback()
    init_visitors()


def _should_track_visitor() -> bool:
    if request.method != "GET":
        return False
    path = request.path or "/"
    if path.startswith("/static") or path.startswith("/api/") or path == "/health":
        return False
    if path.endswith(".json"):
        return False
    if wants_plain():
        return False
    return True


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
    if _should_track_visitor() and "text/html" in ctype and response.status_code < 400:
        ip = client_ip_from_request(request)
        threading.Thread(target=track_visitor, args=(ip,), daemon=True).start()
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
    }


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
    elif slug == "ip":
        result = lookup_ip_info(query, request=request)
    else:
        result = {"ok": False, "error": "Unknown tool"}

    bump(slug)
    return result


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "tools.birolbenli.com"})


@app.get("/")
def index():
    return render_template("index.html")


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
        result = run_tool(slug, query)
        if slug == "ip":
            return Response((result.get("ip") or "") + "\n", mimetype="text/plain")
        hosts = result.get("hosts") or []
        return Response("\n".join(hosts) + ("\n" if hosts else ""), mimetype="text/plain")

    if query and request.args.get("format") == "json" and slug not in {"mailtest"}:
        return jsonify(run_tool(slug, query, {"type": dns_type}))

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

    extra = {"type": data.get("type") or "A"}
    return jsonify(run_tool(slug, str(query), extra))


@app.post("/api/mailtest/create")
def api_mailtest_create():
    domain = app.config["MAILTEST_DOMAIN"]
    result = create_test(domain)
    bump("mailtest")
    return jsonify(result)


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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=True)
