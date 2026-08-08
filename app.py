"""lookup4.me — DNS, email & SSL lookup tools."""

from __future__ import annotations

import os
from urllib.parse import unquote

from flask import Flask, Response, jsonify, render_template, request

from tools.blacklist import check_blacklist
from tools.dkim import lookup_dkim
from tools.dmarc import lookup_dmarc
from tools.dns_lookup import SUPPORTED_TYPES, lookup_caa, lookup_dns, lookup_ns
from tools.http_check import check_http
from tools.ip_info import client_ip_from_request, lookup_ip_info
from tools.mx import lookup_mx
from tools.port_check import check_port
from tools.rdns import lookup_rdns
from tools.smtp_test import test_smtp
from tools.spf import lookup_spf
from tools.ssl_check import check_bulk
from tools.stats import bump, get_counts, init_stats, total_count
from tools.whois_lookup import lookup_whois

app = Flask(__name__)
app.config["BUYMEACOFFEE_URL"] = os.environ.get(
    "BUYMEACOFFEE_URL", "https://buymeacoffee.com/birolbenli"
)
app.config["LINKEDIN_URL"] = os.environ.get(
    "LINKEDIN_URL", "https://tr.linkedin.com/in/birolbenli"
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
def _ensure_stats():
    init_stats()


@app.context_processor
def inject_globals():
    return {
        "tools": TOOLS,
        "buymeacoffee_url": app.config["BUYMEACOFFEE_URL"],
        "linkedin_url": app.config["LINKEDIN_URL"],
        "site_name": "lookup4.me",
        "total_queries": total_count(),
        "dns_types": SUPPORTED_TYPES,
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
    elif slug == "ip":
        result = lookup_ip_info(query, request=request)
    else:
        result = {"ok": False, "error": "Unknown tool"}

    bump(slug)
    return result


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "lookup4.me"})


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/about")
def about():
    return render_template("about.html", counts=get_counts())


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
    # Convenience: /tools/dns/example.com/AAAA style via ?type= or trailing
    dns_type = request.args.get("type", "A")
    if slug == "dns" and query and "/" in query:
        # path already decoded; support example.com/TXT only if typed oddly — skip
        pass

    # Curl-friendly direct responses for simple tools
    if query and wants_plain() and slug in {"ip", "rdns"}:
        result = run_tool(slug, query)
        if slug == "ip":
            return Response((result.get("ip") or "") + "\n", mimetype="text/plain")
        hosts = result.get("hosts") or []
        return Response("\n".join(hosts) + ("\n" if hosts else ""), mimetype="text/plain")

    if query and request.args.get("format") == "json":
        return jsonify(run_tool(slug, query, {"type": dns_type}))

    return render_template(
        "tool.html",
        tool=tool,
        auto_query=query,
        dns_type=dns_type,
    )


@app.post("/api/<slug>")
def api_tool(slug: str):
    tool = get_tool(slug)
    if not tool:
        return jsonify({"ok": False, "error": "Unknown tool"}), 404

    data = request.get_json(silent=True) or {}
    field = tool["field"]
    query = data.get(field)
    if query is None:
        query = data.get("query") or data.get("domain") or data.get("host") or ""
    if isinstance(query, list):
        query = "\n".join(str(x) for x in query)

    # Allow empty IP lookup (self)
    if not str(query).strip() and not tool.get("optional"):
        return jsonify({"ok": False, "error": "Missing query"}), 400

    extra = {"type": data.get("type") or "A"}
    return jsonify(run_tool(slug, str(query), extra))


@app.errorhandler(404)
def not_found(_err):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=True)
