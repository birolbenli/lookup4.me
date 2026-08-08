"""lookup4.me — DNS, email & SSL lookup tools."""

from __future__ import annotations

import os

from flask import Flask, jsonify, render_template, request

from tools.dkim import lookup_dkim
from tools.dmarc import lookup_dmarc
from tools.mx import lookup_mx
from tools.rdns import lookup_rdns
from tools.smtp_test import test_smtp
from tools.spf import lookup_spf
from tools.ssl_check import check_bulk

app = Flask(__name__)
app.config["BUYMEACOFFEE_URL"] = os.environ.get(
    "BUYMEACOFFEE_URL", "https://www.buymeacoffee.com/"
)

TOOLS = [
    {
        "slug": "mx",
        "name": "MX Lookup",
        "desc": "Find mail exchangers and resolve their IPs.",
    },
    {
        "slug": "spf",
        "name": "SPF Lookup",
        "desc": "Inspect SPF records and included policies.",
    },
    {
        "slug": "dkim",
        "name": "DKIM Lookup",
        "desc": "Detect common DKIM selectors and follow host chains.",
    },
    {
        "slug": "dmarc",
        "name": "DMARC Lookup",
        "desc": "Check DMARC policy, rua/ruf and alignment tags.",
    },
    {
        "slug": "ssl",
        "name": "SSL Checker",
        "desc": "Check up to 10 certificates at once in a table.",
    },
    {
        "slug": "rdns",
        "name": "Reverse DNS",
        "desc": "Resolve PTR records for an IP address.",
    },
    {
        "slug": "smtp",
        "name": "SMTP Test",
        "desc": "Test SMTP banner, EHLO and STARTTLS on port 25.",
    },
]


@app.context_processor
def inject_globals():
    return {
        "tools": TOOLS,
        "buymeacoffee_url": app.config["BUYMEACOFFEE_URL"],
        "site_name": "lookup4.me",
    }


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "lookup4.me"})


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/about")
def about():
    return render_template("about.html")


@app.get("/tools/<slug>")
def tool_page(slug: str):
    tool = next((t for t in TOOLS if t["slug"] == slug), None)
    if not tool:
        return render_template("404.html"), 404
    return render_template(f"tools/{slug}.html", tool=tool)


@app.post("/api/mx")
def api_mx():
    data = request.get_json(silent=True) or {}
    domain = data.get("domain") or request.form.get("domain", "")
    return jsonify(lookup_mx(domain))


@app.post("/api/spf")
def api_spf():
    data = request.get_json(silent=True) or {}
    domain = data.get("domain") or request.form.get("domain", "")
    return jsonify(lookup_spf(domain))


@app.post("/api/dkim")
def api_dkim():
    data = request.get_json(silent=True) or {}
    domain = data.get("domain") or request.form.get("domain", "")
    selectors = data.get("selectors")
    if isinstance(selectors, str):
        selectors = [s.strip() for s in selectors.replace(",", " ").split() if s.strip()]
    return jsonify(lookup_dkim(domain, selectors or None))


@app.post("/api/dmarc")
def api_dmarc():
    data = request.get_json(silent=True) or {}
    domain = data.get("domain") or request.form.get("domain", "")
    return jsonify(lookup_dmarc(domain))


@app.post("/api/ssl")
def api_ssl():
    data = request.get_json(silent=True) or {}
    domains = data.get("domains") or request.form.get("domains", "")
    return jsonify(check_bulk(domains, max_domains=10))


@app.post("/api/rdns")
def api_rdns():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip") or request.form.get("ip", "")
    return jsonify(lookup_rdns(ip))


@app.post("/api/smtp")
def api_smtp():
    data = request.get_json(silent=True) or {}
    host = data.get("host") or request.form.get("host", "")
    port = data.get("port") or request.form.get("port") or 25
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 25
    return jsonify(test_smtp(host, port=port))


@app.errorhandler(404)
def not_found(_err):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=True)
