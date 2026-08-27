"""Exchange CVE Checker — expandable external CVE library (safe probes only)."""

from __future__ import annotations

from typing import Any, Callable
from urllib.parse import urlparse

from .dns_common import is_ip, normalize_domain
from .exchange_cve_2026_62911 import (
    CVE_ID as CVE_2026_62911_ID,
    assess_cve_2026_62911,
    findings_for_cve_2026_62911,
)
from .exchange_endpoints import hosts_to_probe, public_ips, request
from .exchange_findings import ui_severity, weighted_score

# Registry — add new CVE modules here later (id, title, assess callable).
CVECheckFn = Callable[..., dict[str, Any]]


def _probe_build_hint(hosts: list[str]) -> str | None:
    """Best-effort x-owa-version from a few public paths (no auth)."""
    paths = ("/owa/", "/owa/auth/logon.aspx", "/ecp/")
    for host in hosts[:3]:
        for path in paths:
            res = request(f"https://{host}{path}", method="GET", follow_redirects=True)
            headers = {k.lower(): v for k, v in (res.get("headers") or {}).items()}
            ver = headers.get("x-owa-version")
            if ver:
                return ver.strip()
            for h in res.get("redirect_chain") or []:
                hh = {k.lower(): v for k, v in (h.get("headers") or {}).items()}
                ver = hh.get("x-owa-version")
                if ver:
                    return ver.strip()
    return None


def _run_cve_2026_62911(hosts: list[str], build_hint: str | None) -> dict[str, Any]:
    assessment = assess_cve_2026_62911(hosts, build_hint=build_hint)
    findings = findings_for_cve_2026_62911(assessment)
    return {
        "id": CVE_2026_62911_ID,
        "name": "MRSProxy HTTP.sys / capture-replay",
        "assessment": assessment,
        "findings": findings,
        "risk": assessment.get("risk") or "info",
        "risk_label": assessment.get("risk_label") or assessment.get("risk") or "info",
        "verdict": assessment.get("verdict") or "",
        "verdict_label": assessment.get("verdict_label") or assessment.get("verdict") or "",
        "summary": assessment.get("summary") or "",
        "cvss": assessment.get("cvss"),
        "advisory": assessment.get("advisory"),
    }


# Ordered library — first entry is the initial shipped check.
CVE_LIBRARY: list[dict[str, Any]] = [
    {
        "id": CVE_2026_62911_ID,
        "name": "MRSProxy HTTP.sys / capture-replay",
        "enabled": True,
        "runner": _run_cve_2026_62911,
    },
]


def library_catalog() -> list[dict[str, str]]:
    return [
        {
            "id": c["id"],
            "name": c["name"],
            "enabled": bool(c.get("enabled")),
        }
        for c in CVE_LIBRARY
    ]


def check_exchange_cves(host: str) -> dict[str, Any]:
    raw = (host or "").strip()
    if not raw:
        return {"ok": False, "error": "Please enter an Exchange hostname (e.g. mail.example.com)", "external_check": True}

    if "://" in raw:
        raw = urlparse(raw).hostname or raw
    host = normalize_domain(raw.replace("\\", "/").split("/")[0])
    if not host or ("." not in host and not is_ip(host)):
        return {"ok": False, "error": "Enter a valid hostname such as mail.example.com", "external_check": True}

    if not public_ips(host):
        return {
            "ok": False,
            "error": "Hostname must resolve to a public IP address (private/local targets are blocked).",
            "host": host,
            "external_check": True,
        }

    host_rows = []
    for item in hosts_to_probe(host):
        ips = public_ips(item["host"])
        host_rows.append({**item, "ips": ips, "resolves": bool(ips)})

    cve_hosts = [h["host"] for h in host_rows if h.get("resolves")]
    if host not in cve_hosts:
        cve_hosts.insert(0, host)

    build_hint = _probe_build_hint(cve_hosts)

    checks: list[dict[str, Any]] = []
    all_findings: list[dict] = []
    for entry in CVE_LIBRARY:
        if not entry.get("enabled"):
            checks.append(
                {
                    "id": entry["id"],
                    "name": entry["name"],
                    "enabled": False,
                    "skipped": True,
                    "summary": "Disabled in library",
                }
            )
            continue
        runner: CVECheckFn = entry["runner"]
        result = runner(cve_hosts, build_hint)
        checks.append({**result, "enabled": True, "skipped": False})
        all_findings.extend(result.get("findings") or [])

    order = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    all_findings.sort(key=lambda f: order.get(ui_severity(f), 9))
    for f in all_findings:
        f["severity"] = f.get("ui_severity") or ui_severity(f)

    summary = weighted_score(all_findings)
    worst = "info"
    for c in checks:
        if c.get("skipped"):
            continue
        r = (c.get("risk") or "info").lower()
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        if rank.get(r, 9) < rank.get(worst, 9):
            worst = r

    active = [c for c in checks if not c.get("skipped")]
    title = "Exchange CVE Checker"
    note = (
        "Safe external check for CVE-2026-62911. "
        "No credentials, no relay, no exploit — only public HTTP signals."
    )

    return {
        "ok": True,
        "external_check": True,
        "mode": "external_only",
        "tool": "Exchange CVE Checker",
        "title": title,
        "note": note,
        "host": host,
        "hosts": host_rows,
        "build_hint": build_hint,
        "score": summary.get("score"),
        "summary": summary,
        "worst_risk": worst,
        "library": library_catalog(),
        "checks": checks,
        "findings": all_findings,
        "guidance": [
            "This page answers one question: is the CVE-2026-62911 public exposure fingerprint visible from the internet?",
            "Missing x-owa-version is good (less fingerprinting). Confirm the build on the server with the PowerShell command below.",
            "Exchange Online is out of scope for this on-prem MRSProxy check.",
        ],
        # First CVE surfaced at top-level for the dedicated UI block
        "cve_2026_62911": next(
            (c.get("assessment") for c in checks if c.get("id") == CVE_2026_62911_ID),
            None,
        ),
    }
