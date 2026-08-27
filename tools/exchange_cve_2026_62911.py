"""Safe external signals for CVE-2026-62911 (Exchange MRSProxy / HTTP.sys).

Defensive checks only — no auth relay, no WCF calls, no file-write probes.
Public signal (vendor/research check-only): anonymous HTTPS GET to the HTTP.sys
MRSProxy path returns Microsoft-HTTPAPI/2.0 with Negotiate.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .exchange_endpoints import parse_auth, request
from .exchange_findings import finding

CVE_ID = "CVE-2026-62911"
# HTTP.sys binding without Extended Protection (research / MSRC Aug 2026 SU)
HTTPSYS_MRS_PATH = "/Microsoft.Exchange.MailboxReplicationService.ProxyService"
IIS_MRS_PATH = "/EWS/mrsproxy.svc"

# Patched at or above (Exchange build = major.minor.build.revision).
# Sources: MSRC advisory + public research notes (Aug 2026 SUs).
PATCHED_AT_OR_ABOVE: dict[str, tuple[int, int, int, int]] = {
    "2016_cu23": (15, 1, 2507, 72),
    "2019_cu14": (15, 2, 1544, 43),
    "2019_cu15": (15, 2, 1748, 48),
    "se_rtm": (15, 2, 2562, 45),
}

MSRC_URL = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62911"
KB_REFS = (
    "https://support.microsoft.com/help/5121576",  # 2016 CU23
    "https://support.microsoft.com/help/5121575",  # 2019 CU14
    "https://support.microsoft.com/help/5121574",  # 2019 CU15
    "https://support.microsoft.com/help/5121573",  # SE RTM
)

# Microsoft MSRC CVSS 3.1 for CVE-2026-62911
CVSS = {
    "version": "3.1",
    "base_score": 8.0,
    "severity": "High",
    "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H",
    "source": "Microsoft MSRC",
}

# Human labels (English msgids — translated in the UI via gettext)
VERDICT_COPY: dict[str, dict[str, str]] = {
    "likely_affected": {
        "label": "Exposure found — likely unpatched",
        "summary": (
            "The public HTTP.sys MRSProxy fingerprint was found, and the passive build hint "
            "looks below the August 2026 security update. Treat this host as at risk until patched."
        ),
        "headline": "Exposure found",
        "exposure": "yes",
    },
    "surface_present_build_looks_patched": {
        "label": "Exposure found — build hint looks patched",
        "summary": (
            "The public HTTP.sys MRSProxy fingerprint was found. The passive build hint looks "
            "patched, but confirm Extended Protection and SU on the server — this tool cannot prove EPA."
        ),
        "headline": "Exposure found",
        "exposure": "yes",
    },
    "surface_present_build_unknown": {
        "label": "Exposure found — patch level not visible",
        "summary": (
            "The public HTTP.sys MRSProxy fingerprint was found (Microsoft-HTTPAPI + Negotiate). "
            "Patch level was not visible from outside. Verify the August 2026 SU on the server."
        ),
        "headline": "Exposure found",
        "exposure": "yes",
    },
    "path_reachable_no_httpsys_negotiate": {
        "label": "No exposure found",
        "summary": (
            "The MRSProxy HTTP.sys URL answered, but the vulnerable fingerprint "
            "(Microsoft-HTTPAPI + Negotiate) was not seen. From the internet, this host does not "
            "show the CVE-2026-62911 exposure signal."
        ),
        "headline": "No exposure found",
        "exposure": "no",
    },
    "httpsys_mrs_not_exposed": {
        "label": "No exposure found",
        "summary": (
            "No public HTTP.sys MRSProxy exposure signal was found. From the internet, this host "
            "does not show the CVE-2026-62911 exposure fingerprint."
        ),
        "headline": "No exposure found",
        "exposure": "no",
    },
}

PATCH_COPY: dict[str, dict[str, str]] = {
    "patched": {
        "label": "Looks patched (header hint)",
        "detail": "Passive x-owa-version hint is at or above the August 2026 SU floor for this CU.",
    },
    "vulnerable": {
        "label": "Looks unpatched (header hint)",
        "detail": "Passive x-owa-version hint is below the August 2026 SU floor for this CU.",
    },
    "not_visible": {
        "label": "Not disclosed externally",
        "detail": (
            "No x-owa-version header was returned. Hiding version headers is good for security — "
            "it is not a failed check. Confirm the build inside the server with PowerShell."
        ),
    },
    "needs_confirm": {
        "label": "Confirm on the server",
        "detail": "Build is outside the known CU tables for this check — confirm SU with HealthChecker.",
    },
}

INTERNAL_PATCH_CMD = (
    '[System.Diagnostics.FileVersionInfo]::GetVersionInfo('
    '"$env:ExchangeInstallPath\\bin\\ExSetup.exe").FileVersion'
)
INTERNAL_PATCH_HINT = (
    "On the Exchange server, run this in Exchange Management Shell to read the build, "
    "then compare it to the August 2026 SU for your CU."
)


def parse_build(raw: str | None) -> tuple[int, int, int, int] | None:
    if not raw:
        return None
    text = str(raw).strip()
    # Accept 15.2.1748.39 or Version 15.2 (Build 1748.39) style fragments
    parts: list[int] = []
    token = ""
    for ch in text:
        if ch.isdigit():
            token += ch
        else:
            if token:
                parts.append(int(token))
                token = ""
            if len(parts) >= 4:
                break
    if token and len(parts) < 4:
        parts.append(int(token))
    if len(parts) < 4:
        return None
    return parts[0], parts[1], parts[2], parts[3]


def classify_build(build: tuple[int, int, int, int] | None) -> dict[str, Any]:
    if not build:
        copy = PATCH_COPY["not_visible"]
        return {
            "status": "not_visible",
            "label": copy["label"],
            "branch": None,
            "patched": None,
            "detail": copy["detail"],
            "tech": None,
        }
    major, minor, cu_build, rev = build
    label = f"{major}.{minor}.{cu_build}.{rev}"

    if (major, minor) == (15, 1):
        floor = PATCHED_AT_OR_ABOVE["2016_cu23"]
        patched = build >= floor
        status = "patched" if patched else "vulnerable"
        copy = PATCH_COPY[status]
        return {
            "status": status,
            "label": copy["label"],
            "branch": "Exchange 2016 (CU23 lineage)",
            "patched": patched,
            "detail": copy["detail"],
            "tech": f"Build {label}; floor {'.'.join(map(str, floor))}",
            "floor": floor,
        }

    if (major, minor) != (15, 2):
        copy = PATCH_COPY["needs_confirm"]
        return {
            "status": "needs_confirm",
            "label": copy["label"],
            "branch": f"Unrecognized {major}.{minor}",
            "patched": None,
            "detail": copy["detail"],
            "tech": f"Seen build {label}",
        }

    if cu_build == 2562:
        floor = PATCHED_AT_OR_ABOVE["se_rtm"]
        branch = "Exchange SE RTM"
    elif cu_build == 1748:
        floor = PATCHED_AT_OR_ABOVE["2019_cu15"]
        branch = "Exchange 2019 CU15"
    elif cu_build == 1544:
        floor = PATCHED_AT_OR_ABOVE["2019_cu14"]
        branch = "Exchange 2019 CU14"
    elif cu_build < 1544:
        copy = PATCH_COPY["vulnerable"]
        return {
            "status": "vulnerable",
            "label": copy["label"],
            "branch": f"Exchange 2019 older CU (build {cu_build})",
            "patched": False,
            "detail": copy["detail"],
            "tech": f"Build {label} is below CU14 lineage",
            "floor": PATCHED_AT_OR_ABOVE["2019_cu14"],
        }
    else:
        copy = PATCH_COPY["needs_confirm"]
        return {
            "status": "needs_confirm",
            "label": copy["label"],
            "branch": f"Exchange 15.2 build {cu_build}",
            "patched": None,
            "detail": copy["detail"],
            "tech": f"Seen build {label}",
        }

    patched = build >= floor
    status = "patched" if patched else "vulnerable"
    copy = PATCH_COPY[status]
    return {
        "status": status,
        "label": copy["label"],
        "branch": branch,
        "patched": patched,
        "detail": copy["detail"],
        "tech": f"Build {label}; floor {'.'.join(map(str, floor))}",
        "floor": floor,
    }


def _probe_path(host: str, path: str) -> dict[str, Any]:
    url = f"https://{host}{path}"
    res = request(url, method="GET", follow_redirects=False)
    headers = {k.lower(): v for k, v in (res.get("headers") or {}).items()}
    server = headers.get("server") or ""
    www = headers.get("www-authenticate") or ""
    auth = parse_auth(www)
    status = res.get("status_code")
    httpsys = "httpapi" in server.lower() or "microsoft-httpapi" in server.lower()
    negotiate = bool(
        auth.get("ntlm")
        or any("negotiate" in (s or "").lower() for s in (auth.get("schemes") or []))
        or "negotiate" in www.lower()
    )
    # Research check-only signal: HTTP.sys + Negotiate on this path
    risk_surface = bool(
        res.get("reachable")
        and status in (401, 403)
        and httpsys
        and negotiate
    )
    return {
        "host": host,
        "path": path,
        "url": url,
        "reachable": bool(res.get("reachable")),
        "status_code": status,
        "server": server[:120],
        "www_authenticate": www[:240],
        "schemes": auth.get("schemes") or [],
        "httpsys": httpsys,
        "negotiate": negotiate,
        "risk_surface": risk_surface,
        "error": res.get("error"),
    }


def assess_cve_2026_62911(
    hosts: list[str],
    *,
    build_hint: str | None = None,
) -> dict[str, Any]:
    """Probe resolved public hosts for the HTTP.sys MRSProxy exposure signal."""
    unique = []
    seen: set[str] = set()
    for h in hosts:
        h = (h or "").strip().lower().rstrip(".")
        if not h or h in seen:
            continue
        seen.add(h)
        unique.append(h)

    probes: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(6, max(1, len(unique) * 2))) as pool:
        futs = []
        for h in unique:
            futs.append(pool.submit(_probe_path, h, HTTPSYS_MRS_PATH))
            futs.append(pool.submit(_probe_path, h, IIS_MRS_PATH))
        for fut in as_completed(futs):
            try:
                probes.append(fut.result())
            except Exception as exc:  # noqa: BLE001
                probes.append(
                    {
                        "reachable": False,
                        "risk_surface": False,
                        "error": str(exc),
                        "path": "?",
                    }
                )

    httpsys_hits = [p for p in probes if p.get("path") == HTTPSYS_MRS_PATH and p.get("risk_surface")]
    httpsys_any = [p for p in probes if p.get("path") == HTTPSYS_MRS_PATH and p.get("reachable")]
    iis_mrs = [p for p in probes if p.get("path") == IIS_MRS_PATH and p.get("reachable")]

    build = parse_build(build_hint)
    build_info = classify_build(build)

    if httpsys_hits and build_info.get("patched") is False:
        risk = "critical"
        verdict = "likely_affected"
    elif httpsys_hits and build_info.get("patched") is True:
        risk = "high"
        verdict = "surface_present_build_looks_patched"
    elif httpsys_hits:
        risk = "high"
        verdict = "surface_present_build_unknown"
    elif httpsys_any:
        risk = "info"
        verdict = "path_reachable_no_httpsys_negotiate"
    else:
        risk = "info"
        verdict = "httpsys_mrs_not_exposed"

    vcopy = VERDICT_COPY.get(verdict) or VERDICT_COPY["httpsys_mrs_not_exposed"]
    summary = vcopy["summary"]
    exposed = vcopy.get("exposure") == "yes"

    # Only push patch/restrict steps when exposure (or clear unpatched hint) exists.
    if exposed:
        remediation = [
            "Apply the August 2026 Exchange security updates for CVE-2026-62911 (see MSRC).",
            "Confirm build is at or above your CU’s fixed revision (2016 CU23 / 2019 CU14–CU15 / SE).",
            "Restrict MRSProxy publishing if it is not required for hybrid or migration.",
            "Enable Exchange Extended Protection where supported.",
        ]
    elif build_info.get("patched") is False:
        remediation = [
            "No public exposure fingerprint was seen, but the passive build hint looks below "
            "the August 2026 SU — still patch on-prem Exchange if you run it.",
        ]
    else:
        remediation = []

    return {
        "cve": CVE_ID,
        "title": "CVE-2026-62911 — MRSProxy HTTP.sys",
        "verdict": verdict,
        "verdict_label": vcopy["label"],
        "headline": vcopy.get("headline") or vcopy["label"],
        "exposure": vcopy.get("exposure") or "no",
        "risk": risk,
        "risk_label": {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Informational",
        }.get(risk, risk),
        "summary": summary,
        "cvss": dict(CVSS),
        "mode": "external_safe_check_only",
        "build_hint": build_hint,
        "build_parsed": ".".join(map(str, build)) if build else None,
        "build": build_info,
        "httpsys_exposed": bool(httpsys_hits),
        "httpsys_hits": httpsys_hits,
        "httpsys_probes": [p for p in probes if p.get("path") == HTTPSYS_MRS_PATH],
        "iis_mrsproxy_reachable": bool(iis_mrs),
        "iis_mrs_probes": [p for p in probes if p.get("path") == IIS_MRS_PATH],
        "advisory": MSRC_URL,
        "kb_refs": list(KB_REFS),
        "internal_patch_check": {
            "title": "Check patch level on the server",
            "why": INTERNAL_PATCH_HINT,
            "command": INTERNAL_PATCH_CMD,
        },
        "limitations": [
            "Safe external check only — no relay, no WCF calls, no exploit.",
            "Missing x-owa-version is normal and preferable; it does not mean the host is unpatched.",
        ],
        "remediation": remediation,
    }


def findings_for_cve_2026_62911(assessment: dict[str, Any]) -> list[dict]:
    """Convert assessment into Exchange HC finding objects."""
    out: list[dict] = []
    verdict = assessment.get("verdict") or ""
    hits = assessment.get("httpsys_hits") or []
    urls = [h.get("url") for h in hits if h.get("url")]
    target = (hits[0].get("host") if hits else "") or ""
    exposed = assessment.get("exposure") == "yes"
    rem = "; ".join(assessment.get("remediation") or [])[:500]

    if verdict == "likely_affected":
        out.append(
            finding(
                id="CVE-2026-62911-LIKELY",
                title="CVE-2026-62911: exposure found — likely unpatched",
                status="FAIL",
                severity="critical",
                confidence="medium",
                target=target,
                observed=assessment.get("summary") or "",
                expected="Remove public HTTP.sys MRSProxy exposure and install the August 2026 SU.",
                why="Public Microsoft-HTTPAPI + Negotiate on the MRSProxy HTTP.sys path is the check-only exposure signal.",
                remediation=rem,
                ref_keys=("CVE-2026-62911", "M6", "M2b"),
                category="cve",
                endpoints=urls[:6],
            )
        )
    elif exposed:
        out.append(
            finding(
                id="CVE-2026-62911-EXPOSED",
                title="CVE-2026-62911: exposure found",
                status="FAIL",
                severity="high",
                confidence="medium",
                target=target,
                observed=assessment.get("summary") or "",
                expected="Verify August 2026 SU and Extended Protection; restrict MRSProxy if unused.",
                why="The public HTTP.sys MRSProxy fingerprint was observed from the internet.",
                remediation=rem,
                ref_keys=("CVE-2026-62911", "M6", "M2b"),
                category="cve",
                endpoints=urls[:6],
            )
        )
    else:
        out.append(
            finding(
                id="CVE-2026-62911-CLEAN",
                title="CVE-2026-62911: no exposure found",
                status="PASS",
                severity="info",
                confidence="medium",
                target=target or "probed hosts",
                observed=assessment.get("summary") or "",
                expected="No public HTTP.sys MRSProxy exposure fingerprint.",
                why="From the internet, the vulnerable fingerprint was not seen.",
                remediation="",
                ref_keys=("CVE-2026-62911",),
                category="cve",
            )
        )

    build = assessment.get("build") or {}
    if build.get("status") == "vulnerable":
        out.append(
            finding(
                id="CVE-2026-62911-BUILD",
                title="Passive build hint looks below August 2026 SU",
                status="WARN" if exposed else "INFO",
                severity="high" if exposed else "low",
                confidence="low",
                target=assessment.get("build_hint") or "",
                observed=build.get("detail") or "",
                expected="Install the matching August 2026 SU for your CU.",
                why="x-owa-version is only a weak hint — confirm with ExSetup.exe version on the server.",
                remediation=rem,
                ref_keys=("CVE-2026-62911", "M1", "M2b"),
                category="cve",
            )
        )

    return out
