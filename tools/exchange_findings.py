"""Structured findings + topology-aware rule helpers for Exchange assessment v2."""

from __future__ import annotations

from typing import Any

from .exchange_ms_refs import NOT_OBSERVABLE_CATALOG, refs

SEVERITY_UI = {
    "critical": "critical",
    "high": "warning",
    "medium": "warning",
    "low": "info",
    "info": "info",
    "ok": "ok",
}


def finding(
    *,
    id: str,
    title: str,
    status: str,
    severity: str,
    confidence: str = "medium",
    target: str = "",
    observed: str = "",
    expected: str = "",
    why: str = "",
    scope_limitation: str = "",
    remediation: str = "",
    ref_keys: tuple[str, ...] = (),
    category: str = "",
    endpoints: list[str] | None = None,
) -> dict[str, Any]:
    """Build a spec-compliant finding. Also exposes legacy UI fields."""
    sev = (severity or "info").lower()
    st = (status or "INFO").upper()
    ui_sev = SEVERITY_UI.get(sev, "info")
    if st == "PASS":
        ui_sev = "ok"
    elif st == "NOT_OBSERVABLE":
        ui_sev = "info"
    return {
        "id": id,
        "title": title,
        "status": st,
        "severity": sev if sev != "ok" else "info",
        "confidence": confidence,
        "target": target,
        "observed": observed,
        "expected": expected,
        "why": why,
        "scope_limitation": scope_limitation,
        "remediation": remediation,
        "refs": refs(*ref_keys),
        "category": category,
        "endpoints": endpoints or [],
        # Legacy UI compatibility
        "detail": observed or why,
        "guidance": remediation,
        "context": category,
        # Map for existing sev-* CSS: critical|warning|info|ok
        "ui_severity": ui_sev,
    }


def not_observable_section() -> list[dict]:
    return [dict(x) for x in NOT_OBSERVABLE_CATALOG]


# Endpoints that classic hybrid may legitimately publish.
HYBRID_EXPECTED_PUBLIC = {"ews", "ews_asmx", "mrsproxy", "autodiscover", "autodiscover_svc", "eas", "mapi", "mapi_emsmdb"}

# Admin surfaces that should rarely be public.
ADMIN_SURFACE = {"ecp", "powershell", "ecp_default"}


def score_buckets() -> dict[str, int]:
    return {
        "tls": 20,
        "auth": 15,
        "exchange_web": 15,
        "http": 10,
        "smtp": 15,
        "mail_domain": 10,
        "dns_network": 5,
        "hybrid": 5,
        "disclosure": 5,
    }


def _deduct_for(status: str, severity: str, confidence: str) -> float:
    if status in {"PASS", "NA", "NOT_OBSERVABLE", "INFO"} and severity in {"info", "low"}:
        if status == "INFO" and severity == "low":
            return 0.5
        if status in {"PASS", "NA", "NOT_OBSERVABLE"}:
            return 0.0
    if confidence == "low" and status in {"WARN", "INFO"}:
        # Low-confidence oauth/hybrid signals should barely move the needle.
        return 0.5 if severity in {"medium", "low", "info"} else 2.0
    table = {
        ("FAIL", "critical"): 12,
        ("FAIL", "high"): 8,
        ("FAIL", "medium"): 5,
        ("WARN", "high"): 6,
        ("WARN", "medium"): 4,
        ("WARN", "low"): 2,
        ("WARN", "info"): 1,
        ("INFO", "medium"): 1,
        ("INFO", "low"): 0.5,
        ("INFO", "info"): 0.5,
        ("ERROR", "medium"): 2,
    }
    return float(table.get((status, severity), 0))


def category_for_finding(f: dict) -> str:
    cat = (f.get("category") or f.get("context") or "").lower()
    mapping = {
        "tls": "tls",
        "auth": "auth",
        "legacy_auth": "auth",
        "modern_auth": "auth",
        "exchange_web": "exchange_web",
        "exposure": "exchange_web",
        "http": "http",
        "smtp": "smtp",
        "mail_domain": "mail_domain",
        "dns": "dns_network",
        "dns_network": "dns_network",
        "hybrid": "hybrid",
        "disclosure": "disclosure",
        "headers": "disclosure",
        "fingerprint": "disclosure",
        "cve": "exchange_web",
    }
    return mapping.get(cat, "exchange_web")


def weighted_score(findings: list[dict]) -> dict:
    """Spec scoring: 100 points across weighted buckets; critical overrides label."""
    buckets = score_buckets()
    remaining = {k: float(v) for k, v in buckets.items()}
    critical_hit = False

    for f in findings:
        st = (f.get("status") or "").upper()
        sev = (f.get("severity") or "info").lower()
        conf = (f.get("confidence") or "medium").lower()
        # Skip oauth inconclusive / low-confidence modern_auth INFO
        if f.get("id") in {"AUTH-OAUTH-INCONCLUSIVE", "AUTH-BEARER-INCONCLUSIVE"}:
            continue
        if (
            (f.get("category") == "modern_auth" or f.get("context") == "modern_auth")
            and conf == "low"
            and st in {"INFO", "WARN"}
        ):
            continue

        cat = category_for_finding(f)
        if cat not in remaining:
            cat = "exchange_web"
        deduct = _deduct_for(st, sev, conf)
        # Scale deduct relative to bucket size (cap at bucket)
        remaining[cat] = max(0.0, remaining[cat] - deduct)
        if st == "FAIL" and sev == "critical":
            critical_hit = True

    parts = {k: round(v, 1) for k, v in remaining.items()}
    score = int(round(sum(parts.values())))
    score = max(0, min(100, score))

    if critical_hit:
        grade, label = "D", "Critical findings present"
    elif score >= 85:
        grade, label = "A", "Good"
    elif score >= 70:
        grade, label = "B", "Fair"
    elif score >= 50:
        grade, label = "C", "Needs work"
    else:
        grade, label = "D", "High risk"

    severity_counts = {
        "critical": sum(1 for f in findings if (f.get("severity") or "").lower() == "critical" and (f.get("status") or "").upper() == "FAIL"),
        "high": sum(1 for f in findings if (f.get("severity") or "").lower() == "high" and (f.get("status") or "").upper() in {"FAIL", "WARN"}),
        "medium": sum(1 for f in findings if (f.get("severity") or "").lower() == "medium" and (f.get("status") or "").upper() in {"FAIL", "WARN"}),
        "low": sum(1 for f in findings if (f.get("severity") or "").lower() == "low"),
        "info": sum(1 for f in findings if (f.get("status") or "").upper() == "INFO"),
        "pass": sum(1 for f in findings if (f.get("status") or "").upper() == "PASS"),
    }

    return {
        "score": score,
        "grade": grade,
        "label": label,
        "buckets": parts,
        "weights": buckets,
        "severity_counts": severity_counts,
        "critical_override": critical_hit,
    }


def ui_severity(f: dict) -> str:
    return f.get("ui_severity") or SEVERITY_UI.get((f.get("severity") or "info").lower(), "info")
