"""Admin panel storage: IP lists, query/visit logs, settings."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from .ua_parse import parse_ua

_LOCK = threading.Lock()
_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "instance",
    "admin.db",
)

LIST_WHITELIST = "whitelist"
LIST_BLACKLIST = "blacklist"
_MAX_QUERY_LEN = 240
_RETENTION_DAYS = 45


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None = None) -> str:
    return (dt or _now()).astimezone(timezone.utc).isoformat()


@contextmanager
def _conn():
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(_DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_admin_store() -> None:
    with _conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ip_lists (
                ip TEXT NOT NULL,
                list_type TEXT NOT NULL,
                note TEXT,
                created_at TEXT NOT NULL,
                PRIMARY KEY (ip, list_type)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS query_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                ip TEXT NOT NULL,
                tool TEXT NOT NULL,
                query TEXT,
                ok INTEGER,
                status_code INTEGER,
                user_agent TEXT,
                os TEXT,
                browser TEXT,
                device TEXT,
                country_code TEXT,
                country_name TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_query_ts ON query_logs(ts DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_query_ip ON query_logs(ip)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_query_tool ON query_logs(tool)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS visit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                ip TEXT NOT NULL,
                path TEXT,
                user_agent TEXT,
                os TEXT,
                browser TEXT,
                device TEXT,
                country_code TEXT,
                country_name TEXT,
                city TEXT,
                isp TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_visit_ts ON visit_logs(ts DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_visit_ip ON visit_logs(ip)"
        )


def get_setting(key: str, default: str | None = None) -> str | None:
    init_admin_store()
    with _conn() as conn:
        row = conn.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    init_admin_store()
    with _LOCK:
        with _conn() as conn:
            conn.execute(
                """
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )


def is_whitelisted(ip: str) -> bool:
    return _in_list(ip, LIST_WHITELIST)


def is_blacklisted(ip: str) -> bool:
    return _in_list(ip, LIST_BLACKLIST)


def _in_list(ip: str, list_type: str) -> bool:
    ip = (ip or "").strip()
    if not ip:
        return False
    init_admin_store()
    with _conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM ip_lists WHERE ip = ? AND list_type = ?",
            (ip, list_type),
        ).fetchone()
    return bool(row)


def list_ips(list_type: str | None = None) -> list[dict]:
    init_admin_store()
    with _conn() as conn:
        if list_type:
            rows = conn.execute(
                """
                SELECT ip, list_type, note, created_at
                FROM ip_lists WHERE list_type = ?
                ORDER BY created_at DESC
                """,
                (list_type,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT ip, list_type, note, created_at
                FROM ip_lists ORDER BY list_type, created_at DESC
                """
            ).fetchall()
    return [dict(r) for r in rows]


def add_ip(ip: str, list_type: str, note: str = "") -> dict:
    ip = (ip or "").strip()
    list_type = (list_type or "").strip().lower()
    if not ip:
        return {"ok": False, "error": "IP required"}
    if list_type not in {LIST_WHITELIST, LIST_BLACKLIST}:
        return {"ok": False, "error": "Invalid list type"}
    # Mutual exclusion
    init_admin_store()
    other = LIST_BLACKLIST if list_type == LIST_WHITELIST else LIST_WHITELIST
    with _LOCK:
        with _conn() as conn:
            conn.execute(
                "DELETE FROM ip_lists WHERE ip = ? AND list_type = ?",
                (ip, other),
            )
            conn.execute(
                """
                INSERT INTO ip_lists (ip, list_type, note, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ip, list_type) DO UPDATE SET
                    note = excluded.note,
                    created_at = excluded.created_at
                """,
                (ip, list_type, (note or "")[:200], _iso()),
            )
    return {"ok": True, "ip": ip, "list_type": list_type}


def remove_ip(ip: str, list_type: str) -> dict:
    ip = (ip or "").strip()
    list_type = (list_type or "").strip().lower()
    with _LOCK:
        with _conn() as conn:
            cur = conn.execute(
                "DELETE FROM ip_lists WHERE ip = ? AND list_type = ?",
                (ip, list_type),
            )
            return {"ok": True, "removed": cur.rowcount > 0}


def _truncate_query(query: str | None) -> str:
    text = (query or "").replace("\r", " ").replace("\n", " ").strip()
    if len(text) > _MAX_QUERY_LEN:
        return text[: _MAX_QUERY_LEN - 1] + "…"
    return text


def _geo_for_ip(ip: str) -> tuple[str, str, str, str]:
    """Cached geo only (no network on request path). Returns code, name, city, isp."""
    try:
        from .visitors import _cached_geo

        cached = _cached_geo(ip)
        if cached:
            return cached[0], cached[1], "", ""
    except Exception:  # noqa: BLE001
        pass
    return "", "", "", ""


def log_query(
    *,
    ip: str,
    tool: str,
    query: str = "",
    ok: bool | None = None,
    status_code: int | None = None,
    user_agent: str = "",
) -> None:
    init_admin_store()
    ua = parse_ua(user_agent)
    code, name, _city, _isp = _geo_for_ip(ip)
    with _LOCK:
        with _conn() as conn:
            conn.execute(
                """
                INSERT INTO query_logs (
                    ts, ip, tool, query, ok, status_code,
                    user_agent, os, browser, device, country_code, country_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _iso(),
                    (ip or "unknown")[:64],
                    (tool or "unknown")[:40],
                    _truncate_query(query),
                    None if ok is None else (1 if ok else 0),
                    status_code,
                    ua["ua"],
                    ua["os"],
                    ua["browser"],
                    ua["device"],
                    code,
                    name,
                ),
            )


def log_visit(
    *,
    ip: str,
    path: str = "",
    user_agent: str = "",
    country_code: str = "",
    country_name: str = "",
    city: str = "",
    isp: str = "",
) -> None:
    init_admin_store()
    ua = parse_ua(user_agent)
    if not country_code:
        code, name, city2, isp2 = _geo_for_ip(ip)
        country_code = country_code or code
        country_name = country_name or name
        city = city or city2
        isp = isp or isp2
    with _LOCK:
        with _conn() as conn:
            conn.execute(
                """
                INSERT INTO visit_logs (
                    ts, ip, path, user_agent, os, browser, device,
                    country_code, country_name, city, isp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _iso(),
                    (ip or "unknown")[:64],
                    (path or "/")[:200],
                    ua["ua"],
                    ua["os"],
                    ua["browser"],
                    ua["device"],
                    country_code,
                    country_name,
                    (city or "")[:80],
                    (isp or "")[:120],
                ),
            )


def cleanup_old_logs() -> None:
    cutoff = _iso(_now() - timedelta(days=_RETENTION_DAYS))
    with _LOCK:
        with _conn() as conn:
            conn.execute("DELETE FROM query_logs WHERE ts < ?", (cutoff,))
            conn.execute("DELETE FROM visit_logs WHERE ts < ?", (cutoff,))


def overview_stats() -> dict:
    init_admin_store()
    day = _now().strftime("%Y-%m-%d")
    with _conn() as conn:
        q_today = conn.execute(
            "SELECT COUNT(*) AS c FROM query_logs WHERE ts >= ?", (day,)
        ).fetchone()["c"]
        v_today = conn.execute(
            "SELECT COUNT(*) AS c FROM visit_logs WHERE ts >= ?", (day,)
        ).fetchone()["c"]
        q_total = conn.execute("SELECT COUNT(*) AS c FROM query_logs").fetchone()["c"]
        v_total = conn.execute("SELECT COUNT(*) AS c FROM visit_logs").fetchone()["c"]
        uniq = conn.execute(
            "SELECT COUNT(DISTINCT ip) AS c FROM query_logs WHERE ts >= ?", (day,)
        ).fetchone()["c"]
        wl = conn.execute(
            "SELECT COUNT(*) AS c FROM ip_lists WHERE list_type = ?",
            (LIST_WHITELIST,),
        ).fetchone()["c"]
        bl = conn.execute(
            "SELECT COUNT(*) AS c FROM ip_lists WHERE list_type = ?",
            (LIST_BLACKLIST,),
        ).fetchone()["c"]
    return {
        "queries_today": int(q_today),
        "visits_today": int(v_today),
        "queries_total": int(q_total),
        "visits_total": int(v_total),
        "unique_ips_today": int(uniq),
        "whitelist": int(wl),
        "blacklist": int(bl),
    }


def top_ips(limit: int = 30, days: int = 7) -> list[dict]:
    init_admin_store()
    since = _iso(_now() - timedelta(days=days))
    with _conn() as conn:
        rows = conn.execute(
            """
            SELECT ip,
                   COUNT(*) AS hits,
                   COUNT(DISTINCT tool) AS tools,
                   MAX(ts) AS last_seen,
                   MAX(country_code) AS country_code,
                   MAX(country_name) AS country_name,
                   MAX(os) AS os,
                   MAX(browser) AS browser
            FROM query_logs
            WHERE ts >= ?
            GROUP BY ip
            ORDER BY hits DESC
            LIMIT ?
            """,
            (since, limit),
        ).fetchall()
        out = []
        for r in rows:
            tools = conn.execute(
                """
                SELECT tool, COUNT(*) AS c FROM query_logs
                WHERE ip = ? AND ts >= ?
                GROUP BY tool ORDER BY c DESC LIMIT 8
                """,
                (r["ip"], since),
            ).fetchall()
            item = dict(r)
            item["tool_breakdown"] = [
                {"tool": t["tool"], "count": int(t["c"])} for t in tools
            ]
            item["listed"] = None
            wl = conn.execute(
                "SELECT 1 FROM ip_lists WHERE ip = ? AND list_type = ?",
                (r["ip"], LIST_WHITELIST),
            ).fetchone()
            bl = conn.execute(
                "SELECT 1 FROM ip_lists WHERE ip = ? AND list_type = ?",
                (r["ip"], LIST_BLACKLIST),
            ).fetchone()
            if wl:
                item["listed"] = LIST_WHITELIST
            elif bl:
                item["listed"] = LIST_BLACKLIST
            out.append(item)
    return out


def recent_queries(limit: int = 100, tool: str | None = None, ip: str | None = None) -> list[dict]:
    init_admin_store()
    clauses = []
    args: list = []
    if tool:
        clauses.append("tool = ?")
        args.append(tool)
    if ip:
        clauses.append("ip = ?")
        args.append(ip)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    args.append(limit)
    with _conn() as conn:
        rows = conn.execute(
            f"""
            SELECT id, ts, ip, tool, query, ok, status_code, os, browser, device,
                   country_code, country_name, user_agent
            FROM query_logs
            {where}
            ORDER BY id DESC
            LIMIT ?
            """,
            args,
        ).fetchall()
    return [dict(r) for r in rows]


def tool_stats(days: int = 14) -> dict:
    init_admin_store()
    since = _iso(_now() - timedelta(days=days))
    with _conn() as conn:
        by_tool = conn.execute(
            """
            SELECT tool, COUNT(*) AS c FROM query_logs
            WHERE ts >= ? GROUP BY tool ORDER BY c DESC
            """,
            (since,),
        ).fetchall()
        by_day = conn.execute(
            """
            SELECT substr(ts, 1, 10) AS day, tool, COUNT(*) AS c
            FROM query_logs
            WHERE ts >= ?
            GROUP BY day, tool
            ORDER BY day ASC
            """,
            (since,),
        ).fetchall()
    return {
        "by_tool": [{"tool": r["tool"], "count": int(r["c"])} for r in by_tool],
        "by_day": [
            {"day": r["day"], "tool": r["tool"], "count": int(r["c"])}
            for r in by_day
        ],
        "days": days,
    }


def recent_visits(limit: int = 100, ip: str | None = None) -> list[dict]:
    init_admin_store()
    with _conn() as conn:
        if ip:
            rows = conn.execute(
                """
                SELECT * FROM visit_logs WHERE ip = ?
                ORDER BY id DESC LIMIT ?
                """,
                (ip, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM visit_logs ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
    return [dict(r) for r in rows]


def top_visitors(limit: int = 40, days: int = 7) -> list[dict]:
    init_admin_store()
    since = _iso(_now() - timedelta(days=days))
    with _conn() as conn:
        rows = conn.execute(
            """
            SELECT ip,
                   COUNT(*) AS hits,
                   MAX(ts) AS last_seen,
                   MAX(country_code) AS country_code,
                   MAX(country_name) AS country_name,
                   MAX(city) AS city,
                   MAX(isp) AS isp,
                   MAX(os) AS os,
                   MAX(browser) AS browser,
                   MAX(device) AS device
            FROM visit_logs
            WHERE ts >= ?
            GROUP BY ip
            ORDER BY hits DESC
            LIMIT ?
            """,
            (since, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def country_visit_stats(days: int = 30) -> list[dict]:
    init_admin_store()
    since = _iso(_now() - timedelta(days=days))
    with _conn() as conn:
        rows = conn.execute(
            """
            SELECT country_code AS code,
                   MAX(country_name) AS name,
                   COUNT(*) AS count,
                   COUNT(DISTINCT ip) AS ips
            FROM visit_logs
            WHERE ts >= ? AND country_code != ''
            GROUP BY country_code
            ORDER BY count DESC
            """,
            (since,),
        ).fetchall()
    return [dict(r) for r in rows]
