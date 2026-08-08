"""Visitor country counters for the footer map."""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import contextmanager

_LOCK = threading.Lock()
_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "instance",
    "visitors.db",
)

# Re-count the same IP at most once per day for the visitor map.
_IP_TTL_SEC = 60 * 60 * 24
# Cache geo lookups for 30 days.
_GEO_TTL_SEC = 60 * 60 * 24 * 30


@contextmanager
def _conn():
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(_DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_visitors() -> None:
    with _conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS country_counts (
                country_code TEXT PRIMARY KEY,
                country_name TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS visitor_ips (
                ip TEXT PRIMARY KEY,
                seen_at REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS geo_cache (
                ip TEXT PRIMARY KEY,
                country_code TEXT,
                country_name TEXT,
                checked_at REAL NOT NULL
            )
            """
        )


def _cached_geo(ip: str) -> tuple[str, str] | None:
    now = time.time()
    with _conn() as conn:
        row = conn.execute(
            "SELECT country_code, country_name, checked_at FROM geo_cache WHERE ip = ?",
            (ip,),
        ).fetchone()
        if not row:
            return None
        if now - float(row["checked_at"]) > _GEO_TTL_SEC:
            return None
        code = (row["country_code"] or "").upper()
        name = row["country_name"] or code
        if not code or code == "XX":
            return None
        return code, name


def _store_geo(ip: str, code: str | None, name: str | None) -> None:
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO geo_cache (ip, country_code, country_name, checked_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                country_code = excluded.country_code,
                country_name = excluded.country_name,
                checked_at = excluded.checked_at
            """,
            (ip, code, name, time.time()),
        )


def _resolve_country(ip: str) -> tuple[str, str] | None:
    cached = _cached_geo(ip)
    if cached:
        return cached

    from .ip_info import lookup_geo

    geo = lookup_geo(ip)
    if not geo.get("ok"):
        _store_geo(ip, None, None)
        return None
    code = (geo.get("country_code") or "").strip().upper()
    name = (geo.get("country") or code).strip()
    if not code:
        _store_geo(ip, None, None)
        return None
    _store_geo(ip, code, name)
    return code, name


def track_visitor(ip: str) -> bool:
    """Count a unique visitor (per IP / day) toward their country. Returns True if counted."""
    ip = (ip or "").strip()
    if not ip:
        return False

    init_visitors()
    now = time.time()

    with _LOCK:
        with _conn() as conn:
            row = conn.execute(
                "SELECT seen_at FROM visitor_ips WHERE ip = ?", (ip,)
            ).fetchone()
            if row and now - float(row["seen_at"]) < _IP_TTL_SEC:
                return False
            conn.execute(
                """
                INSERT INTO visitor_ips (ip, seen_at) VALUES (?, ?)
                ON CONFLICT(ip) DO UPDATE SET seen_at = excluded.seen_at
                """,
                (ip, now),
            )

    country = _resolve_country(ip)
    if not country:
        return False
    code, name = country

    with _LOCK:
        with _conn() as conn:
            conn.execute(
                """
                INSERT INTO country_counts (country_code, country_name, count)
                VALUES (?, ?, 1)
                ON CONFLICT(country_code) DO UPDATE SET
                    count = count + 1,
                    country_name = excluded.country_name
                """,
                (code, name),
            )
    return True


def get_country_counts() -> list[dict]:
    init_visitors()
    with _conn() as conn:
        rows = conn.execute(
            """
            SELECT country_code, country_name, count
            FROM country_counts
            WHERE count > 0
            ORDER BY count DESC, country_name ASC
            """
        ).fetchall()
    return [
        {
            "code": row["country_code"],
            "name": row["country_name"],
            "count": int(row["count"]),
        }
        for row in rows
    ]


def visitor_total() -> int:
    return sum(item["count"] for item in get_country_counts())
