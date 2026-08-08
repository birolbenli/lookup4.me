"""Per-IP daily rate limits for tool APIs."""

from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

_LOCK = threading.Lock()
_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "instance",
    "rate_limit.db",
)

BUCKET_MAILTEST = "mailtest"
BUCKET_TOOLS = "tools"

DEFAULT_LIMITS = {
    BUCKET_MAILTEST: 5,
    BUCKET_TOOLS: 10,
}


def limit_for(bucket: str) -> int:
    env_key = {
        BUCKET_MAILTEST: "RATE_LIMIT_MAILTEST",
        BUCKET_TOOLS: "RATE_LIMIT_TOOLS",
    }.get(bucket)
    raw = os.environ.get(env_key or "", "")
    if raw.strip().isdigit():
        return max(0, int(raw.strip()))
    return DEFAULT_LIMITS.get(bucket, 10)


def _day_key(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%d")


def _reset_at(day: str) -> str:
    """ISO timestamp when the daily window resets (next UTC midnight)."""
    base = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return (base + timedelta(days=1)).isoformat()


@contextmanager
def _conn():
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(_DB_PATH, timeout=10)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_rate_limit() -> None:
    with _conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ip_daily (
                ip TEXT NOT NULL,
                bucket TEXT NOT NULL,
                day TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (ip, bucket, day)
            )
            """
        )
        # Drop stale rows (keep today + yesterday).
        today = _day_key()
        yesterday = (
            datetime.now(timezone.utc) - timedelta(days=1)
        ).strftime("%Y-%m-%d")
        conn.execute(
            "DELETE FROM ip_daily WHERE day NOT IN (?, ?)",
            (today, yesterday),
        )


def peek(ip: str, bucket: str) -> dict:
    """Read usage without consuming a credit."""
    ip = (ip or "").strip() or "unknown"
    bucket = (bucket or BUCKET_TOOLS).strip().lower()
    limit = limit_for(bucket)
    day = _day_key()
    init_rate_limit()
    with _conn() as conn:
        row = conn.execute(
            "SELECT count FROM ip_daily WHERE ip = ? AND bucket = ? AND day = ?",
            (ip, bucket, day),
        ).fetchone()
    used = int(row[0]) if row else 0
    remaining = max(0, limit - used)
    return {
        "ok": True,
        "ip": ip,
        "bucket": bucket,
        "limit": limit,
        "used": used,
        "remaining": remaining,
        "day": day,
        "reset_at": _reset_at(day),
        "allowed": used < limit if limit > 0 else False,
    }


def consume(ip: str, bucket: str) -> dict:
    """
    Consume one daily credit for ip/bucket.
    Returns allowed=False when the limit is already reached (no increment).
    """
    ip = (ip or "").strip() or "unknown"
    bucket = (bucket or BUCKET_TOOLS).strip().lower()
    limit = limit_for(bucket)
    day = _day_key()
    init_rate_limit()

    with _LOCK:
        with _conn() as conn:
            row = conn.execute(
                "SELECT count FROM ip_daily WHERE ip = ? AND bucket = ? AND day = ?",
                (ip, bucket, day),
            ).fetchone()
            used = int(row[0]) if row else 0
            if limit <= 0 or used >= limit:
                return {
                    "ok": False,
                    "allowed": False,
                    "code": "rate_limited",
                    "ip": ip,
                    "bucket": bucket,
                    "limit": limit,
                    "used": used,
                    "remaining": 0,
                    "day": day,
                    "reset_at": _reset_at(day),
                    "error": _error_message(bucket, limit),
                }
            if row:
                conn.execute(
                    """
                    UPDATE ip_daily SET count = count + 1
                    WHERE ip = ? AND bucket = ? AND day = ?
                    """,
                    (ip, bucket, day),
                )
                used = used + 1
            else:
                conn.execute(
                    """
                    INSERT INTO ip_daily (ip, bucket, day, count)
                    VALUES (?, ?, ?, 1)
                    """,
                    (ip, bucket, day),
                )
                used = 1

    return {
        "ok": True,
        "allowed": True,
        "ip": ip,
        "bucket": bucket,
        "limit": limit,
        "used": used,
        "remaining": max(0, limit - used),
        "day": day,
        "reset_at": _reset_at(day),
    }


def _error_message(bucket: str, limit: int) -> str:
    if bucket == BUCKET_MAILTEST:
        return (
            f"Daily Mail Tester limit reached ({limit}/day per IP). "
            "Try again after UTC midnight."
        )
    return (
        f"Daily tool limit reached ({limit}/day per IP). "
        "Try again after UTC midnight."
    )
