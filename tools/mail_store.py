"""Persistent mail-test sessions and inbox storage."""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import string
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

_LOCK = threading.Lock()
_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "instance",
    "mailtest.db",
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


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


def init_mail_store() -> None:
    with _conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mail_tests (
                id TEXT PRIMARY KEY,
                token TEXT UNIQUE NOT NULL,
                address TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL,
                peer_ip TEXT,
                envelope_from TEXT,
                raw_message TEXT,
                analysis_json TEXT
            )
            """
        )


def _token(length: int = 10) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def create_test(domain: str, ttl_hours: int = 24) -> dict:
    init_mail_store()
    domain = domain.strip().lower().rstrip(".")
    now = _now()
    test_id = secrets.token_hex(8)
    token = _token()
    address = f"{token}@{domain}"
    with _LOCK:
        with _conn() as conn:
            # ensure unique token
            for _ in range(5):
                exists = conn.execute(
                    "SELECT 1 FROM mail_tests WHERE token = ?", (token,)
                ).fetchone()
                if not exists:
                    break
                token = _token()
                address = f"{token}@{domain}"
            conn.execute(
                """
                INSERT INTO mail_tests (id, token, address, created_at, expires_at, status)
                VALUES (?, ?, ?, ?, ?, 'waiting')
                """,
                (test_id, token, address, _iso(now), _iso(now + timedelta(hours=ttl_hours))),
            )
    return {
        "ok": True,
        "id": test_id,
        "token": token,
        "address": address,
        "domain": domain,
        "status": "waiting",
        "expires_at": _iso(now + timedelta(hours=ttl_hours)),
    }


def get_test(test_id: str) -> dict | None:
    init_mail_store()
    with _conn() as conn:
        row = conn.execute("SELECT * FROM mail_tests WHERE id = ?", (test_id,)).fetchone()
    if not row:
        return None
    return _row_to_dict(row)


def get_test_by_token(token: str) -> dict | None:
    init_mail_store()
    token = (token or "").strip().lower()
    with _conn() as conn:
        row = conn.execute("SELECT * FROM mail_tests WHERE token = ?", (token,)).fetchone()
    if not row:
        return None
    return _row_to_dict(row)


def _row_to_dict(row: sqlite3.Row) -> dict:
    analysis = None
    if row["analysis_json"]:
        try:
            analysis = json.loads(row["analysis_json"])
        except json.JSONDecodeError:
            analysis = None
    expired = False
    try:
        expires = datetime.fromisoformat(row["expires_at"])
        expired = _now() > expires
    except Exception:  # noqa: BLE001
        pass
    status = row["status"]
    if expired and status == "waiting":
        status = "expired"
    return {
        "ok": True,
        "id": row["id"],
        "token": row["token"],
        "address": row["address"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "status": status,
        "peer_ip": row["peer_ip"],
        "envelope_from": row["envelope_from"],
        "has_message": bool(row["raw_message"]),
        "analysis": analysis,
    }


def accept_address(address: str, expected_domain: str | None = None) -> dict | None:
    """Return waiting test if address matches an active token."""
    address = (address or "").strip().lower()
    if "@" not in address:
        return None
    local, _, domain = address.partition("@")
    if expected_domain and domain != expected_domain.strip().lower().rstrip("."):
        return None
    test = get_test_by_token(local)
    if not test:
        return None
    if test["status"] != "waiting":
        return None
    if test["address"] != address:
        return None
    return test


def store_message(
    token: str,
    raw_message: str,
    peer_ip: str | None,
    envelope_from: str | None,
    analysis: dict,
) -> bool:
    init_mail_store()
    with _LOCK:
        with _conn() as conn:
            cur = conn.execute(
                """
                UPDATE mail_tests
                SET status = 'received',
                    peer_ip = ?,
                    envelope_from = ?,
                    raw_message = ?,
                    analysis_json = ?
                WHERE token = ? AND status = 'waiting'
                """,
                (
                    peer_ip,
                    envelope_from,
                    raw_message,
                    json.dumps(analysis),
                    token.lower(),
                ),
            )
            return cur.rowcount > 0


def list_tests(limit: int = 100, status: str | None = None) -> list[dict]:
    """Admin listing of mail tests (no raw message bodies)."""
    init_mail_store()
    with _conn() as conn:
        if status:
            rows = conn.execute(
                """
                SELECT id, token, address, created_at, expires_at, status,
                       peer_ip, envelope_from, raw_message, analysis_json
                FROM mail_tests
                WHERE status = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (status, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, token, address, created_at, expires_at, status,
                       peer_ip, envelope_from, raw_message, analysis_json
                FROM mail_tests
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
    out = []
    for row in rows:
        item = _row_to_dict(row)
        # Drop bulky analysis for list view; keep score if present.
        analysis = item.pop("analysis", None) or {}
        item["score"] = analysis.get("score")
        item["score_label"] = analysis.get("score_label")
        item["from_header"] = (analysis.get("meta") or {}).get("from")
        item["subject"] = (analysis.get("meta") or {}).get("subject")
        out.append(item)
    return out


def cleanup_expired(limit: int = 200) -> int:
    init_mail_store()
    cutoff = _iso(_now())
    with _LOCK:
        with _conn() as conn:
            cur = conn.execute(
                """
                DELETE FROM mail_tests
                WHERE expires_at < ?
                   OR (status = 'received' AND created_at < ?)
                """,
                (cutoff, _iso(_now() - timedelta(days=7))),
            )
            return cur.rowcount
