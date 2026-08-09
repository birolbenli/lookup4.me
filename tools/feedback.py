"""Issue / bug / feature request submissions + email delivery."""

from __future__ import annotations

import os
import smtplib
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

import dns.resolver

_LOCK = threading.Lock()
_RATE: dict[str, list[float]] = {}
_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "instance",
    "feedback.db",
)

TYPES = {
    "bug": "Bug report",
    "issue": "Issue",
    "feature": "Feature request",
}


@contextmanager
def _conn():
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(_DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_feedback() -> None:
    with _conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                contact_email TEXT,
                page_url TEXT,
                ip TEXT,
                user_agent TEXT,
                emailed INTEGER NOT NULL DEFAULT 0,
                mail_error TEXT,
                created_at TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        cols = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(feedback)").fetchall()
        }
        if "is_read" not in cols:
            conn.execute(
                "ALTER TABLE feedback ADD COLUMN is_read INTEGER NOT NULL DEFAULT 0"
            )


def _rate_ok(ip: str, limit: int = 5, window: int = 3600) -> bool:
    now = time.time()
    with _LOCK:
        hits = [t for t in _RATE.get(ip, []) if now - t < window]
        if len(hits) >= limit:
            _RATE[ip] = hits
            return False
        hits.append(now)
        _RATE[ip] = hits
        return True


def _send_via_smtp(msg: EmailMessage, to_addr: str, from_addr: str) -> None:
    from .feedback_dkim import sign_message_bytes

    host = os.environ.get("FEEDBACK_SMTP_HOST", "").strip()
    port = int(os.environ.get("FEEDBACK_SMTP_PORT", "587"))
    user = os.environ.get("FEEDBACK_SMTP_USER", "").strip()
    password = os.environ.get("FEEDBACK_SMTP_PASSWORD", "").strip()
    use_tls = os.environ.get("FEEDBACK_SMTP_TLS", "1") == "1"
    helo = os.environ.get("FEEDBACK_HELO", "tools.birolbenli.com")
    from_domain = from_addr.rsplit("@", 1)[-1]
    payload = sign_message_bytes(msg.as_bytes(), from_domain)

    if host:
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            smtp.ehlo(helo)
            if use_tls:
                smtp.starttls()
                smtp.ehlo(helo)
            if user:
                smtp.login(user, password)
            smtp.sendmail(from_addr, [to_addr], payload)
        return

    # Direct delivery to recipient MX (works when outbound :25 is open)
    domain = to_addr.rsplit("@", 1)[-1]
    answers = dns.resolver.resolve(domain, "MX")
    mx_hosts = sorted(
        [(r.preference, str(r.exchange).rstrip(".")) for r in answers],
        key=lambda x: x[0],
    )
    last_err: Exception | None = None
    for _, mx in mx_hosts[:3]:
        try:
            with smtplib.SMTP(mx, 25, timeout=30) as smtp:
                smtp.ehlo(helo)
                smtp.sendmail(from_addr, [to_addr], payload)
            return
        except Exception as exc:  # noqa: BLE001
            last_err = exc
    raise RuntimeError(f"MX delivery failed: {last_err}")


def send_feedback_email(
    *,
    kind: str,
    title: str,
    message: str,
    contact_email: str = "",
    page_url: str = "",
    ip: str = "",
    user_agent: str = "",
) -> None:
    to_addr = os.environ.get("FEEDBACK_TO", "birolbenli@gmail.com")
    from_addr = os.environ.get("FEEDBACK_FROM", "noreply@tools.birolbenli.com")
    kind_label = TYPES.get(kind, kind)

    domain = from_addr.rsplit("@", 1)[-1]
    msg = EmailMessage()
    msg["Subject"] = f"[tools.birolbenli.com {kind_label}] {title[:120]}"
    msg["From"] = f"tools.birolbenli.com <{from_addr}>"
    msg["To"] = to_addr
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=domain)
    msg["X-Mailer"] = "tools.birolbenli.com-feedback"
    if contact_email:
        msg["Reply-To"] = contact_email

    body = (
        f"Type: {kind_label}\n"
        f"Title: {title}\n"
        f"Contact: {contact_email or '(not provided)'}\n"
        f"Page: {page_url or '(not provided)'}\n"
        f"IP: {ip or '(unknown)'}\n"
        f"User-Agent: {user_agent or '(unknown)'}\n"
        f"Time (UTC): {datetime.now(timezone.utc).isoformat()}\n"
        f"\n--- Message ---\n{message}\n"
    )
    msg.set_content(body)
    _send_via_smtp(msg, to_addr, from_addr)


def submit_feedback(
    *,
    kind: str,
    title: str,
    message: str,
    contact_email: str = "",
    page_url: str = "",
    ip: str = "",
    user_agent: str = "",
    honeypot: str = "",
) -> dict:
    init_feedback()

    if honeypot.strip():
        # Silent success for bots
        return {"ok": True, "queued": True}

    kind = (kind or "").strip().lower()
    title = (title or "").strip()
    message = (message or "").strip()
    contact_email = (contact_email or "").strip()
    page_url = (page_url or "").strip()[:500]

    if kind not in TYPES:
        return {"ok": False, "error": "Please choose a valid report type."}
    if len(title) < 3:
        return {"ok": False, "error": "Please enter a short title."}
    if len(message) < 10:
        return {"ok": False, "error": "Please describe the issue or request in more detail."}
    if len(title) > 200:
        return {"ok": False, "error": "Title is too long."}
    if len(message) > 8000:
        return {"ok": False, "error": "Message is too long (max 8000 characters)."}
    if contact_email and ("@" not in contact_email or "." not in contact_email.split("@")[-1]):
        return {"ok": False, "error": "Contact email looks invalid."}

    ip = ip or "unknown"
    if not _rate_ok(ip):
        return {"ok": False, "error": "Too many submissions from this IP. Please try again later."}

    # Optional email (off by default — admin Inbox is the primary destination).
    emailed = 0
    mail_error = None
    send_mail = os.environ.get("FEEDBACK_EMAIL", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if send_mail:
        try:
            send_feedback_email(
                kind=kind,
                title=title,
                message=message,
                contact_email=contact_email,
                page_url=page_url,
                ip=ip,
                user_agent=user_agent,
            )
            emailed = 1
        except Exception as exc:  # noqa: BLE001
            mail_error = str(exc)[:500]

    with _conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO feedback
            (kind, title, message, contact_email, page_url, ip, user_agent,
             emailed, mail_error, created_at, is_read)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (
                kind,
                title,
                message,
                contact_email,
                page_url,
                ip,
                (user_agent or "")[:400],
                emailed,
                mail_error,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        row_id = cur.lastrowid

    return {
        "ok": True,
        "id": row_id,
        "message": "Thanks — your report was received.",
    }


def _row_to_item(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "kind": row["kind"],
        "title": row["title"],
        "message": row["message"],
        "contact_email": row["contact_email"] or "",
        "page_url": row["page_url"] or "",
        "ip": row["ip"] or "",
        "user_agent": row["user_agent"] or "",
        "emailed": bool(row["emailed"]),
        "created_at": row["created_at"],
        "is_read": bool(row["is_read"]),
    }


def list_feedback(limit: int = 100, unread_only: bool = False) -> list[dict]:
    init_feedback()
    limit = max(1, min(int(limit), 500))
    with _conn() as conn:
        if unread_only:
            rows = conn.execute(
                """
                SELECT * FROM feedback
                WHERE is_read = 0
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM feedback
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
    return [_row_to_item(r) for r in rows]


def feedback_unread_count() -> int:
    init_feedback()
    with _conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM feedback WHERE is_read = 0"
        ).fetchone()
    return int(row["c"] if row else 0)


def get_feedback(item_id: int) -> dict | None:
    init_feedback()
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM feedback WHERE id = ?", (int(item_id),)
        ).fetchone()
    return _row_to_item(row) if row else None


def mark_feedback_read(item_id: int, is_read: bool = True) -> bool:
    init_feedback()
    with _LOCK:
        with _conn() as conn:
            cur = conn.execute(
                "UPDATE feedback SET is_read = ? WHERE id = ?",
                (1 if is_read else 0, int(item_id)),
            )
            return cur.rowcount > 0


def delete_feedback(item_id: int) -> bool:
    init_feedback()
    with _LOCK:
        with _conn() as conn:
            cur = conn.execute(
                "DELETE FROM feedback WHERE id = ?", (int(item_id),)
            )
            return cur.rowcount > 0
