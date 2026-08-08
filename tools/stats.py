"""Persistent query counters."""

from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager

_LOCK = threading.Lock()
_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "instance",
    "stats.db",
)


@contextmanager
def _conn():
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(_DB_PATH, timeout=10)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_stats() -> None:
    with _conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS query_counts (
                tool TEXT PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0
            )
            """
        )


def bump(tool: str) -> int:
    tool = (tool or "unknown").strip().lower()
    with _LOCK:
        with _conn() as conn:
            conn.execute(
                """
                INSERT INTO query_counts (tool, count) VALUES (?, 1)
                ON CONFLICT(tool) DO UPDATE SET count = count + 1
                """,
                (tool,),
            )
            row = conn.execute(
                "SELECT count FROM query_counts WHERE tool = ?", (tool,)
            ).fetchone()
            return int(row[0]) if row else 1


def get_counts() -> dict[str, int]:
    init_stats()
    with _conn() as conn:
        rows = conn.execute(
            "SELECT tool, count FROM query_counts ORDER BY count DESC, tool ASC"
        ).fetchall()
    return {tool: int(count) for tool, count in rows}


def total_count() -> int:
    return sum(get_counts().values())
