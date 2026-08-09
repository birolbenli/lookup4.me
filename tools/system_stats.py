"""Container resource snapshot + 24h history (Cacti-style sampling)."""

from __future__ import annotations

import os
import shutil
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

_LOCK = threading.Lock()
_SAMPLER_STARTED = False
_LAST_CPU: tuple[float, float] | None = None

_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "instance",
    "system_metrics.db",
)
_RETENTION_HOURS = 24
_SAMPLE_INTERVAL_SEC = 60


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None = None) -> str:
    return (dt or _now()).astimezone(timezone.utc).isoformat()


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


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


def init_metrics_store() -> None:
    with _conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS samples (
                ts TEXT PRIMARY KEY,
                cpu REAL,
                mem REAL,
                disk REAL,
                load1 REAL
            )
            """
        )


def _cpu_times() -> tuple[float, float] | None:
    line = ""
    for row in _read_text("/proc/stat").splitlines():
        if row.startswith("cpu "):
            line = row
            break
    if not line:
        return None
    parts = line.split()[1:]
    try:
        vals = [float(x) for x in parts]
    except ValueError:
        return None
    if len(vals) < 4:
        return None
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0.0)
    total = sum(vals)
    return idle, total


def _cpu_percent_delta() -> float | None:
    """CPU % since previous sample (no sleep)."""
    global _LAST_CPU
    now = _cpu_times()
    if not now:
        return None
    prev = _LAST_CPU
    _LAST_CPU = now
    if not prev:
        return 0.0
    idle = now[0] - prev[0]
    total = now[1] - prev[1]
    if total <= 0:
        return 0.0
    return round(max(0.0, min(100.0, (1.0 - idle / total) * 100.0)), 1)


def _cpu_percent_sample(sample_sec: float = 0.12) -> float | None:
    a = _cpu_times()
    if not a:
        return None
    time.sleep(max(0.05, sample_sec))
    b = _cpu_times()
    if not b:
        return None
    idle = b[0] - a[0]
    total = b[1] - a[1]
    if total <= 0:
        return 0.0
    return round(max(0.0, min(100.0, (1.0 - idle / total) * 100.0)), 1)


def _mem_cgroup() -> tuple[int | None, int | None]:
    for base in ("/sys/fs/cgroup", "/sys/fs/cgroup/memory"):
        cur = _read_text(f"{base}/memory.current").strip() or _read_text(
            f"{base}/memory.usage_in_bytes"
        ).strip()
        lim = _read_text(f"{base}/memory.max").strip() or _read_text(
            f"{base}/memory.limit_in_bytes"
        ).strip()
        if cur.isdigit():
            used = int(cur)
            limit = None
            if lim and lim != "max" and lim.isdigit():
                n = int(lim)
                if n < 1 << 50:
                    limit = n
            return used, limit
    return None, None


def _mem_proc() -> tuple[int, int]:
    info = {}
    for line in _read_text("/proc/meminfo").splitlines():
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        bits = rest.strip().split()
        if bits and bits[0].isdigit():
            info[key] = int(bits[0]) * 1024
    total = info.get("MemTotal") or 0
    avail = info.get("MemAvailable") or info.get("MemFree") or 0
    used = max(0, total - avail) if total else 0
    return used, total


def _disk_usage(path: str = "/app") -> dict:
    try:
        u = shutil.disk_usage(path)
        percent = round((u.used / u.total) * 100.0, 1) if u.total else 0.0
        return {
            "path": path,
            "total_bytes": u.total,
            "used_bytes": u.used,
            "free_bytes": u.free,
            "percent": percent,
        }
    except OSError:
        return {
            "path": path,
            "total_bytes": 0,
            "used_bytes": 0,
            "free_bytes": 0,
            "percent": 0.0,
        }


def _fmt_bytes(n: int | None) -> str:
    if n is None or n < 0:
        return "—"
    units = ["B", "KB", "MB", "GB", "TB"]
    val = float(n)
    for unit in units:
        if val < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(val)} {unit}"
            return f"{val:.1f} {unit}"
        val /= 1024
    return f"{n} B"


def _memory_stats() -> dict:
    cg_used, cg_limit = _mem_cgroup()
    proc_used, proc_total = _mem_proc()
    if cg_used is not None and cg_limit:
        mem_used, mem_total = cg_used, cg_limit
        mem_source = "cgroup"
    else:
        mem_used, mem_total = proc_used, proc_total
        mem_source = "proc"
        if cg_used is not None:
            mem_used = cg_used
    mem_percent = round((mem_used / mem_total) * 100.0, 1) if mem_total else 0.0
    return {
        "used_bytes": mem_used,
        "total_bytes": mem_total,
        "percent": mem_percent,
        "used_human": _fmt_bytes(mem_used),
        "total_human": _fmt_bytes(mem_total),
        "source": mem_source,
    }


def collect_sample(*, live_cpu: bool = False) -> dict:
    cpu = _cpu_percent_sample() if live_cpu else _cpu_percent_delta()
    mem = _memory_stats()
    disk = _disk_usage("/app")
    loadavg = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)
    return {
        "ts": _iso(),
        "cpu_percent": cpu if cpu is not None else 0.0,
        "mem_percent": mem["percent"],
        "disk_percent": disk["percent"],
        "load1": round(float(loadavg[0]), 2),
        "memory": mem,
        "disk": {
            **disk,
            "used_human": _fmt_bytes(disk["used_bytes"]),
            "total_human": _fmt_bytes(disk["total_bytes"]),
            "free_human": _fmt_bytes(disk["free_bytes"]),
        },
        "loadavg": [round(x, 2) for x in loadavg],
        "hostname": _read_text("/etc/hostname").strip()
        or os.environ.get("HOSTNAME")
        or "—",
    }


def record_sample() -> dict:
    init_metrics_store()
    sample = collect_sample(live_cpu=False)
    cutoff = _iso(_now() - timedelta(hours=_RETENTION_HOURS))
    with _LOCK:
        with _conn() as conn:
            conn.execute(
                """
                INSERT INTO samples (ts, cpu, mem, disk, load1)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ts) DO UPDATE SET
                  cpu=excluded.cpu, mem=excluded.mem,
                  disk=excluded.disk, load1=excluded.load1
                """,
                (
                    sample["ts"],
                    sample["cpu_percent"],
                    sample["mem_percent"],
                    sample["disk_percent"],
                    sample["load1"],
                ),
            )
            conn.execute("DELETE FROM samples WHERE ts < ?", (cutoff,))
    return sample


def history(hours: int = 24) -> list[dict]:
    init_metrics_store()
    hours = max(1, min(int(hours), 72))
    cutoff = _iso(_now() - timedelta(hours=hours))
    with _conn() as conn:
        rows = conn.execute(
            """
            SELECT ts, cpu, mem, disk, load1
            FROM samples
            WHERE ts >= ?
            ORDER BY ts ASC
            """,
            (cutoff,),
        ).fetchall()
    return [
        {
            "ts": r["ts"],
            "cpu": r["cpu"],
            "mem": r["mem"],
            "disk": r["disk"],
            "load1": r["load1"],
        }
        for r in rows
    ]


def system_snapshot(*, with_history: bool = True) -> dict:
    # Live snapshot uses a short sample for accurate current CPU.
    sample = collect_sample(live_cpu=True)
    # Also persist this point so the graph fills even without waiting for sampler.
    try:
        init_metrics_store()
        cutoff = _iso(_now() - timedelta(hours=_RETENTION_HOURS))
        with _LOCK:
            with _conn() as conn:
                conn.execute(
                    """
                    INSERT INTO samples (ts, cpu, mem, disk, load1)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(ts) DO UPDATE SET
                      cpu=excluded.cpu, mem=excluded.mem,
                      disk=excluded.disk, load1=excluded.load1
                    """,
                    (
                        sample["ts"],
                        sample["cpu_percent"],
                        sample["mem_percent"],
                        sample["disk_percent"],
                        sample["load1"],
                    ),
                )
                conn.execute("DELETE FROM samples WHERE ts < ?", (cutoff,))
    except Exception:  # noqa: BLE001
        pass

    out = {
        "ok": True,
        "cpu_percent": sample["cpu_percent"],
        "loadavg": sample["loadavg"],
        "memory": sample["memory"],
        "disk": sample["disk"],
        "hostname": sample["hostname"],
        "sampled_at": sample["ts"],
    }
    if with_history:
        out["history"] = history(24)
    return out


def _sampler_loop() -> None:
    # Prime CPU delta baseline
    _cpu_percent_delta()
    while True:
        try:
            record_sample()
        except Exception:  # noqa: BLE001
            pass
        time.sleep(_SAMPLE_INTERVAL_SEC)


def start_metrics_sampler() -> None:
    global _SAMPLER_STARTED
    if _SAMPLER_STARTED:
        return
    _SAMPLER_STARTED = True
    init_metrics_store()
    t = threading.Thread(target=_sampler_loop, name="metrics-sampler", daemon=True)
    t.start()
