"""Lightweight container/host resource snapshot (no extra deps)."""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _cpu_times() -> tuple[float, float] | None:
    """Return (idle, total) jiffies from /proc/stat."""
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


def _cpu_percent(sample_sec: float = 0.12) -> float | None:
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
    used = max(0.0, min(100.0, (1.0 - idle / total) * 100.0))
    return round(used, 1)


def _mem_cgroup() -> tuple[int | None, int | None]:
    """Return (used_bytes, limit_bytes) from cgroup v2/v1 when available."""
    # cgroup v2
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
                # Ignore absurd host-sized limits
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
            info[key] = int(bits[0]) * 1024  # kB → bytes
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


def system_snapshot() -> dict:
    cpu = _cpu_percent()
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

    mem_percent = (
        round((mem_used / mem_total) * 100.0, 1) if mem_total else 0.0
    )
    disk = _disk_usage("/app")
    loadavg = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)

    return {
        "ok": True,
        "cpu_percent": cpu,
        "loadavg": [round(x, 2) for x in loadavg],
        "memory": {
            "used_bytes": mem_used,
            "total_bytes": mem_total,
            "percent": mem_percent,
            "used_human": _fmt_bytes(mem_used),
            "total_human": _fmt_bytes(mem_total),
            "source": mem_source,
        },
        "disk": {
            **disk,
            "used_human": _fmt_bytes(disk["used_bytes"]),
            "total_human": _fmt_bytes(disk["total_bytes"]),
            "free_human": _fmt_bytes(disk["free_bytes"]),
        },
        "hostname": _read_text("/etc/hostname").strip() or os.environ.get("HOSTNAME") or "—",
    }
