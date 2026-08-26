"""Limit concurrent heavy external probes so gunicorn stays responsive."""

from __future__ import annotations

import os
import threading

# Keep small on 512MB hosts — Exchange/SSL/SMTP can each hold a thread for a long time.
_LIMIT = max(1, int(os.environ.get("HEAVY_CONCURRENCY", "2")))
_SEM = threading.BoundedSemaphore(_LIMIT)

HEAVY_SLUGS = frozenset(
    {
        "exchange",
        "exchangecve",
        "autodiscover",
        "ssl",
        "smtp",
        "blacklist",
        "whois",
        "secheaders",
        "redirect",
        "hsts",
        "mtasts",
        "bimi",
        "dane",
        "securitytxt",
        "robots",
        "spfgen",
        "dmarcgen",
        "mtastsgen",
        "tlsrptgen",
        "caagen",
        "securitytxtgen",
    }
)


def try_acquire_heavy(slug: str) -> bool:
    """Non-blocking. Returns True if caller must release_heavy() later."""
    if slug not in HEAVY_SLUGS:
        return False
    return _SEM.acquire(blocking=False)


def release_heavy() -> None:
    try:
        _SEM.release()
    except ValueError:
        pass
