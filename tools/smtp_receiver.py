"""Lightweight SMTP sink for mail-tester addresses."""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from email.utils import parseaddr

from .email_analyze import analyze_email
from .mail_store import accept_address, cleanup_expired, store_message

log = logging.getLogger("lookup4me.smtp")

_STARTED = False


class _Handler:
    def __init__(self, domain: str):
        self.domain = domain

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        test = accept_address(address, expected_domain=self.domain)
        if not test:
            return "550 No such test mailbox. Create a new test on tools.birolbenli.com first."
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        if not envelope.rcpt_tos:
            return "554 No valid recipients"
        cleanup_expired()
        raw = envelope.content
        if isinstance(raw, bytes):
            raw_text = raw.decode("utf-8", errors="replace")
            raw_bytes_len = len(raw)
        else:
            raw_text = str(raw)
            raw_bytes_len = len(raw_text.encode("utf-8", errors="replace"))

        if raw_bytes_len > 1_500_000:
            return "552 Message too large"

        peer_ip = None
        if session.peer:
            peer_ip = session.peer[0]

        envelope_from = envelope.mail_from or ""
        # Normalize mail_from angle brackets
        envelope_from = parseaddr(f"<{envelope_from}>")[1] or envelope_from

        analysis = analyze_email(
            raw_text,
            peer_ip=peer_ip,
            envelope_from=envelope_from,
            mode="mailtest",
        )

        domain = os.environ.get("MAILTEST_DOMAIN", "tools.birolbenli.com").lower()
        saved_any = False
        for rcpt in envelope.rcpt_tos:
            test = accept_address(rcpt, expected_domain=domain)
            if not test:
                continue
            token = test["token"]
            if store_message(token, raw_text, peer_ip, envelope_from, analysis):
                saved_any = True
                log.info("Stored mailtest message for %s from %s", rcpt, peer_ip)

        if not saved_any:
            return "550 Mailbox no longer waiting for messages"
        return "250 Message accepted for analysis"


async def _run_smtp(host: str, port: int, domain: str) -> None:
    from aiosmtpd.controller import Controller

    handler = _Handler(domain)
    controller = Controller(handler, hostname=host, port=port, decode_data=False)
    controller.start()
    log.info("Mail-test SMTP sink listening on %s:%s", host, port)
    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        controller.stop()


def start_smtp_receiver() -> None:
    global _STARTED
    if _STARTED:
        return
    if os.environ.get("MAILTEST_SMTP_ENABLED", "1") != "1":
        log.info("MAILTEST_SMTP_ENABLED!=1 — SMTP sink not started")
        return

    host = os.environ.get("MAILTEST_SMTP_HOST", "0.0.0.0")
    port = int(os.environ.get("MAILTEST_SMTP_PORT", "2525"))
    domain = os.environ.get("MAILTEST_DOMAIN", "tools.birolbenli.com")

    def runner():
        try:
            asyncio.run(_run_smtp(host, port, domain))
        except Exception:  # noqa: BLE001
            log.exception("SMTP sink crashed")

    thread = threading.Thread(target=runner, name="smtp-sink", daemon=True)
    thread.start()
    _STARTED = True
