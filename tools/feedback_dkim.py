"""Optional DKIM signing for feedback outbound mail."""

from __future__ import annotations

import os
from pathlib import Path

INSTANCE = Path(__file__).resolve().parent.parent / "instance"
PRIV_PATH = INSTANCE / "feedback_dkim_private.pem"
PUB_PATH = INSTANCE / "feedback_dkim_public.pem"
SELECTOR = os.environ.get("FEEDBACK_DKIM_SELECTOR", "feedback")


def ensure_dkim_keys() -> tuple[bytes, bytes] | None:
    INSTANCE.mkdir(parents=True, exist_ok=True)
    if PRIV_PATH.exists() and PUB_PATH.exists():
        return PRIV_PATH.read_bytes(), PUB_PATH.read_bytes()

    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except Exception:  # noqa: BLE001
        return None

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    PRIV_PATH.write_bytes(priv)
    PUB_PATH.write_bytes(pub)
    return priv, pub


def dkim_dns_value() -> str | None:
    keys = ensure_dkim_keys()
    if not keys:
        return None
    _, pub_pem = keys
    # Extract base64 body from PEM
    lines = [
        ln.strip()
        for ln in pub_pem.decode().splitlines()
        if ln and not ln.startswith("-----")
    ]
    b64 = "".join(lines)
    return f"v=DKIM1; k=rsa; p={b64}"


def sign_message_bytes(raw: bytes, domain: str) -> bytes:
    keys = ensure_dkim_keys()
    if not keys:
        return raw
    priv, _ = keys
    try:
        import dkim
    except Exception:  # noqa: BLE001
        return raw

    sig = dkim.sign(
        raw,
        selector=SELECTOR.encode(),
        domain=domain.encode(),
        privkey=priv,
        include_headers=[b"from", b"to", b"subject", b"date", b"message-id"],
    )
    return sig + raw
