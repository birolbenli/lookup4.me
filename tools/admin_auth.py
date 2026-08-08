"""TOTP admin authentication helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import os
import secrets
import time

import pyotp

from .admin_store import get_setting, set_setting

SESSION_TTL_SEC = 60 * 60 * 12  # 12 hours
SETTING_TOTP = "totp_secret"
SETTING_TOTP_ACTIVE = "totp_active"


def _secret_key() -> bytes:
    key = os.environ.get("SECRET_KEY", "").strip()
    if key:
        return key.encode("utf-8")
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "instance",
        "secret.key",
    )
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.isfile(path):
        return open(path, "rb").read().strip()
    raw = secrets.token_bytes(32)
    with open(path, "wb") as fh:
        fh.write(raw)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return raw


def flask_secret_key() -> str:
    return base64.urlsafe_b64encode(_secret_key()).decode("ascii")


def is_setup_complete() -> bool:
    return get_setting(SETTING_TOTP_ACTIVE) == "1" and bool(get_setting(SETTING_TOTP))


def begin_setup(force_new: bool = False) -> dict:
    """Create (or reuse pending) TOTP secret and return provisioning info."""
    if is_setup_complete() and not force_new:
        return {"ok": False, "error": "Authenticator already configured", "active": True}

    secret = get_setting(SETTING_TOTP)
    if force_new or not secret:
        secret = pyotp.random_base32()
        set_setting(SETTING_TOTP, secret)
        set_setting(SETTING_TOTP_ACTIVE, "0")

    issuer = "tools.birolbenli.com"
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name="admin", issuer_name=issuer)
    return {
        "ok": True,
        "secret": secret,
        "otpauth_url": uri,
        "qr_svg": _qr_svg(uri),
        "active": False,
    }


def confirm_setup(code: str) -> dict:
    secret = get_setting(SETTING_TOTP)
    if not secret:
        return {"ok": False, "error": "No TOTP secret — start setup first"}
    if not verify_code(code, secret):
        return {"ok": False, "error": "Invalid authenticator code"}
    set_setting(SETTING_TOTP_ACTIVE, "1")
    return {"ok": True}


def verify_login(code: str) -> dict:
    if not is_setup_complete():
        return {"ok": False, "error": "Admin TOTP is not set up yet"}
    secret = get_setting(SETTING_TOTP) or ""
    if not verify_code(code, secret):
        return {"ok": False, "error": "Invalid authenticator code"}
    token = issue_session()
    return {"ok": True, "token": token}


def verify_code(code: str, secret: str | None = None) -> bool:
    secret = secret or get_setting(SETTING_TOTP) or ""
    code = (code or "").strip().replace(" ", "")
    if not secret or not code.isdigit():
        return False
    totp = pyotp.TOTP(secret)
    return bool(totp.verify(code, valid_window=1))


def issue_session() -> str:
    ts = str(int(time.time()))
    nonce = secrets.token_hex(8)
    msg = f"{ts}:{nonce}".encode()
    sig = hmac.new(_secret_key(), msg, hashlib.sha256).hexdigest()
    return f"{ts}:{nonce}:{sig}"


def validate_session(token: str | None) -> bool:
    if not token or token.count(":") != 2:
        return False
    ts_s, nonce, sig = token.split(":", 2)
    try:
        ts = int(ts_s)
    except ValueError:
        return False
    if abs(time.time() - ts) > SESSION_TTL_SEC:
        return False
    msg = f"{ts_s}:{nonce}".encode()
    expect = hmac.new(_secret_key(), msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expect, sig)


def setup_token_ok(provided: str | None) -> bool:
    """Optional gate for first-time setup via ADMIN_SETUP_TOKEN env."""
    expected = os.environ.get("ADMIN_SETUP_TOKEN", "").strip()
    if not expected:
        return True
    return hmac.compare_digest(expected, (provided or "").strip())


def _qr_svg(data: str) -> str:
    try:
        import qrcode
        import qrcode.image.svg

        factory = qrcode.image.svg.SvgPathImage
        img = qrcode.make(data, image_factory=factory, box_size=6, border=2)
        buf = io.BytesIO()
        img.save(buf)
        return buf.getvalue().decode("utf-8")
    except Exception:  # noqa: BLE001
        return ""
