"""Admin auth: username/password + TOTP authenticator."""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import os
import secrets
import time
from urllib.parse import quote

import pyotp

from .admin_store import get_setting, set_setting

SESSION_TTL_SEC = 60 * 60 * 12  # full session 12h
PREAUTH_TTL_SEC = 60 * 15  # password-ok window for OTP/setup
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


def admin_credentials() -> tuple[str, str]:
    user = (os.environ.get("ADMIN_USER") or "admin").strip()
    password = (os.environ.get("ADMIN_PASSWORD") or "").strip()
    return user, password


def password_configured() -> bool:
    return bool(admin_credentials()[1])


def verify_password(username: str, password: str) -> bool:
    expect_user, expect_pass = admin_credentials()
    if not expect_pass:
        return False
    user_ok = hmac.compare_digest(expect_user, (username or "").strip())
    pass_ok = hmac.compare_digest(expect_pass, password or "")
    return user_ok and pass_ok


def is_setup_complete() -> bool:
    return get_setting(SETTING_TOTP_ACTIVE) == "1" and bool(get_setting(SETTING_TOTP))


def _sign(parts: list[str]) -> str:
    msg = ":".join(parts).encode()
    sig = hmac.new(_secret_key(), msg, hashlib.sha256).hexdigest()
    return f"{':'.join(parts)}:{sig}"


def _parse_token(token: str | None, expected_kind: str, ttl: int) -> bool:
    if not token:
        return False
    bits = token.split(":")
    if len(bits) != 4:
        return False
    kind, ts_s, nonce, sig = bits
    if kind != expected_kind:
        return False
    try:
        ts = int(ts_s)
    except ValueError:
        return False
    if abs(time.time() - ts) > ttl:
        return False
    msg = f"{kind}:{ts_s}:{nonce}".encode()
    expect = hmac.new(_secret_key(), msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expect, sig)


def issue_session(kind: str = "full") -> str:
    """kind: full | preauth"""
    ts = str(int(time.time()))
    nonce = secrets.token_hex(8)
    return _sign([kind, ts, nonce])


def validate_session(token: str | None) -> bool:
    return _parse_token(token, "full", SESSION_TTL_SEC)


def validate_preauth(token: str | None) -> bool:
    return _parse_token(token, "preauth", PREAUTH_TTL_SEC)


def begin_setup() -> dict:
    """Create/reuse pending TOTP secret and return QR provisioning info."""
    secret = get_setting(SETTING_TOTP)
    if is_setup_complete():
        return {"ok": False, "error": "Authenticator already configured", "active": True}
    if not secret:
        secret = pyotp.random_base32()
        set_setting(SETTING_TOTP, secret)
        set_setting(SETTING_TOTP_ACTIVE, "0")

    issuer = "tools.birolbenli.com"
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name="admin@" + issuer, issuer_name=issuer)
    return {
        "ok": True,
        "secret": secret,
        "otpauth_url": uri,
        "qr_svg": _qr_svg(uri),
        "qr_img": f"https://api.qrserver.com/v1/create-qr-code/?size=220x220&data={quote(uri, safe='')}",
        "active": False,
    }


def confirm_setup(code: str) -> dict:
    if is_setup_complete():
        return {"ok": False, "error": "Already configured"}
    secret = get_setting(SETTING_TOTP)
    if not secret:
        begin_setup()
        secret = get_setting(SETTING_TOTP)
    if not verify_code(code, secret):
        return {"ok": False, "error": "Invalid authenticator code — try the current 6 digits"}
    set_setting(SETTING_TOTP_ACTIVE, "1")
    return {"ok": True, "token": issue_session("full")}


def login(username: str, password: str, otp: str = "") -> dict:
    """
    Step 1: username+password.
    - If TOTP not set: return need_setup + preauth cookie token
    - If TOTP set and otp empty: need_otp
    - If TOTP set and otp ok: full session
    """
    if not password_configured():
        return {
            "ok": False,
            "error": "ADMIN_PASSWORD is not set on the server",
        }
    if not verify_password(username, password):
        return {"ok": False, "error": "Invalid username or password"}

    if not is_setup_complete():
        setup = begin_setup()
        return {
            "ok": True,
            "need_setup": True,
            "preauth": issue_session("preauth"),
            "setup": setup,
        }

    otp = (otp or "").strip()
    if not otp:
        return {
            "ok": True,
            "need_otp": True,
            "preauth": issue_session("preauth"),
        }

    if not verify_code(otp):
        return {"ok": False, "error": "Invalid authenticator code"}

    return {"ok": True, "token": issue_session("full")}


def login_otp(otp: str) -> dict:
    """Complete login after password preauth when TOTP already configured."""
    if not is_setup_complete():
        return {"ok": False, "error": "Authenticator not configured"}
    if not verify_code(otp):
        return {"ok": False, "error": "Invalid authenticator code"}
    return {"ok": True, "token": issue_session("full")}


def verify_code(code: str, secret: str | None = None) -> bool:
    secret = secret or get_setting(SETTING_TOTP) or ""
    code = (code or "").strip().replace(" ", "")
    if not secret or not code.isdigit() or len(code) < 6:
        return False
    totp = pyotp.TOTP(secret)
    return bool(totp.verify(code, valid_window=1))


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
