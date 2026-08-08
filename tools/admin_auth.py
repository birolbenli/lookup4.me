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
SETTING_USER = "admin_username"
SETTING_PASS_HASH = "admin_password_hash"
_PBKDF2_ITERS = 200_000
_MIN_PASSWORD_LEN = 10


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


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        (password or "").encode("utf-8"),
        salt.encode("ascii"),
        _PBKDF2_ITERS,
    )
    return f"pbkdf2_sha256${_PBKDF2_ITERS}${salt}${dk.hex()}"


def verify_password_hash(password: str, stored: str) -> bool:
    try:
        algo, iters_s, salt, digest = (stored or "").split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iters = int(iters_s)
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            (password or "").encode("utf-8"),
            salt.encode("ascii"),
            iters,
        )
        return hmac.compare_digest(dk.hex(), digest)
    except Exception:  # noqa: BLE001
        return False


def admin_username() -> str:
    db_user = (get_setting(SETTING_USER) or "").strip()
    if db_user:
        return db_user
    return (os.environ.get("ADMIN_USER") or "admin").strip() or "admin"


def admin_credentials() -> tuple[str, str]:
    """Bootstrap credentials from env (used only when no DB password hash)."""
    user = admin_username()
    password = (os.environ.get("ADMIN_PASSWORD") or "").strip()
    return user, password


def password_configured() -> bool:
    if get_setting(SETTING_PASS_HASH):
        return True
    return bool((os.environ.get("ADMIN_PASSWORD") or "").strip())


def verify_password(username: str, password: str) -> bool:
    expect_user = admin_username()
    if not hmac.compare_digest(expect_user, (username or "").strip()):
        return False
    stored = get_setting(SETTING_PASS_HASH) or ""
    if stored:
        return verify_password_hash(password or "", stored)
    expect_pass = (os.environ.get("ADMIN_PASSWORD") or "").strip()
    if not expect_pass:
        return False
    return hmac.compare_digest(expect_pass, password or "")


def is_setup_complete() -> bool:
    return get_setting(SETTING_TOTP_ACTIVE) == "1" and bool(get_setting(SETTING_TOTP))


def profile_info() -> dict:
    return {
        "ok": True,
        "username": admin_username(),
        "password_source": "database" if get_setting(SETTING_PASS_HASH) else "env",
        "totp_active": is_setup_complete(),
        "min_password_len": _MIN_PASSWORD_LEN,
    }


def update_username(new_username: str, current_password: str) -> dict:
    new_username = (new_username or "").strip()
    if len(new_username) < 3 or len(new_username) > 64:
        return {"ok": False, "error": "Username must be 3–64 characters"}
    if not all(ch.isalnum() or ch in "._-" for ch in new_username):
        return {"ok": False, "error": "Username may only use letters, digits, . _ -"}
    if not verify_password(admin_username(), current_password):
        return {"ok": False, "error": "Current password is wrong"}
    set_setting(SETTING_USER, new_username)
    return {"ok": True, "username": new_username}


def change_password(current_password: str, new_password: str, otp: str = "") -> dict:
    if not verify_password(admin_username(), current_password):
        return {"ok": False, "error": "Current password is wrong"}
    new_password = new_password or ""
    if len(new_password) < _MIN_PASSWORD_LEN:
        return {
            "ok": False,
            "error": f"New password must be at least {_MIN_PASSWORD_LEN} characters",
        }
    if new_password == current_password:
        return {"ok": False, "error": "New password must be different"}
    if is_setup_complete() and not verify_code(otp):
        return {"ok": False, "error": "Invalid authenticator code"}
    set_setting(SETTING_PASS_HASH, hash_password(new_password))
    return {"ok": True}


def reset_authenticator(current_password: str, otp: str = "") -> dict:
    """Clear TOTP and start a new enrollment (requires password + current OTP)."""
    if not verify_password(admin_username(), current_password):
        return {"ok": False, "error": "Current password is wrong"}
    if is_setup_complete() and not verify_code(otp):
        return {"ok": False, "error": "Invalid authenticator code"}
    set_setting(SETTING_TOTP, "")
    set_setting(SETTING_TOTP_ACTIVE, "0")
    setup = begin_setup()
    setup["ok"] = True
    setup["reset"] = True
    return setup


def confirm_authenticator(code: str) -> dict:
    """Confirm TOTP while already logged in (re-enrollment)."""
    return confirm_setup(code)


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
    secret = (get_setting(SETTING_TOTP) or "").strip()
    if is_setup_complete():
        return {"ok": False, "error": "Authenticator already configured", "active": True}
    if not secret:
        secret = pyotp.random_base32()
        set_setting(SETTING_TOTP, secret)
        set_setting(SETTING_TOTP_ACTIVE, "0")

    issuer = "tools.birolbenli.com"
    account = f"{admin_username()}@{issuer}"
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=account, issuer_name=issuer)
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
