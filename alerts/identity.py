"""Local accounts for the reference backend: scrypt password hashes, server-side sessions with a CSRF token, lock-out after repeated failures, and TOTP
(RFC 6238) as the second factor. This is the minimum needed to test the rest honestly; a hosted MacGuard Cloud would delegate to the customer's OIDC
provider (the schema keeps `users` free of provider-specific columns so that `external_subject` can be added without a rewrite).

What is stored: the e-mail (lower case), a scrypt hash, a salt. Never a plain password, never a session token (only its SHA-256), never the TOTP secret
in a log. Passwords are limited to 12..256 characters; the 100 most common are refused.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from . import store

SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}
SCRYPT_TEST = {"n": 2 ** 10, "r": 8, "p": 1}      # tests only: the production value is far slower on purpose
SESSION_HOURS = 12
LOCK_AFTER = 5
LOCK_MINUTES = 15
EMAIL = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,}$")
COMMON = {"password1234", "123456789012", "qwertyuiop12", "administrator", "welcome12345", "letmein12345", "password12345", "changeme1234", "iloveyou1234", "macguard12345"}


class AuthError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _kdf(password: str, salt: bytes, params: Dict[str, int]) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=params["n"], r=params["r"], p=params["p"], dklen=32, maxmem=256 * 1024 * 1024)


def check_password_rules(password: str) -> None:
    if not isinstance(password, str) or not 12 <= len(password) <= 256:
        raise AuthError("weak_password", "the password must have 12 to 256 characters")
    if password.lower() in COMMON or len(set(password)) < 5:
        raise AuthError("weak_password", "that password is too common or too repetitive")


def normalise_email(email: Any) -> str:
    if not isinstance(email, str) or not EMAIL.match(email.strip()):
        raise AuthError("bad_email", "not a valid e-mail address")
    return email.strip().lower()


def register(db, email: str, password: str, now: str, *, display_name: Optional[str] = None, locale: str = "es", params: Optional[Dict[str, int]] = None) -> str:
    email = normalise_email(email)
    check_password_rules(password)
    if locale not in ("es", "en"):
        raise AuthError("bad_locale", "locale must be es or en")
    params = params or SCRYPT
    salt = secrets.token_bytes(16)
    uid = store.new_id("u")
    with store.tx(db):
        if db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            # the same answer a caller gets for a new address would reveal nothing; the API layer returns a generic message for both cases
            raise AuthError("email_taken", "that address is already registered")
        db.execute("INSERT INTO users(user_id, email, display_name, locale, created_utc) VALUES(?,?,?,?,?)", (uid, email, (display_name or "")[:80] or None, locale, now))
        db.execute("INSERT INTO credentials(user_id, scheme, salt, hash, params, updated_utc) VALUES(?,?,?,?,?,?)", (uid, "scrypt", salt, _kdf(password, salt, params), json.dumps(params), now))
        store.audit(db, now, uid, None, "user.register", uid, {})
    return uid


def _locked(user, now: datetime) -> bool:
    return bool(user["locked_until_utc"]) and datetime.strptime(user["locked_until_utc"], "%Y-%m-%dT%H:%M:%SZ") > now.replace(tzinfo=None)


def login(db, email: str, password: str, now: datetime, totp_code: Optional[str] = None) -> Tuple[str, str, bool]:
    """Returns (session_token, csrf_token, mfa_verified). The token is shown once; only its hash is stored. Same error for every failure."""
    t = store.utc(now)
    generic = AuthError("invalid_credentials", "wrong e-mail or password")
    try:
        email = normalise_email(email)
    except AuthError:
        raise generic
    u = db.execute("SELECT * FROM users WHERE email=? AND state='active'", (email,)).fetchone()
    if u is None:
        _kdf(password if isinstance(password, str) else "", b"\0" * 16, SCRYPT_TEST)         # same work whether or not the account exists
        raise generic
    if _locked(u, now):
        raise AuthError("locked", "too many failed attempts: try again later")
    c = db.execute("SELECT * FROM credentials WHERE user_id=?", (u["user_id"],)).fetchone()
    ok = isinstance(password, str) and hmac.compare_digest(_kdf(password, bytes(c["salt"]), json.loads(c["params"])), bytes(c["hash"]))
    if not ok:
        fails = u["failed_logins"] + 1
        lock = store.utc(now + timedelta(minutes=LOCK_MINUTES)) if fails >= LOCK_AFTER else None
        db.execute("UPDATE users SET failed_logins=?, locked_until_utc=? WHERE user_id=?", (0 if lock else fails, lock, u["user_id"]))
        store.audit(db, t, u["user_id"], None, "user.login_failed", u["user_id"], {"locked": bool(lock)})
        raise generic
    mfa = False
    if c["totp_confirmed"]:
        if not totp_code or not verify_totp(c["totp_secret"], totp_code, now):
            raise AuthError("mfa_required", "a valid second-factor code is required")
        mfa = True
    db.execute("UPDATE users SET failed_logins=0, locked_until_utc=NULL WHERE user_id=?", (u["user_id"],))
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    db.execute("INSERT INTO sessions(session_hash, user_id, csrf, created_utc, expires_utc, last_seen_utc, mfa_verified) VALUES(?,?,?,?,?,?,?)",
               (hashlib.sha256(token.encode()).hexdigest(), u["user_id"], csrf, t, store.utc(now + timedelta(hours=SESSION_HOURS)), t, int(mfa)))
    store.audit(db, t, u["user_id"], None, "user.login", u["user_id"], {"mfa": mfa})
    return token, csrf, mfa


def session(db, token: Optional[str], now: datetime) -> Optional[Dict[str, Any]]:
    if not token or len(token) > 100:
        return None
    r = db.execute("SELECT s.*, u.email, u.locale, u.state FROM sessions s JOIN users u ON u.user_id=s.user_id WHERE s.session_hash=?", (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
    if r is None or r["state"] != "active" or datetime.strptime(r["expires_utc"], "%Y-%m-%dT%H:%M:%SZ") <= now.replace(tzinfo=None):
        return None
    return dict(r)


def logout(db, token: str, now: str) -> None:
    db.execute("DELETE FROM sessions WHERE session_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))


def revoke_all_sessions(db, user_id: str) -> None:
    db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))


# ---- TOTP (RFC 6238: HMAC-SHA1, 30 s, 6 digits) -------------------------------------------------------------------------------------
def totp_code(secret_b32: str, at: int) -> str:
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    mac = hmac.new(key, struct.pack(">Q", at // 30), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return f"{(struct.unpack('>I', mac[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** 6:06d}"


def verify_totp(secret_b32: str, code: str, now: datetime, window: int = 1) -> bool:
    if not isinstance(code, str) or not re.match(r"^\d{6}$", code):
        return False
    t = int(now.timestamp())
    return any(hmac.compare_digest(totp_code(secret_b32, t + 30 * d), code) for d in range(-window, window + 1))


def totp_enroll(db, user_id: str, now: str) -> str:
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
    db.execute("UPDATE credentials SET totp_secret=?, totp_confirmed=0, updated_utc=? WHERE user_id=?", (secret, now, user_id))
    store.audit(db, now, user_id, None, "user.mfa_enroll_started", user_id, {})
    return secret


def totp_confirm(db, user_id: str, code: str, now: datetime) -> bool:
    c = db.execute("SELECT totp_secret FROM credentials WHERE user_id=?", (user_id,)).fetchone()
    if not c or not c["totp_secret"] or not verify_totp(c["totp_secret"], code, now):
        return False
    db.execute("UPDATE credentials SET totp_confirmed=1, updated_utc=? WHERE user_id=?", (store.utc(now), user_id))
    store.audit(db, store.utc(now), user_id, None, "user.mfa_enabled", user_id, {})
    return True


def now_ts() -> float:
    return time.time()
