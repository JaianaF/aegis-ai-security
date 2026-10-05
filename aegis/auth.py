from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

from fastapi import Header, HTTPException

from .config import ADMIN_PASSWORD, ADMIN_USERNAME, APP_SECRET, TOKEN_TTL_SECONDS


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def verify_credentials(username: str, password: str) -> bool:
    return secrets.compare_digest(username, ADMIN_USERNAME) and secrets.compare_digest(password, ADMIN_PASSWORD)


def create_token(username: str) -> str:
    expires = int(time.time()) + TOKEN_TTL_SECONDS
    nonce = secrets.token_hex(8)
    payload = f"{username}:{expires}:{nonce}".encode()
    encoded = _b64e(payload)
    sig = hmac.new(APP_SECRET.encode(), encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{sig}"


def decode_token(token: str) -> str:
    try:
        encoded, sig = token.split(".", 1)
        expected = hmac.new(APP_SECRET.encode(), encoded.encode(), hashlib.sha256).hexdigest()
        if not secrets.compare_digest(sig, expected):
            raise ValueError("bad signature")
        username, expires, _ = _b64d(encoded).decode().split(":", 2)
        if int(expires) < int(time.time()):
            raise ValueError("expired")
        if not secrets.compare_digest(username, ADMIN_USERNAME):
            raise ValueError("unknown user")
        return username
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired session token.") from exc


def require_user(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Authentication required.")
    return decode_token(authorization.split(" ", 1)[1].strip())
