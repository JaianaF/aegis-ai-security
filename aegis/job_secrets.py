from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from .config import APP_SECRET


def _fernet() -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(APP_SECRET.encode("utf-8")).digest())
    return Fernet(key)


def seal_job_payload(data: dict[str, Any]) -> str:
    raw = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return _fernet().encrypt(raw).decode("ascii")


def unseal_job_payload(token: str) -> dict[str, Any]:
    try:
        raw = _fernet().decrypt(token.encode("ascii"))
    except InvalidToken as exc:
        raise ValueError("Unable to decrypt scan job payload. Check APP_SECRET consistency between web and worker.") from exc
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Invalid scan job payload.")
    return data
