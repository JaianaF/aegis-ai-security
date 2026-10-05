from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'aegis_v03.db'}")
ALLOW_PRIVATE_TARGETS = os.getenv("ALLOW_PRIVATE_TARGETS", "false").lower() in {"1", "true", "yes"}
REQUEST_TIMEOUT_SECONDS = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "20"))
MAX_RESPONSE_BYTES = int(os.getenv("MAX_RESPONSE_BYTES", "100000"))
APP_SECRET = os.getenv("APP_SECRET", "dev-only-change-this-secret")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-me")
TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", "28800"))
WORKER_POLL_SECONDS = float(os.getenv("WORKER_POLL_SECONDS", "1.0"))
WORKER_STALE_MINUTES = int(os.getenv("WORKER_STALE_MINUTES", "30"))
DEFAULT_ORG_NAME = os.getenv("DEFAULT_ORG_NAME", "AegisAI Lab")
DEFAULT_PROJECT_NAME = os.getenv("DEFAULT_PROJECT_NAME", "Default Project")
