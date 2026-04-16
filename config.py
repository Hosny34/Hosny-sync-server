# -*- coding: utf-8 -*-
"""Sync server configuration.

Reads settings from environment variables with sensible defaults for
local development. The server runs unchanged against SQLite (default)
or Postgres (set DATABASE_URL).
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path


# Where to store the SQLite file when DATABASE_URL is not set.
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_SQLITE_PATH = BASE_DIR / "sync_server.sqlite3"

# DATABASE_URL examples:
#   sqlite:///C:/path/to/sync_server.sqlite3
#   postgresql://user:password@host:5432/sync_db
DATABASE_URL: str = os.environ.get(
    "DATABASE_URL",
    "sqlite:///" + str(DEFAULT_SQLITE_PATH).replace("\\", "/"),
)

# JWT signing secret. MUST be set in production. Falls back to a random
# value at startup in dev so tokens don't survive a restart.
JWT_SECRET: str = os.environ.get("JWT_SECRET") or secrets.token_urlsafe(32)
JWT_ALGORITHM: str = "HS256"
JWT_TTL_SECONDS: int = int(os.environ.get("JWT_TTL_SECONDS", "86400"))  # 24h

# Max events accepted in a single push and returned by a single pull.
MAX_PUSH_BATCH: int = int(os.environ.get("MAX_PUSH_BATCH", "500"))
MAX_PULL_BATCH: int = int(os.environ.get("MAX_PULL_BATCH", "500"))


def is_sqlite() -> bool:
    return DATABASE_URL.startswith("sqlite:")


def sqlite_path() -> str:
    assert is_sqlite(), "DATABASE_URL is not SQLite"
    # Strip the "sqlite:///" prefix.
    return DATABASE_URL.replace("sqlite:///", "", 1)
