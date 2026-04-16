# -*- coding: utf-8 -*-
"""Device registration, token hashing, and JWT issuance.

Design:
- Each device has a single long-lived **API key** (32-byte URL-safe
  string) given to them at registration time. Only a hash is stored
  server-side.
- At /auth/token the client sends `{device_name, api_key}` and we
  return a short-lived JWT (`JWT_TTL_SECONDS`) bound to their
  device_uuid, device_name, and role.
- Every other endpoint requires the JWT in `Authorization: Bearer ...`.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import jwt

from config import JWT_ALGORITHM, JWT_SECRET, JWT_TTL_SECONDS
import db

# One-year token lifetime for simple device-based auth flow.
SIMPLE_TOKEN_TTL_SECONDS = 365 * 24 * 60 * 60


# ---- Helpers ----

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def new_api_key() -> str:
    """Generate a fresh API key for a newly-registered device."""
    return secrets.token_urlsafe(32)


def hash_api_key(api_key: str) -> str:
    """Deterministic SHA-256 hash. The API key is never stored in plain."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def verify_api_key(api_key: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_api_key(api_key), stored_hash)


# ---- Registration ----

def register_device(device_name: str, role: str) -> Tuple[str, str]:
    """Create a new device. Returns (device_uuid, api_key).

    The API key is returned ONCE. After this, only its hash is retained
    and authentication depends on the client presenting the original.
    """
    if role not in ("warehouse", "pos"):
        raise ValueError("role must be 'warehouse' or 'pos'")
    if db.get_device_by_name(device_name) is not None:
        raise ValueError(f"device name '{device_name}' is already registered")

    device_uuid = str(uuid.uuid4())
    api_key = new_api_key()
    db.insert_device(
        device_uuid=device_uuid,
        device_name=device_name,
        role=role,
        api_token_hash=hash_api_key(api_key),
        created_at=_now_iso(),
    )
    return device_uuid, api_key


# ---- Token issuance ----

def issue_jwt(device_row: Dict[str, Any]) -> Tuple[str, int]:
    """Return (jwt_string, ttl_seconds)."""
    now = int(time.time())
    payload = {
        "sub": device_row["device_uuid"],
        "name": device_row["device_name"],
        "role": device_row["role"],
        "iat": now,
        "exp": now + JWT_TTL_SECONDS,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token, JWT_TTL_SECONDS


def issue_simple_device_jwt(device_name: str) -> Tuple[str, int]:
    """Issue a stateless JWT from device_name only.

    This is used by the simplified `/v1/auth/token` flow required by the
    desktop client. No DB lookup is needed.
    """
    now = int(time.time())
    clean_name = device_name.strip()
    role = "warehouse" if clean_name.lower().startswith("warehouse") else "pos"
    payload = {
        "device_name": clean_name,
        "role": role,
        "iat": now,
        "exp": now + SIMPLE_TOKEN_TTL_SECONDS,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token, SIMPLE_TOKEN_TTL_SECONDS


def authenticate_device(device_name: str, api_key: str) -> Optional[Dict[str, Any]]:
    dev = db.get_device_by_name(device_name)
    if dev is None:
        return None
    if dev.get("revoked_at"):
        return None
    if not verify_api_key(api_key, dev["api_token_hash"]):
        return None
    return dev


# ---- Token validation ----

class AuthError(Exception):
    pass


def decode_jwt(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise AuthError("token expired")
    except jwt.InvalidTokenError:
        raise AuthError("invalid token")
    # Stateless fallback mode for simple device-only tokens.
    if "sub" not in payload:
        device_name = str(payload.get("device_name") or payload.get("name") or "").strip()
        if not device_name:
            raise AuthError("invalid token payload")
        return {
            "device_uuid": str(payload.get("device_uuid") or ""),
            "device_name": device_name,
            "role": str(payload.get("role") or "device"),
        }

    # Stateful mode: sanity check against registered devices in DB.
    dev = db.get_device_by_uuid(payload["sub"])
    if dev is None:
        raise AuthError("unknown device")
    if dev.get("revoked_at"):
        raise AuthError("device revoked")
    # Update last_seen_at opportunistically.
    db.touch_device(dev["device_uuid"], _now_iso())
    return {
        "device_uuid": dev["device_uuid"],
        "device_name": dev["device_name"],
        "role": dev["role"],
    }


# ---- Scope resolution ----

def allowed_scopes_for_pull(device_name: str, role: str) -> list:
    """What `target_scope` values is this device allowed to pull?"""
    if role == "warehouse":
        # Warehouse sees everything addressed to it plus global fan-outs.
        return ["warehouse", "all"]
    if role == "pos":
        # A POS only sees events aimed specifically at it, plus all-pos
        # broadcasts and truly global events.
        return [f"pos:{device_name}", "all-pos", "all"]
    return []
