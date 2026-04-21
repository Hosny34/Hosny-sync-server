# -*- coding: utf-8 -*-
"""Database layer for the sync server.

Plain SQLite via stdlib. Schema is created on startup (idempotent).
Two tables:

- `devices`   — registered warehouse/POS devices and their hashed tokens.
- `events`    — append-only event log. server_seq is the monotonic cursor.

Notes
-----
We store JSON payloads as TEXT so the server has no schema knowledge of
domain events. The server is a dumb event relay; interpretation lives
on the clients.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Optional, Tuple

from config import is_sqlite, sqlite_path


# Single writer connection, serialized with a lock. Simpler than a pool
# for a low-volume server, and safe because SQLite serializes writes
# anyway. Readers use the same connection since SQLite is fine with it.
_lock = threading.RLock()
_conn: Optional[sqlite3.Connection] = None


def get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        if not is_sqlite():
            raise RuntimeError(
                "Only SQLite is wired up in this phase. Set DATABASE_URL "
                "to a sqlite:// URL, or add a Postgres backend later."
            )
        _conn = sqlite3.connect(
            sqlite_path(),
            isolation_level=None,
            check_same_thread=False,
        )
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL;")
        _conn.execute("PRAGMA synchronous=NORMAL;")
        _conn.execute("PRAGMA foreign_keys=ON;")
    return _conn


@contextmanager
def tx():
    """Serialized transaction context for writes."""
    conn = get_conn()
    with _lock:
        conn.execute("BEGIN IMMEDIATE;")
        try:
            yield conn
            conn.execute("COMMIT;")
        except Exception:
            conn.execute("ROLLBACK;")
            raise


def init_schema() -> None:
    conn = get_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS devices (
            device_uuid    TEXT PRIMARY KEY,
            device_name    TEXT NOT NULL UNIQUE,
            role           TEXT NOT NULL CHECK (role IN ('warehouse','pos')),
            api_token_hash TEXT NOT NULL,
            created_at     TEXT NOT NULL,
            last_seen_at   TEXT,
            revoked_at     TEXT
        );

        CREATE TABLE IF NOT EXISTS events (
            server_seq    INTEGER PRIMARY KEY AUTOINCREMENT,
            event_uuid    TEXT NOT NULL UNIQUE,
            event_type    TEXT NOT NULL,
            source_device TEXT NOT NULL REFERENCES devices(device_uuid),
            target_scope  TEXT NOT NULL,
            payload       TEXT NOT NULL,
            created_at    TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_events_scope_seq
            ON events(target_scope, server_seq);
        CREATE INDEX IF NOT EXISTS ix_events_source
            ON events(source_device);

        CREATE TABLE IF NOT EXISTS device_cursors (
            device_uuid     TEXT NOT NULL REFERENCES devices(device_uuid),
            channel         TEXT NOT NULL,
            last_pulled_seq INTEGER NOT NULL DEFAULT 0,
            updated_at      TEXT NOT NULL,
            PRIMARY KEY (device_uuid, channel)
        );
        """
    )


# ---- Devices ----

def insert_device(
    device_uuid: str,
    device_name: str,
    role: str,
    api_token_hash: str,
    created_at: str,
) -> None:
    with tx() as conn:
        conn.execute(
            """
            INSERT INTO devices
                (device_uuid, device_name, role, api_token_hash, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (device_uuid, device_name, role, api_token_hash, created_at),
        )


def upsert_device(
    device_uuid: str,
    device_name: str,
    role: str,
    api_token_hash: str,
    created_at: str,
) -> None:
    """Create or refresh a device row keyed by device_name.

    This is used by the simplified device-name auth flow so every
    authenticated client still has a real device_uuid for foreign keys,
    cursor tracking, and status reporting.
    """
    with tx() as conn:
        conn.execute(
            """
            INSERT INTO devices
                (device_uuid, device_name, role, api_token_hash, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(device_name) DO UPDATE SET
                role           = excluded.role,
                api_token_hash = CASE
                    WHEN devices.api_token_hash = '' THEN excluded.api_token_hash
                    ELSE devices.api_token_hash
                END
            """,
            (device_uuid, device_name, role, api_token_hash, created_at),
        )


def get_device_by_name(name: str) -> Optional[Dict[str, Any]]:
    row = get_conn().execute(
        "SELECT * FROM devices WHERE device_name = ?", (name,)
    ).fetchone()
    return dict(row) if row else None


def get_device_by_uuid(device_uuid: str) -> Optional[Dict[str, Any]]:
    row = get_conn().execute(
        "SELECT * FROM devices WHERE device_uuid = ?", (device_uuid,)
    ).fetchone()
    return dict(row) if row else None


def list_devices() -> List[Dict[str, Any]]:
    rows = get_conn().execute(
        "SELECT * FROM devices ORDER BY role, device_name"
    ).fetchall()
    return [dict(r) for r in rows]


def touch_device(device_uuid: str, seen_at: str) -> None:
    with tx() as conn:
        conn.execute(
            "UPDATE devices SET last_seen_at = ? WHERE device_uuid = ?",
            (seen_at, device_uuid),
        )


# ---- Events ----

def insert_events(
    rows: Iterable[Tuple[str, str, str, str, str, str]],
) -> int:
    """Insert events, ignoring duplicates by event_uuid. Returns the
    number of actually-inserted rows (duplicates are not counted).

    Each tuple is: (event_uuid, event_type, source_device, target_scope,
                    payload_json, created_at)
    """
    inserted = 0
    with tx() as conn:
        for r in rows:
            try:
                conn.execute(
                    """
                    INSERT INTO events
                        (event_uuid, event_type, source_device,
                         target_scope, payload, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    r,
                )
                inserted += 1
            except sqlite3.IntegrityError:
                # Duplicate event_uuid — silently skipped.
                pass
    return inserted


def pull_events(
    scopes: List[str],
    since_seq: int,
    limit: int,
) -> List[Dict[str, Any]]:
    """Return events whose target_scope is in `scopes`, with
    server_seq > since_seq, ordered ascending. Capped at `limit`.
    """
    if not scopes:
        return []
    placeholders = ",".join("?" * len(scopes))
    sql = (
        "SELECT server_seq, event_uuid, event_type, source_device, "
        "target_scope, payload, created_at "
        "FROM events WHERE target_scope IN (" + placeholders + ") "
        "AND server_seq > ? ORDER BY server_seq ASC LIMIT ?"
    )
    rows = get_conn().execute(
        sql, (*scopes, int(since_seq), int(limit))
    ).fetchall()
    return [dict(r) for r in rows]


def update_cursor(
    device_uuid: str,
    channel: str,
    last_pulled_seq: int,
    now_iso: str,
) -> None:
    with tx() as conn:
        conn.execute(
            """
            INSERT INTO device_cursors
                (device_uuid, channel, last_pulled_seq, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(device_uuid, channel) DO UPDATE SET
                last_pulled_seq = excluded.last_pulled_seq,
                updated_at      = excluded.updated_at
            """,
            (device_uuid, channel, int(last_pulled_seq), now_iso),
        )


def device_status_summary() -> List[Dict[str, Any]]:
    """For the warehouse-only /sync/status endpoint."""
    rows = get_conn().execute(
        """
        SELECT d.device_uuid, d.device_name, d.role,
               d.created_at, d.last_seen_at, d.revoked_at,
               (SELECT COUNT(*) FROM events e WHERE e.source_device = d.device_uuid) AS pushed_count,
               (SELECT MAX(server_seq) FROM events e WHERE e.source_device = d.device_uuid) AS last_pushed_seq,
               (SELECT last_pulled_seq FROM device_cursors c
                WHERE c.device_uuid = d.device_uuid AND c.channel='main') AS last_pulled_seq
        FROM devices d
        ORDER BY d.role, d.device_name
        """
    ).fetchall()
    return [dict(r) for r in rows]


def get_max_server_seq() -> int:
    """Return the highest server_seq currently stored, or 0 if empty.

    Clients use this to detect a server-side DB reset (e.g. after a
    Railway redeploy onto ephemeral storage): if their local cursor is
    greater than this value, their cursor is stale and must be reset.
    """
    row = get_conn().execute(
        "SELECT COALESCE(MAX(server_seq), 0) AS mx FROM events"
    ).fetchone()
    return int((row["mx"] if row else 0) or 0)


def readiness_probe() -> Dict[str, Any]:
    """Lightweight DB readiness check used by /v1/ready."""
    conn = get_conn()
    conn.execute("SELECT 1").fetchone()
    return {"db": "ok", "sqlite_path": sqlite_path()}


def health_summary() -> Dict[str, Any]:
    """Operational counters for /v1/health."""
    conn = get_conn()
    row = conn.execute(
        """
        SELECT
            (SELECT COUNT(*) FROM devices) AS devices_count,
            (SELECT COUNT(*) FROM devices WHERE revoked_at IS NULL) AS active_devices_count,
            (SELECT COUNT(*) FROM events) AS events_count,
            (SELECT COALESCE(MAX(server_seq), 0) FROM events) AS max_server_seq
        """
    ).fetchone()
    return {
        "devices_count": int(row["devices_count"] or 0),
        "active_devices_count": int(row["active_devices_count"] or 0),
        "events_count": int(row["events_count"] or 0),
        "max_server_seq": int(row["max_server_seq"] or 0),
    }
