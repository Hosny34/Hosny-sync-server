# -*- coding: utf-8 -*-
"""Tiny admin CLI for the sync server.

Usage
-----
    python admin_cli.py init
    python admin_cli.py register <device_name> <role>
    python admin_cli.py list
    python admin_cli.py revoke <device_name>
    python admin_cli.py reset-key <device_name>

Examples
--------
    python admin_cli.py init
    python admin_cli.py register WAREHOUSE-MAIN warehouse
    python admin_cli.py register POS-01 pos
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone

import auth
import db


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def cmd_init() -> int:
    db.init_schema()
    print("schema initialized")
    return 0


def cmd_register(device_name: str, role: str) -> int:
    try:
        device_uuid, api_key = auth.register_device(device_name, role)
    except ValueError as e:
        print(f"ERROR: {e}")
        return 2
    print("=" * 60)
    print(f"  device_name: {device_name}")
    print(f"  role:        {role}")
    print(f"  device_uuid: {device_uuid}")
    print(f"  api_key:     {api_key}")
    print("=" * 60)
    print("SAVE THIS API KEY NOW — it is not stored in plain and cannot be")
    print("recovered. Give it to the device's sync setup dialog.")
    return 0


def cmd_list() -> int:
    rows = db.list_devices()
    if not rows:
        print("(no devices registered)")
        return 0
    print(f"{'NAME':<24} {'ROLE':<12} {'LAST_SEEN':<28} {'STATUS'}")
    for d in rows:
        status = "revoked" if d.get("revoked_at") else "active"
        print(
            f"{d['device_name']:<24} {d['role']:<12} "
            f"{(d.get('last_seen_at') or '-'):<28} {status}"
        )
    return 0


def cmd_revoke(device_name: str) -> int:
    dev = db.get_device_by_name(device_name)
    if dev is None:
        print(f"ERROR: no device named '{device_name}'")
        return 2
    with db.tx() as conn:
        conn.execute(
            "UPDATE devices SET revoked_at = ? WHERE device_uuid = ?",
            (_now_iso(), dev["device_uuid"]),
        )
    print(f"revoked {device_name}")
    return 0


def cmd_reset_key(device_name: str) -> int:
    dev = db.get_device_by_name(device_name)
    if dev is None:
        print(f"ERROR: no device named '{device_name}'")
        return 2
    new_key = auth.new_api_key()
    with db.tx() as conn:
        conn.execute(
            "UPDATE devices SET api_token_hash = ?, revoked_at = NULL "
            "WHERE device_uuid = ?",
            (auth.hash_api_key(new_key), dev["device_uuid"]),
        )
    print(f"new api_key for {device_name}:")
    print(f"  {new_key}")
    return 0


def main(argv: list) -> int:
    db.init_schema()
    if len(argv) < 2:
        print(__doc__)
        return 1
    cmd = argv[1]
    if cmd == "init":
        return cmd_init()
    if cmd == "register" and len(argv) == 4:
        return cmd_register(argv[2], argv[3])
    if cmd == "list":
        return cmd_list()
    if cmd == "revoke" and len(argv) == 3:
        return cmd_revoke(argv[2])
    if cmd == "reset-key" and len(argv) == 3:
        return cmd_reset_key(argv[2])
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
