# -*- coding: utf-8 -*-
"""Quick smoke checks for auth/scope hardening.

Run:
    python smoke_auth_scope.py

This test is local and does not require the HTTP server to be running.
"""

from __future__ import annotations

from fastapi import HTTPException

import auth
import config
import db
from main import _normalize_target_scope


def _expect_http_error(fn) -> None:
    try:
        fn()
    except (HTTPException, ValueError):
        return
    raise AssertionError("Expected validation error was not raised")


def run() -> None:
    db.init_schema()

    # 1) Device allowlist / auto-provision for simple auth.
    token, ttl = auth.issue_simple_device_jwt("STOCK-MONITOR")
    assert token and isinstance(token, str)
    assert ttl == int(config.SIMPLE_DEVICE_JWT_TTL_SECONDS)
    _expect_http_error(lambda: auth.issue_simple_device_jwt("RANDOM-DEVICE"))

    # 2) Scope normalization rules.
    pos_dev = {"role": "pos", "device_name": "POS-ZAY"}
    wh_dev = {"role": "warehouse", "device_name": "WAREHOUSE"}

    assert _normalize_target_scope("", pos_dev) == "warehouse"
    assert _normalize_target_scope("warehouse", pos_dev) == "warehouse"
    assert _normalize_target_scope("pos:POS-ZAY", pos_dev) == "pos:POS-ZAY"
    _expect_http_error(lambda: _normalize_target_scope("all-pos", pos_dev))
    _expect_http_error(lambda: _normalize_target_scope("all", pos_dev))
    _expect_http_error(lambda: _normalize_target_scope("pos:POS-OCT", pos_dev))
    _expect_http_error(lambda: _normalize_target_scope("not-a-scope", pos_dev))

    assert _normalize_target_scope("", wh_dev) == "all-pos"
    assert _normalize_target_scope("all-pos", wh_dev) == "all-pos"
    assert _normalize_target_scope("all", wh_dev) == "all"
    assert _normalize_target_scope("warehouse", wh_dev) == "warehouse"
    assert _normalize_target_scope("pos:POS-ZAY", wh_dev) == "pos:POS-ZAY"

    print("SMOKE_AUTH_SCOPE_PASSED")


if __name__ == "__main__":
    run()
