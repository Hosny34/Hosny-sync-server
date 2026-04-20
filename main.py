# -*- coding: utf-8 -*-
"""Sync server — FastAPI routes.

Endpoints:
    GET  /v1/health
    POST /v1/auth/token       {device_name, api_key} -> {access_token, expires_in}
    POST /v1/sync/push        {events: [...]}        -> {accepted, duplicates}
    GET  /v1/sync/pull        ?since=<seq>&limit=<n> -> {events, next_seq}
    GET  /v1/sync/status      (warehouse only)       -> device list
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from config import MAX_PULL_BATCH, MAX_PUSH_BATCH
import auth
import db


app = FastAPI(title="HosnyWarehouse Sync Server", version="0.2.0")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@app.on_event("startup")
def _startup() -> None:
    db.init_schema()


# ------------------------------- Schemas ------------------------------- #

class TokenRequest(BaseModel):
    device_name: str
    api_key: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


class EventIn(BaseModel):
    event_uuid: str
    event_type: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    # target_scope is optional — if the client doesn't set it, the
    # server derives it from the caller's role: POS → 'warehouse',
    # warehouse → 'all-pos'. Clients may override (e.g. warehouse
    # targeting a specific POS with 'pos:POS-03').
    target_scope: Optional[str] = None
    created_at: Optional[str] = None


class PushRequest(BaseModel):
    events: List[EventIn]


class PushResponse(BaseModel):
    accepted: int
    duplicates: int
    received: int


class PullResponse(BaseModel):
    events: List[Dict[str, Any]]
    next_seq: int
    server_time: str


# ------------------------------- Auth dep ------------------------------ #

def current_device(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.split(None, 1)[1].strip()
    try:
        return auth.decode_jwt(token)
    except auth.AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))


def warehouse_only(device: Dict[str, Any] = Depends(current_device)) -> Dict[str, Any]:
    if device["role"] != "warehouse":
        raise HTTPException(status_code=403, detail="warehouse role required")
    return device


# ------------------------------- Routes -------------------------------- #

@app.get("/v1/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "server_time": _utc_now_iso()}


@app.post("/v1/auth/token", response_model=TokenResponse)
def issue_token(body: TokenRequest) -> TokenResponse:
    device_name = (body.device_name or "").strip()
    if not device_name:
        raise HTTPException(status_code=422, detail="device_name is required")

    # Compatibility mode:
    # - If api_key is provided and valid, issue the classic registered-device JWT.
    # - Otherwise, issue a simple stateless device JWT (no DB auth required).
    if body.api_key:
        dev = auth.authenticate_device(device_name, body.api_key)
        if dev is None:
            raise HTTPException(status_code=401, detail="invalid device or key")
        token, _ = auth.issue_jwt(dev)
    else:
        try:
            token, _ = auth.issue_simple_device_jwt(device_name)
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc))

    return TokenResponse(
        access_token=token,
        token_type="bearer",
    )


def _default_scope_for(role: str) -> str:
    """If client omits target_scope, pick a sensible default.

    - warehouse-originated events default to fan-out to all POS devices.
    - pos-originated events default to the warehouse.
    """
    if role == "warehouse":
        return "all-pos"
    if role == "pos":
        return "warehouse"
    return "all"


@app.post("/v1/sync/push", response_model=PushResponse)
def sync_push(
    body: PushRequest,
    device: Dict[str, Any] = Depends(current_device),
) -> PushResponse:
    if len(body.events) > MAX_PUSH_BATCH:
        raise HTTPException(
            status_code=413,
            detail=f"too many events in one push (limit {MAX_PUSH_BATCH})",
        )

    rows = []
    for ev in body.events:
        # Server-enforced: source_device is ALWAYS the caller. Clients
        # cannot forge events as other devices.
        scope = (ev.target_scope or _default_scope_for(device["role"])).strip()
        rows.append(
            (
                ev.event_uuid,
                ev.event_type,
                device["device_uuid"],
                scope,
                json.dumps(ev.payload, ensure_ascii=False, default=str),
                ev.created_at or _utc_now_iso(),
            )
        )

    inserted = db.insert_events(rows)
    return PushResponse(
        received=len(body.events),
        accepted=inserted,
        duplicates=len(body.events) - inserted,
    )


@app.get("/v1/sync/pull", response_model=PullResponse)
def sync_pull(
    since: int = Query(0, ge=0),
    limit: int = Query(MAX_PULL_BATCH, ge=1, le=MAX_PULL_BATCH),
    device: Dict[str, Any] = Depends(current_device),
) -> PullResponse:
    scopes = auth.allowed_scopes_for_pull(device["device_name"], device["role"])
    rows = db.pull_events(scopes=scopes, since_seq=since, limit=limit)

    # Parse payloads back for the wire.
    events: List[Dict[str, Any]] = []
    max_seq = since
    for r in rows:
        try:
            payload_obj = json.loads(r["payload"])
        except Exception:
            payload_obj = {"_raw": r["payload"]}
        events.append({
            "server_seq": int(r["server_seq"]),
            "event_uuid": r["event_uuid"],
            "event_type": r["event_type"],
            "source_device": r["source_device"],
            "target_scope": r["target_scope"],
            "payload": payload_obj,
            "created_at": r["created_at"],
        })
        if int(r["server_seq"]) > max_seq:
            max_seq = int(r["server_seq"])

    if events:
        db.update_cursor(
            device_uuid=device["device_uuid"],
            channel="main",
            last_pulled_seq=max_seq,
            now_iso=_utc_now_iso(),
        )

    return PullResponse(
        events=events,
        next_seq=max_seq,
        server_time=_utc_now_iso(),
    )


@app.get("/v1/sync/status")
def sync_status(device: Dict[str, Any] = Depends(warehouse_only)) -> Dict[str, Any]:
    return {
        "server_time": _utc_now_iso(),
        "devices": db.device_status_summary(),
    }
