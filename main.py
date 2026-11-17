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
import os
import secrets
import time
from functools import wraps
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from config import (
    CUSTOMER_STOCK_UPLOAD_TOKEN,
    MAX_PULL_BATCH,
    MAX_PUSH_BATCH,
    MOJEEB_API_KEY,
    POS_UPDATES_DIR,
)
import auth
import db
import season_protocol


app = FastAPI(title="HosnyWarehouse Sync Server", version="0.2.0")


def _require_sync_ready() -> None:
    if os.environ.get("SYNC_MAINTENANCE", "").strip() == "1":
        raise HTTPException(
            status_code=503,
            detail="Sync temporarily paused for database recovery; retry later.",
            headers={"Retry-After": "60"},
        )


@app.exception_handler(season_protocol.ProtocolError)
async def season_protocol_error(_request, exc):
    return JSONResponse(status_code=409, content={'detail': str(exc)})


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


POS_MUTATING_WAREHOUSE_EVENTS = {
    "STOCK_TRANSFER_OUT",
    "STOCK_TRANSFER_CANCELLED",
    "BRANCH_STOCK_RECLASSIFIED",
    "BRANCH_CATALOG_DELETED",
    "SPEC_RENAMED",
    "PRICE_UPDATE",
    "CATALOG_UPSERT",
    "POS_OWNERSHIP_SNAPSHOT",
}


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
    # Highest server_seq currently stored on the server. Clients compare
    # this against their local `last_pulled_seq` to detect a server-side
    # DB reset (common on Railway ephemeral storage) and auto-heal their
    # cursor back to 0 instead of pulling 0 events forever.
    max_server_seq: int = 0


class WaitResponse(BaseModel):
    has_updates: bool
    next_seq: int
    server_time: str
    max_server_seq: int = 0


class AdminResetDeviceRequest(BaseModel):
    device_name: str
    target_scope: Optional[str] = None


class AdminResetAllRequest(BaseModel):
    confirm: str


class PosUpdateLatestResponse(BaseModel):
    available: bool
    manifest: Optional[Dict[str, Any]] = None
    server_time: str


class CustomerStockRowIn(BaseModel):
    source_device: str
    item_type: str
    school: str
    color: str
    size: str
    unit_price: float = 0
    count: int = 0
    snapshot_at: Optional[str] = None


class CustomerStockUploadRequest(BaseModel):
    uploaded_at: Optional[str] = None
    season_context: Optional[Dict[str, Any]] = None
    rows: List[CustomerStockRowIn]


class CustomerReservationRowIn(BaseModel):
    source_device: str
    bill_number: str
    reservation_key: str
    item_type: str
    school: str
    color: str
    size: str
    pending_qty: int = 0
    updated_at: Optional[str] = None


class CustomerReservationUploadRequest(BaseModel):
    uploaded_at: Optional[str] = None
    season_context: Optional[Dict[str, Any]] = None
    rows: List[CustomerReservationRowIn]


class CustomerSnapshotUploadRequest(BaseModel):
    uploaded_at: Optional[str] = None
    season_context: Dict[str, Any]
    stock_rows: List[CustomerStockRowIn]
    reservation_rows: List[CustomerReservationRowIn]


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


def customer_stock_upload_auth(x_customer_stock_token: Optional[str] = Header(None)) -> None:
    expected = CUSTOMER_STOCK_UPLOAD_TOKEN
    if not expected:
        raise HTTPException(status_code=503, detail="customer stock upload token is not configured")
    if (x_customer_stock_token or "").strip() != expected:
        raise HTTPException(status_code=401, detail="invalid customer stock upload token")


def mojeeb_api_auth(x_api_key: Optional[str] = Header(None)) -> None:
    if not MOJEEB_API_KEY:
        raise HTTPException(status_code=503, detail="Mojeeb API is not configured")
    supplied = (x_api_key or "").strip()
    if not supplied or not secrets.compare_digest(supplied, MOJEEB_API_KEY):
        raise HTTPException(status_code=401, detail="invalid API key")


# ------------------------------- Routes -------------------------------- #

@app.get("/v1/health")
def health() -> Dict[str, Any]:
    try:
        summary = db.health_summary()
        return {
            "status": "ok",
            "server_time": _utc_now_iso(),
            "db": "ok",
            **summary,
        }
    except Exception as ex:
        return {
            "status": "degraded",
            "server_time": _utc_now_iso(),
            "db": "error",
            "detail": str(ex),
        }


@app.get("/v1/ready")
def ready() -> Dict[str, Any]:
    try:
        probe = db.readiness_probe()
        return {"status": "ready", "server_time": _utc_now_iso(), **probe}
    except Exception as ex:
        raise HTTPException(status_code=503, detail=f"not ready: {ex}")


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


def _normalize_target_scope(scope: str, device: Dict[str, Any]) -> str:
    s = (scope or "").strip()
    role = str(device.get("role") or "")
    dev_name = str(device.get("device_name") or "")
    if not s:
        return _default_scope_for(role)
    if s in ("all", "all-pos", "warehouse"):
        if role == "pos" and s != "warehouse":
            raise HTTPException(status_code=403, detail="pos device may only target warehouse")
        return s
    if s.startswith("pos:"):
        target = s[4:].strip()
        if not target:
            raise HTTPException(status_code=422, detail="invalid target_scope")
        if role == "pos" and target != dev_name:
            raise HTTPException(status_code=403, detail="pos device cannot target another pos")
        return f"pos:{target}"
    raise HTTPException(status_code=422, detail="invalid target_scope")


@app.post("/v1/sync/push", response_model=PushResponse)
def sync_push(
    body: PushRequest,
    device: Dict[str, Any] = Depends(current_device),
    x_season_protocol: Optional[int] = Header(None),
    x_database_generation: Optional[str] = Header(None),
    x_generation_token: Optional[str] = Header(None),
) -> PushResponse:
    _require_sync_ready()
    if len(body.events) > MAX_PUSH_BATCH:
        raise HTTPException(
            status_code=413,
            detail=f"too many events in one push (limit {MAX_PUSH_BATCH})",
        )

    rows = []
    for ev in body.events:
        # Server-enforced: source_device is ALWAYS the caller. Clients
        # cannot forge events as other devices.
        requested_scope = str(ev.target_scope or ev.payload.get("__target_scope__") or "").strip()
        if (
            str(device.get("role") or "") == "warehouse"
            and str(ev.event_type or "").strip().upper() in POS_MUTATING_WAREHOUSE_EVENTS
            and not requested_scope
        ):
            raise HTTPException(
                status_code=422,
                detail=f"{ev.event_type} requires explicit target_scope",
            )
        scope = _normalize_target_scope(requested_scope, device)
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

    with db.tx() as conn:
        if season_protocol.enabled(conn):
            inserted = season_protocol.append_events(conn, rows, device,
                protocol_version=x_season_protocol, generation_id=x_database_generation,
                secret=x_generation_token)
        else:
            inserted = 0
            for row in rows:
                cur = conn.execute('INSERT INTO events(event_uuid,event_type,source_device,target_scope,payload,created_at) '
                                   'VALUES(?,?,?,?,?,?) ON CONFLICT(event_uuid) DO NOTHING', row)
                inserted += cur.rowcount
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
    x_season_protocol: Optional[int] = Header(None),
    x_database_generation: Optional[str] = Header(None),
    x_generation_token: Optional[str] = Header(None),
) -> PullResponse:
    _require_sync_ready()
    scopes = auth.allowed_scopes_for_pull(device["device_name"], device["role"])
    with db.tx() as conn:
        if season_protocol.enabled(conn):
            rows = season_protocol.pull(conn, scopes, since, limit, device,
                protocol_version=x_season_protocol, generation_id=x_database_generation,
                secret=x_generation_token)
        else:
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
            "season_origin": {key: r.get(key) for key in
                              ('source_season_id', 'generation_id', 'target_generation_id', 'current_generation')}
                             if 'source_season_id' in r else None,
        })
        if int(r["server_seq"]) > max_seq:
            max_seq = int(r["server_seq"])

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
        max_server_seq=db.get_max_server_seq(),
    )


@app.get("/v1/sync/wait", response_model=WaitResponse)
def sync_wait(
    since: int = Query(0, ge=0),
    timeout_s: int = Query(25, ge=1, le=60),
    device: Dict[str, Any] = Depends(current_device),
    x_season_protocol: Optional[int] = Header(None),
    x_database_generation: Optional[str] = Header(None),
    x_generation_token: Optional[str] = Header(None),
) -> WaitResponse:
    """Long-poll for new events visible to the current device.

    Returns immediately when a matching event is available, otherwise
    waits up to `timeout_s` and returns `has_updates=false`.
    """
    _require_sync_ready()
    scopes = auth.allowed_scopes_for_pull(device["device_name"], device["role"])
    deadline = time.monotonic() + float(timeout_s)
    while True:
        with db.tx() as conn:
            if season_protocol.enabled(conn):
                available = season_protocol.pull(conn, scopes, since, 1, device,
                    protocol_version=x_season_protocol, generation_id=x_database_generation,
                    secret=x_generation_token)
                nxt = available[0]['server_seq'] if available else 0
            else:
                nxt = db.next_event_seq_for_scopes(scopes=scopes, since_seq=since)
        if int(nxt) > int(since):
            return WaitResponse(
                has_updates=True,
                next_seq=int(nxt),
                server_time=_utc_now_iso(),
                max_server_seq=db.get_max_server_seq(),
            )
        if time.monotonic() >= deadline:
            break
        time.sleep(0.5)

    return WaitResponse(
        has_updates=False,
        next_seq=int(since),
        server_time=_utc_now_iso(),
        max_server_seq=db.get_max_server_seq(),
    )


@app.get("/v1/sync/status")
def sync_status(device: Dict[str, Any] = Depends(warehouse_only)) -> Dict[str, Any]:
    return {
        "server_time": _utc_now_iso(),
        "devices": db.device_status_summary(),
    }


class SeasonChangeRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=128)
    expected_revision: int = Field(ge=0)
    action: str
    season_id: Optional[str] = None
    name: Optional[str] = None


class GenerationEnrollmentRequest(BaseModel):
    device_uuid: str
    generation_id: str = Field(min_length=1, max_length=128)
    secret: str = Field(min_length=32, max_length=256)
    season_id: str
    protocol_version: int


class EnrollmentAuthorizationRequest(BaseModel):
    device_uuid: str


class EnrollmentClaimRequest(BaseModel):
    enrollment_code: str = Field(min_length=16, max_length=256)
    generation_id: str = Field(min_length=1, max_length=128)
    secret: str = Field(min_length=32, max_length=256)
    protocol_version: int


class DefinitionBootstrapRequest(BaseModel):
    target_scope: str
    revision: int = Field(ge=1)
    definitions: Dict[str, Any]


class ApplyLeaseRequest(BaseModel):
    lease_id: str = Field(min_length=1, max_length=128)
    action: str
    expected_revision: int = Field(ge=0)


@app.post('/v1/seasons/apply-lease')
def season_apply_lease(body: ApplyLeaseRequest, device: Dict[str, Any] = Depends(warehouse_only)):
    with db.tx() as conn:
        return season_protocol.apply_lease(conn, device['device_uuid'], body.lease_id,
                                          body.action, body.expected_revision)


@app.get('/v1/seasons/status')
def season_status(device: Dict[str, Any] = Depends(warehouse_only)):
    with db.tx() as conn:
        generations, sources = season_protocol.authority(conn)
        return {'state': season_protocol.state(conn), 'generations': generations, 'sources':sources,
                'protocol_version': season_protocol.PROTOCOL_VERSION}


@app.post('/v1/seasons/change')
def season_change(body: SeasonChangeRequest, device: Dict[str, Any] = Depends(warehouse_only)):
    with db.tx() as conn:
        return season_protocol.change_state(conn, operation_id=body.operation_id,
            expected_revision=body.expected_revision, action=body.action,
            season_id=body.season_id, name=body.name)


@app.post('/v1/seasons/enroll')
def season_enroll(body: GenerationEnrollmentRequest, device: Dict[str, Any] = Depends(warehouse_only)):
    with db.tx() as conn:
        return season_protocol.enroll(conn, device_uuid=body.device_uuid,
            generation_id=body.generation_id, secret=body.secret, season_id=body.season_id,
            protocol_version=body.protocol_version)


@app.post('/v1/seasons/authorize-enrollment')
def season_authorize_enrollment(body: EnrollmentAuthorizationRequest,
                                device: Dict[str, Any] = Depends(warehouse_only)):
    with db.tx() as conn:
        return season_protocol.authorize_enrollment(conn, device_uuid=body.device_uuid)


@app.post('/v1/seasons/claim')
def season_claim(body: EnrollmentClaimRequest, device: Dict[str, Any] = Depends(current_device)):
    if device['role'] != 'pos':
        raise HTTPException(status_code=403, detail='POS identity required')
    with db.tx() as conn:
        return season_protocol.claim_enrollment(conn, device_uuid=device['device_uuid'],
            enrollment_code=body.enrollment_code,generation_id=body.generation_id,
            secret=body.secret,protocol_version=body.protocol_version)


@app.get('/v1/seasons/client-status')
def season_client_status(device: Dict[str, Any] = Depends(current_device)):
    with db.tx() as conn:
        return season_protocol.client_status(conn,device['device_uuid'])


@app.post('/v1/seasons/definitions')
def season_definitions(body: DefinitionBootstrapRequest, device: Dict[str, Any] = Depends(warehouse_only)):
    with db.tx() as conn:
        season_protocol.publish_definitions(conn, body.target_scope, body.revision, body.definitions)
    return {'revision': body.revision}


@app.get('/v1/seasons/bootstrap')
def season_bootstrap(device: Dict[str, Any] = Depends(current_device),
                     x_season_protocol: Optional[int] = Header(None),
                     x_database_generation: Optional[str] = Header(None),
                     x_generation_token: Optional[str] = Header(None)):
    with db.tx() as conn:
        return season_protocol.bootstrap(conn, device, x_database_generation,
                                         x_generation_token, x_season_protocol)


def customer_cache_read(fn):
    @wraps(fn)
    def read(*args, **kwargs):
        with db.customer_cache_read_lock():
            return fn(*args, **kwargs)
    return read


@app.post('/v1/customer/snapshot/upload', dependencies=[Depends(customer_stock_upload_auth)])
def customer_snapshot_upload(body: CustomerSnapshotUploadRequest) -> Dict[str, Any]:
    result = db.replace_customer_snapshot(
        [row.model_dump() for row in body.stock_rows],
        [row.model_dump() for row in body.reservation_rows],
        (body.uploaded_at or '').strip() or _utc_now_iso(),
        season_context=body.season_context,
    )
    return {'server_time': _utc_now_iso(), **result}


@app.get("/v1/customer/stock")
@customer_cache_read
def customer_stock(
    source_device: str = "",
    item_type: str = "",
    school: str = "",
    color: str = "",
    size: str = "",
    min_count: int = Query(1, ge=0),
    limit: int = Query(30, ge=1, le=200),
) -> Dict[str, Any]:
    return {
        "server_time": _utc_now_iso(),
        "summary": db.customer_stock_summary(),
        "rows": db.query_customer_stock(
            source_device=source_device,
            item_type=item_type,
            school=school,
            color=color,
            size=size,
            min_count=min_count,
            limit=limit,
        ),
    }


@app.get("/v1/customer/known-values")
@customer_cache_read
def customer_known_values(
    field: str,
    source_device: str = "",
    item_type: str = "",
    school: str = "",
    color: str = "",
    min_count: int = Query(0, ge=0),
    limit: int = Query(2000, ge=1, le=10000),
) -> Dict[str, Any]:
    if field not in {"item_type", "school", "color", "size"}:
        raise HTTPException(status_code=422, detail="invalid field")
    return {
        "server_time": _utc_now_iso(),
        "field": field,
        "values": db.customer_known_values(
            field,
            limit,
            source_device=source_device,
            item_type=item_type,
            school=school,
            color=color,
            min_count=min_count,
        ),
    }


@app.post("/v1/customer/stock/upload", dependencies=[Depends(customer_stock_upload_auth)])
def customer_stock_upload(body: CustomerStockUploadRequest) -> Dict[str, Any]:
    uploaded_at = (body.uploaded_at or "").strip() or _utc_now_iso()
    rows = [
        r.model_dump() if hasattr(r, "model_dump") else r.dict()
        for r in body.rows
    ]
    result = db.replace_customer_stock(rows, uploaded_at, season_context=body.season_context)
    return {"ok": True, "server_time": _utc_now_iso(), **result}


@app.get("/v1/customer/reservations/summary")
@customer_cache_read
def customer_reservations_summary(
    source_device: str = "",
    item_type: str = "",
    school: str = "",
    color: str = "",
    size: str = "",
) -> Dict[str, Any]:
    return {
        "server_time": _utc_now_iso(),
        **db.query_customer_reserved_quantity(
            source_device=source_device,
            item_type=item_type,
            school=school,
            color=color,
            size=size,
        ),
    }


@app.get("/v1/customer/reservations/check")
@customer_cache_read
def customer_reservations_check(
    source_device: str,
    bill_number: str,
    item_type: str = "",
    school: str = "",
    color: str = "",
    size: str = "",
) -> Dict[str, Any]:
    row = db.check_customer_reservation(
        source_device=source_device,
        bill_number=bill_number,
        item_type=item_type,
        school=school,
        color=color,
        size=size,
    )
    if not row:
        raise HTTPException(status_code=404, detail="reservation not found")
    return {"server_time": _utc_now_iso(), **row}


@app.get("/v1/mojeeb/branches", dependencies=[Depends(mojeeb_api_auth)])
@customer_cache_read
def mojeeb_branches() -> Dict[str, Any]:
    """Return only branch identifiers represented in the current live cache."""
    return {
        "server_time": _utc_now_iso(),
        "branches": db.query_mojeeb_branches(),
    }


@app.get("/v1/mojeeb/stock", dependencies=[Depends(mojeeb_api_auth)])
@customer_cache_read
def mojeeb_stock(
    branch: str = "",
    item_type: str = "",
    school: str = "",
    color: str = "",
    size: str = "",
    limit: int = Query(20, ge=1, le=50),
) -> Dict[str, Any]:
    """Customer-safe stock, prices, and availability after reservations."""
    rows = db.query_mojeeb_stock(
        source_device=branch,
        item_type=item_type,
        school=school,
        color=color,
        size=size,
        limit=limit,
    )
    return {
        "server_time": _utc_now_iso(),
        "matches": len(rows),
        "rows": rows,
    }


@app.get("/v1/mojeeb/reservation", dependencies=[Depends(mojeeb_api_auth)])
@customer_cache_read
def mojeeb_reservation(
    branch: str,
    bill_number: str,
) -> Dict[str, Any]:
    """Look up one branch reservation without exposing customer information."""
    row = db.check_customer_reservation(
        source_device=branch,
        bill_number=bill_number,
    )
    if not row:
        return {
            "server_time": _utc_now_iso(),
            "found": False,
            "message": "No active reservation matched this branch and bill number.",
        }
    return {"server_time": _utc_now_iso(), "found": True, **row}


@app.post("/v1/customer/reservations/upload", dependencies=[Depends(customer_stock_upload_auth)])
def customer_reservations_upload(body: CustomerReservationUploadRequest) -> Dict[str, Any]:
    uploaded_at = (body.uploaded_at or "").strip() or _utc_now_iso()
    rows = [
        r.model_dump() if hasattr(r, "model_dump") else r.dict()
        for r in body.rows
    ]
    result = db.replace_customer_reservations(rows, uploaded_at, season_context=body.season_context)
    return {"ok": True, "server_time": _utc_now_iso(), **result}


def _pos_updates_dir() -> Path:
    return Path(POS_UPDATES_DIR).resolve()


def _read_latest_pos_manifest() -> Optional[Dict[str, Any]]:
    manifest_path = _pos_updates_dir() / "latest.json"
    if not manifest_path.is_file():
        return None
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"invalid POS update manifest: {ex}")
    if not isinstance(data, dict):
        raise HTTPException(status_code=500, detail="invalid POS update manifest")
    return data


@app.get("/v1/updates/pos/latest", response_model=PosUpdateLatestResponse)
def pos_update_latest(
    device: Dict[str, Any] = Depends(current_device),
) -> PosUpdateLatestResponse:
    if device["role"] not in ("pos", "warehouse"):
        raise HTTPException(status_code=403, detail="invalid device role")
    manifest = _read_latest_pos_manifest()
    return PosUpdateLatestResponse(
        available=manifest is not None,
        manifest=manifest,
        server_time=_utc_now_iso(),
    )


@app.get("/v1/updates/pos/package/{filename}")
def pos_update_package(
    filename: str,
    device: Dict[str, Any] = Depends(current_device),
) -> FileResponse:
    if device["role"] not in ("pos", "warehouse"):
        raise HTTPException(status_code=403, detail="invalid device role")
    safe_name = Path(filename).name
    if safe_name != filename or not safe_name.lower().endswith(".zip"):
        raise HTTPException(status_code=404, detail="package not found")
    package_path = (_pos_updates_dir() / safe_name).resolve()
    updates_dir = _pos_updates_dir()
    try:
        package_path.relative_to(updates_dir)
    except ValueError:
        raise HTTPException(status_code=404, detail="package not found")
    if not package_path.is_file():
        raise HTTPException(status_code=404, detail="package not found")
    return FileResponse(
        str(package_path),
        media_type="application/zip",
        filename=safe_name,
    )


@app.post("/v1/admin/reset-device")
def admin_reset_device(
    body: AdminResetDeviceRequest,
) -> Dict[str, Any]:
    device_name = auth.validate_simple_device_name(body.device_name)
    target_scope = (body.target_scope or "").strip()
    if not target_scope:
        role = auth.infer_role_from_device_name(device_name)
        target_scope = "warehouse" if role == "warehouse" else ("pos:" + device_name)
    result = db.reset_device_state(device_name, target_scope)
    result["server_time"] = _utc_now_iso()
    return result


@app.post("/v1/admin/reset-all")
def admin_reset_all(
    body: AdminResetAllRequest,
) -> Dict[str, Any]:
    if (body.confirm or "").strip().upper() != "RESET ALL":
        raise HTTPException(status_code=422, detail="confirmation text must be RESET ALL")
    result = db.reset_all_state()
    result["server_time"] = _utc_now_iso()
    return result
