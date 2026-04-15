from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional
from uuid import uuid4
from datetime import datetime, timezone

app = FastAPI(title="Hosny Sync Server", version="0.1.0")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EventIn(BaseModel):
    event_uuid: str
    event_type: str
    source_device: str
    target_scope: str
    created_at: Optional[str] = None
    payload: dict


class PushRequest(BaseModel):
    events: List[EventIn]


@app.get("/")
def root():
    return {
        "ok": True,
        "service": "hosny-sync-server",
        "message": "Server is running"
    }


@app.get("/health")
def health():
    return {
        "ok": True,
        "time": utc_now()
    }


@app.post("/v1/auth/token")
def auth_token():
    return {
        "access_token": str(uuid4()),
        "token_type": "bearer"
    }


@app.post("/v1/sync/push")
def sync_push(req: PushRequest):
    return {
        "ok": True,
        "received": len(req.events),
        "acked_event_uuids": [e.event_uuid for e in req.events],
        "server_time": utc_now()
    }


@app.get("/v1/sync/pull")
def sync_pull(since: int = 0, limit: int = 100):
    return {
        "ok": True,
        "events": [],
        "next_seq": since,
        "limit": limit,
        "server_time": utc_now()
    }
