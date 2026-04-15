import os
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional
from uuid import uuid4
from datetime import datetime, timezone
import psycopg2
import json

app = FastAPI()

DATABASE_URL = os.getenv("DATABASE_URL")

def get_conn():
    return psycopg2.connect(DATABASE_URL)

def utc_now():
    return datetime.now(timezone.utc).isoformat()


class EventIn(BaseModel):
    event_uuid: str
    event_type: str
    source_device: str
    target_scope: str
    payload: dict


class PushRequest(BaseModel):
    events: List[EventIn]


@app.on_event("startup")
def startup():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        server_seq SERIAL PRIMARY KEY,
        event_uuid TEXT UNIQUE,
        event_type TEXT,
        source_device TEXT,
        target_scope TEXT,
        payload JSONB,
        created_at TIMESTAMP DEFAULT NOW()
    );
    """)

    conn.commit()
    cur.close()
    conn.close()


@app.get("/")
def root():
    return {"ok": True}


@app.post("/v1/sync/push")
def push(req: PushRequest):
    conn = get_conn()
    cur = conn.cursor()

    inserted = 0

    for e in req.events:
        try:
            cur.execute("""
            INSERT INTO events (event_uuid, event_type, source_device, target_scope, payload)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (event_uuid) DO NOTHING;
            """, (e.event_uuid, e.event_type, e.source_device, e.target_scope, json.dumps(e.payload)))
            inserted += 1
        except:
            pass

    conn.commit()
    cur.close()
    conn.close()

    return {"ok": True, "inserted": inserted}


@app.get("/v1/sync/pull")
def pull(since: int = 0):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    SELECT server_seq, event_uuid, event_type, payload
    FROM events
    WHERE server_seq > %s
    ORDER BY server_seq ASC
    LIMIT 100;
    """, (since,))

    rows = cur.fetchall()

    events = []
    last_seq = since

    for r in rows:
        events.append({
            "server_seq": r[0],
            "event_uuid": r[1],
            "event_type": r[2],
            "payload": r[3]
        })
        last_seq = r[0]

    cur.close()
    conn.close()

    return {"events": events, "next_seq": last_seq}
