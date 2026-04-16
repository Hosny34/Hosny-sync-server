# HosnyWarehouse Sync Server

Minimal event-relay hub for the HosnyWarehouse warehouse + POS apps.

## What it does

- **Stores an append-only event log** — every business operation from
  every client lands in a single `events` table, ordered by a server
  bigserial `server_seq`.
- **Scopes events per device** — warehouse sees everything, each POS
  sees only its own events and "all-pos" broadcasts. A POS can never
  read another POS's events.
- **Idempotent push** — duplicate `event_uuid` values are silently
  dropped, so retries after a network flake are safe.
- **Monotonic pull cursor** — clients pull `GET /sync/pull?since=N`,
  receive events in `server_seq` order, and advance their local
  cursor.

## Stack

- Python 3.10+, FastAPI, uvicorn
- SQLite by default (good for dev and small deployments); set
  `DATABASE_URL` to a Postgres URL to upgrade.
- PyJWT for bearer tokens.

## Quick start (dev, SQLite)

```bash
cd sync_server
python -m venv .venv
.venv/Scripts/activate        # Windows
pip install -r requirements.txt
python admin_cli.py init                                # create schema
python admin_cli.py register WAREHOUSE-MAIN warehouse   # → prints token
python admin_cli.py register POS-01 pos                 # → prints token
python admin_cli.py register POS-02 pos                 # → prints token
uvicorn main:app --host 0.0.0.0 --port 8000
```

Copy each printed bearer token into the corresponding client's sync
setup dialog along with the server URL (e.g.
`http://192.168.1.10:8000`).

## Endpoints

| Method | Path                 | Who                      |
|--------|----------------------|--------------------------|
| GET    | /v1/health           | anyone                   |
| POST   | /v1/auth/token       | any registered device    |
| POST   | /v1/sync/push        | any authenticated device |
| GET    | /v1/sync/pull        | any authenticated device |
| GET    | /v1/sync/status      | warehouse only           |

## Access control summary

- Every request must carry `Authorization: Bearer <jwt>`.
- The token encodes the caller's `device_uuid`, `device_name`, `role`.
- **Push:** events are always stored with `source_device = caller`,
  regardless of what the client sent in `source_device`. No spoofing.
- **Pull:** the `WHERE` clause filters events to
  `target_scope IN (...)` where the allowed set depends on role:
  - `warehouse` → `warehouse`, `all`
  - `pos`       → `pos:<device_name>`, `all-pos`, `all`
- **Status endpoint** is warehouse-only.

## What this phase does NOT include

- No background auto-sync — clients push/pull only when the user
  clicks the sync button.
- No event appliers on either side — pulled events are stored in
  `sync_inbox` but not applied to domain tables yet. Phase 3/4 adds
  appliers.
- No monitoring dashboard — stale-branch alerts come in Phase 6.

## Upgrading to Postgres later

Set `DATABASE_URL=postgresql://user:pass@host/db` and rerun
`admin_cli.py init`. The SQL is plain vanilla and works on both.
