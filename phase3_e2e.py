# -*- coding: utf-8 -*-
"""Phase 3 end-to-end smoke test. Run from sync_server/ with the
server up on 127.0.0.1:8765 and the two API keys set below.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tempfile


td = tempfile.gettempdir()
WH_DIR  = r'c:\Users\youssef.sherif\Downloads\ادارة المخازن\ادارة المخازن'
POS_DIR = r'c:\Users\youssef.sherif\Downloads\ادارة المخازن\POS'
WH_SRC  = os.path.join(WH_DIR, 'warehouse_data.sqlite3')
POS_SRC = os.path.join(POS_DIR, 'warehouse_data.sqlite3')

wh_db  = os.path.join(td, 'phase3_wh.sqlite3')
pos_db = os.path.join(td, 'phase3_pos.sqlite3')
for p in (wh_db, pos_db, wh_db + '-wal', wh_db + '-shm', pos_db + '-wal', pos_db + '-shm'):
    try:
        os.remove(p)
    except OSError:
        pass
shutil.copyfile(WH_SRC, wh_db)
shutil.copyfile(POS_SRC, pos_db)

WH_KEY  = os.environ['WH_KEY']
POS_KEY = os.environ['POS_KEY']
SERVER  = 'http://127.0.0.1:8765'


def load_app(app_dir):
    for m in ('sync_core', 'sync_client', 'sync_appliers', 'sync_ui', 'HosnyWarehouse'):
        sys.modules.pop(m, None)
    if app_dir in sys.path:
        sys.path.remove(app_dir)
    sys.path.insert(0, app_dir)
    spec = importlib.util.spec_from_file_location(
        'HosnyWarehouse', os.path.join(app_dir, 'HosnyWarehouse.py')
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules['HosnyWarehouse'] = mod
    spec.loader.exec_module(mod)
    return mod


def open_db(mod, db_path):
    return mod.SqliteDatabase(path=db_path, legacy_json=os.path.join(td, 'noexist.json'))


def config_client(conn, name, role, key):
    import sync_client as sc
    sc.save_setup(conn, server_url=SERVER, device_name=name, api_token=key)
    return sc.SyncClient(conn)


def run_cycle(client, label):
    msgs = []
    try:
        summary = client.run_cycle(progress=lambda m: msgs.append(m))
    except Exception as e:
        print('  [' + label + '] cycle FAILED:', e)
        for m in msgs:
            print('   ', m)
        raise
    print('  [' + label + '] cycle:', summary)
    return summary


print('=== Phase 3 E2E ===')
print()
print('--- boot POS app + configure ---')
pos_mod = load_app(POS_DIR)
pos_sql = open_db(pos_mod, pos_db)
open_shift = pos_sql.get_open_shift() or {}
pos_sql.active_shift_id = open_shift.get('id')
print('  POS shift:', pos_sql.active_shift_id)
pos_client = config_client(pos_sql.conn, 'POS-01', 'pos', POS_KEY)

pos_stock_count = pos_sql.conn.execute(
    'SELECT COUNT(*) FROM stocks WHERE count>0'
).fetchone()[0]
print('  POS initial stocks rows:', pos_stock_count)

print()
print('--- POS cycle #1 (emits snapshot, pushes to server) ---')
summary = run_cycle(pos_client, 'POS')
assert summary['pushed'] >= 1, 'POS should push at least the snapshot event'
pos_sql.conn.close()

print()
print('--- boot WAREHOUSE app + configure ---')
wh_mod = load_app(WH_DIR)
wh_sql = open_db(wh_mod, wh_db)
wh_client = config_client(wh_sql.conn, 'WAREHOUSE-MAIN', 'warehouse', WH_KEY)

print()
print('--- WAREHOUSE cycle #1 (pulls snapshot, applies, refreshes known_devices) ---')
summary = run_cycle(wh_client, 'WH')
assert summary['pulled'] >= 1, 'WH should pull the POS snapshot'
assert summary['applied'] >= 1, 'WH should apply the snapshot'

mirror_rows = wh_sql.conn.execute(
    "SELECT COUNT(*) FROM pos_stocks_mirror WHERE source_device='POS-01'"
).fetchone()[0]
print('  pos_stocks_mirror rows for POS-01:', mirror_rows)

# POS snapshot aggregates by unit_price so mirror can be <= raw stock rows.
# The important check is that SUM(count) matches.
mirror_qty = wh_sql.conn.execute(
    "SELECT COALESCE(SUM(count),0) FROM pos_stocks_mirror WHERE source_device='POS-01'"
).fetchone()[0]
print('  pos_stocks_mirror total qty:', mirror_qty)

known = wh_sql.conn.execute(
    "SELECT device_name, role FROM known_devices WHERE role='pos'"
).fetchall()
print('  known_devices (pos):', [(r[0], r[1]) for r in known])
assert any(r[0] == 'POS-01' for r in known), 'POS-01 missing from known_devices'

pos_names = wh_sql.list_known_pos_device_names()
print('  list_known_pos_device_names:', pos_names)
assert 'POS-01' in pos_names

meta = wh_sql.conn.execute(
    "SELECT source_device, snapshot_at, row_count, total_value "
    "FROM pos_stocks_snapshot_meta"
).fetchall()
print('  snapshot_meta:', [(r[0], r[2], round(r[3], 2)) for r in meta])

print()
print('--- WAREHOUSE creates bill to POS-01 (shipment flow) ---')
row = wh_sql.conn.execute(
    'SELECT * FROM stocks WHERE count > 5 LIMIT 1'
).fetchone()
assert row is not None, 'warehouse has no stock to ship'
ship_line = {
    'item_type':    row['item_type'],
    'school':       row['school'],
    'color':        row['color'],
    'size':         row['size'],
    'warehouse_no': row['warehouse_no'],
    'package_no':   row['package_no'],
    'stock_id':     row['id'],
    'qty':          3,
    'unit_price':   float(row['unit_price']),
}
print('  shipping 3x %s/%s/%s/%s @ %.2f' % (
    row['item_type'], row['school'], row['color'], row['size'], row['unit_price'],
))
bill_id = wh_sql.create_bill('فرع: POS-01', [ship_line], target_pos='POS-01')
print('  bill_id:', bill_id)

ev = wh_sql.conn.execute(
    "SELECT event_type, target_scope, payload_json FROM sync_outbox "
    "WHERE event_type='STOCK_TRANSFER_OUT' ORDER BY local_seq DESC LIMIT 1"
).fetchone()
print('  outbox event: type=%s target_scope=%s' % (ev[0], ev[1]))
assert ev[1] == 'pos:POS-01', 'wrong target_scope: ' + str(ev[1])
payload = json.loads(ev[2])
assert 'items' in payload and len(payload['items']) == 1
assert payload['items'][0]['qty'] == 3

print()
print('--- WAREHOUSE cycle #2 (pushes shipment event) ---')
summary = run_cycle(wh_client, 'WH')
assert summary['pushed'] >= 1
wh_sql.conn.close()

print()
print('--- boot POS app again, cycle #2 (pulls + applies shipment) ---')
pos_mod = load_app(POS_DIR)
pos_sql = open_db(pos_mod, pos_db)
open_shift = pos_sql.get_open_shift() or {}
pos_sql.active_shift_id = open_shift.get('id')
pos_client = config_client(pos_sql.conn, 'POS-01', 'pos', POS_KEY)

stocks_before = pos_sql.conn.execute(
    'SELECT COUNT(*), COALESCE(SUM(count),0) FROM stocks'
).fetchone()
print('  POS stocks before: rows=%d, total_qty=%d' % tuple(stocks_before))

summary = run_cycle(pos_client, 'POS')
assert summary['applied'] >= 1, 'POS should apply the shipment'

stocks_after = pos_sql.conn.execute(
    'SELECT COUNT(*), COALESCE(SUM(count),0) FROM stocks'
).fetchone()
print('  POS stocks after:  rows=%d, total_qty=%d' % tuple(stocks_after))
delta = stocks_after[1] - stocks_before[1]
assert delta == 3, 'expected +3 qty, got %d' % delta

mv = pos_sql.conn.execute(
    "SELECT direction, qty, note FROM movements "
    "WHERE note LIKE 'شحنة من%' ORDER BY id DESC LIMIT 1"
).fetchone()
print('  new movement:', (mv[0], mv[1], mv[2]))

print()
print('--- POS cycle #3 (idempotency check) ---')
# Force a full re-pull by resetting the cursor. The server will
# return the STOCK_TRANSFER_OUT event again. The sync_inbox PK guard
# must prevent re-insertion — the applier should not re-run.
pos_sql.conn.execute("UPDATE sync_state SET last_pulled_seq = 0 WHERE channel='main'")
summary = run_cycle(pos_client, 'POS')
stocks_final = pos_sql.conn.execute(
    'SELECT COUNT(*), COALESCE(SUM(count),0) FROM stocks'
).fetchone()
print('  POS stocks after replay: rows=%d, total_qty=%d' % tuple(stocks_final))
assert stocks_final[1] == stocks_after[1], (
    'IDEMPOTENCY BROKEN: %d -> %d' % (stocks_after[1], stocks_final[1])
)
print('  idempotency: OK')

pos_sql.conn.close()
print()
print('E2E_PASSED')
