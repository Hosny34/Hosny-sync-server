"""Opt-in, authenticated season/generation boundary for the event relay.

All mutations require the caller's existing serialized server transaction.
No season is activated by schema installation or by a POS client.
"""
import hashlib
import hmac
import json
import secrets

PROTOCOL_VERSION = 1


class ProtocolError(ValueError):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                   separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def initialize(conn):
    statements = (
        """CREATE TABLE IF NOT EXISTS relay_seasons(
            season_id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
            activation_revision INTEGER NOT NULL UNIQUE)""",
        """CREATE TABLE IF NOT EXISTS relay_season_state(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            active_season_id TEXT REFERENCES relay_seasons(season_id),
            revision INTEGER NOT NULL DEFAULT 0, paused INTEGER NOT NULL DEFAULT 0)""",
        """CREATE TABLE IF NOT EXISTS relay_generations(
            generation_id TEXT PRIMARY KEY, device_uuid TEXT NOT NULL REFERENCES devices(device_uuid),
            season_id TEXT NOT NULL REFERENCES relay_seasons(season_id),
            secret_hash TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('ACTIVE','RETIRED')),
            start_seq INTEGER NOT NULL, protocol_version INTEGER NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS relay_branch_bindings(
            device_uuid TEXT PRIMARY KEY REFERENCES devices(device_uuid),
            branch_id TEXT NOT NULL)""",
        """CREATE UNIQUE INDEX IF NOT EXISTS relay_one_generation_per_device
            ON relay_generations(device_uuid) WHERE status='ACTIVE'""",
        """CREATE TABLE IF NOT EXISTS relay_event_origins(
            event_uuid TEXT PRIMARY KEY REFERENCES events(event_uuid),
            source_season_id TEXT NOT NULL, generation_id TEXT,
            target_generation_id TEXT, content_digest TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS relay_definition_bootstrap(
            target_scope TEXT PRIMARY KEY, revision INTEGER NOT NULL,
            state_json TEXT NOT NULL, content_digest TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS relay_season_operations(
            operation_id TEXT PRIMARY KEY, content_digest TEXT NOT NULL, result_json TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS relay_customer_cache_versions(
            kind TEXT PRIMARY KEY, season_id TEXT NOT NULL, sequence INTEGER NOT NULL,
            content_digest TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS relay_apply_lease(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1), lease_id TEXT NOT NULL,
            owner TEXT NOT NULL, revision INTEGER NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS relay_enrollment_authorizations(
            device_uuid TEXT NOT NULL REFERENCES devices(device_uuid),
            season_id TEXT NOT NULL REFERENCES relay_seasons(season_id),
            code_hash TEXT NOT NULL,created_revision INTEGER NOT NULL,
            claimed_generation_id TEXT,PRIMARY KEY(device_uuid,season_id))""",
    )
    for sql in statements:
        conn.execute(sql)
    conn.execute('INSERT OR IGNORE INTO relay_season_state(singleton) VALUES(1)')
    # Adopt existing managed installations once; subsequent renames must not
    # silently move their history to another branch.
    conn.execute("INSERT OR IGNORE INTO relay_branch_bindings "
                 "SELECT DISTINCT d.device_uuid,d.device_name FROM devices d "
                 "JOIN relay_generations g USING(device_uuid) "
                 "WHERE d.role='pos' AND TRIM(COALESCE(d.device_name,''))<>''")


def branch_binding(conn, device_uuid):
    device = conn.execute('SELECT device_name,role,revoked_at FROM devices WHERE device_uuid=?',
                          (device_uuid,)).fetchone()
    if not device or device['role'] != 'pos' or device['revoked_at']:
        raise ProtocolError('Unknown, revoked or non-POS device')
    name = device['device_name']
    if not isinstance(name, str) or not name.strip() or name != name.strip():
        raise ProtocolError('Device requires an unambiguous branch identity')
    saved = conn.execute('SELECT branch_id FROM relay_branch_bindings WHERE device_uuid=?',
                         (device_uuid,)).fetchone()
    if saved and saved['branch_id'] != name:
        raise ProtocolError('Device branch identity changed; manager reconciliation required')
    return saved['branch_id'] if saved else name


def authority(conn):
    generations = [dict(row) for row in conn.execute(
        "SELECT g.device_uuid,g.generation_id,g.season_id,g.status,d.device_name "
        "FROM relay_generations g JOIN devices d USING(device_uuid) "
        "WHERE g.status='ACTIVE' AND d.revoked_at IS NULL")]
    owners = set()
    for row in generations:
        row['device_name'] = branch_binding(conn, row['device_uuid'])
        key = (row['season_id'], row['device_name'])
        if key in owners:
            raise ProtocolError('Multiple active installations own one branch; manager reconciliation required')
        owners.add(key)
    sources = {row['device_uuid']: row['branch_id'] for row in conn.execute(
        "SELECT d.device_uuid,COALESCE(b.branch_id,d.device_name) AS branch_id "
        "FROM devices d LEFT JOIN relay_branch_bindings b USING(device_uuid) WHERE d.role='pos'")}
    return generations, sources


def state(conn):
    row = conn.execute('SELECT * FROM relay_season_state WHERE singleton=1').fetchone()
    return dict(row) if row else None


def enabled(conn):
    if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='relay_season_state'").fetchone():
        return False
    return bool(state(conn)['active_season_id'])


def require_transaction(conn):
    if not conn.in_transaction:
        raise ProtocolError('Season protocol mutations require a transaction')


def change_state(conn, *, operation_id, expected_revision, action, season_id=None, name=None):
    require_transaction(conn)
    request = digest([action, expected_revision, season_id, name])
    old = conn.execute('SELECT * FROM relay_season_operations WHERE operation_id=?', (operation_id,)).fetchone()
    if old:
        if old['content_digest'] != request:
            raise ProtocolError('Operation identity reused with different contents')
        return json.loads(old['result_json'])
    require_no_apply_lease(conn)
    current = state(conn)
    if current['revision'] != expected_revision:
        raise ProtocolError('Season revision changed; refresh before retrying')
    revision = current['revision'] + 1
    if action == 'activate':
        if not season_id or not name:
            raise ProtocolError('Season ID and name are required')
        if current['active_season_id'] and not current['paused']:
            raise ProtocolError('Pause routing before activating a new season')
        conn.execute('INSERT INTO relay_seasons VALUES(?,?,?)', (season_id, name, revision))
        # Keep the server paused until the local Warehouse cutover is verified.
        conn.execute('UPDATE relay_season_state SET active_season_id=?,paused=1,revision=?',
                     (season_id, revision))
        # Public read models must never expose the preceding season after cutover.
        for table in ('customer_stock_cache', 'customer_reservation_cache'):
            if conn.execute('SELECT 1 FROM sqlite_master WHERE name=?', (table,)).fetchone():
                conn.execute('DELETE FROM ' + table)
        conn.execute('DELETE FROM relay_customer_cache_versions')
    elif action in ('pause', 'resume'):
        if not current['active_season_id']:
            raise ProtocolError('No active season')
        conn.execute('UPDATE relay_season_state SET paused=?,revision=?', (int(action == 'pause'), revision))
    else:
        raise ProtocolError('Unknown season operation')
    result = state(conn)
    conn.execute('INSERT INTO relay_season_operations VALUES(?,?,?)',
                 (operation_id, request, json.dumps(result)))
    return result


def enroll(conn, *, device_uuid, generation_id, secret, season_id, protocol_version):
    require_transaction(conn)
    require_no_apply_lease(conn)
    if protocol_version != PROTOCOL_VERSION or len(secret) < 32 or not generation_id:
        raise ProtocolError('Unsupported protocol or invalid generation credentials')
    if season_id != state(conn)['active_season_id']:
        raise ProtocolError('Enroll only in the active season')
    device = conn.execute('SELECT role,revoked_at FROM devices WHERE device_uuid=?', (device_uuid,)).fetchone()
    if not device or device['role'] != 'pos' or device['revoked_at']:
        raise ProtocolError('Unknown, revoked or non-POS device')
    branch = branch_binding(conn, device_uuid)
    generations, _ = authority(conn)
    if any(row['device_name'] == branch and row['season_id'] == season_id
           and row['device_uuid'] != device_uuid for row in generations):
        raise ProtocolError('Branch already has an active installation; revoke it before replacement')
    conn.execute('INSERT OR IGNORE INTO relay_branch_bindings VALUES(?,?)', (device_uuid, branch))
    secret_hash = hashlib.sha256(secret.encode()).hexdigest()
    old = conn.execute('SELECT * FROM relay_generations WHERE generation_id=?', (generation_id,)).fetchone()
    if old:
        if (old['device_uuid'], old['season_id'], old['secret_hash']) != (device_uuid, season_id, secret_hash):
            raise ProtocolError('Generation identity conflict')
        if old['status'] != 'ACTIVE':
            raise ProtocolError('A retired generation cannot be reactivated')
        return {k: old[k] for k in ('generation_id', 'season_id', 'start_seq', 'protocol_version')}
    start_seq = conn.execute('SELECT COALESCE(MAX(server_seq),0) FROM events').fetchone()[0]
    conn.execute("UPDATE relay_generations SET status='RETIRED' WHERE device_uuid=?", (device_uuid,))
    conn.execute('INSERT INTO relay_generations VALUES(?,?,?,?,?,?,?)',
                 (generation_id, device_uuid, season_id, secret_hash, 'ACTIVE', start_seq, protocol_version))
    conn.execute('UPDATE relay_season_state SET revision=revision+1')
    return {'generation_id': generation_id, 'season_id': season_id,
            'start_seq': start_seq, 'protocol_version': protocol_version}


def authorize_enrollment(conn, *, device_uuid):
    """Create a one-time manager authorization for the active season."""
    require_transaction(conn)
    require_no_apply_lease(conn)
    current = state(conn)
    if not current['active_season_id']:
        raise ProtocolError('No active season')
    device = conn.execute('SELECT role,revoked_at FROM devices WHERE device_uuid=?', (device_uuid,)).fetchone()
    if not device or device['role'] != 'pos' or device['revoked_at']:
        raise ProtocolError('Unknown, revoked or non-POS device')
    code = secrets.token_urlsafe(24)
    conn.execute('INSERT INTO relay_enrollment_authorizations VALUES(?,?,?,?,NULL) '
        'ON CONFLICT(device_uuid,season_id) DO UPDATE SET code_hash=excluded.code_hash,'
        'created_revision=excluded.created_revision,claimed_generation_id=NULL',
        (device_uuid,current['active_season_id'],hashlib.sha256(code.encode()).hexdigest(),current['revision']))
    return {'device_uuid':device_uuid,'season_id':current['active_season_id'],'enrollment_code':code}


def claim_enrollment(conn, *, device_uuid, enrollment_code, generation_id, secret, protocol_version):
    require_transaction(conn)
    require_no_apply_lease(conn)
    current = state(conn)
    row = conn.execute('SELECT * FROM relay_enrollment_authorizations WHERE device_uuid=? AND season_id=?',
                       (device_uuid,current['active_season_id'])).fetchone()
    supplied = hashlib.sha256(str(enrollment_code or '').encode()).hexdigest()
    if not row or not hmac.compare_digest(row['code_hash'], supplied):
        raise ProtocolError('Invalid or expired enrollment authorization')
    if row['claimed_generation_id'] and row['claimed_generation_id'] != generation_id:
        raise ProtocolError('Enrollment authorization was already claimed')
    result = enroll(conn, device_uuid=device_uuid,generation_id=generation_id,secret=secret,
                    season_id=current['active_season_id'],protocol_version=protocol_version)
    conn.execute('UPDATE relay_enrollment_authorizations SET claimed_generation_id=? '
                 'WHERE device_uuid=? AND season_id=?',
                 (generation_id,device_uuid,current['active_season_id']))
    result['device_uuid'] = device_uuid
    return result


def client_status(conn, device_uuid):
    current = state(conn)
    season = conn.execute('SELECT name FROM relay_seasons WHERE season_id=?',
                          (current['active_season_id'],)).fetchone()
    generation = conn.execute("SELECT generation_id,season_id,status FROM relay_generations "
                              "WHERE device_uuid=? AND status='ACTIVE'", (device_uuid,)).fetchone()
    return {'enabled':enabled(conn),'active_season_id':current['active_season_id'],
            'active_season_name':season['name'] if season else None,
            'device_uuid':device_uuid,
            'paused':bool(current['paused']),'revision':current['revision'],
            'protocol_version':PROTOCOL_VERSION,'generation':dict(generation) if generation else None}


def authenticate_generation(conn, device_uuid, generation_id, secret, *, current=False):
    branch_binding(conn, device_uuid)
    row = conn.execute('SELECT * FROM relay_generations WHERE generation_id=?', (generation_id,)).fetchone()
    supplied = hashlib.sha256(str(secret or '').encode()).hexdigest()
    if not row or row['device_uuid'] != device_uuid or not hmac.compare_digest(row['secret_hash'], supplied):
        raise ProtocolError('Invalid database-generation credentials')
    if row['status'] == 'ACTIVE':
        authority(conn)
    if current and (row['status'] != 'ACTIVE' or row['season_id'] != state(conn)['active_season_id']):
        raise ProtocolError('This database generation cannot receive current commands')
    return dict(row)


def ready(conn, protocol_version):
    if protocol_version != PROTOCOL_VERSION:
        raise ProtocolError('Season-aware client upgrade required')
    current = state(conn)
    if current['paused']:
        raise ProtocolError('Season cutover in progress; retry after routing resumes')
    return current


def require_no_apply_lease(conn):
    if conn.execute('SELECT 1 FROM relay_apply_lease').fetchone():
        raise ProtocolError('Warehouse apply cycle is active; recover/release its lease before changing authority')


def apply_lease(conn, owner, lease_id, action, expected_revision):
    """Durable, non-expiring fence. A crashed Warehouse resumes its saved ID.

    Expiring leases cannot fence an in-flight SQLite commit after a slow network
    request. This lease deliberately requires explicit release by its owner.
    """
    require_transaction(conn)
    old = conn.execute('SELECT * FROM relay_apply_lease WHERE singleton=1').fetchone()
    if action == 'release':
        if old and (old['owner'], old['lease_id']) != (owner, lease_id):
            raise ProtocolError('Apply lease belongs to another cycle')
        conn.execute('DELETE FROM relay_apply_lease WHERE singleton=1')
        return {'released': True}
    if action != 'acquire' or not lease_id:
        raise ProtocolError('Invalid apply lease operation')
    current = ready(conn, PROTOCOL_VERSION)
    if current['revision'] != expected_revision:
        raise ProtocolError('Authority changed before apply lease acquisition')
    if old and (old['owner'], old['lease_id'], old['revision']) != (owner, lease_id, expected_revision):
        raise ProtocolError('Another Warehouse apply cycle owns the lease')
    conn.execute('INSERT OR IGNORE INTO relay_apply_lease VALUES(1,?,?,?)',
                 (lease_id, owner, expected_revision))
    return {'lease_id':lease_id, 'revision':expected_revision}


def authorize_customer_cache(conn, kind, context, rows):
    """Validate and version a cache replacement inside its mutation transaction."""
    require_transaction(conn)
    if not enabled(conn):
        if context is not None:
            raise ProtocolError('Managed cache upload requires an activated season')
        return True
    current = ready(conn, PROTOCOL_VERSION)
    if not isinstance(context, dict) or context.get('season_id') != current['active_season_id']:
        raise ProtocolError('Customer cache upload requires the active season')
    if context.get('revision') != current['revision']:
        raise ProtocolError('Customer cache authority changed; prepare a fresh snapshot')
    sequence = context.get('sequence')
    if type(sequence) is not int or sequence < 1:
        raise ProtocolError('Customer cache requires a positive export sequence')
    checksum = digest(rows)
    old = conn.execute('SELECT * FROM relay_customer_cache_versions WHERE kind=?', (kind,)).fetchone()
    if old and old['season_id'] == current['active_season_id']:
        if sequence < old['sequence']:
            raise ProtocolError('Stale customer cache upload')
        if sequence == old['sequence']:
            if old['content_digest'] != checksum:
                raise ProtocolError('Customer cache export sequence reused with different data')
            return False
    conn.execute('INSERT INTO relay_customer_cache_versions VALUES(?,?,?,?) '
                 'ON CONFLICT(kind) DO UPDATE SET season_id=excluded.season_id, '
                 'sequence=excluded.sequence,content_digest=excluded.content_digest',
                 (kind, current['active_season_id'], sequence, checksum))
    return True


def append_events(conn, rows, device, *, protocol_version, generation_id=None, secret=None):
    require_transaction(conn)
    current = ready(conn, protocol_version)
    origin = None
    if device['role'] == 'pos':
        origin = authenticate_generation(conn, device['device_uuid'], generation_id, secret)
    inserted = 0
    for row in rows:
        event_uuid, event_type, source, scope, payload, created_at = row
        if source != device['device_uuid']:
            raise ProtocolError('Authenticated source mismatch')
        content_hash = digest([event_type, source, scope, json.loads(payload)])
        existing = conn.execute('SELECT e.*,o.content_digest,o.generation_id FROM events e '
                                'LEFT JOIN relay_event_origins o USING(event_uuid) WHERE event_uuid=?',
                                (event_uuid,)).fetchone()
        if existing:
            prior = existing['content_digest'] or digest([
                existing['event_type'], existing['source_device'], existing['target_scope'],
                json.loads(existing['payload'])])
            if prior != content_hash or (existing['generation_id'] is not None and existing['generation_id'] != generation_id):
                raise ProtocolError('Event UUID reused with different contents or generation')
            continue
        target_generation = None
        if device['role'] == 'warehouse' and event_type in {
            'STOCK_TRANSFER_OUT', 'STOCK_TRANSFER_CANCELLED', 'BRANCH_STOCK_RECLASSIFIED',
            'REMOTE_RESERVATION_REQUEST', 'POS_OWNERSHIP_SNAPSHOT'
        } and not scope.startswith('pos:'):
            raise ProtocolError('Stock and reservation commands require a single enrolled target')
        if device['role'] == 'warehouse' and scope.startswith('pos:'):
            generations, _ = authority(conn)
            targets = [g for g in generations if g['device_name'] == scope[4:]
                       and g['season_id'] == current['active_season_id']]
            if len(targets) != 1:
                raise ProtocolError('Target branch has no enrolled current database')
            target_generation = targets[0]['generation_id']
        conn.execute('INSERT INTO events(event_uuid,event_type,source_device,target_scope,payload,created_at) VALUES(?,?,?,?,?,?)', row)
        conn.execute('INSERT INTO relay_event_origins VALUES(?,?,?,?,?)',
                     (event_uuid, origin['season_id'] if origin else current['active_season_id'],
                      generation_id if origin else None, target_generation, content_hash))
        inserted += 1
    return inserted


def pull(conn, scopes, since, limit, device, *, protocol_version, generation_id=None, secret=None):
    ready(conn, protocol_version)
    params = list(scopes)
    where = 'e.target_scope IN (' + ','.join('?' for _ in scopes) + ') AND e.server_seq>?'
    if not scopes:
        return []
    if device['role'] == 'pos':
        origin = authenticate_generation(conn, device['device_uuid'], generation_id, secret, current=True)
        since = max(since, origin['start_seq'])
        where += " AND o.source_season_id=? AND (o.target_generation_id=? OR (e.target_scope='all-pos' " \
                 "AND e.event_type IN ('PRICE_UPDATE','CATALOG_UPSERT','SPEC_RENAMED','BRANCH_CATALOG_DELETED')))"
        params.extend([since, origin['season_id'], generation_id])
    else:
        params.append(since)
        where += " AND (e.event_type<>'POS_STOCK_SNAPSHOT' OR NOT EXISTS (" \
                 "SELECT 1 FROM events newer JOIN relay_event_origins no ON no.event_uuid=newer.event_uuid " \
                 "WHERE newer.event_type=e.event_type AND newer.source_device=e.source_device " \
                 "AND newer.target_scope=e.target_scope AND no.generation_id=o.generation_id " \
                 "AND newer.server_seq>e.server_seq))"
    rows = conn.execute(
        'SELECT e.*,o.source_season_id,o.generation_id,o.target_generation_id,'
        "CASE WHEN g.status='ACTIVE' AND g.season_id=s.active_season_id THEN 1 ELSE 0 END AS current_generation "
        'FROM events e LEFT JOIN relay_event_origins o USING(event_uuid) '
        'LEFT JOIN relay_generations g ON g.generation_id=o.generation_id '
        'CROSS JOIN relay_season_state s WHERE ' + where + ' ORDER BY e.server_seq LIMIT ?',
        (*params, limit)).fetchall()
    return [dict(r) for r in rows]


def publish_definitions(conn, scope, revision, definitions):
    require_transaction(conn)
    if not scope.startswith('pos:'):
        raise ProtocolError('Definition bootstrap must target one branch')
    if not isinstance(definitions, dict) or set(definitions) - {
        'schema_version', 'catalog', 'price_profiles', 'size_profiles', 'fabric_weights', 'tombstones'
    }:
        raise ProtocolError('Bootstrap accepts definition collections only, never inventory or history')
    if definitions.get('schema_version') == 1:
        collections = {
            'catalog': {'item_defaults','spec_history'},
            'price_profiles': {'price_profiles','price_profile_lines','price_profile_assignments','price_profile_manual_overrides'},
            'size_profiles': {'size_profiles'}, 'fabric_weights': {'fabric_weights'},
            'tombstones': {'deleted_catalog_definitions','deleted_catalog_specs'},
        }
        if set(definitions) != {'schema_version',*collections}:
            raise ProtocolError('Incomplete definition bootstrap')
        for category,tables in collections.items():
            content = definitions[category]
            if not isinstance(content,dict) or set(content) != tables:
                raise ProtocolError('Invalid definition tables; inventory/history is not bootstrap data')
            for rows in content.values():
                if not isinstance(rows,list) or any(not isinstance(row,dict) or
                    any(isinstance(value,(dict,list)) for value in row.values()) for row in rows):
                    raise ProtocolError('Invalid definition rows')
    content_hash = digest(definitions)
    old = conn.execute('SELECT * FROM relay_definition_bootstrap WHERE target_scope=?', (scope,)).fetchone()
    if old and (revision < old['revision'] or (revision == old['revision'] and content_hash != old['content_digest'])):
        raise ProtocolError('Definition revision is stale or conflicting')
    conn.execute('INSERT INTO relay_definition_bootstrap VALUES(?,?,?,?) '
                 'ON CONFLICT(target_scope) DO UPDATE SET revision=excluded.revision, '
                 'state_json=excluded.state_json,content_digest=excluded.content_digest',
                 (scope, revision, json.dumps(definitions, ensure_ascii=True), content_hash))


def bootstrap(conn, device, generation_id, secret, protocol_version):
    ready(conn, protocol_version)
    origin = authenticate_generation(conn, device['device_uuid'], generation_id, secret, current=True)
    row = conn.execute('SELECT * FROM relay_definition_bootstrap WHERE target_scope=?',
                       ('pos:' + device['device_name'],)).fetchone()
    return {'season_id': origin['season_id'], 'generation_id': generation_id,
            'start_seq': origin['start_seq'], 'definitions_available': row is not None,
            'definition_revision': row['revision'] if row else None,
            'definitions': json.loads(row['state_json']) if row else None}
