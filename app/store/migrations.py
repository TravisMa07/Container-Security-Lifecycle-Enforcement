"""Ordered migrations: never edit an applied tuple; append a new migration."""

_APPEND_ONLY_TABLES = ("raw_documents", "scans", "scan_findings")

DEFAULT_MIGRATIONS = (
    (
        "CREATE TABLE raw_documents (document_hash TEXT PRIMARY KEY, body BLOB NOT NULL)",
        "CREATE TABLE scans (scan_id TEXT PRIMARY KEY, source_document_hash TEXT NOT NULL "
        "REFERENCES raw_documents(document_hash), db_document_hash TEXT "
        "REFERENCES raw_documents(document_hash), payload TEXT NOT NULL)",
        "CREATE TABLE scan_findings (scan_id TEXT NOT NULL REFERENCES scans(scan_id), "
        "finding_id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(scan_id, finding_id))",
        "CREATE INDEX scan_findings_identity ON scan_findings(finding_id)",
        *(
            f"CREATE TRIGGER {table}_no_{operation.lower()} BEFORE {operation} ON {table} "
            "BEGIN SELECT RAISE(ABORT, 'scan evidence is append-only'); END"
            for table in _APPEND_ONLY_TABLES
            for operation in ("UPDATE", "DELETE")
        ),
    ),
)

# P2 adds history and mutable projections; migration1 remains byte-identical.
DEFAULT_MIGRATIONS += (
    (
        'CREATE TABLE inventory_events (event_id TEXT PRIMARY KEY, payload TEXT NOT NULL)',
        'CREATE TABLE inventory_observations (observation_id TEXT PRIMARY KEY, event_id TEXT NOT NULL REFERENCES inventory_events(event_id), payload TEXT NOT NULL)',
        'CREATE TABLE inventory_current (cluster_id TEXT NOT NULL, namespace TEXT NOT NULL, kind TEXT NOT NULL, uid TEXT NOT NULL, event_id TEXT NOT NULL REFERENCES inventory_events(event_id), present INTEGER NOT NULL CHECK(present IN (0,1)), absence_reason TEXT, last_seen TEXT NOT NULL, PRIMARY KEY(cluster_id,namespace,kind,uid))',
        'CREATE TABLE inventory_checkpoints (cluster_id TEXT NOT NULL, namespace TEXT NOT NULL, kind TEXT NOT NULL, resource_version TEXT NOT NULL, observed_at TEXT NOT NULL, PRIMARY KEY(cluster_id,namespace,kind))',
        'CREATE TABLE inventory_scopes (cluster_id TEXT NOT NULL, namespace TEXT NOT NULL, server_id TEXT NOT NULL, PRIMARY KEY(cluster_id,namespace))',
        'CREATE TABLE inventory_gap_events (gap_event_id TEXT PRIMARY KEY, gap_id TEXT NOT NULL, cluster_id TEXT NOT NULL, namespace TEXT NOT NULL, kind TEXT NOT NULL, event_type TEXT NOT NULL, reason TEXT NOT NULL, observed_at TEXT NOT NULL, started_at TEXT NOT NULL)',
        *(
            f"CREATE TRIGGER {table}_no_{operation.lower()} BEFORE {operation} ON {table} "
            "BEGIN SELECT RAISE(ABORT, 'inventory evidence is append-only'); END"
            for table in ('inventory_events', 'inventory_observations', 'inventory_gap_events')
            for operation in ('UPDATE', 'DELETE')
        ),
    ),
)

# Preserve already executed migration2: add immutable complete-list receipts.
DEFAULT_MIGRATIONS += (
    (
        'CREATE TABLE inventory_snapshots (snapshot_id TEXT PRIMARY KEY, payload TEXT NOT NULL)',
        *(f"CREATE TRIGGER inventory_snapshots_no_{operation.lower()} BEFORE {operation} ON inventory_snapshots "
          "BEGIN SELECT RAISE(ABORT, 'inventory snapshots are append-only'); END"
          for operation in ('UPDATE', 'DELETE')),
    ),
)

DEFAULT_MIGRATIONS += (
    (
        'CREATE TABLE lifecycle_assessments (assessment_id TEXT PRIMARY KEY, payload TEXT NOT NULL)',
        *(f"CREATE TRIGGER lifecycle_assessments_no_{operation.lower()} BEFORE {operation} ON lifecycle_assessments "
          "BEGIN SELECT RAISE(ABORT, 'lifecycle assessments are append-only'); END"
          for operation in ('UPDATE', 'DELETE')),
    ),
)
