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
