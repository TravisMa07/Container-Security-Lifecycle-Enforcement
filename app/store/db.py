"""Transactional, append-only scan snapshots; local DB ownership remains a trust boundary."""

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import sqlite3

from app.store.migrations import DEFAULT_MIGRATIONS


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _hash(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _migration_hash(statements):
    return _hash(_json(list(statements)).encode())


class Store:
    """One connection per process/invocation; writes and migrations are all-or-nothing."""

    def __init__(self, path, migrations=None):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if str(path) != ':memory:':
            try:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
            except FileExistsError:
                pass
        self.connection = sqlite3.connect(path, isolation_level=None, timeout=5)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA busy_timeout=5000")
        self.migrations = DEFAULT_MIGRATIONS if migrations is None else tuple(migrations)
        if any(not isinstance(m, tuple) or not m or any(not isinstance(s, str) for s in m)
               for m in self.migrations):
            self.connection.close()
            raise ValueError("migrations must be nonempty ordered SQL tuples")
        self._ready = False

    def __enter__(self):
        try:
            self.initialize()
            return self
        except BaseException:
            self.connection.close()
            raise

    def __exit__(self, *args):
        self.connection.close()

    def initialize(self):
        """Refuse unknown/edited schema versions; rollback DDL together with its ledger."""
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            tables = {r[0] for r in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )}
            user_version = self.connection.execute("PRAGMA user_version").fetchone()[0]
            if "schema_migrations" not in tables:
                if tables or user_version:
                    raise ValueError("database has no compatible CSLE migration ledger")
                self.connection.execute(
                    "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, content_hash TEXT NOT NULL)"
                )
            applied = self.connection.execute(
                "SELECT version, content_hash FROM schema_migrations ORDER BY version"
            ).fetchall()
            if user_version != len(applied) or len(applied) > len(self.migrations):
                raise ValueError("database schema version is incompatible")
            for index, row in enumerate(applied):
                if row["version"] != index + 1 or row["content_hash"] != _migration_hash(self.migrations[index]):
                    raise ValueError("applied database migration was changed or is invalid")
            for index in range(len(applied), len(self.migrations)):
                for statement in self.migrations[index]:
                    self.connection.execute(statement)
                self.connection.execute(
                    "INSERT INTO schema_migrations(version, content_hash) VALUES (?, ?)",
                    (index + 1, _migration_hash(self.migrations[index])),
                )
            self.connection.execute(f"PRAGMA user_version={len(self.migrations)}")
            if self.connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError("database integrity check failed")
            if self.connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise ValueError("database contains broken evidence references")
            self.connection.execute("COMMIT")
            self._ready = True
        except BaseException:
            self.connection.execute("ROLLBACK")
            raise

    def _ensure_ready(self):
        if not self._ready:
            self.initialize()

    def save_scan(self, parsed, raw, db_metadata=None, provenance="imported", resolution=None, execution=None):
        """Persist parsed evidence and original bytes, without upgrading previous provenance."""
        self._ensure_ready()
        if not isinstance(raw, bytes) or (db_metadata is not None and not isinstance(db_metadata, bytes)):
            raise ValueError("scan documents must be original bytes")
        if provenance not in {"imported", "executed_local_trivy"}:
            raise ValueError("unsupported scan provenance")
        if provenance == "imported" and (execution is not None or resolution is not None):
            raise ValueError("imported reports cannot claim scanner execution or verified resolution")
        if provenance == "executed_local_trivy" and (not isinstance(execution, dict) or not execution
                                                     or not isinstance(resolution, dict) or not resolution):
            raise ValueError("executed scans require execution and resolution evidence")
        from app.models import ParsedScan
        payload = ParsedScan.model_validate(parsed.model_dump(mode="json")).model_dump(mode="json")
        if provenance == "executed_local_trivy":
            image = payload["image"]
            if resolution.get("manifest_digest") != image["manifest_digest"]:
                raise ValueError("executed resolution does not match selected manifest")
            for field in ("index_digest", "platform_digest", "platform"):
                if field in resolution and resolution[field] != image[field]:
                    raise ValueError("executed resolution conflicts with image " + field)
            if "scanner_version" in execution and execution["scanner_version"] != payload["scanner_version"]:
                raise ValueError("executed scanner version conflicts with scan")
        source_hash = _hash(raw)
        db_hash = _hash(db_metadata) if db_metadata is not None else None
        if payload["source_document_hash"] != source_hash or payload["db_document_hash"] != db_hash:
            raise ValueError("scan document hashes do not match original bytes")
        findings = payload.pop("findings")
        seen = set()
        for finding in findings:
            if finding["finding_id"] in seen:
                raise ValueError("duplicate finding snapshot identity")
            seen.add(finding["finding_id"])
            if (finding["source_document_hash"] != source_hash
                    or source_hash not in finding["evidence_ids"]
                    or finding["image_digest"] != payload["image"]["manifest_digest"]
                    or finding["parser_version"] != payload["parser_version"]
                    or finding["scanner_version"] != (payload["scanner_version"] or "unknown")
                    or finding["scan_timestamp"] != payload["scan_timestamp"]
                    or finding["scanner_db_updated_at"] != payload["scanner_db_updated_at"]):
                raise ValueError("finding is not bound to this scan and image")
        findings = sorted(findings, key=lambda finding: finding["finding_id"])
        payload.update(provenance=provenance, resolution=resolution, execution=execution)
        envelope = dict(payload, findings=findings)
        scan_id = _hash(_json(envelope).encode())
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            existing = self.connection.execute("SELECT 1 FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
            if existing is not None:
                self.get_scan(scan_id)  # A duplicate must still pass byte/snapshot integrity checks.
                self.connection.execute("COMMIT")
                return {"scan_id": scan_id, "inserted": False}
            for document_hash, body in ((source_hash, raw), (db_hash, db_metadata)):
                if body is None:
                    continue
                self.connection.execute(
                    "INSERT OR IGNORE INTO raw_documents(document_hash, body) VALUES (?, ?)", (document_hash, body)
                )
                if self._read_document(document_hash) != body:
                    raise ValueError("existing raw document bytes conflict")
            self.connection.execute(
                "INSERT INTO scans(scan_id, source_document_hash, db_document_hash, payload) VALUES (?, ?, ?, ?)",
                (scan_id, source_hash, db_hash, _json(payload)),
            )
            for finding in findings:
                self.connection.execute(
                    "INSERT INTO scan_findings(scan_id, finding_id, payload) VALUES (?, ?, ?)",
                    (scan_id, finding["finding_id"], _json(finding)),
                )
            self.connection.execute("COMMIT")
            return {"scan_id": scan_id, "inserted": True}
        except BaseException:
            self.connection.execute("ROLLBACK")
            raise

    def _read_document(self, document_hash):
        row = self.connection.execute("SELECT body FROM raw_documents WHERE document_hash=?", (document_hash,)).fetchone()
        if row is None or not isinstance(row["body"], bytes) or _hash(row["body"]) != document_hash:
            raise ValueError("raw scan document integrity check failed")
        return row["body"]

    def get_scan(self, scan_id):
        self._ensure_ready()
        row = self.connection.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        if row is None:
            return None
        self._read_document(row["source_document_hash"])
        if row["db_document_hash"] is not None:
            self._read_document(row["db_document_hash"])
        try:
            payload = json.loads(row["payload"])
            findings = []
            for finding_row in self.connection.execute(
                    "SELECT finding_id, payload FROM scan_findings WHERE scan_id=? ORDER BY finding_id", (scan_id,)):
                finding = json.loads(finding_row["payload"])
                if finding["finding_id"] != finding_row["finding_id"]:
                    raise ValueError("finding snapshot identity check failed")
                findings.append(finding)
            payload["findings"] = findings
            if (payload["source_document_hash"] != row["source_document_hash"]
                    or payload["db_document_hash"] != row["db_document_hash"]
                    or _hash(_json(payload).encode()) != scan_id):
                raise ValueError("normalized scan snapshot integrity check failed")
            return dict(payload, scan_id=scan_id)
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise ValueError("normalized scan snapshot integrity check failed") from error

    def list_scans(self):
        self._ensure_ready()
        ids = [r[0] for r in self.connection.execute("SELECT scan_id FROM scans ORDER BY scan_id")]
        return [self.get_scan(scan_id) for scan_id in ids]

    def list_findings(self):
        """Display newest observation, preserving evidence links to every original snapshot."""
        groups = {}
        for scan in self.list_scans():
            for finding in scan["findings"]:
                groups.setdefault(finding["finding_id"], []).append(finding)
        findings = []
        for finding_id in sorted(groups):
            snapshots = groups[finding_id]
            latest = max(snapshots, key=lambda f: (
                datetime.fromisoformat(f["scan_timestamp"].replace("Z", "+00:00")), f["source_document_hash"]
            ))
            findings.append(dict(latest, evidence_ids=sorted({
                evidence_id for snapshot in snapshots for evidence_id in snapshot["evidence_ids"]
            })))
        return findings

    def get_finding(self, finding_id):
        return next((f for f in self.list_findings() if f["finding_id"] == finding_id), None)
