"""Freeze coherent inputs and pure lifecycle decisions, never signing approvals."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re

from pydantic import TypeAdapter
from app.models import Digest, Identifier, Timestamp, canonical_json, sha256_bytes
from app.store.inventory import InventoryStore
from app.collectors.kubernetes import RESOURCES
from app.collectors.trivy import load_document

ROOT = Path(__file__).resolve().parents[2]


def _hash(value):
    return sha256_bytes(canonical_json(value).encode())


class AssessmentStore:
    def __init__(self, path):
        self.inventory = InventoryStore(path)
        self.connection = self.inventory.connection

    def __enter__(self):
        self.inventory.__enter__()
        return self

    def __exit__(self, *args):
        self.inventory.__exit__(*args)

    def _read(self, assessment_id):
        from app.engine.lifecycle import evaluate, ENGINE_VERSION
        row = self.connection.execute('SELECT payload FROM lifecycle_assessments WHERE assessment_id=?', (assessment_id,)).fetchone()
        if row is None:
            return None
        try:
            payload = json.loads(row['payload'])
            if payload['engine_version'] != ENGINE_VERSION:
                raise ValueError('assessment requires its recorded engine version')
            if _hash(payload) != assessment_id or payload['result'] != evaluate(payload['facts']):
                raise ValueError('assessment integrity/replay check failed')
            return payload
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise ValueError('assessment integrity check failed') from error

    def _public(self, assessment_id, payload):
        return dict(payload['result'], assessment_id=assessment_id,
                    finding_id=payload['facts']['finding']['finding_id'],
                    image_digest=payload['facts']['finding']['image_digest'],
                    scope=payload['facts']['scope'], facts_hash=_hash(payload['facts']),
                    engine_version=payload['engine_version'])

    def get_assessment(self, assessment_id):
        payload = self._read(assessment_id)
        return self._public(assessment_id, payload) if payload else None

    def list_assessments(self, image_digest=None):
        if image_digest is not None:
            TypeAdapter(Digest).validate_python(image_digest, strict=True)
        result = []
        for row in self.connection.execute('SELECT assessment_id FROM lifecycle_assessments ORDER BY assessment_id'):
            public = self.get_assessment(row['assessment_id'])
            if image_digest is None or public['image_digest'] == image_digest:
                result.append(public)
        return result

    def assess(self, finding_id, cluster_id, namespaces, replacement_digest=None, assessment_at=None,
               inventory_max_age_seconds=30, scan_max_age_seconds=86400, db_max_age_seconds=86400):
        from app.engine.lifecycle import evaluate, ENGINE_VERSION
        TypeAdapter(Identifier).validate_python(cluster_id, strict=True)
        if not isinstance(namespaces, list) or not 1 <= len(namespaces) <= 32:
            raise ValueError('explicit namespace scope of1..32 namespaces required')
        if any(not isinstance(n, str) or len(n) > 63 or not re.fullmatch(r'[a-z0-9]([-a-z0-9]*[a-z0-9])?', n) for n in namespaces):
            raise ValueError('valid namespace scope required')
        namespaces = sorted(set(namespaces))
        for limit in (inventory_max_age_seconds, scan_max_age_seconds, db_max_age_seconds):
            if type(limit) is not int or not 1 <= limit <= 86400:
                raise ValueError('evidence max age must be1..86400 seconds')
        if replacement_digest is not None:
            TypeAdapter(Digest).validate_python(replacement_digest, strict=True)
        if assessment_at is not None:
            TypeAdapter(Timestamp).validate_python(assessment_at, strict=True)
        self.connection.execute('BEGIN')
        try:
            finding = self.inventory.store.get_finding(finding_id)
            if finding is None:
                raise ValueError('finding not found')
            scans = self.inventory.store.list_scans()
            for scan in scans:
                raw = self.inventory.store._read_document(scan['source_document_hash'])
                scan['report'] = load_document(raw, 20 * 1024 * 1024)
            canonical = [row for scan in scans for row in scan['findings']
                         if row['finding_id'] == finding_id and
                         {k:v for k,v in row.items() if k != 'evidence_ids'} == {k:v for k,v in finding.items() if k != 'evidence_ids'}]
            if not canonical:
                raise ValueError('finding source snapshot is unavailable')
            finding = canonical[0]
            facts = {'finding': finding, 'scope': {'cluster_id': cluster_id, 'namespaces': namespaces},
                     'inventory_max_age_seconds': inventory_max_age_seconds,
                     'scan_max_age_seconds': scan_max_age_seconds, 'db_max_age_seconds': db_max_age_seconds,
                     'replacement_digest': replacement_digest}
            for method in ('current', 'events', 'snapshots', 'gaps'):
                facts[method] = [row for ns in namespaces for row in getattr(self.inventory, method)(cluster_id, ns)]
            facts['checkpoints'] = []
            for ns in namespaces:
                for kind in RESOURCES:
                    checkpoint = self.inventory.checkpoint(cluster_id, ns, kind)
                    if checkpoint:
                        facts['checkpoints'].append(dict(checkpoint, namespace=ns, kind=kind))
            facts['scans'] = scans
            lock = json.loads((ROOT / 'toolchain.lock.json').read_text())
            facts['trusted_scanner_hashes'] = sorted({spec['trivy']['executable_sha256'] for spec in lock['profiles'].values() if spec.get('trivy', {}).get('executable_sha256')})
            facts['assessment_at'] = assessment_at or datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            if datetime.fromisoformat(facts['assessment_at'].replace('Z', '+00:00')) > datetime.now(timezone.utc):
                raise ValueError('future assessment time is not supported')
            previous = self.list_assessments()
            facts['previous'] = [{k:p[k] for k in ('assessment_id','finding_id','scope','state')} for p in previous if datetime.fromisoformat(p['state']['assessment_at'].replace('Z', '+00:00')) < datetime.fromisoformat(facts['assessment_at'].replace('Z', '+00:00'))]
            result = evaluate(facts)
            payload = {'facts': facts, 'result': result, 'engine_version': ENGINE_VERSION}
            assessment_id = _hash(payload)
            self.connection.execute('COMMIT')
        except BaseException:
            self.connection.execute('ROLLBACK')
            raise
        # Inputs are immutable now; acquire a short write transaction separately.
        self.connection.execute('BEGIN IMMEDIATE')
        try:
            self.connection.execute('INSERT OR IGNORE INTO lifecycle_assessments(assessment_id,payload) VALUES(?,?)', (assessment_id, canonical_json(payload)))
            self._read(assessment_id)
            self.connection.execute('COMMIT')
        except BaseException:
            self.connection.execute('ROLLBACK')
            raise
        return self._public(assessment_id, payload)
