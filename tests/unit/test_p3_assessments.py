"""Assessment freezing/replay/rollback cases; imported synthetic scan never proves a fix."""
from pathlib import Path
import json
import sqlite3
import tempfile
import unittest

from app.collectors.trivy import parse_report
from app.store.db import Store
from app.store.assessments import AssessmentStore

FIXTURE=Path(__file__).resolve().parents[1]/'fixtures/p1/trivy-synthetic.json'
AT='2026-11-19T12:00:00Z'


class AssessmentStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.db=Path(self.temp.name)/'evidence.sqlite3'
        self.raw=FIXTURE.read_bytes()
        parsed=parse_report(self.raw,json.loads(self.raw)['Metadata']['RepoDigests'][0])
        with Store(self.db) as store:store.save_scan(parsed,self.raw)
        self.finding=parsed.findings[0].finding_id

    def test_freezing_idempotency_restart_and_replay(self):
        with AssessmentStore(self.db) as store:
            first=store.assess(self.finding,'cluster',['demo'],assessment_at=AT)
            second=store.assess(self.finding,'cluster',['demo'],assessment_at=AT)
            self.assertEqual(first,second)
            self.assertEqual(first['state']['exposure'],'unknown')
            self.assertEqual(first['state']['remediation'],'unknown')
            self.assertEqual(first['state']['validity'],'under_investigation')
            self.assertEqual(len(store.list_assessments()),1)
        with AssessmentStore(self.db) as store:
            self.assertEqual(store.get_assessment(first['assessment_id']),first)
            self.assertEqual(store.assess(self.finding,'cluster',['demo'],assessment_at=AT),first)
            later=store.assess(self.finding,'cluster',['demo'],assessment_at='2026-11-19T13:00:00Z')
            self.assertNotEqual(later['assessment_id'],first['assessment_id'])
            self.assertEqual(len(store.list_assessments()),2)

    def test_assessment_failure_is_atomic_and_scan_remains(self):
        with AssessmentStore(self.db) as store:
            store.connection.execute("CREATE TRIGGER injected BEFORE INSERT ON lifecycle_assessments BEGIN SELECT RAISE(ABORT,'fault'); END")
            with self.assertRaises(sqlite3.IntegrityError):store.assess(self.finding,'cluster',['demo'],assessment_at=AT)
            self.assertEqual(store.list_assessments(),[])
            self.assertEqual(len(store.inventory.store.list_scans()),1)

    def test_append_only_and_corruption_detected(self):
        with AssessmentStore(self.db) as store:
            first=store.assess(self.finding,'cluster',['demo'],assessment_at=AT)
            for statement in ['DELETE FROM lifecycle_assessments','UPDATE lifecycle_assessments SET payload=payload']:
                with self.assertRaises(sqlite3.IntegrityError):store.connection.execute(statement)
            store.connection.execute('DROP TRIGGER lifecycle_assessments_no_update')
            store.connection.execute("UPDATE lifecycle_assessments SET payload='{}'")
            with self.assertRaises(ValueError):store.get_assessment(first['assessment_id'])

    def test_invalid_scope_future_time_and_missing_finding_reject(self):
        with AssessmentStore(self.db) as store:
            for namespaces in [[],['invalid/name'],['demo']*33]:
                with self.assertRaises(ValueError):store.assess(self.finding,'cluster',namespaces,assessment_at=AT)
            with self.assertRaises(ValueError):store.assess(self.finding,'cluster',['demo'],assessment_at='2999-01-01T00:00:00Z')
            with self.assertRaises(ValueError):store.assess('missing','cluster',['demo'],assessment_at=AT)
            self.assertEqual(store.list_assessments(),[])
