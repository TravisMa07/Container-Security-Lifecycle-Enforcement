"""Independent persistence cases from the frozen P1 contract; synthetic inputs only."""
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from app.store.db import Store

RAW = b'{"synthetic":"report-a"}'
DB = b'{"UpdatedAt":"2026-11-19T00:00:00Z"}'
DIGEST = 'sha256:' + 'a' * 64

def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()

class Record:
    def __init__(self, value):
        self.value = value
    def model_dump(self, **kwargs):
        return copy.deepcopy(self.value)

def parsed(raw=RAW, severity='HIGH', timestamp='2026-11-19T00:00:00Z'):
    source_hash = digest(raw)
    return Record({
        'image': {'schema_version':'1', 'image_id':DIGEST, 'registry':'localhost:5000',
                  'repository':'demo', 'tags_observed':[], 'manifest_digest':DIGEST,
                  'index_digest':None, 'platform_digest':DIGEST, 'platform':'linux/arm64',
                  'source':'oci_registry', 'source_reference':'localhost:5000/demo@'+DIGEST,
                  'first_seen':timestamp, 'last_seen':timestamp, 'resolution_status':'resolved',
                  'resolution_reason':None},
        'findings':[{'schema_version':'1','finding_id':'finding-a','image_digest':DIGEST,
                     'scanner':'trivy','scanner_version':'0.76.2','parser_version':'trivy-v1',
                     'vuln_id':'CVE-2026-0001','package_name':'demo','package_type':'alpine',
                     'package_path':None,'installed_version':'1','fixed_version':'2',
                     'severity':severity,'severity_source':None,'target_os':'alpine',
                     'platform':'linux/arm64','aliases':[],'scan_timestamp':timestamp,
                     'scanner_db_updated_at':'2026-11-19T00:00:00Z',
                     'source_document_hash':source_hash,'validity':'under_investigation',
                     'evidence_ids':[source_hash]}],
        'source_document_hash':source_hash,'parser_version':'trivy-v1','scanner_version':'0.76.2',
        'scan_timestamp':timestamp,'scanner_db_updated_at':'2026-11-19T00:00:00Z',
        'db_document_hash':digest(DB),'limitations':[]})

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'data.sqlite3'
    def tearDown(self):
        self.temp.cleanup()
    def test_restart_and_reimport_idempotency(self):
        with Store(self.path) as store:
            first = store.save_scan(parsed(), RAW, DB)
            self.assertTrue(first['inserted'])
            self.assertFalse(store.save_scan(parsed(), RAW, DB)['inserted'])
            before = store.list_scans()
            self.assertEqual(len(before), 1)
        with Store(self.path) as store:
            self.assertEqual(store.list_scans(), before)
            self.assertEqual(store.get_scan(first['scan_id'])['source_document_hash'], digest(RAW))
            self.assertFalse(store.save_scan(parsed(), RAW, DB)['inserted'])
            self.assertEqual(len(store.list_findings()), 1)
    def test_raw_hash_mismatch_is_rejected(self):
        with Store(self.path) as store:
            with self.assertRaises(ValueError):
                store.save_scan(parsed(), b'altered', DB)
            self.assertEqual(store.list_scans(), [])
    def test_import_cannot_claim_execution(self):
        with Store(self.path) as store:
            with self.assertRaises(ValueError):
                store.save_scan(parsed(), RAW, DB, execution={'version':'forged'})
            self.assertEqual(store.list_scans(), [])
    def test_new_scan_preserves_prior_snapshot_and_latest_evidence(self):
        newer = b'{"synthetic":"report-b"}'
        with Store(self.path) as store:
            old_id = store.save_scan(parsed(), RAW, DB)['scan_id']
            new_id = store.save_scan(parsed(newer, 'LOW', '2026-11-20T00:00:00Z'), newer, DB)['scan_id']
            self.assertNotEqual(old_id, new_id)
            self.assertEqual(store.get_scan(old_id)['findings'][0]['severity'], 'HIGH')
            finding = store.get_finding('finding-a')
            self.assertEqual(finding['severity'], 'LOW')
            self.assertEqual(finding['evidence_ids'], sorted([digest(RAW), digest(newer)]))
            self.assertIsNone(store.get_scan('missing'))
            self.assertIsNone(store.get_finding('missing'))

    def test_migration_failure_rolls_back_ddl_and_keeps_evidence(self):
        from app.store.migrations import DEFAULT_MIGRATIONS
        with Store(self.path) as store:
            receipt = store.save_scan(parsed(), RAW, DB)
        bad = DEFAULT_MIGRATIONS + (("CREATE TABLE migration_probe (n INTEGER)", "INVALID SQL"),)
        with self.assertRaises(sqlite3.Error):
            with Store(self.path, migrations=bad):
                pass
        with Store(self.path) as store:
            self.assertEqual(len(store.list_scans()), 1)
            self.assertIsNotNone(store.get_scan(receipt['scan_id']))
            self.assertEqual(store.connection.execute('PRAGMA user_version').fetchone()[0], 1)
            self.assertIsNone(store.connection.execute(
                "SELECT name FROM sqlite_master WHERE name='migration_probe'"
            ).fetchone())
        good = DEFAULT_MIGRATIONS + (("CREATE TABLE migration_probe (n INTEGER)",),)
        with Store(self.path, migrations=good) as store:
            self.assertEqual(store.connection.execute('PRAGMA user_version').fetchone()[0], 2)
            self.assertEqual(len(store.list_scans()), 1)
        with self.assertRaises(ValueError):
            with Store(self.path):
                pass

    def test_changed_migration_and_newer_version_reject(self):
        from app.store.migrations import DEFAULT_MIGRATIONS
        with Store(self.path):
            pass
        edited = (DEFAULT_MIGRATIONS[0] + ("CREATE TABLE ignored (n INTEGER)",),)
        with self.assertRaises(ValueError):
            with Store(self.path, migrations=edited):
                pass
        with sqlite3.connect(self.path) as conn:
            conn.execute('PRAGMA user_version=99')
        with self.assertRaises(ValueError):
            with Store(self.path):
                pass

    def test_initial_migration_failure_leaves_no_schema(self):
        with self.assertRaises(sqlite3.Error):
            with Store(self.path, migrations=(("CREATE TABLE probe (n INTEGER)", "INVALID SQL"),)):
                pass
        with sqlite3.connect(self.path) as conn:
            self.assertEqual(conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall(), [])
            self.assertEqual(conn.execute('PRAGMA user_version').fetchone()[0], 0)

    def test_unrelated_database_is_not_adopted(self):
        with sqlite3.connect(self.path) as conn:
            conn.execute('CREATE TABLE unrelated (value TEXT)')
            conn.execute("INSERT INTO unrelated VALUES ('retained')")
        with self.assertRaises(ValueError):
            with Store(self.path):
                pass
        with sqlite3.connect(self.path) as conn:
            self.assertEqual(conn.execute('SELECT value FROM unrelated').fetchone()[0], 'retained')

    def test_mid_import_fault_rolls_back_every_row_then_retry_succeeds(self):
        record = parsed()
        second = copy.deepcopy(record.value['findings'][0])
        second['finding_id'] = 'finding-b'
        second['package_name'] = 'other'
        record.value['findings'].append(second)
        with Store(self.path) as store:
            store.connection.execute("CREATE TRIGGER fault BEFORE INSERT ON scan_findings "
                                     "WHEN NEW.finding_id='finding-b' BEGIN SELECT RAISE(ABORT, 'injected'); END")
            with self.assertRaises(sqlite3.IntegrityError):
                store.save_scan(record, RAW, DB)
            for table in ('scans', 'raw_documents', 'scan_findings'):
                self.assertEqual(store.connection.execute('SELECT COUNT(*) FROM '+table).fetchone()[0], 0)
            store.connection.execute('DROP TRIGGER fault')
            self.assertTrue(store.save_scan(record, RAW, DB)['inserted'])
            self.assertEqual(len(store.list_findings()), 2)

    def test_append_only_guards_and_raw_integrity(self):
        with Store(self.path) as store:
            scan_id = store.save_scan(parsed(), RAW, DB)['scan_id']
            for table in ('scans', 'raw_documents', 'scan_findings'):
                for operation in ('DELETE FROM '+table, 'UPDATE '+table+' SET '+
                                  {'scans':'scan_id=scan_id','raw_documents':'body=body',
                                   'scan_findings':'payload=payload'}[table]):
                    with self.assertRaises(sqlite3.IntegrityError):
                        store.connection.execute(operation)
            store.connection.execute('DROP TRIGGER raw_documents_no_update')
            store.connection.execute('UPDATE raw_documents SET body=? WHERE document_hash=?',
                                     (b'tampered', digest(RAW)))
            with self.assertRaises(ValueError):
                store.get_scan(scan_id)
            with self.assertRaises(ValueError):
                store.list_findings()
            with self.assertRaises(ValueError):
                store.save_scan(parsed(), RAW, DB)

    def test_normalized_snapshot_integrity(self):
        with Store(self.path) as store:
            scan_id = store.save_scan(parsed(), RAW, DB)['scan_id']
            store.connection.execute('DROP TRIGGER scan_findings_no_update')
            changed = copy.deepcopy(parsed().value['findings'][0])
            changed['severity'] = 'LOW'
            store.connection.execute('UPDATE scan_findings SET payload=?', (json.dumps(changed),))
            with self.assertRaises(ValueError):
                store.get_scan(scan_id)

    def test_provenance_is_separate_evidence_not_an_upgrade(self):
        with Store(self.path) as store:
            imported = store.save_scan(parsed(), RAW, DB)['scan_id']
            executed = store.save_scan(parsed(), RAW, DB, provenance='executed_local_trivy',
                                       resolution={'manifest_digest': DIGEST},
                                       execution={'binary_hash':'sha256:'+'b'*64})['scan_id']
            self.assertNotEqual(imported, executed)
            self.assertEqual(store.get_scan(imported)['provenance'], 'imported')
            self.assertIsNone(store.get_scan(imported)['execution'])
            self.assertEqual(store.get_scan(executed)['provenance'], 'executed_local_trivy')
            self.assertEqual(len(store.list_scans()), 2)
            with self.assertRaises(ValueError):
                store.save_scan(parsed(), RAW, DB, provenance='executed_local_trivy')

    def test_sidecar_hash_and_finding_association_reject(self):
        with Store(self.path) as store:
            with self.assertRaises(ValueError):
                store.save_scan(parsed(), RAW, b'changed DB')
            unbound = parsed()
            unbound.value['findings'][0]['image_digest'] = 'sha256:'+'b'*64
            with self.assertRaises(ValueError):
                store.save_scan(unbound, RAW, DB)
            self.assertEqual(store.list_scans(), [])

    def test_fractional_timestamp_order_is_chronological(self):
        later = b'{"synthetic":"fractional"}'
        with Store(self.path) as store:
            store.save_scan(parsed(), RAW, DB)
            store.save_scan(parsed(later, 'LOW', '2026-11-19T00:00:00.1Z'), later, DB)
            self.assertEqual(store.get_finding('finding-a')['severity'], 'LOW')

    def test_executed_context_binding_and_constructed_model_validation(self):
        from app.models import ParsedScan
        with Store(self.path) as store:
            for field in ('manifest_digest', 'index_digest', 'platform_digest', 'platform'):
                resolution = {'manifest_digest': DIGEST, field: 'different'}
                with self.assertRaises(ValueError):
                    store.save_scan(parsed(), RAW, DB, provenance='executed_local_trivy',
                                    resolution=resolution, execution={'scanner_version':'0.76.2'})
            with self.assertRaises(ValueError):
                store.save_scan(parsed(), RAW, DB, resolution={'manifest_digest':DIGEST})
            with self.assertRaises(ValueError):
                store.save_scan(parsed(), RAW, DB, provenance='executed_local_trivy',
                                resolution={'manifest_digest':DIGEST}, execution={'scanner_version':'forged'})
            # Pydantic's construction/copy escape hatches cannot bypass save validation.
            good = ParsedScan.model_validate(parsed().value)
            forged_image = good.image.model_copy(update={'image_id':'sha256:'+'b'*64})
            forged = good.model_copy(update={'image':forged_image})
            with self.assertRaises(ValueError):
                store.save_scan(forged, RAW, DB)
            self.assertEqual(store.list_scans(), [])

    def test_malformed_normalized_snapshot_is_integrity_error(self):
        for index, malformed in enumerate(['{}', '[]', 'null']):
            with self.subTest(malformed=malformed):
                path = Path(self.temp.name) / ('corrupt-' + str(index) + '.sqlite3')
                with Store(path) as store:
                    scan_id = store.save_scan(parsed(), RAW, DB)['scan_id']
                    store.connection.execute('DROP TRIGGER scans_no_update')
                    store.connection.execute('UPDATE scans SET payload=?', (malformed,))
                    with self.assertRaises(ValueError):
                        store.get_scan(scan_id)

if __name__ == '__main__':
    unittest.main()
