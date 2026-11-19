"""P1 CLI acceptance: subprocesses cross restart/argument/error boundaries."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'tests/fixtures/p1/trivy-synthetic.json'


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / 'evidence.sqlite3'
        report = json.loads(FIXTURE.read_text())
        self.ref = report['Metadata']['RepoDigests'][0]

    def invoke(self, *args):
        result = subprocess.run([sys.executable, '-m', 'app', '--db', str(self.db), *args], cwd=ROOT, capture_output=True, text=True)
        return result

    def test_help_and_json_argument_errors(self):
        for args in [('--help',), ('scan', '--help'), ('scan', 'image', '--help'), ('findings', 'explain', '--help')]:
            with self.subTest(args=args):
                self.assertEqual(self.invoke(*args).returncode, 0)
        result = self.invoke('scan', 'import')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stderr)['error']['code'], 'INVALID_INPUT')
        self.assertEqual(result.stdout, '')

    def test_import_idempotent_restart_queries(self):
        first = self.invoke('scan', 'import', str(FIXTURE), '--image', self.ref)
        self.assertEqual(first.returncode, 0, first.stderr)
        receipt = json.loads(first.stdout)
        self.assertTrue(receipt['inserted'])
        second = self.invoke('scan', 'import', str(FIXTURE), '--image', self.ref)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(json.loads(second.stdout), {'inserted': False, 'scan_id': receipt['scan_id']})
        a = self.invoke('scans', 'list')
        b = self.invoke('scans', 'list')
        self.assertEqual(a.returncode, 0, a.stderr)
        self.assertEqual(a.stdout, b.stdout)
        self.assertEqual(len(json.loads(a.stdout)), 1)
        show = self.invoke('scans', 'show', receipt['scan_id'])
        self.assertEqual(show.returncode, 0, show.stderr)
        self.assertEqual(json.loads(show.stdout)['provenance'], 'imported')
        listing = self.invoke('findings', 'list')
        self.assertEqual(listing.returncode, 0, listing.stderr)
        findings = json.loads(listing.stdout)
        self.assertGreater(len(findings), 0)
        explained = self.invoke('findings', 'explain', findings[0]['finding_id'])
        self.assertEqual(explained.returncode, 0, explained.stderr)
        self.assertEqual(json.loads(explained.stdout)['finding_id'], findings[0]['finding_id'])

    def test_input_failure_does_not_create_database(self):
        report = Path(self.temp.name) / 'bad.json'
        report.write_text('{"SchemaVersion":2,"Results":false}')
        result = self.invoke('scan', 'import', str(report), '--image', self.ref)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
        self.assertFalse(self.db.exists())
        self.assertEqual(json.loads(result.stderr)['error']['code'], 'INVALID_INPUT')

    def test_missing_file_and_unwritable_database_are_operation_errors(self):
        result = self.invoke('scan', 'import', '/no/csle/report.json', '--image', self.ref)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stderr)['error']['code'], 'OPERATION_FAILED')
        self.db.mkdir()
        result = self.invoke('db', 'init')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')

    def test_scanner_failure_has_no_persistence(self):
        from app.cli import main
        from app.collectors.runner import ScannerError
        import io
        with patch('app.cli.execute_scan', side_effect=ScannerError('scanner execution failed (exit 1)')), patch('sys.stderr', new_callable=io.StringIO) as stderr:
            status = main(['--db', str(self.db), 'scan', 'image', self.ref, '--registry-url', 'http://127.0.0.1:15120'])
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(stderr.getvalue())['error']['code'], 'OPERATION_FAILED')
        self.assertFalse(self.db.exists())
