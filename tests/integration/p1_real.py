"""Opt-in P1 acceptance against the existing project-local OCI registry.

Run with the pinned interpreter from repository root; this does not create or
mutate infrastructure. No signing, admission or framework claim is made.
"""
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app.store.db import Store

DIGEST = 'sha256:1829893486be257df5049ab3b7fc95afbd0fc09d89803cbc580bda1ba5386b29'
REF = '127.0.0.1:15120/000000000000/us-east-1/csle-p0/demo@' + DIGEST


def main():
    run = ROOT / '.local/p1/qualification' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    run.mkdir(parents=True)
    database = run / 'evidence.sqlite3'
    commands = []

    def cli(*args):
        argv = [sys.executable, '-m', 'app', '--db', str(database), *map(str, args)]
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=660)
        index = len(commands)
        (run / f'{index:02d}-stdout.json').write_text(result.stdout)
        (run / f'{index:02d}-stderr.log').write_text(result.stderr)
        commands.append({'argv': argv, 'exit_code': result.returncode})
        (run / 'commands.json').write_text(json.dumps(commands, indent=2))
        if result.returncode:
            raise AssertionError(f'command failed: {run}/{index:02d}-stderr.log')
        return result.stdout

    receipt = json.loads(cli('scan', 'image', REF, '--registry-url', 'http://127.0.0.1:15120', '--platform', 'linux/arm64'))
    assert receipt['inserted'] is True
    scan = json.loads(cli('scans', 'show', receipt['scan_id']))
    assert scan['provenance'] == 'executed_local_trivy'
    assert scan['image']['image_id'] == scan['resolution']['manifest_digest'] == DIGEST
    assert scan['image']['platform'] == scan['resolution']['platform'] == 'linux/arm64/v8'
    assert scan['scanner_version'] == scan['execution']['scanner_version'] == '0.76.2'
    assert scan['scanner_db_updated_at'] is not None
    with sqlite3.connect(database) as connection:
        raw = connection.execute('SELECT body FROM raw_documents WHERE document_hash=?', (scan['source_document_hash'],)).fetchone()[0]
        db_raw = connection.execute('SELECT body FROM raw_documents WHERE document_hash=?', (scan['db_document_hash'],)).fetchone()[0]
    assert 'sha256:' + hashlib.sha256(raw).hexdigest() == scan['source_document_hash']
    assert 'sha256:' + hashlib.sha256(db_raw).hexdigest() == scan['db_document_hash']
    report = json.loads(raw)
    assert report['Metadata']['ImageID'] == scan['resolution']['config_digest']
    assert REF in report['Metadata']['RepoDigests']
    expected_count = sum(len(result.get('Vulnerabilities') or []) for result in report.get('Results', []))
    assert len(scan['findings']) == expected_count
    for finding in scan['findings']:
        assert finding['source_document_hash'] == scan['source_document_hash']
        assert finding['image_digest'] == DIGEST
        assert finding['validity'] == 'under_investigation'
    raw_path, db_path = run / 'report.json', run / 'db-metadata.json'
    raw_path.write_bytes(raw)
    db_path.write_bytes(db_raw)
    first = json.loads(cli('scan', 'import', raw_path, '--image', REF, '--db-metadata', db_path))
    second = json.loads(cli('scan', 'import', raw_path, '--image', REF, '--db-metadata', db_path))
    assert first['inserted'] is True and second == {'scan_id': first['scan_id'], 'inserted': False}
    assert first['scan_id'] != receipt['scan_id']
    assert cli('scans', 'list') == cli('scans', 'list')
    assert cli('findings', 'list') == cli('findings', 'list')
    if scan['findings']:
        explanation = json.loads(cli('findings', 'explain', scan['findings'][0]['finding_id']))
        assert explanation['finding_id'] == scan['findings'][0]['finding_id']
    with Store(database) as store:
        assert len(store.list_scans()) == 2
        assert store.get_scan(receipt['scan_id'])['execution'] == scan['execution']
        assert store.get_scan(first['scan_id'])['provenance'] == 'imported'
        assert store.get_scan(first['scan_id'])['execution'] is None
    result = {'executed_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'dirty_working_tree': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
              'image_ref': REF, 'scan_id': receipt['scan_id'], 'imported_scan_id': first['scan_id'],
              'source_document_hash': scan['source_document_hash'], 'db_document_hash': scan['db_document_hash'],
              'scanner_db_updated_at': scan['scanner_db_updated_at'], 'scan_timestamp': scan['scan_timestamp'],
              'scanner_version': scan['scanner_version'], 'execution': scan['execution'],
              'resolution': scan['resolution'], 'normalized_findings': len(scan['findings']),
              'passed': ['real_pinned_scan', 'manifest_config_platform_binding', 'raw_hash_persistence',
                         'scanner_db_provenance', 'normalized_rows', 'reimport_idempotency',
                         'restart_query_determinism', 'import_execution_separation'],
              'local_directory': str(run.relative_to(ROOT))}
    (run / 'result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
