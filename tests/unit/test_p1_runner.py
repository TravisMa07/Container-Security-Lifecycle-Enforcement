"""P1 external failure and binary integrity cases; fixtures do not qualify Trivy."""
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from app.collectors.runner import ScannerError, _run, verified_scanner, execute_scan
from app.models import sha256_bytes


class RunnerTests(unittest.TestCase):
    def test_process_failure_and_missing_scanner(self):
        with self.assertRaisesRegex(ScannerError, 'exit 7'):
            _run([sys.executable, '-c', 'raise SystemExit(7)'])
        with self.assertRaisesRegex(ScannerError, 'unavailable'):
            _run(['/no/csle/scanner'])
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('scanner', 1)):
            with self.assertRaisesRegex(ScannerError, 'timed out'):
                _run(['scanner'])

    def test_binary_verified_against_pinned_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / '.tools'
            (tools / 'downloads').mkdir(parents=True)
            (tools / 'bin').mkdir()
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode='w:gz') as stream:
                entry = tarfile.TarInfo('trivy')
                entry.size = len(b'pinned')
                stream.addfile(entry, io.BytesIO(b'pinned'))
            content = archive.getvalue()
            digest = sha256_bytes(content).split(':')[1]
            (tools / 'downloads' / digest).write_bytes(content)
            binary = tools / 'bin/trivy'
            binary.write_bytes(b'pinned')
            key = platform.system().lower() + '-' + platform.machine().lower()
            (root / 'toolchain.lock.json').write_text(json.dumps({'profiles': {key: {'trivy': {'sha256': digest, 'member': 'trivy', 'version': 'v0.76.2'}}}}))
            with patch('app.collectors.runner.ROOT', root):
                self.assertEqual(verified_scanner()[2], sha256_bytes(b'pinned'))
                binary.write_bytes(b'changed')
                with self.assertRaisesRegex(ScannerError, 'executable checksum'):
                    verified_scanner()
                binary.write_bytes(b'pinned')
                (tools / 'downloads' / digest).write_bytes(b'changed')
                with self.assertRaisesRegex(ScannerError, 'archive checksum'):
                    verified_scanner()

    def test_conflicting_scanned_config_rejected(self):
        fixture = Path(__file__).resolve().parents[1] / 'fixtures/p1/trivy-synthetic.json'
        raw = fixture.read_bytes()
        ref = json.loads(raw)['Metadata']['RepoDigests'][0]
        resolution = {'manifest_digest': ref.split('@')[1], 'platform_digest': ref.split('@')[1], 'index_digest': None, 'config_digest': 'sha256:'+'b'*64, 'platform': 'linux/arm64'}
        def run(argv, **kwargs):
            if '--version' in argv:
                return b'{"Version":"0.76.2"}'
            Path(argv[argv.index('--output')+1]).write_bytes(raw)
            return b''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'cache/db').mkdir(parents=True)
            (root / 'cache/db/metadata.json').write_bytes(b'{"UpdatedAt":"2026-11-19T00:00:00Z"}')
            (root / 'cache/db/trivy.db').write_bytes(b'synthetic DB')
            with patch('app.collectors.runner.ROOT', root), patch('app.collectors.runner.verified_scanner', return_value=(Path('trivy'), '0.76.2', 'sha256:'+'c'*64)), patch('app.collectors.runner.resolve', return_value=resolution), patch('app.collectors.runner._run', side_effect=run):
                with self.assertRaisesRegex(ScannerError, 'config identity'):
                    execute_scan(ref, 'http://localhost:15120', 'linux/arm64', root / 'cache')

    def test_environment_overrides_removed(self):
        with patch.dict(os.environ, {'TRIVY_IGNORE_UNFIXED': 'true', 'TRIVY_SEVERITY': 'LOW'}), patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, b'{}', b'')) as run:
            _run(['scanner'])
        env = run.call_args.kwargs['env']
        self.assertFalse(any(key.startswith('TRIVY_') for key in env))

    def test_cache_concurrent_writer_fails_explicitly(self):
        from app.collectors.runner import _cache_lock
        with tempfile.TemporaryDirectory() as directory:
            with _cache_lock(Path(directory)):
                with self.assertRaisesRegex(ScannerError, 'cache is in use'):
                    with _cache_lock(Path(directory)):
                        self.fail('concurrent lock acquired')
