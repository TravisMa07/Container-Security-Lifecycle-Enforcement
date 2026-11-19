"""Execute the pinned scanner against independently resolved local OCI bytes."""
from datetime import datetime, timezone
import hashlib
import json
import os
import fcntl
from contextlib import contextmanager
from pathlib import Path
import platform as host_platform
import subprocess
import tarfile
import tempfile

from app.collectors.oci import resolve

ROOT = Path(__file__).resolve().parents[2]


class ScannerError(RuntimeError):
    pass


def verified_scanner():
    lock = json.loads((ROOT / 'toolchain.lock.json').read_text())
    key = host_platform.system().lower() + '-' + host_platform.machine().lower()
    spec = lock['profiles'].get(key, {}).get('trivy')
    if not spec:
        raise ScannerError('scanner platform is not qualified; see toolchain.lock.json')
    archive = ROOT / '.tools/downloads' / spec['sha256']
    binary = ROOT / '.tools/bin/trivy'
    if not archive.is_file() or not binary.is_file():
        raise ScannerError('pinned scanner missing; run make bootstrap')
    if hashlib.sha256(archive.read_bytes()).hexdigest() != spec['sha256']:
        raise ScannerError('scanner archive checksum mismatch')
    with tarfile.open(archive) as stream:
        members = [x for x in stream.getmembers() if x.name == spec['member']]
        if len(members) != 1 or not members[0].isfile() or members[0].size > 512 * 1024 * 1024:
            raise ScannerError('invalid pinned scanner archive')
        expected = hashlib.sha256(stream.extractfile(members[0]).read()).hexdigest()
    actual = hashlib.sha256(binary.read_bytes()).hexdigest()
    if actual != expected:
        raise ScannerError('scanner executable checksum mismatch')
    return binary, spec['version'].removeprefix('v'), 'sha256:' + actual


@contextmanager
def _cache_lock(path):
    with (path / '.csle-scan.lock').open('a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ScannerError('scanner cache is in use by another CSLE scan') from error
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def _run(argv, timeout=600, log_dir=None):
    # Scanner output is kept in a private run directory, never echoed with secrets.
    try:
        env = {key: value for key, value in os.environ.items() if not key.startswith('TRIVY_')}
        completed = subprocess.run([str(x) for x in argv], capture_output=True, timeout=timeout,
                                   env=env, cwd=log_dir)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ScannerError('scanner unavailable or timed out') from error
    if log_dir is not None:
        (log_dir / 'stdout.log').write_bytes(completed.stdout)
        (log_dir / 'stderr.log').write_bytes(completed.stderr)
        (log_dir / 'command.json').write_text(json.dumps({'argv': [str(x) for x in argv], 'returncode': completed.returncode}, sort_keys=True))
    if completed.returncode != 0:
        raise ScannerError('scanner execution failed (exit ' + str(completed.returncode) + ')')
    return completed.stdout


def execute_scan(image_ref, registry_url, platform, cache_dir=None):
    from app.collectors.trivy import parse_report, load_document
    binary, version, binary_hash = verified_scanner()
    resolution = resolve(image_ref, registry_url, platform)
    images = json.loads((ROOT / 'toolchain.lock.json').read_text())['images']
    known = {images[name]['linux_arm64_digest'] for name in ('demo', 'p3_patched') if name in images}
    if resolution['manifest_digest'] not in known:
        raise ScannerError('executed scanning is restricted to the qualified pinned demo artifacts; see dependencies.md')
    selected_ref = image_ref.split('@')[0] + '@' + resolution['manifest_digest']
    cache = (Path(cache_dir) if cache_dir else ROOT / '.local/trivy-cache').resolve()
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    with _cache_lock(cache):
        actual_version = load_document(_run([binary, '--version', '--format', 'json']), 1024 * 1024)
        if not isinstance(actual_version, dict) or actual_version.get('Version') != version:
            raise ScannerError('scanner version does not match pin')
        runs = ROOT / '.local/p1/runs'
        runs.mkdir(parents=True, exist_ok=True, mode=0o700)
        run = tempfile.mkdtemp(prefix='scan-', dir=runs)
        output = Path(run) / 'report.json'
        argv = [binary, 'image', '--config', '', '--ignorefile', '', '--skip-version-check',
                '--ignore-unfixed=false', '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
                '--exit-code', '0', '--image-src', 'remote', '--scanners', 'vuln',
                '--list-all-pkgs', '--format', 'json', '--output', output, '--cache-dir', cache,
                '--platform', platform, '--insecure', selected_ref]
        started = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        _run(argv, log_dir=Path(run))
        finished = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        if not output.is_file() or output.stat().st_size > 20 * 1024 * 1024:
            raise ScannerError('scanner report missing or exceeds limit')
        raw = output.read_bytes()
        db_path = cache / 'db/metadata.json'
        if not db_path.is_file() or db_path.stat().st_size > 1024 * 1024:
            raise ScannerError('scanner DB metadata missing or exceeds limit')
        db_raw = db_path.read_bytes()
        # Hash the actual vulnerability DB as well as its self-declared metadata.
        database = cache / 'db/trivy.db'
        if not database.is_file():
            raise ScannerError('scanner vulnerability database missing')
        with database.open('rb') as stream:
            db_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
        parsed = parse_report(raw, selected_ref, version, db_raw)
        report = load_document(raw, 20 * 1024 * 1024)
        if report.get('Metadata', {}).get('ImageID') != resolution['config_digest']:
            raise ScannerError('scanner config identity conflicts with verified OCI config')
        if parsed.image.platform != resolution['platform']:
            raise ScannerError('scanner platform conflicts with verified OCI config')
        if parsed.scanner_db_updated_at is None:
            raise ScannerError('executed scan DB update timestamp missing')
        image = parsed.image.model_copy(update={
            'index_digest': resolution['index_digest'],
            'platform_digest': resolution['manifest_digest'],
        })
        parsed = parsed.model_copy(update={'image': image})
        execution = {'scanner_version': version, 'executable_hash': binary_hash,
                     'db_content_hash': 'sha256:' + db_hash,
                     'started_at': started, 'finished_at': finished,
                     'argv': [str(x) for x in argv],
                     'purpose': 'P1_local_scan_evidence_not_signing_authorization'}
        return parsed, raw, db_raw, resolution, execution
