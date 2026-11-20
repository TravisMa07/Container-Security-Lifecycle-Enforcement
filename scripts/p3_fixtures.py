"""Build only the vetted P3 package fixture on the explicit local Docker engine."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
RECIPE_DIR = ROOT / 'demos/images/p3-patched'
MAX_ASSET_BYTES = 20 * 1024 * 1024
TARGET = '127.0.0.1:15120/csle-p3/patched:fixed'
REGISTRY = 'http://127.0.0.1:15120'
BASE = 'docker.io/library/alpine@sha256:1829893486be257df5049ab3b7fc95afbd0fc09d89803cbc580bda1ba5386b29'
EPOCH = 1795046400
DOCKERFILE_HASH = '4f565a99e28cf83250dd2cabfe932b1314abf3889755b24c59c18b6454992744'
ASSETS = [
    {'filename':'libcrypto3.apk','url':'https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/libcrypto3-3.5.9-r1.apk','sha256':'58ea027d8bd64fffac7d2106a9034341d6735387298a5e01b551429c73a13c71'},
    {'filename':'libssl3.apk','url':'https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/libssl3-3.5.9-r1.apk','sha256':'4aff30f84e7ac922b026f8b2dd574d91bb3bb01d22767a8a9a0a10c5ef64a44b'},
]
EXPECTED = {
    'schema_version':'1', 'purpose':'P3 fixed package remediation fixture; not a general image builder',
    'base_reference':BASE, 'platform':'linux/arm64/v8', 'source_date_epoch':EPOCH,
    'target_image':TARGET, 'registry_url':REGISTRY, 'dockerfile_sha256':DOCKERFILE_HASH,
    'assets':ASSETS,
}


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def validate_recipe(value):
    # Closed accepted recipe: changing a URL, hash, platform or endpoint is a code review.
    if type(value) is not dict or value != EXPECTED or type(value.get('source_date_epoch')) is not int:
        raise ValueError('only the exact reviewed P3 recipe is supported')
    return value


def verify_asset(raw, expected):
    if not isinstance(raw, bytes) or len(raw) > MAX_ASSET_BYTES or not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise ValueError('invalid or oversized fixture asset')
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('fixture asset checksum mismatch')
    return raw


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('fixture source redirect refused')


def fetch(url, limit):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url, headers={'Accept':'application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'})
    with opener.open(request, timeout=60) as response:
        raw = response.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('fixture download exceeds byte limit')
    return raw


def prepare_context(recipe, directory, packages=None):
    validate_recipe(recipe)
    dockerfile = (RECIPE_DIR / 'Dockerfile').read_bytes()
    if hashlib.sha256(dockerfile).hexdigest() != DOCKERFILE_HASH:
        raise ValueError('fixture Dockerfile checksum mismatch')
    packages = packages or ROOT / '.local/p3/packages'
    packages.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    (directory / 'Dockerfile').write_bytes(dockerfile)
    (directory / 'Dockerfile').chmod(0o644)
    for asset in recipe['assets']:
        path = packages / asset['filename']
        if path.exists():
            with path.open('rb') as stream:
                raw = stream.read(MAX_ASSET_BYTES + 1)
        else:
            raw = fetch(asset['url'], MAX_ASSET_BYTES)
        verify_asset(raw, asset['sha256'])
        if not path.exists():
            path.write_bytes(raw)
        (directory / asset['filename']).write_bytes(raw)
        (directory / asset['filename']).chmod(0o644)
    return directory


def build_arguments(docker, context, no_cache=False):
    if len(docker) != 3 or docker[:2] != ['docker','--host'] or not docker[2].startswith('unix://'):
        raise ValueError('explicit local Unix Docker endpoint required')
    args = [*docker, 'build', '--network=none', '--platform', 'linux/arm64/v8',
            '--provenance=false', '--sbom=false', '--build-arg', 'SOURCE_DATE_EPOCH=1795046400',
            '--output', 'type=docker,dest='+str(Path(context).parent/'image.tar')+',rewrite-timestamp=true', '--tag', TARGET]
    if no_cache:
        args.append('--no-cache')
    return [*args, str(context)]


def check_output_pin(lock, actual):
    pin = lock.get('images', {}).get('p3_patched')
    if pin is None:
        return
    candidates = [pin[key] for key in ('manifest_digest','linux_arm64_digest','selected_digest') if key in pin]
    if not candidates or any(value != actual for value in candidates):
        raise ValueError('rebuilt fixture does not match the independently configured output pin')


class Recorder:
    def __init__(self, directory):
        self.directory = directory
        self.commands = []

    def run(self, args, timeout=600):
        start = time.monotonic()
        timed_out = False
        try:
            completed = subprocess.run([str(arg) for arg in args], cwd=ROOT, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            timed_out = True
            completed = subprocess.CompletedProcess(args, -1, error.stdout or b'', error.stderr or b'')
        except OSError as error:
            completed = subprocess.CompletedProcess(args, 127, b'', str(error).encode())
        index = len(self.commands)
        self.commands.append({'argv':[str(arg) for arg in args], 'exit_code':completed.returncode,
                              'elapsed_seconds':round(time.monotonic()-start, 6), 'timed_out':timed_out})
        (self.directory / 'commands.json').write_text(json.dumps(self.commands, indent=2)+'\n')
        for name, raw in [('stdout',completed.stdout),('stderr',completed.stderr)]:
            # These fixed commands never receive credentials or arbitrary user arguments.
            (self.directory / f'{index:02d}-{name}.log').write_bytes(raw[:2*1024*1024])
        if completed.returncode:
            raise RuntimeError('fixture command failed; inspect ignored local command logs')
        return completed.stdout


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-cache', action='store_true', help='rebuild layers for a reproducibility check')
    args = parser.parse_args(argv)
    recipe = validate_recipe(json.loads((RECIPE_DIR / 'recipe.json').read_text()))
    run = ROOT / '.local/p3/builds' / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8])
    run.mkdir(parents=True, mode=0o700)
    run.chmod(0o700)
    context = prepare_context(recipe, run / 'context')
    # Existing P0 helper rejects ambient remote engines; no Docker/Kubernetes cleanup.
    from p0_lab import local_docker
    docker = local_docker()
    recorder = Recorder(run)
    recorder.run(build_arguments(docker, context, args.no_cache))
    recorder.run([*docker, 'load', '--input', run/'image.tar'])
    recorder.run([*docker, 'push', TARGET])
    manifest = fetch(REGISTRY+'/v2/csle-p3/patched/manifests/fixed', MAX_ASSET_BYTES)
    selected = digest(manifest)
    lock = json.loads((ROOT / 'toolchain.lock.json').read_text())
    check_output_pin(lock, selected)
    sys.path.insert(0, str(ROOT))
    from app.collectors.oci import resolve
    ref = TARGET.rsplit(':',1)[0]+'@'+selected
    resolution = resolve(ref, REGISTRY, 'linux/arm64')
    if resolution['manifest_digest'] != selected:
        raise ValueError('fixture resolved manifest mismatch')
    (run / 'manifest.json').write_bytes(manifest)
    result = {'purpose':recipe['purpose'], 'image_ref':ref, 'manifest_digest':selected,
              'resolution':resolution, 'base_reference':BASE,
              'recipe_hash':digest((RECIPE_DIR/'recipe.json').read_bytes()),
              'dockerfile_hash':'sha256:'+DOCKERFILE_HASH,
              'assets':ASSETS, 'source_date_epoch':EPOCH, 'no_cache':args.no_cache,
              'revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
              'dirty_working_tree':bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT)),
              'local_directory':str(run.relative_to(ROOT)),
              'limitations':['build/push fixture only; no scan, remediation or signing verdict',
                             'bit-for-bit reproduction requires separate no-cache comparison']}
    (run/'result.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    (ROOT/'.local/p3/fixture-result-path.txt').write_text(str(run/'result.json')+'\n')
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
