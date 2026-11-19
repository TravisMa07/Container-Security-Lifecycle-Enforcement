"""Seven bounded list/watch workers; evidence uncertainty is explicit."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import math
import fcntl
import os
from pathlib import Path
from contextlib import contextmanager
import hashlib
import threading
import time

from app.collectors.kubernetes import KubeError, RESOURCES, rv
from app.store.inventory import InventoryStore


def now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


@contextmanager
def scope_lease(db_path, cluster_id, namespace):
    suffix = hashlib.sha256((cluster_id + '\0' + namespace).encode()).hexdigest()
    path = Path(str(db_path) + '.' + suffix + '.watch.lock')
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(fd, 'a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError('collector scope is already active') from error
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


class Collector:
    def __init__(self, api, db_path, cluster_id, namespace, reconcile_seconds=30, watch_seconds=5):
        if not isinstance(cluster_id, str) or not cluster_id.strip() or len(cluster_id) > 512:
            raise ValueError('explicit cluster ID required')
        if type(reconcile_seconds) is not int or not 1 <= reconcile_seconds <= 3600 or type(watch_seconds) is not int or not 1 <= watch_seconds <= 30:
            raise ValueError('reconcile interval1..3600 and watch interval1..30 required')
        self.api, self.db_path, self.cluster_id, self.namespace = api, db_path, cluster_id, namespace
        self.reconcile_seconds, self.watch_seconds = reconcile_seconds, watch_seconds
        self.stop = threading.Event()
        self.errors = []
        self._lock = threading.Lock()
        with InventoryStore(db_path) as store:
            store.bind_scope(cluster_id, namespace, api.server_id)

    def _gap(self, store, kind, reason):
        checkpoint = store.checkpoint(self.cluster_id, self.namespace, kind)
        store.begin_gap(self.cluster_id, self.namespace, kind, reason, now(),
                        started_at=checkpoint['observed_at'] if checkpoint else None)

    def cycle(self, kind, store, relist=False):
        try:
            if relist:
                checkpoint = store.checkpoint(self.cluster_id, self.namespace, kind)
                self._gap(store, kind, 'RECONCILIATION_WINDOW' if checkpoint else 'COLLECTOR_START')
                objects, version = self.api.list(kind)
                store.apply_snapshot(self.cluster_id, self.namespace, kind, objects, version, now(),
                                     source='kubernetes_reconcile' if checkpoint else 'kubernetes_list')
            checkpoint = store.checkpoint(self.cluster_id, self.namespace, kind)
            if checkpoint is None:
                raise ValueError('list checkpoint required before watch')
            stream = self.api.watch(kind, checkpoint['resource_version'], self.watch_seconds)
            try:
                for event in stream:
                    if self.stop.is_set():
                        break
                    if event['type'] == 'BOOKMARK':
                        metadata = event['object'].get('metadata')
                        if not isinstance(metadata, dict):
                            raise ValueError('bookmark metadata required')
                        version = rv(metadata.get('resourceVersion'))
                        store.bookmark(self.cluster_id, self.namespace, kind, version, now())
                    else:
                        store.apply_event(self.cluster_id, self.namespace, kind, event['type'], event['object'], now())
            finally:
                if hasattr(stream, 'close'):
                    stream.close()
            if not self.stop.is_set():
                checkpoint = store.checkpoint(self.cluster_id, self.namespace, kind)
                store.bookmark(self.cluster_id, self.namespace, kind, checkpoint['resource_version'], now())
            return True
        except (KubeError, ValueError, OSError) as error:
            reason = 'RESOURCE_VERSION_EXPIRED' if isinstance(error, KubeError) and error.code == 410 else 'COLLECTION_FAILED'
            self._gap(store, kind, reason)
            with self._lock:
                self.errors.append({'kind': kind, 'reason': reason})
            return False

    def worker(self, kind):
        with InventoryStore(self.db_path) as store:
            self._gap(store, kind, 'COLLECTOR_START_OR_RESTART')
            relist, last_reconcile = True, 0
            try:
                while not self.stop.is_set():
                    do_relist = relist or time.monotonic() - last_reconcile >= self.reconcile_seconds
                    success = self.cycle(kind, store, relist=do_relist)
                    if do_relist and success:
                        last_reconcile = time.monotonic()
                    relist = not success
                    if not success:
                        self.stop.wait(1)
            finally:
                self._gap(store, kind, 'COLLECTOR_STOPPED')

    def guarded_worker(self, kind):
        try:
            self.worker(kind)
        except Exception:
            self.stop.set()
            raise

    def run(self, duration=None):
        if duration is not None and (not isinstance(duration, (float, int)) or not math.isfinite(duration) or not 0 < duration <= 86400):
            raise ValueError('duration must be positive and at most86400 seconds')
        with scope_lease(self.db_path, self.cluster_id, self.namespace), ThreadPoolExecutor(max_workers=len(RESOURCES), thread_name_prefix='csle-watch') as executor:
            futures = [executor.submit(self.guarded_worker, kind) for kind in RESOURCES]
            try:
                self.stop.wait(duration)
            except KeyboardInterrupt:
                pass
            finally:
                self.stop.set()
            for future in futures:
                future.result()
        return {'status': 'stopped', 'cluster_id': self.cluster_id, 'namespace': self.namespace,
                'errors': len(self.errors), 'error_reasons': sorted({x['reason'] for x in self.errors})}
