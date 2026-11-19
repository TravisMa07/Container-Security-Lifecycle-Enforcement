"""Frozen P2 recovery expectations with deterministic synthetic API faults."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.collectors.lifecycle import Collector, scope_lease
from app.collectors.kubernetes import KubeError
from app.store.inventory import InventoryStore


def pod(version='opaque-a', uid='uid-a'):
    return {'kind':'Pod','metadata':{'namespace':'demo','name':'worker','uid':uid,'resourceVersion':version},
            'spec':{'containers':[{'name':'worker','image':'localhost:15120/demo:tag'}]},'status':{'phase':'Running'}}


class API:
    server_id = 'synthetic-server'
    def __init__(self):
        self.objects, self.version, self.events = [pod()], 'snapshot-rv', []
        self.error = None
    def list(self, kind):
        if self.error: raise self.error
        return self.objects, self.version
    def watch(self, kind, version, timeout):
        for event in self.events:
            if isinstance(event, Exception): raise event
            yield event


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / 'inventory.sqlite3'
        self.api = API()
        self.collector = Collector(self.api, self.db, 'cluster', 'demo')

    def test_list_watch_bookmark_and_opaque_checkpoint(self):
        self.api.events = [{'type':'MODIFIED','object':pod('watch-z')}, {'type':'BOOKMARK','object':{'metadata':{'resourceVersion':'bookmark-x'}}}]
        with InventoryStore(self.db) as store:
            self.assertTrue(self.collector.cycle('Pod', store, relist=True))
            self.assertEqual(store.checkpoint('cluster','demo','Pod')['resource_version'], 'bookmark-x')
            self.assertEqual(len(store.events('cluster')), 2)
            self.assertEqual(len(store.observations('cluster')), 2)
            self.assertTrue(all(g['ended_at'] is not None for g in store.gaps('cluster')))

    def test_410_opens_gap_and_relist_converges_without_invented_delete(self):
        self.api.events = [KubeError(410)]
        with InventoryStore(self.db) as store:
            self.assertFalse(self.collector.cycle('Pod',store,relist=True))
            self.assertEqual(store.checkpoint('cluster','demo','Pod')['resource_version'], 'snapshot-rv')
            self.assertTrue(any(g['reason']=='RESOURCE_VERSION_EXPIRED' and g['ended_at'] is None for g in store.gaps('cluster')))
            self.api.events=[];self.api.objects=[];self.api.version='relist-new'
            self.assertTrue(self.collector.cycle('Pod',store,relist=True))
            self.assertFalse(store.current('cluster')[0]['present'])
            self.assertEqual(store.current('cluster')[0]['absence_reason'],'RECONCILED_ABSENT')
            self.assertFalse(any(e['event_type']=='DELETED' for e in store.events('cluster')))
            self.assertTrue(all(g['ended_at'] is not None for g in store.gaps('cluster')))

    def test_failed_relist_preserves_history_and_checkpoint(self):
        with InventoryStore(self.db) as store:
            self.assertTrue(self.collector.cycle('Pod',store,relist=True))
            before=store.checkpoint('cluster','demo','Pod')
            self.api.error=KubeError(403)
            self.assertFalse(self.collector.cycle('Pod',store,relist=True))
            self.assertEqual(store.checkpoint('cluster','demo','Pod'),before)
            self.assertEqual(len(store.events('cluster')),1)
            self.assertTrue(any(g['ended_at'] is None for g in store.gaps('cluster')))

    def test_malformed_bookmark_is_gap_not_fabricated_observation(self):
        self.api.events=[{'type':'BOOKMARK','object':{'metadata':None}}]
        with InventoryStore(self.db) as store:
            self.assertFalse(self.collector.cycle('Pod',store,relist=True))
            self.assertEqual(len(store.observations('cluster')),1)
            self.assertTrue(any(g['ended_at'] is None for g in store.gaps('cluster')))

    def test_scope_binding_and_concurrent_collector_rejected(self):
        self.api.server_id='different-server'
        with self.assertRaises(ValueError): Collector(self.api,self.db,'cluster','demo')
        with scope_lease(self.db,'cluster','demo'):
            with self.assertRaises(RuntimeError):
                with scope_lease(self.db,'cluster','demo'): self.fail('duplicate lease')

    def test_fatal_worker_failure_stops_indefinite_run(self):
        with patch.object(self.collector,'worker',side_effect=RuntimeError('storage failed')):
            with self.assertRaises(RuntimeError):self.collector.run()
