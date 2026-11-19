"""Requirement-derived P2 persistence oracles; synthetic Kubernetes objects."""
import copy
from pathlib import Path
import sqlite3
import tempfile
import unittest

from app.store.inventory import InventoryStore

T0='2026-11-19T00:00:00Z'
T1='2026-11-19T00:00:01Z'
T2='2026-11-19T00:00:02Z'
C='kind-test'
N='demo'

def obj(uid='uid-a',rv='opaque:a',name='worker',kind='Pod'):
    spec={'containers':[{'name':'main','image':'localhost:15120/demo:tag'}]}
    if kind!='Pod': spec={'replicas':0,'template':{'spec':spec}}
    return {'apiVersion':'v1' if kind=='Pod' else 'apps/v1','kind':kind,
            'metadata':{'name':name,'namespace':N,'uid':uid,'resourceVersion':rv},
            'spec':spec,'status':{'phase':'Pending'}}

class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'evidence.sqlite3'

    def test_event_replay_restart_and_uid_identity(self):
        with InventoryStore(self.path) as store:
            first=store.apply_event(C,N,'Pod','ADDED',obj(),T0)
            self.assertTrue(first['inserted'])
            self.assertFalse(store.apply_event(C,N,'Pod','ADDED',obj(),T1)['inserted'])
            self.assertEqual(len(store.events(C,N)),1)
            self.assertEqual(store.observations(C,N)[0]['observed_at'],T0)
            store.apply_event(C,N,'Pod','ADDED',obj(uid='uid-b'),T1)
            self.assertEqual({r['uid'] for r in store.current(C,N)}, {'uid-a','uid-b'})
            before=store.events(C,N)
        with InventoryStore(self.path) as store:
            self.assertEqual(store.events(C,N),before)
            self.assertEqual(store.checkpoint(C,N,'Pod')['resource_version'],'opaque:a')

    def test_deleted_history_persists_without_closure_verdict(self):
        with InventoryStore(self.path) as store:
            store.apply_event(C,N,'Pod','ADDED',obj(),T0)
            store.apply_event(C,N,'Pod','DELETED',obj(rv='opaque:b'),T1)
            self.assertEqual(len(store.events(C,N)),2)
            current=store.current(C,N)[0]
            self.assertFalse(current['present'])
            self.assertEqual(current['absence_reason'],'WATCH_DELETED')
            self.assertEqual(len(store.observations(C,N)),2)
            self.assertNotIn('remediation',current)

    def test_snapshot_absence_is_not_fabricated_delete(self):
        with InventoryStore(self.path) as store:
            store.apply_snapshot(C,N,'Pod',[obj()],'list:a',T0)
            store.apply_snapshot(C,N,'Pod',[],'list:b',T1)
            self.assertEqual(len(store.events(C,N)),1)
            current=store.current(C,N)[0]
            self.assertFalse(current['present'])
            self.assertEqual(current['absence_reason'],'RECONCILED_ABSENT')
            self.assertEqual(store.checkpoint(C,N,'Pod')['resource_version'],'list:b')

    def test_gap_is_durable_and_closed_only_by_snapshot(self):
        with InventoryStore(self.path) as store:
            gap=store.begin_gap(C,N,'Pod','DISCONNECTED',T1,started_at=T0)
            self.assertEqual(store.begin_gap(C,N,'Pod','RETRY',T2),gap)
            self.assertEqual(len(store.gaps(C,N)),1)
            self.assertIsNone(store.gaps(C,N)[0]['ended_at'])
            store.apply_event(C,N,'Pod','ADDED',obj(),T1)
            self.assertIsNone(store.gaps(C,N)[0]['ended_at'])
            store.apply_snapshot(C,N,'Pod',[obj()],'list:a',T2)
            self.assertEqual(store.gaps(C,N)[0]['ended_at'],T2)
            self.assertEqual(store.gaps(C,N)[0]['reason'],'DISCONNECTED')

    def test_conflicting_replay_and_old_replay_cannot_regress_current(self):
        with InventoryStore(self.path) as store:
            store.apply_event(C,N,'Pod','ADDED',obj(),T0)
            store.apply_event(C,N,'Pod','MODIFIED',obj(rv='rv:z'),T1)
            before=store.current(C,N)
            store.apply_event(C,N,'Pod','ADDED',obj(),T2)
            self.assertEqual(store.current(C,N),before)
            self.assertEqual(store.checkpoint(C,N,'Pod')['resource_version'],'rv:z')
            changed=obj();changed['spec']['containers'][0]['image']='other:tag'
            with self.assertRaises(ValueError): store.apply_event(C,N,'Pod','ADDED',changed,T2)
            self.assertEqual(len(store.events(C,N)),2)

    def test_scope_binding_and_bookmark(self):
        with InventoryStore(self.path) as store:
            store.bind_scope(C,N,'server:a');store.bind_scope(C,N,'server:a')
            with self.assertRaises(ValueError):store.bind_scope(C,N,'server:b')
            store.bookmark(C,N,'Pod','not-numeric',T0)
            self.assertEqual(store.checkpoint(C,N,'Pod')['resource_version'],'not-numeric')
            self.assertEqual(store.events(C,N),[])
            self.assertEqual(store.observations(C,N),[])
            with self.assertRaises(ValueError): store.bookmark(C,N,'Pod','',T1)
            self.assertEqual(store.checkpoint(C,N,'Pod')['resource_version'],'not-numeric')

    def test_failed_event_rolls_back_evidence_membership_and_checkpoint(self):
        with InventoryStore(self.path) as store:
            store.apply_event(C,N,'Pod','ADDED',obj(),T0)
            before=(store.events(C,N),store.current(C,N),store.checkpoint(C,N,'Pod'))
            store.connection.execute("CREATE TRIGGER injected_failure BEFORE INSERT ON inventory_observations BEGIN SELECT RAISE(ABORT,'injected'); END")
            with self.assertRaises(sqlite3.IntegrityError):store.apply_event(C,N,'Pod','MODIFIED',obj(rv='new'),T1)
            self.assertEqual((store.events(C,N),store.current(C,N),store.checkpoint(C,N,'Pod')),before)
            store.connection.execute('DROP TRIGGER injected_failure')
            self.assertTrue(store.apply_event(C,N,'Pod','MODIFIED',obj(rv='new'),T1)['inserted'])

    def test_failed_snapshot_rolls_back_gap_close_and_absence(self):
        with InventoryStore(self.path) as store:
            store.apply_snapshot(C,N,'Pod',[obj()],'rv:list1',T0)
            store.begin_gap(C,N,'Pod','410',T1)
            before=(store.events(C,N),store.current(C,N),store.checkpoint(C,N,'Pod'),store.gaps(C,N))
            store.connection.execute("CREATE TRIGGER injected_failure BEFORE INSERT ON inventory_gap_events WHEN NEW.event_type='END' BEGIN SELECT RAISE(ABORT,'injected'); END")
            with self.assertRaises(sqlite3.IntegrityError):store.apply_snapshot(C,N,'Pod',[],'rv:list2',T2)
            self.assertEqual((store.events(C,N),store.current(C,N),store.checkpoint(C,N,'Pod'),store.gaps(C,N)),before)
            store.connection.execute('DROP TRIGGER injected_failure')
            store.apply_snapshot(C,N,'Pod',[],'rv:list2',T2)
            self.assertIsNotNone(store.gaps(C,N)[0]['ended_at'])

    def test_invalid_snapshot_retains_prior_state(self):
        with InventoryStore(self.path) as store:
            store.apply_snapshot(C,N,'Pod',[obj()],'list:first',T0)
            before=(store.events(C,N),store.current(C,N),store.checkpoint(C,N,'Pod'))
            for objects in [[obj(),obj()], [obj(),{}], {}, [obj(uid='other',name='other',rv='new'), {'kind':'Pod'}]]:
                with self.subTest(objects=objects),self.assertRaises(ValueError):store.apply_snapshot(C,N,'Pod',objects,'list:bad',T1)
                self.assertEqual((store.events(C,N),store.current(C,N),store.checkpoint(C,N,'Pod')),before)

    def test_zero_replica_controller_and_no_container_resource_retained(self):
        with InventoryStore(self.path) as store:
            store.apply_snapshot(C,N,'Deployment',[obj(kind='Deployment')],'list:d',T0)
            current=store.current(C,N)[0]
            self.assertTrue(current['present'])
            self.assertEqual(current['observations'][0]['replicas_desired'],0)
            self.assertEqual(current['observations'][0]['desired_image_ref'],'localhost:15120/demo:tag')
            empty=obj();empty['spec']['containers']=[]
            store.apply_event(C,N,'Pod','ADDED',empty,T1)
            self.assertTrue(any(r['kind']=='Pod' for r in store.current(C,N)))
            self.assertEqual(next(r for r in store.events(C,N) if r['kind']=='Pod')['observations'],[])

    def test_append_only_and_tamper_checks(self):
        with InventoryStore(self.path) as store:
            store.apply_event(C,N,'Pod','ADDED',obj(),T0)
            store.begin_gap(C,N,'Pod','DISCONNECTED',T1)
            for table in ['inventory_events','inventory_observations','inventory_gap_events']:
                for sql in ['DELETE FROM '+table,'UPDATE '+table+' SET '+ {'inventory_events':'event_id=event_id','inventory_observations':'observation_id=observation_id','inventory_gap_events':'gap_id=gap_id'}[table]]:
                    with self.assertRaises(sqlite3.IntegrityError):store.connection.execute(sql)
            store.connection.execute('DROP TRIGGER inventory_events_no_update')
            store.connection.execute("UPDATE inventory_events SET payload='{}'")
            with self.assertRaises(ValueError):store.events(C,N)
            with self.assertRaises(ValueError):store.observations(C,N)
            with self.assertRaises(ValueError):store.current(C,N)

    def test_fractional_gap_chronology_and_scope_isolation(self):
        with InventoryStore(self.path) as store:
            store.begin_gap(C,N,'Pod','DISCONNECTED','2026-11-19T00:00:00.1Z',started_at=T0)
            store.apply_snapshot(C,N,'Pod',[],'list:empty','2026-11-19T00:00:00.2Z')
            self.assertEqual(store.gaps(C,N)[0]['ended_at'],'2026-11-19T00:00:00.2Z')
            self.assertEqual(store.gaps('another',N),[])
            self.assertEqual(store.events('another',N),[])
            self.assertEqual(store.current('another',N),[])

    def test_gap_close_before_recorded_start_rejects_atomically(self):
        with InventoryStore(self.path) as store:
            store.begin_gap(C,N,'Pod','DISCONNECTED',T2,started_at=T0)
            with self.assertRaises(ValueError):store.apply_snapshot(C,N,'Pod',[obj()],'list:backwards',T1)
            self.assertEqual(store.events(C,N),[])
            self.assertIsNone(store.checkpoint(C,N,'Pod'))
            self.assertIsNone(store.gaps(C,N)[0]['ended_at'])
