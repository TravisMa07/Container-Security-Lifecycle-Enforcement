"""P2 JSON query and help contracts across process restart; synthetic source only."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from app.store.inventory import InventoryStore
from test_p2_lifecycle import pod

ROOT=Path(__file__).resolve().parents[2]

class InventoryCLITests(unittest.TestCase):
    def test_history_queries_and_help_are_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            database=Path(directory)/'inventory.sqlite3'
            with InventoryStore(database) as store:
                store.apply_snapshot('cluster','demo','Pod',[pod()],'rv','2026-11-19T00:00:00Z')
                store.begin_gap('cluster','demo','Pod','COLLECTOR_STOPPED','2026-11-19T00:00:01Z')
            for operation in ('workloads','observations','events','snapshots','gaps'):
                argv=[sys.executable,'-m','app','--db',str(database),'inventory',operation,'--cluster','cluster','--namespace','demo']
                a=subprocess.run(argv,cwd=ROOT,capture_output=True,text=True)
                b=subprocess.run(argv,cwd=ROOT,capture_output=True,text=True)
                self.assertEqual(a.returncode,0,a.stderr)
                self.assertEqual(a.stdout,b.stdout)
                self.assertTrue(json.loads(a.stdout))
            for command in (['inventory','--help'],['inventory','collect','--help']):
                result=subprocess.run([sys.executable,'-m','app',*command],cwd=ROOT,capture_output=True,text=True)
                self.assertEqual(result.returncode,0)

    def test_missing_scope_and_remote_endpoint_reject_without_database(self):
        with tempfile.TemporaryDirectory() as directory:
            database=Path(directory)/'not-created.sqlite3'
            for args in [['inventory','workloads'],['inventory','collect','--cluster','c','--namespace','demo','--server','https://example.com:443','--ca','missing','--token-file','missing']]:
                result=subprocess.run([sys.executable,'-m','app','--db',str(database),*args],cwd=ROOT,capture_output=True,text=True)
                self.assertEqual(result.returncode,2,result.stderr)
                self.assertEqual(result.stdout,'')
                self.assertEqual(json.loads(result.stderr)['error']['code'],'INVALID_INPUT')
                self.assertFalse(database.exists())
