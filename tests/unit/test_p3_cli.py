"""P3 CLI evaluation/query contracts with imported synthetic inputs."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from app.collectors.trivy import parse_report
from app.store.db import Store

ROOT=Path(__file__).resolve().parents[2]
FIXTURE=ROOT/'tests/fixtures/p1/trivy-synthetic.json'

class LifecycleCLITests(unittest.TestCase):
    def test_assessment_queries_are_stable_and_unknown_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            db=Path(directory)/'evidence.sqlite3';raw=FIXTURE.read_bytes()
            parsed=parse_report(raw,json.loads(raw)['Metadata']['RepoDigests'][0])
            with Store(db) as store:store.save_scan(parsed,raw)
            base=[sys.executable,'-m','app','--db',str(db)]
            arguments=['findings','assess',parsed.findings[0].finding_id,'--cluster','cluster','--namespace','demo','--at','2026-11-19T12:00:00Z']
            a=subprocess.run([*base,*arguments],cwd=ROOT,capture_output=True,text=True)
            b=subprocess.run([*base,*arguments],cwd=ROOT,capture_output=True,text=True)
            self.assertEqual(a.returncode,0,a.stderr);self.assertEqual(a.stdout,b.stdout)
            result=json.loads(a.stdout)
            self.assertEqual(result['state']['remediation'],'unknown')
            query=subprocess.run([*base,'assessments','show',result['assessment_id']],cwd=ROOT,capture_output=True,text=True)
            self.assertEqual(query.returncode,0,query.stderr);self.assertEqual(query.stdout,a.stdout)
            history=subprocess.run([*base,'lifecycle','image',parsed.image.image_id],cwd=ROOT,capture_output=True,text=True)
            self.assertEqual(history.returncode,0,history.stderr);self.assertEqual(len(json.loads(history.stdout)),1)

    def test_help_and_missing_replacement_are_not_approval(self):
        for arguments in [['findings','assess','--help'],['remediation','verify','--help'],['lifecycle','image','--help']]:
            result=subprocess.run([sys.executable,'-m','app',*arguments],cwd=ROOT,capture_output=True,text=True)
            self.assertEqual(result.returncode,0)
        with tempfile.TemporaryDirectory() as directory:
            result=subprocess.run([sys.executable,'-m','app','--db',str(Path(directory)/'none.sqlite3'),'remediation','verify','unknown','--cluster','c','--namespace','demo'],cwd=ROOT,capture_output=True,text=True)
            self.assertEqual(result.returncode,2);self.assertEqual(result.stdout,'')
            self.assertEqual(json.loads(result.stderr)['error']['code'],'INVALID_INPUT')
