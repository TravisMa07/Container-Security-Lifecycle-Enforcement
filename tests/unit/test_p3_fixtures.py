"""Frozen P3 fixture safety cases; no Docker, network or scanner execution."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('p3_fixtures', ROOT / 'scripts/p3_fixtures.py')
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class FixtureSafetyTests(unittest.TestCase):
    def test_wrong_recipe_cannot_expand_source_or_registry(self):
        for value in [{}, {'target_image':'attacker.example/image:tag'}, {'platform':'linux/amd64'}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                fixture.validate_recipe(value)

    def test_asset_bytes_must_match_pinned_hash(self):
        with self.assertRaises(ValueError):
            fixture.verify_asset(b'changed', hashlib.sha256(b'expected').hexdigest())

    def test_build_is_offline_fixed_and_does_not_emit_attestations(self):
        argv = fixture.build_arguments(['docker','--host','unix:///project/docker.sock'], Path('/context'))
        self.assertIn('--network=none',argv)
        self.assertIn('--provenance=false',argv)
        self.assertIn('--sbom=false',argv)
        self.assertEqual(argv[argv.index('--platform')+1],'linux/arm64/v8')
        self.assertIn('SOURCE_DATE_EPOCH=1795046400',argv)
        self.assertIn('127.0.0.1:15120/csle-p3/patched:fixed',argv)
        self.assertIn('type=docker,dest=/image.tar,rewrite-timestamp=true',argv)

    def test_exact_tracked_recipe_and_dockerfile_match(self):
        import json
        recipe=json.loads((ROOT/'demos/images/p3-patched/recipe.json').read_text())
        self.assertEqual(fixture.validate_recipe(recipe),recipe)
        self.assertEqual(hashlib.sha256((ROOT/'demos/images/p3-patched/Dockerfile').read_bytes()).hexdigest(),recipe['dockerfile_sha256'])
        for key,value in [('target_image','127.0.0.1:15120/unreviewed:tag'),('base_reference','alpine:latest'),('source_date_epoch',0),('extra',True)]:
            bad=copy.deepcopy(recipe);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):fixture.validate_recipe(bad)
        bad=copy.deepcopy(recipe);bad['assets'][0]['url']='https://unreviewed.example/asset.apk'
        with self.assertRaises(ValueError):fixture.validate_recipe(bad)

    def test_cached_corruption_fails_without_network_or_build(self):
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);packages=root/'packages';packages.mkdir()
            (packages/'libcrypto3.apk').write_bytes(b'corrupt cached package')
            with patch.object(fixture,'fetch',side_effect=AssertionError('unexpected network')):
                with self.assertRaisesRegex(ValueError,'checksum'):
                    fixture.prepare_context(copy.deepcopy(fixture.EXPECTED),root/'context',packages)

    def test_asset_size_limit_and_known_good_hash(self):
        from unittest.mock import patch
        raw=b'known'
        self.assertEqual(fixture.verify_asset(raw,hashlib.sha256(raw).hexdigest()),raw)
        with patch.object(fixture,'MAX_ASSET_BYTES',3):
            with self.assertRaises(ValueError):fixture.verify_asset(raw,hashlib.sha256(raw).hexdigest())

    def test_known_output_pin_and_no_arbitrary_engine(self):
        selected='sha256:'+'a'*64
        fixture.check_output_pin({'images':{}},selected)
        fixture.check_output_pin({'images':{'p3_patched':{'linux_arm64_digest':selected}}},selected)
        for pin in [{},{'manifest_digest':'sha256:'+'b'*64},{'manifest_digest':selected,'selected_digest':'different'}]:
            with self.subTest(pin=pin),self.assertRaises(ValueError):
                fixture.check_output_pin({'images':{'p3_patched':pin}},selected)
        with self.assertRaises(ValueError):fixture.build_arguments(['docker','--host','tcp://remote:2375'],Path('/context'))
        self.assertIn('--no-cache',fixture.build_arguments(['docker','--host','unix:///project/docker.sock'],Path('/context'),True))

    def test_no_package_signature_bypass_or_mutable_base(self):
        dockerfile=(ROOT/'demos/images/p3-patched/Dockerfile').read_text()
        self.assertIn('FROM docker.io/library/alpine@sha256:',dockerfile)
        self.assertIn('apk add --no-network',dockerfile)
        self.assertNotIn('--allow-untrusted',dockerfile)
        self.assertNotIn('curl',dockerfile)
        self.assertNotIn('wget',dockerfile)

    def test_command_timeout_retains_failed_evidence(self):
        import json
        import subprocess
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            recorder=fixture.Recorder(Path(directory))
            with patch.object(fixture.subprocess,'run',side_effect=subprocess.TimeoutExpired('docker',1,output=b'partial',stderr=b'failure')):
                with self.assertRaises(RuntimeError):recorder.run(['docker','build'],timeout=1)
            evidence=json.loads((Path(directory)/'commands.json').read_text())
            self.assertTrue(evidence[0]['timed_out'])
            self.assertEqual(evidence[0]['exit_code'],-1)
            self.assertEqual((Path(directory)/'00-stderr.log').read_bytes(),b'failure')

    def test_build_removes_timestamped_install_log_without_changing_package_db(self):
        dockerfile=(ROOT/'demos/images/p3-patched/Dockerfile').read_text()
        self.assertIn('rm -f /var/log/apk.log',dockerfile)
        self.assertNotIn('rm -rf /lib/apk',dockerfile)
        self.assertNotIn('--allow-untrusted',dockerfile)
