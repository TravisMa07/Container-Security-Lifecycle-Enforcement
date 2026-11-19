"""Independent P1-12/13 resolver oracles; synthetic bytes, no network."""
import hashlib
import json
import unittest
from app.collectors.oci import resolve, endpoint_url


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


def digest(value):
    return 'sha256:' + hashlib.sha256(value).hexdigest()


class OCIResolutionTests(unittest.TestCase):
    def setUp(self):
        self.config = encoded({'os': 'linux', 'architecture': 'arm64'})
        self.manifest = encoded({'schemaVersion': 2, 'config': {'digest': digest(self.config), 'size': len(self.config)}, 'layers': []})
        self.ref = '127.0.0.1:15120/demo@' + digest(self.manifest)
        self.endpoint = 'http://127.0.0.1:15120'
        self.fetch = lambda path, limit: self.config if '/blobs/' in path else self.manifest

    def test_manifest_hash_mismatch_rejected(self):
        with self.assertRaisesRegex(ValueError, 'digest'):
            resolve(self.ref, self.endpoint, 'linux/arm64', lambda path, limit: b'{}')

    def test_config_hash_mismatch_rejected(self):
        def fetch(path, limit):
            return b' ' * len(self.config) if '/blobs/' in path else self.manifest
        with self.assertRaisesRegex(ValueError, 'digest'):
            resolve(self.ref, self.endpoint, 'linux/arm64', fetch)

    def test_platform_mismatch_rejected(self):
        with self.assertRaisesRegex(ValueError, 'platform'):
            resolve(self.ref, self.endpoint, 'linux/amd64', self.fetch)

    def test_positive_identity(self):
        result = resolve(self.ref, self.endpoint, 'linux/arm64', self.fetch)
        self.assertEqual(result['manifest_digest'], digest(self.manifest))
        self.assertEqual(result['config_digest'], digest(self.config))
        self.assertIsNone(result['index_digest'])

    def test_index_preserves_parent_and_selects_platform(self):
        index = encoded({'schemaVersion': 2, 'manifests': [
            {'digest': digest(self.manifest), 'size': len(self.manifest), 'platform': {'os': 'linux', 'architecture': 'arm64'}}]})
        def fetch(path, limit):
            return index if digest(index) in path else self.fetch(path, limit)
        result = resolve('127.0.0.1:15120/demo@' + digest(index), self.endpoint, 'linux/arm64', fetch)
        self.assertEqual(result['index_digest'], digest(index))
        self.assertEqual(result['manifest_digest'], digest(self.manifest))

    def test_generic_arch_preserves_resolved_variant(self):
        self.config = encoded({'os': 'linux', 'architecture': 'arm64', 'variant': 'v8'})
        self.manifest = encoded({'schemaVersion': 2, 'config': {'digest': digest(self.config), 'size': len(self.config)}, 'layers': []})
        self.ref = '127.0.0.1:15120/demo@' + digest(self.manifest)
        result = resolve(self.ref, self.endpoint, 'linux/arm64', self.fetch)
        self.assertEqual(result['platform'], 'linux/arm64/v8')

    def test_local_endpoint_only(self):
        for endpoint in ['https://127.0.0.1:12', 'http://example.com:12', 'http://localhost', 'http://u:p@localhost:12', 'http://localhost:12/x', 'http://localhost:12/?x=1']:
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                endpoint_url(endpoint)
