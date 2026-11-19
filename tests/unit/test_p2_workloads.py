"""P2 requirement-derived normalization cases; all resource objects are synthetic."""
import copy
import json
from pathlib import Path
import unittest

from app.workloads import normalize_object

NOW = '2026-11-19T23:00:00Z'
DIGEST = 'sha256:' + 'a' * 64
REF = 'registry.example/demo@' + DIGEST
KINDS = ['Pod', 'Job', 'CronJob', 'Deployment', 'ReplicaSet', 'StatefulSet', 'DaemonSet']


def resource(kind='Pod'):
    pod_spec = {'containers': [{'name': 'main', 'image': REF}]}
    spec = pod_spec if kind == 'Pod' else {'template': {'spec': pod_spec}}
    if kind == 'CronJob':
        spec = {'jobTemplate': {'spec': spec}}
    return {'apiVersion': 'v1', 'kind': kind,
            'metadata': {'name': 'demo', 'namespace': 'csle-p2', 'uid': 'uid-1',
                         'resourceVersion': 'opaque:rv',
                         'creationTimestamp': '2026-11-01T00:00:00Z',
                         'ownerReferences': [{'kind': 'Job', 'name': 'parent', 'uid': 'owner-1', 'controller': True}]},
            'spec': spec, 'status': {}}


def normalize(obj, **kwargs):
    return normalize_object('kind-csle', 'csle-p2', obj.get('kind', 'Pod'), obj,
                            kwargs.get('event_type', 'MODIFIED'), kwargs.get('source', 'kubernetes_watch'),
                            kwargs.get('observed_at', NOW))


class NormalizationRedTests(unittest.TestCase):
    def test_reject_missing_uid_and_wrong_namespace(self):
        for mutate in [lambda obj: obj['metadata'].pop('uid'),
                       lambda obj: obj['metadata'].update(namespace='another'),
                       lambda obj: obj['metadata'].update(resourceVersion=123),
                       lambda obj: obj.update(spec=False)]:
            obj = resource(); mutate(obj)
            with self.assertRaises(ValueError):
                normalize(obj)

    def test_invalid_known_container_shapes(self):
        for value in [None, {}, False, 0, '']:
            obj = resource(); obj['spec']['containers'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize(obj)

    def test_source_event_shape(self):
        with self.assertRaises(ValueError):
            normalize(resource(), source='kubernetes_list', event_type='DELETED')
        with self.assertRaises(ValueError):
            normalize(resource(), observed_at='2026-02-30T00:00:00Z')


class NormalizationBehaviorTests(unittest.TestCase):
    def test_all_resource_template_paths(self):
        for kind in KINDS:
            with self.subTest(kind=kind):
                normalized = normalize(resource(kind))
                self.assertEqual(normalized.kind, kind)
                self.assertEqual(normalized.uid, 'uid-1')
                self.assertEqual(normalized.resource_version, 'opaque:rv')
                self.assertEqual(len(normalized.observations), 1)
                observation = normalized.observations[0]
                self.assertEqual(observation.desired_image_ref, REF)
                self.assertEqual(observation.source_event_at, None)
                self.assertEqual(observation.observed_at, NOW)
                self.assertEqual(observation.ingested_at, NOW)
                self.assertEqual(observation.owner_refs[0]['uid'], 'owner-1')
                self.assertEqual(observation.resolved_digest, None if kind == 'Pod' else DIGEST)

    def test_regular_init_ephemeral_statuses_by_name(self):
        obj = resource()
        obj['spec'].update(initContainers=[{'name': 'prepare', 'image': REF}],
                           ephemeralContainers=[{'name': 'debug', 'image': 'debug:tag'}])
        obj['status'].update(containerStatuses=[{'name': 'main', 'imageID': 'docker-pullable://' + REF}],
                             initContainerStatuses=[{'name': 'prepare', 'imageID': REF}],
                             ephemeralContainerStatuses=[{'name': 'debug', 'imageID': 'containerd://' + DIGEST}],
                             phase='Running')
        normalized = normalize(obj)
        rows = {row.container_type: row for row in normalized.observations}
        self.assertEqual(set(rows), {'regular', 'init', 'ephemeral'})
        self.assertEqual(rows['regular'].resolved_digest, DIGEST)
        self.assertEqual(rows['init'].resolved_digest, DIGEST)
        self.assertIsNone(rows['ephemeral'].resolved_digest)
        self.assertEqual(rows['ephemeral'].runtime_image_id, 'containerd://' + DIGEST)
        self.assertTrue(all(row.phase == 'Running' for row in rows.values()))

    def test_runtime_unknowns_never_inherit_desired_digest(self):
        for value in [None, '', DIGEST, 'containerd://' + DIGEST, 'prefix://docker-pullable://' + REF, 'unknown']:
            obj = resource()
            obj['status']['containerStatuses'] = [{'name': 'main', 'imageID': value}]
            row = normalize(obj).observations[0]
            with self.subTest(value=value):
                self.assertEqual(row.desired_image_ref, REF)
                self.assertIsNone(row.resolved_digest)
                self.assertEqual(row.resolution_status, 'unknown')
                self.assertEqual(row.runtime_image_id, value or None)
        obj = resource()
        obj['status']['containerStatuses'] = [{'name': 'other', 'imageID': REF}]
        self.assertIsNone(normalize(obj).observations[0].resolved_digest)

    def test_tag_reference_retained_without_resolution(self):
        obj = resource('Deployment')
        obj['spec']['template']['spec']['containers'][0]['image'] = 'example/app:latest'
        row = normalize(obj).observations[0]
        self.assertEqual(row.desired_image_ref, 'example/app:latest')
        self.assertIsNone(row.resolved_digest)

    def test_replica_zero_is_observation_not_closure(self):
        for kind in ['Deployment', 'ReplicaSet', 'StatefulSet']:
            obj = resource(kind)
            obj['spec']['replicas'] = 0
            obj['status']['readyReplicas'] = 0
            row = normalize(obj).observations[0]
            self.assertEqual(row.replicas_desired, 0)
            self.assertEqual(row.replicas_ready, 0)
            self.assertEqual(row.desired_image_ref, REF)
            self.assertNotIn('remediation', row.model_dump())
        obj = resource('DaemonSet')
        obj['status'].update(desiredNumberScheduled=2, numberReady=1)
        row = normalize(obj).observations[0]
        self.assertEqual((row.replicas_desired, row.replicas_ready), (2, 1))
        obj = resource('Job'); obj['spec']['parallelism'] = 1; obj['status']['ready'] = 0
        row = normalize(obj).observations[0]
        self.assertEqual((row.replicas_desired, row.replicas_ready), (1, 0))

    def test_identity_replay_and_uid_resource_version_semantics(self):
        first = normalize(resource())
        replay = normalize(resource(), observed_at='2026-11-19T23:01:00Z')
        self.assertEqual(first.event_id, replay.event_id)
        self.assertEqual(first.observations[0].observation_id, replay.observations[0].observation_id)
        self.assertNotEqual(first.observed_at, replay.observed_at)
        obj = resource(); obj['metadata']['uid'] = 'uid-2'
        self.assertNotEqual(first.event_id, normalize(obj).event_id)
        obj = resource(); obj['metadata']['resourceVersion'] = '1'
        self.assertNotEqual(first.event_id, normalize(obj).event_id)
        obj['metadata']['resourceVersion'] = '0001'
        self.assertNotEqual(normalize(obj).event_id, first.event_id)
        self.assertNotEqual(first.event_id, normalize(resource(), event_type='DELETED').event_id)
        obj = resource(); obj['status']['phase'] = 'Succeeded'
        self.assertEqual(first.event_id, normalize(obj).event_id)
        self.assertNotEqual(first.raw_object_hash, normalize(obj).raw_object_hash)

    def test_raw_resource_retained_and_detached_without_containers(self):
        obj = resource()
        obj['spec'] = {}
        obj['metadata']['annotations'] = {'example.org/context': 'preserved'}
        normalized = normalize(obj)
        self.assertEqual(normalized.observations, [])
        self.assertEqual(normalized.raw_object, obj)
        obj['metadata']['annotations']['example.org/context'] = 'changed'
        self.assertEqual(normalized.raw_object['metadata']['annotations']['example.org/context'], 'preserved')

    def test_owners_preserved_as_contract_subset(self):
        obj = resource()
        obj['metadata']['ownerReferences'][0].update(apiVersion='batch/v1', blockOwnerDeletion=True)
        normalized = normalize(obj)
        self.assertEqual(normalized.raw_object['metadata']['ownerReferences'][0]['apiVersion'], 'batch/v1')
        self.assertEqual(normalized.observations[0].owner_refs, [{'kind': 'Job', 'name': 'parent', 'uid': 'owner-1', 'controller': True}])

    def test_reject_malformed_known_values_and_duplicates(self):
        mutations = [lambda obj: obj['metadata'].update(ownerReferences=None),
                     lambda obj: obj['metadata']['ownerReferences'][0].update(controller=1),
                     lambda obj: obj['metadata']['ownerReferences'][0].update(blockOwnerDeletion=1),
                     lambda obj: obj['spec']['containers'][0].update(image=False),
                     lambda obj: obj['spec']['containers'].append(copy.deepcopy(obj['spec']['containers'][0])),
                     lambda obj: obj['status'].update(containerStatuses=[{'name': 'main', 'imageID': False}]),
                     lambda obj: obj['status'].update(containerStatuses=[{'name': 'main'}, {'name': 'main'}]),
                     lambda obj: obj['status'].update(phase=0)]
        for index, mutate in enumerate(mutations):
            obj = resource(); mutate(obj)
            with self.subTest(index=index), self.assertRaises(ValueError):
                normalize(obj)
        for value in [False, -1, '0', 1.0]:
            obj = resource('Deployment'); obj['spec']['replicas'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize(obj)
        obj = resource('Deployment'); obj['spec'] = {'replicas': -1}
        with self.assertRaises(ValueError):
            normalize(obj)

    def test_observations_match_frozen_schema(self):
        from jsonschema import Draft202012Validator, FormatChecker
        from referencing import Registry, Resource
        root = Path(__file__).resolve().parents[2] / 'contracts/v1'
        common = json.loads((root / 'common.schema.json').read_text())
        registry = Registry().with_resource(common['$id'], Resource.from_contents(common))
        schema = json.loads((root / 'workload-observation.schema.json').read_text())
        validator = Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())
        for kind in KINDS:
            for row in normalize(resource(kind)).observations:
                validator.validate(row.model_dump())

    def test_constructed_incoherent_models_reject(self):
        from app.workloads import NormalizedResource, WorkloadObservation
        obj = normalize(resource()).model_dump()
        for field, value in [('raw_object_hash', 'sha256:'+'b'*64), ('uid', 'other'), ('event_id', 'other')]:
            bad = copy.deepcopy(obj); bad[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                NormalizedResource.model_validate(bad)
        row = obj['observations'][0]
        for field, value in [('resolved_digest', DIGEST), ('replicas_ready', False), ('source', 'invalid'), ('owner_refs', [{'kind':'Job','uid':'x','name':None}]), ('idempotency_key', 'different')]:
            bad = copy.deepcopy(row); bad[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                WorkloadObservation.model_validate(bad)

    def test_container_bounds_and_rejected_scope_kind(self):
        obj = resource(); obj['spec']['containers'] = [{'name':'n'+str(n),'image':'demo:v1'} for n in range(1001)]
        with self.assertRaises(ValueError):
            normalize(obj)
        for cluster, namespace, kind in [(False,'csle-p2','Pod'), ('kind-csle',0,'Pod'), ('kind-csle','csle-p2',{})]:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                normalize_object(cluster, namespace, kind, resource(), 'ADDED', 'kubernetes_watch', NOW)
