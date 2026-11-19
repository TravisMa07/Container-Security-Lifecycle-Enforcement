"""Strict Kubernetes observations; identities and absence never establish remediation."""
from datetime import datetime
import json
from typing import Annotated, Any, Literal

from pydantic import Field, TypeAdapter, model_validator

from app.collectors.trivy import parse_image_ref
from app.models import Digest, Identifier, Record, Text, Timestamp, canonical_json, sha256_bytes

KINDS = ('Pod', 'Job', 'CronJob', 'Deployment', 'ReplicaSet', 'StatefulSet', 'DaemonSet')
Kind = Literal['Pod', 'Job', 'CronJob', 'Deployment', 'ReplicaSet', 'StatefulSet', 'DaemonSet']
Source = Literal['kubernetes_watch', 'kubernetes_list', 'kubernetes_reconcile', 'synthetic_contract_test']
EventType = Literal['ADDED', 'MODIFIED', 'DELETED', 'SNAPSHOT']
Replicas = Annotated[int, Field(ge=0)]
_ID = TypeAdapter(Identifier)
_TEXT = TypeAdapter(Text)
_TIME = TypeAdapter(Timestamp)


class OwnerReference(Record):
    kind: Identifier
    uid: Identifier
    name: Identifier | None = None
    controller: bool | None = None


class WorkloadObservation(Record):
    schema_version: Literal['1'] = '1'
    cluster_id: Identifier
    namespace: Identifier
    kind: Kind
    name: Identifier
    uid: Identifier
    owner_refs: Annotated[list[dict[str, Any]], Field(max_length=100)]
    container_name: Identifier
    container_type: Literal['regular', 'init', 'ephemeral']
    desired_image_ref: Text
    runtime_image_id: Text | None
    resolved_digest: Digest | None
    resolution_status: Literal['resolved', 'unknown']
    phase: Text | None
    replicas_desired: Replicas | None
    replicas_ready: Replicas | None
    observed_at: Timestamp
    source_event_at: Timestamp | None
    ingested_at: Timestamp
    source: Source
    event_type: EventType
    observation_id: Identifier
    resource_version: Identifier
    idempotency_key: Identifier

    @model_validator(mode='after')
    def coherent(self):
        if (self.resolution_status == 'resolved') != (self.resolved_digest is not None):
            raise ValueError('resolved status must match digest presence')
        if self.source == 'kubernetes_watch' and self.event_type == 'SNAPSHOT':
            raise ValueError('watch event cannot be snapshot')
        if self.source in ('kubernetes_list', 'kubernetes_reconcile') and self.event_type != 'SNAPSHOT':
            raise ValueError('list/reconcile must be snapshot')
        if datetime.fromisoformat(self.observed_at.replace('Z', '+00:00')) > datetime.fromisoformat(self.ingested_at.replace('Z', '+00:00')):
            raise ValueError('observation cannot follow ingestion')
        for owner in self.owner_refs:
            _owner(owner)
        if self.observation_id != self.idempotency_key:
            raise ValueError('observation identity must match idempotency key')
        return self


class NormalizedResource(Record):
    event_id: Identifier
    cluster_id: Identifier
    namespace: Identifier
    kind: Kind
    name: Identifier
    uid: Identifier
    resource_version: Identifier
    event_type: EventType
    source: Source
    observed_at: Timestamp
    raw_object_hash: Digest
    raw_object: dict[str, Any]
    observations: list[WorkloadObservation]

    @model_validator(mode='after')
    def coherent(self):
        if (self.source == 'kubernetes_watch' and self.event_type == 'SNAPSHOT') or (self.source in ('kubernetes_list', 'kubernetes_reconcile') and self.event_type != 'SNAPSHOT'):
            raise ValueError('source and event type conflict')
        if self.event_id != _event_id(self.cluster_id, self.namespace, self.kind, self.uid, self.resource_version, self.event_type, self.source):
            raise ValueError('event identity does not match context')
        if self.raw_object_hash != sha256_bytes(canonical_json(self.raw_object).encode()):
            raise ValueError('raw object hash does not match')
        metadata = _object(self.raw_object.get('metadata'), 'metadata')
        if self.raw_object.get('kind') != self.kind or any(metadata.get(key) != value for key, value in [('namespace', self.namespace), ('name', self.name), ('uid', self.uid), ('resourceVersion', self.resource_version)]):
            raise ValueError('raw object identity does not match context')
        seen = set()
        for observation in self.observations:
            for field in ('cluster_id', 'namespace', 'kind', 'name', 'uid', 'resource_version', 'event_type', 'source', 'observed_at'):
                if getattr(observation, field) != getattr(self, field):
                    raise ValueError('container observation context mismatch')
            expected = _observation_id(self.event_id, observation.container_type, observation.container_name)
            if observation.observation_id != expected or expected in seen:
                raise ValueError('container observation identity mismatch or duplicate')
            seen.add(expected)
        return self


def _object(value, label):
    if not isinstance(value, dict):
        raise ValueError(label + ' must be an object')
    return value


def _array(value, label, limit=1000):
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(label + ' must be a bounded array')
    return value


def _owner(value):
    value = _object(value, 'owner reference')
    if any(value.get(key) is None for key in value):
        raise ValueError('owner reference values must not be null')
    return OwnerReference.model_validate(value).model_dump(exclude_none=True)


def _provider_owner(value):
    value = _object(value, 'owner reference')
    if 'apiVersion' in value:
        _ID.validate_python(value['apiVersion'], strict=True)
    if 'blockOwnerDeletion' in value and type(value['blockOwnerDeletion']) is not bool:
        raise ValueError('blockOwnerDeletion must be boolean')
    return _owner({key: value[key] for key in ('kind', 'uid', 'name', 'controller') if key in value})


def _event_id(cluster_id, namespace, kind, uid, resource_version, event_type, source):
    return sha256_bytes(canonical_json([cluster_id, namespace, kind, uid, resource_version, event_type, source]).encode())


def _observation_id(event_id, container_type, container_name):
    return sha256_bytes(canonical_json([event_id, container_type, container_name]).encode())


def _manifest(value):
    if value is None:
        return None
    try:
        return parse_image_ref(value)[2]
    except ValueError:
        return None


def normalize_object(cluster_id, namespace, kind, obj, event_type, source, observed_at):
    cluster_id = _ID.validate_python(cluster_id, strict=True)
    namespace = _ID.validate_python(namespace, strict=True)
    kind = TypeAdapter(Kind).validate_python(kind, strict=True)
    event_type = TypeAdapter(EventType).validate_python(event_type, strict=True)
    source = TypeAdapter(Source).validate_python(source, strict=True)
    observed_at = _TIME.validate_python(observed_at, strict=True)
    if (source == 'kubernetes_watch' and event_type == 'SNAPSHOT') or (source in ('kubernetes_list', 'kubernetes_reconcile') and event_type != 'SNAPSHOT'):
        raise ValueError('source and event type conflict')
    obj = _object(obj, 'resource')
    raw = canonical_json(obj).encode()
    if len(raw) > 20 * 1024 * 1024:
        raise ValueError('resource exceeds byte limit')
    obj = json.loads(raw)  # Detach provider data from the immutable evidence value.
    if obj.get('kind') != kind:
        raise ValueError('resource kind differs from requested kind')
    metadata = _object(obj.get('metadata'), 'metadata')
    if metadata.get('namespace') != namespace:
        raise ValueError('resource namespace differs from configured scope')
    name = _ID.validate_python(metadata.get('name'), strict=True)
    uid = _ID.validate_python(metadata.get('uid'), strict=True)
    rv = _ID.validate_python(metadata.get('resourceVersion'), strict=True)
    owners = [_provider_owner(owner) for owner in _array(metadata.get('ownerReferences', []), 'ownerReferences', 100)]
    owners.sort(key=canonical_json)
    spec = _object(obj.get('spec', {}), 'spec')
    status = _object(obj.get('status', {}), 'status')
    pod_spec = spec
    if kind == 'CronJob':
        job_spec = _object(_object(spec.get('jobTemplate', {}), 'jobTemplate').get('spec', {}), 'jobTemplate.spec')
        pod_spec = _object(_object(job_spec.get('template', {}), 'template').get('spec', {}), 'template.spec')
    elif kind != 'Pod':
        pod_spec = _object(_object(spec.get('template', {}), 'template').get('spec', {}), 'template.spec')
    desired, ready = None, None
    if kind in ('Deployment', 'ReplicaSet', 'StatefulSet'):
        desired, ready = spec.get('replicas'), status.get('readyReplicas')
    elif kind == 'Job':
        desired, ready = spec.get('parallelism'), status.get('ready')
    elif kind == 'DaemonSet':
        desired, ready = status.get('desiredNumberScheduled'), status.get('numberReady')
    for value in (desired, ready):
        if value is not None:
            TypeAdapter(Replicas).validate_python(value, strict=True)
    phase = status.get('phase') if kind == 'Pod' else None
    if phase is not None:
        _TEXT.validate_python(phase, strict=True)
    event_id = _event_id(cluster_id, namespace, kind, uid, rv, event_type, source)
    observations = []
    total = 0
    for category, field, status_field in [('regular', 'containers', 'containerStatuses'), ('init', 'initContainers', 'initContainerStatuses'), ('ephemeral', 'ephemeralContainers', 'ephemeralContainerStatuses')]:
        containers = _array(pod_spec.get(field, []), field)
        total += len(containers)
        if total > 1000:
            raise ValueError('container observation limit exceeded')
        statuses = {}
        if kind == 'Pod':
            for item in _array(status.get(status_field, []), status_field):
                item = _object(item, status_field + ' entry')
                item_name = _ID.validate_python(item.get('name'), strict=True)
                if item_name in statuses:
                    raise ValueError('duplicate container status name')
                image_id = item.get('imageID')
                if image_id == '':
                    image_id = None
                if image_id is not None:
                    image_id = _TEXT.validate_python(image_id, strict=True)
                statuses[item_name] = image_id
        names = set()
        for container in containers:
            container = _object(container, 'container')
            container_name = _ID.validate_python(container.get('name'), strict=True)
            if container_name in names:
                raise ValueError('duplicate container name')
            names.add(container_name)
            desired_ref = _TEXT.validate_python(container.get('image'), strict=True)
            runtime = statuses.get(container_name) if kind == 'Pod' else None
            candidate = runtime
            if candidate and candidate.startswith('docker-pullable://'):
                candidate = candidate[len('docker-pullable://'):]
            resolved = _manifest(candidate) if kind == 'Pod' else _manifest(desired_ref)
            observation_id = _observation_id(event_id, category, container_name)
            observations.append(WorkloadObservation(cluster_id=cluster_id, namespace=namespace, kind=kind, name=name, uid=uid, owner_refs=owners, container_name=container_name, container_type=category, desired_image_ref=desired_ref, runtime_image_id=runtime, resolved_digest=resolved, resolution_status='resolved' if resolved else 'unknown', phase=phase, replicas_desired=desired, replicas_ready=ready, observed_at=observed_at, source_event_at=None, ingested_at=observed_at, source=source, event_type=event_type, observation_id=observation_id, resource_version=rv, idempotency_key=observation_id))
    return NormalizedResource(event_id=event_id, cluster_id=cluster_id, namespace=namespace, kind=kind, name=name, uid=uid, resource_version=rv, event_type=event_type, source=source, observed_at=observed_at, raw_object_hash=sha256_bytes(raw), raw_object=obj, observations=sorted(observations, key=lambda observation: observation.observation_id))
