# P2 observation runbook

Supported real profile remains the P0 macOS ARM64 Kind1.35.10 lab. `make bootstrap`, `make test` and `make check` install/run the pinned application. No new Python dependency or service was introduced. P2 observes one explicit namespace per process; distinct namespace processes can share the database. An advisory file lease prevents two collectors writing the same DB/cluster/namespace concurrently.

## Reproduce the acceptance scenarios

The existing explicit kubeconfig `.local/p0/source-clone/.local/p0/kubeconfig`, context `kind-csle-p0-cis`, must refer to the project lab. The opt-in test uses admin only to create a new uniquely named `csle-p2-*` namespace, its ServiceAccount/Role/RoleBinding and nonprivileged demo workloads. It does not delete or modify existing namespaces/resources. Workload TTL cleanup is part of the new test Job definitions. Read-only observation uses the dedicated SA token; secrets/create/delete and other-namespace access must receive actual403.

```sh
.tools/venv/bin/python tests/integration/p2_real.py > .local/p2/latest-result.json
```

The result identifies the namespace and ignored local evidence directory. The test runs seven actual watches, captures Job TTL deletion/name reuse, observes scale-zero, closes normal watch connections/reconnects, reconciles periodically, stops the observer while a Job's entire lifecycle happens, then restarts. To exercise expiry it makes one actual Pod watch request at old RV1 and requires an actual server410 followed by successful relist/recovery. It never substitutes a mock410. Offline tests separately cover failed relists, early EOF, malformed input, storage faults and rollback. These are different evidence claims.

Raw objects, credentials and database remain under the local run directory. Observer tokens expire after the requested1h and are owner-readable only. No implicit cleanup/reset command is provided; retained resources/evidence are listed in the ledger.

## CLI

Use the run directory/namespace from your result; the following placeholders must be replaced with those actual values:

```sh
.tools/venv/bin/csle --db .local/p2/qualification/RUN/evidence.sqlite3 inventory workloads --cluster kind-csle-p0-cis --namespace NAMESPACE
.tools/venv/bin/csle --db .local/p2/qualification/RUN/evidence.sqlite3 inventory events --cluster kind-csle-p0-cis --namespace NAMESPACE
.tools/venv/bin/csle --db .local/p2/qualification/RUN/evidence.sqlite3 inventory observations --cluster kind-csle-p0-cis --namespace NAMESPACE
.tools/venv/bin/csle --db .local/p2/qualification/RUN/evidence.sqlite3 inventory snapshots --cluster kind-csle-p0-cis --namespace NAMESPACE
.tools/venv/bin/csle --db .local/p2/qualification/RUN/evidence.sqlite3 inventory gaps --cluster kind-csle-p0-cis --namespace NAMESPACE
```

For a new observation interval use `inventory collect --cluster ID --namespace NS --server https://127.0.0.1:PORT --ca CA_FILE --token-file TOKEN_FILE --duration 30 --reconcile-seconds 8 --watch-seconds 2`. The server URL comes from the explicit project kubeconfig; CA/token files come from the namespaced setup. `infra/p2-rbac.json` is the read-only template; change its namespace consistently when provisioning another project-owned scope. `--duration` is optional; Ctrl-C stops the foreground collector. An in-flight bounded watch may take its read timeout to finish after stop. No kubeconfig, context or credential plugin is implicitly selected by the collector.

HTTPS CA and server-name validation is mandatory. Remote endpoints, HTTP, proxy routing and redirects are rejected. The token is read from its owner-only file for each connection, allowing explicit token rotation; it is never logged or accepted as a CLI argument. One cluster ID is bound to a server URL+CA hash across all its namespaces, preventing mixed-server aggregation. A bad credential, 410, malformed response or disconnect creates a gap and relists; a failed list cannot become an empty successful snapshot. Collection returns nonzero after any observed error even if recovery succeeds; gaps preserve that history. The controlled410 acceptance therefore expects one error in the recovery collector summary.

## Interpret the evidence

- Events/raw objects and per-container observations are append-only, UID-based and idempotent by RV/source/type/container. Same-name/new-UID resources remain distinct. Acquisition timestamps are local observations; object creation timestamps are not relabeled as watch-event times.
- Complete snapshot receipts include scope/kind/list RV, acquisition time and full membership, including empty snapshots. Each acquisition has its own receipt; identical import of the same receipt is idempotent. Replayed unchanged resource observations keep their original acquisition time; receipt/current last_seen/checkpoint establish later contact.
- `workloads` returns derived tracked membership with present/absence_reason and last_seen. `present:false` from reconciliation is RECONCILED_ABSENT, not a fabricated DELETED event. Watched deletion retains its original raw event. Current entries are last observations, not a promise of fresh live state: read their timestamp/checkpoint and gaps.
- Startup/restart opens a conservative gap from prior contact; periodic relist also records a reconciliation window because unobserved transitions may occur before the new list RV. Gaps describe a resource kind and namespace, not globally atomic coverage. An unseen workload during outage stays unknown; later lists cannot reconstruct it.
- Runtime repo@digest and the supported docker-pullable prefix are parsed conservatively. Bare/containerd config IDs stay unknown. Pod desired digest never becomes runtime proof. Controller desired references remain visible at zero replicas.
- P2 emits no finding validity, exposure classification, fix/false-positive status, policy approval or compliance result. P3 must combine current membership, immutable snapshots, scan evidence and coverage/freshness.

Migration1 (P1) and already executed migration2 remain unchanged. Migration3 adds immutable complete-snapshot receipts; no historical empty snapshots are invented when upgrading an early development DB. Earlier history lacking receipts remains incomplete. Migrations are atomic and hash-checked; old executables reject newer schema versions. Preserve a backup and diagnose incompatibility rather than deleting/resetting evidence.

The local DB owner can rewrite data/guards/hashes; this is not cryptographically protected audit storage. Namespace lists are capped at10000 objects,21 pages and20MiB cumulatively; each watch event is capped at20MiB/depth64. Threads are fixed at seven. Query paths revalidate/materialize small local history; high-volume and production operation are unqualified. Filesystem lease support and local REST transport were tested only on the supported profile; no real AWS/EKS claim exists.
