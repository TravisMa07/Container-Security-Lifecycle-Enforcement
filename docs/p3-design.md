# P3 — deterministic correlation and scoped remediation

Base: merged P2 `e62a80ee184ec9ea5f04aad58df0994b996ba4c2`. Authority: HANDOFF5.3/5.4/6/12-P3 and S3/S4/S12/S13. Parent owns interfaces, facts loader, assessments persistence/migration4, CLI, pins/CI and serialized integration. Scoped agents own pure engine/tests and fixture recipe/builder/tests; independent reviews are read-only. No new service/database/third-party runtime dependency. P3 merge is not authorized.

## Scope and facts

Keep validity, exposure and remediation orthogonal. Do not change scanner-derived validity from under_investigation because workload/image disappears. Explicit scope is one cluster plus sorted nonempty namespace set, not an implied whole cluster. All seven workload kinds must have fresh complete-list receipts/checkpoints; per-kind coverage is not a globally atomic snapshot. Tags, unknown runtime IDs, uncertain index/platform relationships, missing/stale scans or inventory and gaps prevent verified closure.

Parent loads one coherent SQLite read transaction into a JSON facts envelope:

- `finding`: canonical VulnerabilityFinding; `scope`: `{cluster_id,namespaces}`; `assessment_at`: canonical UTC Z.
- `inventory_max_age_seconds` default30, `scan_max_age_seconds` default86400, `db_max_age_seconds` default86400; positive bounded integers.
- `current`, `events`, `snapshots`, `gaps`: P2 query records filtered to scope; `checkpoints`: rows `{namespace,kind,resource_version,observed_at}`; every kind/namespace required.
- `scans`: P1 full scan records with additional `report` (hash-verified original JSON), not reclassified imports. `trusted_scanner_hashes`: independently configured binary hashes from repository pins, never scanner payload declarations.
- `replacement_digest`: explicit optional selected manifest digest. `previous`: only strictly earlier persisted assessments `{assessment_id,finding_id,scope,state}` for regression; no self-reference/reimport recursion.

`app.engine.lifecycle.evaluate(facts:dict)->dict` is pure and exports strict `DerivedFindingState`/verification models matching P0 schema. Return `{state:canonical_v1_state,links:{running:[],configured:[],historical:[],unknown:[]},regression_of:assessment_id|null,replacement_digest:digest|null}`. Link arrays contain observation IDs, sorted/unique. Parent adds assessment_id, finding_id, image_digest, scope and facts_hash, stores immutable input/result together and verifies/replays it on read. Identical facts/evaluation is idempotent. Facts including mutable current/checkpoints are frozen in the assessment, never silently reconstructed later.

## Independent rules

- A matching fresh Pod runtime manifest is running only when its raw matching container status has `state.running` and Pod phase Running. A terminated/unknown status is not asserted running. Desired refs remain distinct from runtime. Controller/Pod desired digest refs count as configured even at zero replicas. Pod desired digest cannot establish its runtime identity.
- Join selected immutable manifests; recognize only P2-supported runtime forms. Tags never inherit old/new digest findings. Known index->platform containment may establish a remaining reference only with independently verified scan resolution; it cannot prove absence of vulnerable platforms. Unknown desired index/kind or unresolvable active runtime identity prevents closure. Current digests not established as selected manifests by trusted scans remain uncertain for closure.
- Historical evidence requires a captured scoped observation of the finding digest. No observation is unknown, not historical. With complete fresh inventory and no uncertainty, exposure precedence is running, configured_not_running, historical_observed, unknown. Incomplete/stale/gapped inventory or uncertain current identities yields exposure unknown while retaining positive links/reasons.
- Coverage window starts at latest complete-list receipt time across required kind/namespace pairs and ends at assessment_at. All receipts/checkpoints must be fresh, not future, and match scope; no open or intersecting gap in that window. A closed earlier gap remains retained in history but does not poison every future assessment. Snapshot/read times bound the claim; no perfect earlier historical reconstruction is asserted.
- Remediation is unknown when coverage/identity or required scan provenance/freshness is unknown. Otherwise current old references mean open; absence plus history means open retirement candidate. With explicit observed replacement it may be in_progress until every verification prerequisite passes. No disappearance-only closure.
- `verified_in_scope` requires historical original, no old desired/runtime references anywhere in scope, no relevant uncertainty/gaps, fresh trusted original and replacement scan/DB, and current running replacement tied through owner-UID ancestry to an original observed workload/container. Walk only captured same-namespace UID owners; never join controller replacements by reused names. Controller identity must persist through rollout (or captured owner lineage must establish the same workload root).
- Fixed-package proof requires raw replacement `Results[].Packages` inventory (Trivy --list-all-pkgs), same package manager/type/name/path and OS family/platform, installed version exactly matching the original single FixedVersion token, plus no same vulnerability ID/alias on that package. Removed package, absent CVE, missing package list, unsupported range/multiple fixes, changed type/path/platform or stale/untrusted scan is insufficient. No invented cross-manager version ordering. This bounded equality rule may conservatively require review for newer versions; preserve that limitation.
- Trusted scan means executed_local_trivy, independently pinned executable hash and scanner version, complete metadata/report digest binding, DB content/metadata identity/time and scan freshness. Imported/fixture reports remain useful correlation inputs, never trusted remediation proof. No signing/policy authorization is added.
- A fresh positive old reference after an earlier verified assessment in the same cluster and an equal/expanded namespace scope yields regressed and links `regression_of`. Different cluster, unrelated finding or disjoint/narrowed scope cannot inherit remediation. Verification remains scoped, never a statement that the original image/CVE became unaffected.
- Stable reasons include RUNNING_REFERENCE_PRESENT, DESIRED_REFERENCE_PRESENT, HISTORICAL_OBSERVATION_PRESENT, NO_OBSERVATION, INVENTORY_INCOMPLETE, INVENTORY_STALE, COVERAGE_GAP, IDENTITY_UNRESOLVED, TRUSTED_SCAN_REQUIRED, SCAN_STALE, DB_STALE, REPLACEMENT_NOT_OBSERVED, REPLACEMENT_LINEAGE_UNKNOWN, PACKAGE_FIX_UNCONFIRMED, REMAINING_REFERENCES, VERIFIED_SCOPED_REPLACEMENT, REGRESSION_OBSERVED. Additional precise reasons may be documented, not output-dependent or prose-only.

## Persistence / CLI

Migration4 appends lifecycle_assessments(assessment_id PK,payload TEXT) with append-only guards; earlier migrations stay unchanged. `app.store.assessments.AssessmentStore(path)` wraps InventoryStore and exposes `assess(finding_id,cluster_id,namespaces,replacement_digest=None,assessment_at=None,inventory_max_age_seconds=30,scan_max_age_seconds=86400,db_max_age_seconds=86400)->dict`, `list_assessments(image_digest=None)->list`, `get_assessment(id)->dict|None`. Store immutable facts and result/hash, replay pure evaluation for integrity on reads. Defaults choose clock after coherent fact load; explicit historical --at cannot imply reconstruction from current projections. Only strictly earlier assessments are regression candidates. No signed approval or trust promotion by CLI flags.

CLI: `findings assess ID --cluster ID --namespace NS` (repeatable namespace) optionally `--replacement DIGEST --at UTC`; `remediation verify ID` with same scope/options and required replacement; `lifecycle image DIGEST` lists persisted assessments; `assessments show ID`. Existing finding list/explain unchanged. JSON deterministic for identical explicit time/facts, P1 exit codes retained. An honest open/unknown/regressed result is evaluation success, not an enforcement allow; P5 owns security gate semantics.

## Real fixture / qualification

Use existing local Kind/registry and new labeled P3 namespaces. Original is the exact P0 pinned Alpine manifest. Replacement is built solely from that base plus verified, signed official Alpine libcrypto3/libssl3 3.5.9-r1 APKs, offline install with signature checks and fixed build timestamp. Pin recipe/asset hashes and resulting manifest/config before broadening the execution allowlist to this exact second fixture. Trivy gets --list-all-pkgs; no arbitrary-image scanning or signing expansion. Build helper owns no shared pins; parent validates actual output and records it. Keep APK bytes/build context/raw scans out of Git. No bit-for-bit build claim without a clean reproduction test.

Selected source assets: https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/libcrypto3-3.5.9-r1.apk SHA25658ea027d8bd64fffac7d2106a9034341d6735387298a5e01b551429c73a13c71; libssl3-3.5.9-r1.apk SHA2564aff30f84e7ac922b026f8b2dd574d91bb3bb01d22767a8a9a0a10c5ef64a44b. Discovery downloaded/hashed these before implementation, not an engine oracle. Real Trivy original reports libcrypto3 3.5.9-r0 with fixes3.5.9-r1; qualification must establish that independently on its recorded DB.

## Frozen acceptance matrix

| Case | Expected result |
| --- | --- |
| Fresh known original runtime + desired | running/open, validity unchanged, exact observation/scan links |
| Zero replicas still desired original | configured_not_running/open, no fix/false-positive |
| Deleted original without replacement | historical_observed/open retirement candidate only |
| No observation, partial/missing namespace/kind, stale/future receipt, active/intersecting gap | unknown exposure/remediation, no verification |
| Unresolved runtime, mutable tags, desired/runtime disagreement, unknown index | retain unknown/remaining refs, no stale tag inheritance/closure |
| Patch in namespaceA but original desired/runtime inB | not verified, remaining refs/links exact |
| Fresh complete scope, captured original and owner-linked running patch, package/scan proof | verified_in_scope with matching scope/window/fixed-scan/replacement IDs and zero refs |
| Absent CVE only, package removed/list missing, wrong fixed version/type/path/platform/lineage, imported/stale scan | not verified; retain limitation/reason |
| Old digest reintroduced in namespaceB after verification inA+B | regressed with original assessment ID, validity unchanged |
| Other cluster/finding or incomparable scope | no borrowed verification/regression |
| Identical facts/reimport/restart, corrupt/failing assessment insert | deterministic/idempotent; rollback or explicit integrity error |
| Actual rollout retains old zero-replica ReplicaSet | open until that remaining reference is retired; disappearance is not enough |
| Actual patch/retirement/another-namespace regression | recorded Kind + real Trivy proof, independently labeled expected outcomes, zero false closures in those cases only |

Run runnable behavioral red before engine implementation, then state-matrix/schema/CLI/store tests and real serialized scenarios. Report imported/fixture, locally verified, integration-qualified, accepted and merged separately. No P3 completion before all applicable gates pass.

## Source-grounded fixture refinements

Docker's local exporter initially rejected rewrite-timestamp with automatic unpack; the helper now exports a tar and explicitly loads it. Two no-cache builds initially differed only in var/log/apk.log contents; removing that timestamped install log (not package DB/binaries) produced identical manifest/config bytes across two no-cache builds. Resulting selected manifest is pinned in toolchain.lock.json before execution allowlist extension. This verifies the local recipe outcome with available base/build cache; no unrelated platform/cold-daemon claim follows.

Docker's ARM64 config omits default variant even when building arm64/v8. [containerd's normalization](https://raw.githubusercontent.com/containerd/platforms/main/database.go) explicitly treats arm64 v8 as the empty default variant. A focused red/green test refines same-platform comparison to exactly linux/arm64 versus linux/arm64/v8; raw identities/strings remain intact, and v9/cross-architecture still reject. This is source-backed alias equivalence, not permission to ignore unknown platform fields. [Trivy reporting](https://trivy.dev/docs/latest/configuration/reporting/) and the actual pinned report confirm Packages inventory; execution now records --list-all-pkgs. [Docker reproducible builds](https://docs.docker.com/build/ci/github-actions/reproducible-builds/) grounds the fixed SOURCE_DATE_EPOCH/export handling.

Expanded-scope regression clarification: the previous absence proof covers only its namespaces. An older or undated workload first observed in a newly added namespace is a remaining reference, not proof of historical reintroduction. A reference inside the prior verified scope can regress on later fresh presence; a reference only in added scope needs captured resource creation after the prior assessment (and no later than its observation). Otherwise leave it open/unknown and retain evidence. This protects the original no-invented-history rule rather than treating later ingestion as a source transition time.
