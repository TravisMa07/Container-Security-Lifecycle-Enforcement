# P3 scoped lifecycle evaluation

P3 is a deterministic evidence evaluator, not an admission/security approval service. Validity, exposure and remediation stay separate. Replacing a deployment never makes the original vulnerable image not_affected. A verified result covers only its finding, declared cluster/namespaces and recorded window; other CVEs/images/scopes remain separate.

## Reproduce the local acceptance

Prerequisites are the existing supported P0/P2 Kind/registry profile, `make bootstrap`, and explicit project admin kubeconfig `.local/p0/source-clone/.local/p0/kubeconfig`, context kind-csle-p0-cis. No real AWS is used.

```sh
make test
make check
.tools/venv/bin/python scripts/p3_fixtures.py --no-cache > .local/p3/rebuild.json
.tools/venv/bin/python tests/integration/p3_real.py > .local/p3/latest-result.json
```

The recipe builds from the exact pinned Alpine base and two SHA-verified official APKs, installs with APK signature validation and no build network, removes only the timestamped install log and fixes exporter timestamps. Explicit tar export/load avoids Docker's rewrite/unpack conflict. The helper rejects an output different from the recorded manifest pin. Two no-cache builds matched on the supported host; Docker/base cache was available, so cold-daemon or other-platform equivalence is not asserted.

Execution allowlist contains only the original and this vetted patched manifest. Trivy records all packages as well as findings. The patched demo still has an unrelated zlib vulnerability; selected OpenSSL package remediation is not a clean-image or deployment approval claim.

The Kind script creates two new labeled namespaces with namespaced read-only observer tokens. It adds a specific HTTP registry host entry to the project node only if absent or already identical; a conflicting existing entry stops setup. This is explicit local-lab transport, not production TLS. The script never selects another kube context or modifies global admission policy. It retains all new resources/evidence; revisionHistoryLimit0 retires only the newly created demo Deployment's old ReplicaSet as part of its test.

Four independent scenario expectations: original running/open; patched runtime while old scale-zero ReplicaSet still configured/open; after retiring that old reference, fixed-package replacement verified in scope; old digest in the other namespace regressed, linked to the exact prior verification. No disappearance-only verification or extrapolated precision/MTTR metric is claimed. The result records selected CVE/package, IDs, scope and false closures among these four stages only.

## CLI and decisions

Use the database/finding/namespaces from your result (replace RUN, FINDING, NS_A, NS_B and DIGEST):

```sh
.tools/venv/bin/csle --db .local/p3/qualification/RUN/evidence.sqlite3 findings assess FINDING --cluster kind-csle-p0-cis --namespace NS_A --namespace NS_B
.tools/venv/bin/csle --db .local/p3/qualification/RUN/evidence.sqlite3 remediation verify FINDING --cluster kind-csle-p0-cis --namespace NS_A --namespace NS_B --replacement DIGEST
.tools/venv/bin/csle --db .local/p3/qualification/RUN/evidence.sqlite3 lifecycle image DIGEST
.tools/venv/bin/csle --db .local/p3/qualification/RUN/evidence.sqlite3 assessments show ASSESSMENT_ID
```

`--at` freezes an explicit canonical UTC assessment time; future times reject. Historical --at does not reconstruct old mutable projections: future/stale evidence prevents verification. Identical explicit time/facts is idempotent; current default time is selected after coherent SQLite input loading. `--inventory-max-age-seconds` defaults30 and scan/DB age defaults86400; all are recorded in frozen facts. Namespace scope is explicit/repeatable, never inferred to mean the whole cluster.

Success0 means evaluation/query completed, including honest unknown/open/regressed. Invalid arguments/evidence are2; storage/execution errors1. P3 does not emit an enforcement allow. Existing P1 finding list/explain continue to show scanner records. Assessments show reason codes, exact evidence IDs, observed links, scope/window, facts hash and engine version; reads re-evaluate immutable stored facts to detect mismatch. Raw facts are retained in SQLite, never promoted to signing inputs.

For verified_in_scope, require fresh complete seven-kind inventory for every namespace, no relevant gap/unknown reference, no old desired/runtime reference, a current running patched container with captured owner-UID lineage, and trusted executed original/replacement scans. Package inventory must prove the same manager/name/path/OS/platform at exactly the original single FixedVersion, and no same CVE/alias. Absence of a CVE, removed package, imported report, version range, newer-but-unequal version, unknown ID or reused workload name cannot earn verification. The only platform alias recognized is linux/arm64 versus default-v8 linux/arm64/v8, preserving raw strings.

Keep watchers active while verifying. Stopping a collector intentionally opens a gap, so freshness-dependent exposure/verification becomes unknown (a positively observed regression is not erased), even though an earlier recorded verified assessment remains historical evidence. Earlier closed gaps do not poison all future windows; they remain retained. Observations are bounded per-kind snapshots/watch history, not a globally atomic/predictive inventory. Regression requires the same finding/cluster and an equal or expanded namespace scope plus a later positive old reference; unrelated cluster/scope cannot borrow remediation. In added namespaces, an older/undated workload is not called a historical reintroduction merely because it is observed later; resource creation after the earlier proof is required for that added-scope inference.

## Persistence and limits

Migration4 adds append-only assessment envelopes; prior migrations remain unchanged. Each envelope freezes coherent scans, observations, receipts, gaps/checkpoints, independently configured scanner trust and previous candidate states. Hash/version/replay protects against accidental inconsistency, not a DB owner rewriting everything. Later engine semantics need a new version and compatible historical replay support; an unavailable recorded version refuses rather than silently reinterpreting evidence.

Only exact fixed-version equality is implemented; no general APK/RPM/Debian/semantic-version solver or runtime reachability claim. Generic registry/tag resolution, arbitrary image scanning, signing/policy and compliance export remain their owning P4–P6 work. High-volume assessment history/performance and cold full-demo reset remain P7 gates. APKs, raw scans, tokens, build archives, databases and logs stay outside Git.
