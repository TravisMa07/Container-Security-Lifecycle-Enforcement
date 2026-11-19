# Initial threat model and risk register

Assets: immutable image identities, scanner/DB provenance, workload observations and checkpoints, SQLite evidence, policy versions, signer keys/trust roots, admission decisions and exported evidence. Adversaries include an untrusted image publisher, forged scanner-report producer, compromised workload, malicious PR and an operator making context/endpoint mistakes.

| Boundary / risk | Required control | Qualification still required |
| --- | --- | --- |
| Forged reports or attacker-signed allow claims | Independent trusted scan before signing; schema/size validation; separately configured signer identity | Input negatives, wrong signer and tampered predicate |
| Tag mutation, platform/index confusion, wrong subject | Resolve immutable identity, preserve index/platform relationship; reject uncertain joins | S13 and cross-tool same-digest proof |
| Replay after expiry/new policy/DB intelligence | Verify issue/expiry/freshness and active policy version; reassessment invalidates future admission | Real stale/expired/revoked denial, cache behavior |
| Watch outage, expired checkpoint, API loss | Relist/reconnect/reconcile, append-only history and explicit gaps | S5/410/restart and wholly unobserved Job remains unknown |
| False remediation closure | Scope/time-bounded verification plus all remaining refs and fixed-scan evidence | Multi-namespace and regression negatives |
| Evidence corruption or missing DB | Transactional migrations, raw hashes, validated references, explicit failure | Migration/recovery and corruption tests |
| Admission/registry/scanner unavailable | Protected namespace fail closed; documented lab rescue; no earned allow from missing scan | Outage tests and recovery |
| Privilege/context confusion | Read-only watcher RBAC; separate signer and test-apply roles; explicit project context | RBAC negatives and constrained teardown |
| Credentials/host network exposure | Ephemeral demo credentials/keys, ignored local state, loopback bindings, no public signing API | Listener and Git hygiene checks |
| Supply-chain compromise | Pin dependencies/images and verify downloads; minimal CI permissions; no PR signing secrets | Lock/hash verification and own-image scan |
| Misleading compliance | Official reviewed catalogs, bounded technical statuses, unknown/manual scope | Source-reviewed mappings and missing/stale-evidence tests |

Residual risks: cluster administrators can bypass controls; admission does not evict existing workloads; unobserved ephemeral workloads cannot be reconstructed; packages may not be applicable/reachable; scans age; local emulator tests do not validate AWS security; technical mappings do not determine organization-wide compliance.

Resources may be created only for this project. No existing cluster deletion, global Docker prune, credential discovery, real-account access or privilege escalation is part of bootstrap.
