# Phased implementation and acceptance plan

All phases collectively define MVP. No phase is complete merely because code or documentation exists. Current priority is the owner's first delivery: standalone repository creation and initial GitHub push.

| Work | Scope and dependency | Required observable acceptance | Status |
| --- | --- | --- | --- |
| Foundation | Preserve handoff; instructions, ADR, threat model, host discovery, repo hygiene | Full handoff preserved; docs links valid; no secrets; private remote and pushed SHA verified | In progress |
| P0 | Resolve exact compatible tools, image digests, architecture, risk and control-source reviews | Real Kind + Kyverno + Floci/OCI + Trivy + Cosign smoke results; failures/workarounds recorded; license and source decisions explicit | Discovery started; runtime gate open |
| P1 | Typed v1 contracts, SQLite migrations, CLI, digest-bound Trivy ingestion; depends on contract freeze and P0 scan path | Real pinned image scan; reimport idempotency; malformed/oversized input rejection; stable JSON/exit codes; raw report hash and scanner/DB provenance | Planned |
| P2 | Watch/list/reconcile all specified kinds; depends on P1 | S1/S2/S5/S11: deleted Job history, scale-zero reference, reconnect/410/restart, gaps and duplicates; UID reuse and owners | Planned |
| P3 | Pure correlation/remediation; depends on P1/P2 | S3/S4/S12/S13: multi-namespace remaining refs, patched replacement, regression, mutable tags, unresolved runtime IDs, partial inventory and stale evidence | Planned |
| P4 | Mandatory Floci ECR adapter; early feasibility in P0, full slice after P1/P2 | S9: create/list/describe repo and images; push/clean pull; actual Trivy scan; same manifest/platform digest in registry/scan/Kind; explicit emulator provenance | Planned, mandatory |
| P5 | Mandatory signed policy attestations and admission; early feasibility in P0, full slice after P1/P4 | S6/S7/S8/S14: real allow plus unsigned/wrong-digest/modified/unauthorized/expired/stale-policy/revoked denial; privilege denial; unavailable scanner/old DB fails closed | Planned, mandatory |
| P6 | Mandatory versioned technical mappings/export; source review in P0, depends on evidence contracts | S10: 4–6 applicable CIS checks, ≥4 NIST mappings, 2–3 verified PCI 4.0.1 mappings; reproducible hashes, scope, manual/unknown/stale results and JSON + readable export | Planned, mandatory |
| P7 | Demo, recovery, evaluation and polish; depends on all prior gates | S1–S14 with negative controls, reproducible fresh-clone run, baseline comparison/raw timings, resource measurements, CI, safe cleanup and supported-host qualification | Planned |

## Next bounded work: P0 compatibility spike

Freeze exact smoke expectations before tooling experiments: discover ARM64 assets/checksums, resolve Kind node and registry/Floci digests, create an isolated `csle` context without changing other workloads, prove OCI push/pull and ECR metadata identity, scan actual bytes, then prove custom-predicate Cosign/Kyverno verification and expiration/policy rejection. Record each independent failure rather than treating documentation support as compatibility. Do not expose emulator endpoints publicly. Download local binaries only with integrity/provenance checks; never silently use sudo.

## Test matrix

- Unit/contract: validation, deterministic serialization/hash and reason codes, policy freshness/exception boundaries, migrations, replay idempotency, lifecycle state matrix and source-reviewed mapping metadata. No Docker or network.
- Fixture integration: raw Trivy parser schema drift, DB transaction/restart behavior, scanner provenance, mapping export escaping and evidence references. Mark synthetic data explicitly.
- Real local integration: Kind watch/410/reconciliation, Floci OCI and ECR APIs, independent Cosign verification, admission allow/deny and failure recovery.
- Evaluation: each S1–S14 scenario has setup, exact digests, independently expected truth, negative control, timing and artifacts. Compare periodic-only against watch/history on the same scenario inputs; report denominators, unknown coverage and false closures. No invented metrics.

Full scenarios, fields and definition of done remain in HANDOFF.md; this plan does not reduce them. Terraform is optional and must not delay ECR correctness. No real AWS account, production remediation, distributed services or large UI.
