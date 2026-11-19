# Phased implementation and acceptance plan

All phases collectively define MVP. No phase is complete merely because code or documentation exists. Repository creation and initial GitHub push are complete. The owner requested public visibility, phase issues and PRs per future implementation item; this final readiness update prepares P0 without starting product implementation.

| Work | Scope and dependency | Required observable acceptance | Status |
| --- | --- | --- | --- |
| Foundation | Preserve handoff; instructions, ADR, threat model, host discovery, repo hygiene | Full handoff preserved; docs links valid; no committed credentials; public remote and pushed SHA verified; phase issues and item-PR workflow prepared | Repository-ready; [evidence](implementation-ledger.md); P0 gate open |
| [P0](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/1) | Resolve exact compatible tools, image digests, architecture, risk and control-source reviews | Real Kind + Kyverno + Floci/OCI + Trivy + Cosign smoke results; failures/workarounds recorded; license and source decisions explicit | Discovery started; runtime gate open |
| [P1](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/2) | Typed v1 contracts, SQLite migrations, CLI, digest-bound Trivy ingestion; depends on contract freeze and P0 scan path | Real pinned image scan; reimport idempotency; malformed/oversized input rejection; stable JSON/exit codes; raw report hash and scanner/DB provenance | Planned |
| [P2](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/3) | Watch/list/reconcile all specified kinds; depends on P1 | S1/S2/S5/S11: deleted Job history, scale-zero reference, reconnect/410/restart, gaps and duplicates; UID reuse and owners | Planned |
| [P3](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/4) | Pure correlation/remediation; depends on P1/P2 | S3/S4/S12/S13: multi-namespace remaining refs, patched replacement, regression, mutable tags, unresolved runtime IDs, partial inventory and stale evidence | Planned |
| [P4](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/5) | Mandatory Floci ECR adapter; early feasibility in P0, full slice after P1/P2 | S9: create/list/describe repo and images; push/clean pull; actual Trivy scan; same manifest/platform digest in registry/scan/Kind; explicit emulator provenance | Planned, mandatory |
| [P5](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/6) | Mandatory signed policy attestations and admission; early feasibility in P0, full slice after P1/P4 | S6/S7/S8/S14: real allow plus unsigned/wrong-digest/modified/unauthorized/expired/stale-policy/revoked denial; privilege denial; unavailable scanner/old DB fails closed | Planned, mandatory |
| [P6](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/7) | Mandatory versioned technical mappings/export; source review in P0, depends on evidence contracts | S10: 4–6 applicable CIS checks, ≥4 NIST mappings, 2–3 verified PCI 4.0.1 mappings; reproducible hashes, scope, manual/unknown/stale results and JSON + readable export | Planned, mandatory |
| [P7](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/8) | Demo, recovery, evaluation and polish; depends on all prior gates | S1–S14 with negative controls, reproducible fresh-clone run, baseline comparison/raw timings, resource measurements, CI, safe cleanup and supported-host qualification | Planned |

## Next bounded work: P0 compatibility spike

Freeze exact smoke expectations before tooling experiments: discover ARM64 assets/checksums, resolve Kind node and registry/Floci digests, create an isolated `csle` context without changing other workloads, prove OCI push/pull and ECR metadata identity, scan actual bytes, then prove custom-predicate Cosign/Kyverno verification and expiration/policy rejection. Record each independent failure rather than treating documentation support as compatibility. Do not expose emulator endpoints publicly. Download local binaries only with integrity/provenance checks; never silently use sudo.

## Test matrix

- Unit/contract: validation, deterministic serialization/hash and reason codes, policy freshness/exception boundaries, migrations, replay idempotency, lifecycle state matrix and source-reviewed mapping metadata. No Docker or network.
- Fixture integration: raw Trivy parser schema drift, DB transaction/restart behavior, scanner provenance, mapping export escaping and evidence references. Mark synthetic data explicitly.
- Real local integration: Kind watch/410/reconciliation, Floci OCI and ECR APIs, independent Cosign verification, admission allow/deny and failure recovery.
- Evaluation: each S1–S14 scenario has setup, exact digests, independently expected truth, negative control, timing and artifacts. Compare periodic-only against watch/history on the same scenario inputs; report denominators, unknown coverage and false closures. No invented metrics.

Full scenarios, fields and definition of done remain in HANDOFF.md; this plan does not reduce them. Terraform is optional and must not delay ECR correctness. No real AWS account, production remediation, distributed services or large UI.

## GitHub delivery map

| Phase | Tracking issue | Suggested branch | PR state |
| --- | --- | --- | --- |
| P0 | [#1](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/1) | `phase/p0-compatibility` | Not created; open per implementation item when work starts |
| P1 | [#2](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/2) | `phase/p1-ingestion` | Not created; open per implementation item when work starts |
| P2 | [#3](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/3) | `phase/p2-inventory` | Not created; open per implementation item when work starts |
| P3 | [#4](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/4) | `phase/p3-lifecycle` | Not created; open per implementation item when work starts |
| P4 | [#5](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/5) | `phase/p4-floci-ecr` | Not created; open per implementation item when work starts |
| P5 | [#6](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/6) | `phase/p5-attestation-policy` | Not created; open per implementation item when work starts |
| P6 | [#7](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/7) | `phase/p6-compliance-evidence` | Not created; open per implementation item when work starts |
| P7 | [#8](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/8) | `phase/p7-evaluation` | Not created; open per implementation item when work starts |

All phase issues remain open. Their acceptance checklists and dependency links are planning records, not evidence that a phase passed. For a phase with several items, use more specific branch suffixes and separate linked PRs; do not combine unrelated phase work into one PR. No PRs are created during this repository wrap-up, per the owner's clarification.

## P0 start checklist

1. Read HANDOFF.md, the workflow, dependencies and threat model; use issue #1 as the phase tracker.
2. Start a fresh `phase/p0-compatibility` branch from the final repository-readiness commit on `main`.
3. Write the bounded P0 design, independent smoke expectations and ledger; commit the expectation freeze before executable integration changes.
4. Open a linked draft PR for that implementation item when its real commit exists. Run only project-scoped, explicitly identified local resources; serialize heavy qualification.
5. Resolve/pin and prove the chosen toolchain; update the compatibility ledger and issue with actual evidence. Keep P0 open for any unmet gate.

License selection and authoritative framework-source review remain explicit P0 decisions. Missing local tools are work to resolve, not a reason to treat compatibility as passed. Future implementation has not started in this readiness update.
