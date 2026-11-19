# Phased implementation and acceptance plan

All phases collectively define MVP. No phase is complete merely because code or documentation exists. Repository creation and P0 qualification are complete; PR#9 is merged at `eb54a6d`. Each further implementation item uses a linked PR.

| Work | Scope and dependency | Required observable acceptance | Status |
| --- | --- | --- | --- |
| Foundation | Preserve handoff; instructions, ADR, threat model, host discovery, repo hygiene | Full handoff preserved; docs links valid; no committed credentials; public remote and pushed SHA verified; phase issues and item-PR workflow prepared | Repository-ready; [evidence](implementation-ledger.md) |
| [P0](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/1) | Resolve exact compatible tools, image digests, architecture, risk and control-source reviews | Real Kind + Kyverno + Floci/OCI + Trivy + Cosign smoke results; failures/workarounds recorded; license and source decisions explicit | Merged; original source gate satisfied; [final evidence](results/p0-final-qualification.json) |
| [P1](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/2) | Typed v1 contracts, SQLite migrations, CLI, digest-bound Trivy ingestion; depends on contract freeze and P0 scan path | Real pinned image scan; reimport idempotency; malformed/oversized input rejection; stable JSON/exit codes; raw report hash and scanner/DB provenance | Merged; [evidence](results/p1-qualification.json), [ledger](p1-ledger.md), [merged PR#10](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/pull/10) |
| [P2](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/3) | Watch/list/reconcile all specified kinds; depends on P1 | S1/S2/S5/S11: deleted Job history, scale-zero reference, reconnect/410/restart, gaps and duplicates; UID reuse and owners | Locally qualified; [evidence](results/p2-qualification.json), [ledger](p2-ledger.md), [draft PR#11](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/pull/11) |
| [P3](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/4) | Pure correlation/remediation; depends on P1/P2 | S3/S4/S12/S13: multi-namespace remaining refs, patched replacement, regression, mutable tags, unresolved runtime IDs, partial inventory and stale evidence | Planned |
| [P4](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/5) | Mandatory Floci ECR adapter; early feasibility in P0, full slice after P1/P2 | S9: create/list/describe repo and images; push/clean pull; actual Trivy scan; same manifest/platform digest in registry/scan/Kind; explicit emulator provenance | Planned, mandatory |
| [P5](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/6) | Mandatory signed policy attestations and admission; early feasibility in P0, full slice after P1/P4 | S6/S7/S8/S14: real allow plus unsigned/wrong-digest/modified/unauthorized/expired/stale-policy/revoked denial; privilege denial; unavailable scanner/old DB fails closed | Planned, mandatory |
| [P6](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/7) | Mandatory versioned technical mappings/export; source review in P0, depends on evidence contracts | S10: 4–6 applicable CIS checks, ≥4 NIST mappings, 2–3 verified PCI 4.0.1 mappings; reproducible hashes, scope, manual/unknown/stale results and JSON + readable export | Planned, mandatory |
| [P7](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/8) | Demo, recovery, evaluation and polish; depends on all prior gates | S1–S14 with negative controls, reproducible fresh-clone run, baseline comparison/raw timings, resource measurements, CI, safe cleanup and supported-host qualification | Planned |

## Current bounded work: P2 review / next P3

P1 PR#10 merged with owner authorization at2bffd97;96 tests and real P1 acceptance passed on that merge commit. P2 implements and locally qualifies the [frozen design](p2-design.md) in draft PR#11: read-only namespaced list/watch, append-only events/snapshot membership, atomic current/checkpoints and explicit coverage gaps. P3 correlation/remediation decisions are the next item after the chosen accepted P2 integration. P2 remains unmerged.

## Test matrix

- Unit/contract: validation, deterministic serialization/hash and reason codes, policy freshness/exception boundaries, migrations, replay idempotency, lifecycle state matrix and source-reviewed mapping metadata. No Docker or network.
- Fixture integration: raw Trivy parser schema drift, DB transaction/restart behavior, scanner provenance, mapping export escaping and evidence references. Mark synthetic data explicitly.
- Real local integration: Kind watch/410/reconciliation, Floci OCI and ECR APIs, independent Cosign verification, admission allow/deny and failure recovery.
- Evaluation: each S1–S14 scenario has setup, exact digests, independently expected truth, negative control, timing and artifacts. Compare periodic-only against watch/history on the same scenario inputs; report denominators, unknown coverage and false closures. No invented metrics.

Full scenarios, fields and definition of done remain in HANDOFF.md; this plan does not reduce them. Terraform is optional and must not delay ECR correctness. No real AWS account, production remediation, distributed services or large UI.

## GitHub delivery map

| Phase | Tracking issue | Suggested branch | PR state |
| --- | --- | --- | --- |
| P0 | [#1](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/1) | `phase/p0-compatibility` | [Merged #9](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/pull/9); evidence and gaps in P0 ledger |
| P1 | [#2](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/2) | `phase/p1-ingestion` | [Merged #10](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/pull/10) |
| P2 | [#3](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/3) | `phase/p2-inventory` | [Draft #11](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/pull/11) |
| P3 | [#4](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/4) | `phase/p3-lifecycle` | Not created; open per implementation item when work starts |
| P4 | [#5](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/5) | `phase/p4-floci-ecr` | Not created; open per implementation item when work starts |
| P5 | [#6](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/6) | `phase/p5-attestation-policy` | Not created; open per implementation item when work starts |
| P6 | [#7](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/7) | `phase/p6-compliance-evidence` | Not created; open per implementation item when work starts |
| P7 | [#8](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/8) | `phase/p7-evaluation` | Not created; open per implementation item when work starts |

P0 is closed and merged. P1 is merged and verified at2bffd97. P2 is in draft PR#11; P2–P7 issues remain open. Their checklists and dependency links are planning records, not evidence that those phases passed. For a phase with several items, use more specific branch suffixes and separate linked PRs; do not combine unrelated phase work into one PR. No future-phase PRs were created during the repository wrap-up. P0 PR#9 is merged. P1 PR#10 is merged. P2 has draft PR#11.

## P0 reproduction checklist (qualification completed)

1. Read HANDOFF.md, the workflow, dependencies and threat model; use issue #1 as the phase tracker.
2. Start a fresh `phase/p0-compatibility` branch from the final repository-readiness commit on `main`.
3. Write the bounded P0 design, independent smoke expectations and ledger; commit the expectation freeze before executable integration changes.
4. Open a linked draft PR for that implementation item when its real commit exists. Run only project-scoped, explicitly identified local resources; serialize heavy qualification.
5. Resolve/pin and prove the chosen toolchain; update the compatibility ledger and issue with actual evidence. Keep P0 open for any unmet gate.

Apache-2.0 was selected by the owner during P0. The owner retained the original source gate and supplied the publications; exact-source review and source-aligned runtime qualification passed. [P0 results](p0-ledger.md) retain all earlier failures and final evidence. P1 now proceeds from the observed merged P0 base; P1 merge was owner-authorized; P2 merge remains owner-controlled.
