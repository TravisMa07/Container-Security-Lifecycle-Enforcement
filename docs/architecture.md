# Architecture

Status: accepted initial direction under the authoritative handoff and delegated engineering decisions; P0–P2 are merged with recorded qualification and P3 is qualified on its PR branch.

One Python application/CLI and one watcher worker share SQLite. Collectors normalize Kubernetes observations, Trivy reports and OCI/Floci inventory; append-only observations and raw report hashes support deterministic correlation, lifecycle decisions, policy evaluation and bounded compliance export.

The signer is a separate authorized invocation with separate key access, not a collector capability. Kyverno is the admission barrier; signature verification alone does not establish current policy approval. No admission policy retroactively evicts running workloads.

## Boundaries and invariants

- Artifact identity is immutable digest, preserving index/platform relationships and resolution uncertainty. Tags are timestamped aliases.
- Current snapshots, historical observations and coverage gaps remain separate. Resource versions are opaque checkpoints, not completeness proofs.
- Finding validity, deployment exposure and remediation status are orthogonal. Verification is bounded by inventory scope, freshness, scan evidence and remaining references.
- External inputs are untrusted. Validate schema/size and preserve provenance before persistence or evaluation.
- Registry, scan, predicate and runtime identity must refer to the same resolved artifact; unknown joins must remain unknown.
- Floci provenance is `emulated_aws_ecr`; Trivy is the local vulnerability authority. Emulator results do not establish AWS IAM or Inspector correctness.
- Technical control checks do not establish organizational compliance or CDE applicability.

## Decision register

| Decision | Status | Record |
| --- | --- | --- |
| Small monolith and independent trust boundaries | Accepted | [ADR 0001](decisions/0001-foundation.md) |
| Python runtime baseline | 3.12.16 locally qualified for P0–P3 | [ADR 0001](decisions/0001-foundation.md) |
| Exact local tool/image/build set and admission API | Locally qualified on ARM64 with source-aligned Kubernetes1.35.10 | [P0 ledger](p0-ledger.md) |
| License | Apache-2.0, owner-selected during P0 | [License](../LICENSE) |

Do not add a web service, broker, Postgres, operator framework or full Inspector adapter without a demonstrated requirement and a new decision record.

P0 selects project-local verified tools, isolated local Docker resources, explicit emulator endpoints and a dedicated kubeconfig. [Compatibility results](p0-ledger.md) retain the initial cached older-payload failure and the corrected v2 profile: recognized signed timestamp, current assessment-ID binding, and verification cache disabled. Successive admissions were exercised without deleting old evidence. The P0 contract/negative/fresh-clone gates now pass. This remains a local single-artifact feasibility profile; P5 owns the product policy/issuance contract, and exact official framework source review is now completed for P0. P6 implementation/conformance claims remain separate.

## P1 evidence path

[Design](p1-design.md): strict Pydantic image/finding/scan records, immutable SQLite raw documents and per-scan finding snapshots, hash-checked transactional migrations and a small JSON CLI. Imported assertions and executed local scans remain separate evidence contexts. The bounded loopback OCI resolver verifies index/manifest/config relationships; the Trivy runner records binary and DB identity without issuing a policy verdict. Other canonical models acquire domain behavior in their owning phases.

P1 local verification:96 offline tests and an actual pinned Trivy/OCI/persistence acceptance run passed at the exact revision in [qualification](results/p1-qualification.json). Imported and executed provenance remains separate. P1 PR#10 is merged and its merge revision was verified; later qualification is recorded separately.

## P2 observation path

[P2 design](p2-design.md) adds one fixed seven-thread namespaced read-only REST collector. Explicit local CA/token/server credentials replace implicit kube contexts. Immutable resource observations and complete-snapshot membership receipts support mutable current membership/checkpoints and append-only gaps. Scope identity binds API server/CA across all namespaces for one cluster ID. Reconciliation absence is not a deletion event or remediation result. SQLite migrations2/3 append to P1 without rewriting its evidence. [P2 runbook](p2-runbook.md) owns operator semantics; P3 owns derived lifecycle decisions.

## P3 lifecycle decisions

[Design](p3-design.md): pure deterministic state evaluation over one coherent frozen SQLite fact set. Append-only versioned assessments preserve scans, scope, observations/snapshot receipts, coverage, trust configuration and exact prior decisions. Validity remains distinct from deployment exposure/remediation. Verification needs a remaining-reference-free fresh scope, actual owner-linked patched runtime and exact fixed-package inventory from trusted executed scans; index/tag/unknown/freshness uncertainty blocks closure. Regression links the earlier scoped verification. No approval/signing service or new infrastructure is added.
