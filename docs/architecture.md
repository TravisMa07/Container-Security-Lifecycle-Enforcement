# Architecture

Status: accepted initial direction under the authoritative handoff and delegated engineering decisions; runtime design remains subject to P0 experiments.

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
| Python runtime baseline | Selected for initial development, not qualified | [ADR 0001](decisions/0001-foundation.md) |
| Exact external tool/image set and admission API | Pending compatibility experiments | [Dependencies](dependencies.md) |
| License | Owner decision pending, no release | [Limitations](limitations.md) |

Do not add a web service, broker, Postgres, operator framework or full Inspector adapter without a demonstrated requirement and a new decision record.
