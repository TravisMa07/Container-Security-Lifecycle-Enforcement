# P1 qualification ledger

Base: `eb54a6d557c697a70ee2262d948d9016686d2375`, merged P0. Branch `phase/p1-ingestion`; refs issue #2. Owner requested implementation and a linked PR, not merge. P0 merge observed through GitHub at 2026-11-19T22:21:18Z; merged-revision P0 runtime requalification has not been claimed.

## Ownership and expectation freeze

Parent owns design, shared interfaces, dependencies, runner/CLI, CI and status. `p1_expectations` read-only requirement review at the base; parser/model and store implementation have nonoverlapping ownership after this freeze. No concurrent cluster tests. Expectations in p1-design.md derive from HANDOFF and P0 contracts, not generated output.

Status: design frozen before production implementation; implementation/verification/qualification pending. Record red/green commands, actual revisions and limitations below.

## Implementation and preliminary verification

Expectation freeze `56812e9`. Parser/model owner `p1_parser`, store owner `p1_store`; parent runner/OCI/CLI/pins/CI. Independent expectation review identified empty scans versus safety and provenance/idempotency separation; both are explicitly bounded in the frozen design. No added infrastructure.

Runnable permissive skeletons demonstrated intended failures before their implementations: parser7 failures, store4 failures, OCI3 identity/platform failures (plus2 missing positive fields). Raw logs `.local/p1/parser-red.log`, `store-red.log`, `oci-red.log` are retained. CLI subprocess assertions passed on their first implementation run; no CLI behavioral-red claim is made. New DB snapshots and reports are append-only; imported and executed contexts hash to separate scan IDs.

The first actual scan failed closed on strict platform equality: requested linux/arm64 versus Trivy config linux/arm64/v8. Manifest and config IDs were consistent. Updated the adapter to preserve the verified config variant while allowing a generic architecture request; explicit variant conflicts still reject. Diagnostic actual report retained at `.local/p1/diagnostic-report.json`. A focused resolver regression now checks that generic arm64 preserves v8. A second actual scan persisted11 findings. These were working-tree experiments; final committed-revision qualification remains pending.

Pre-review integrated `make test` passes90 tests (73 unit +17 contract), including all44 P0 tests. `make check`, compileall and git diff --check pass. Actual revisions/log hashes are recorded in the final qualification record after review.20 hash-locked development packages returned no matching OSV advisory in the recorded query; this is a point-in-time match result, not a vulnerability-free claim. Local resolver/scanner support remains bounded to the P0 ARM64 fixture and explicit loopback HTTP; public/authenticated registry adapters belong to P4. Pydantic2.14.4/pydantic-core2.50.5 and setuptools84.2.1 were resolved from current PyPI; existing P0 dependency versions are constrained unchanged in requirements-dev.lock. Pydantic and annotated-types use MIT terms; Python typing packages retain their own terms; setuptools uses MIT.
