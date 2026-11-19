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

## Independent review and corrections

Read-only `p1_review` reviewed actual af5dd4340b317f7eed9d78ca093dca80f2252a8b against merged P0 and freeze56812e9. It reproduced invalid RFC3339 offset normalization and uncaught OCI descriptor/config shape errors. New regressions recorded2 intended timestamp failures plus malformed-descriptor KeyError in `.local/p1/review-red.log`; all pass after explicit offset/descriptor/config validation. CLI malformed-registry tests now require JSON exit2 and no database creation.

Review also identified current-status documentation drift and the need to preserve P0's known malformed-compression advisory boundary. Reconciled dependencies/limitations; execution now requires the exact pinned demo selected manifest and rejects other resolved digests before invoking Trivy. Generic imports remain unverified. New test proves no scanner invocation for an unqualified artifact. This is a documented capability restriction, not a dependency-clearance claim.

Parent corruption review added a regression for valid JSON with missing/wrong normalized DB shape; intended KeyError/TypeError reproduced in `.local/p1/corruption-red.log`, fixed to structured integrity failure. The first attempt placed the test below unittest.main and was not discovered; corrected discovery before recording the behavioral-red run. One initial test path reused a corrupt DB between cases; corrected to unique paths. Green16 store tests pass. No change to append-only semantics or trust claims.

Final code suites pass95 tests (78 unit +17 contract), with make check, compileall and diff whitespace checks. The opt-in real acceptance script is now versioned; it checks executed/imported separation, raw hashes, identity, rows, reimport and restart determinism. Its first working-tree run passed at af5dd43 with only that script uncommitted; final clean committed-revision run is next. Scanner override isolation and cache serialization have focused tests. P1 completion remains pending that run and current-head CI; no merge is authorized.

Focused follow-up review at2dcc196 confirmed the prior corrections and95 passing tests, then found UTC conversion overflow at datetime year boundaries. Two focused out-of-range offset cases reproduced uncaught OverflowError; moved conversion inside the existing input-error handler. Parser green16 passes; logs `.local/p1/utc-boundary-red.log` and `utc-boundary-green.log`. Extra correction commits preserve published expectation and executed-source boundaries rather than rewriting evidence history. The clean real acceptance run at2dcc196 passed, with11 normalized findings and separate executed/imported scans; it will be rerun on the final corrected source commit.
