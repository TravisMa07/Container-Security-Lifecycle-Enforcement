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

## Final P1 local qualification

Executed source `c834c6bc4bb8de000a8ee9a2cbbb7863aa54b8b3`, clean working tree. `make test`:96 passed (79 unit +17 contract). `make check`, compileall and whitespace checks pass. A newly created Python3.12.16 virtual environment installed20 hash-locked development packages and the editable CLI without isolated build downloads; all96 tests pass there too. This is fresh Python installation, not cold Docker/scanner-DB provisioning.

`.tools/venv/bin/python tests/integration/p1_real.py` passed from that clean revision. The retained P0 loopback OCI registry supplied verified selected manifest `sha256:1829893486be257df5049ab3b7fc95afbd0fc09d89803cbc580bda1ba5386b29`, config `sha256:abbc135a7d3909a5eb6a56aac4c769cf15be025e3c9e226b8660f2b2b378158b`, platform linux/arm64/v8. Trivy0.76.2 executable, DB bytes/metadata and report hashes were recorded;11 normalized findings match the actual raw report row count. This is an observed count with the recorded DB, not a vulnerability baseline promise. Imported copies remain separate from executed provenance, repeated import inserts once, and process-restart/query JSON is deterministic. No allow or remediation verdict exists.

[Machine-readable record](results/p1-qualification.json) owns exact run/scan IDs, executable and DB hashes, commands, logs/hashes and limitations. Raw reports, database, scanner DB, logs and ephemeral runtime directories remain ignored, not committed. Multi-platform selection has offline tests; actual qualification is only the fixed ARM64/v8 fixture. No Kind, registry or AWS resource was created/deleted/modified by P1 qualification.

Final read-only review confirmed the original fixes/regressions, found the UTC boundary issue and inspected its correction; no blocking findings remain. Parent owns actual runtime/CI claims. Implementation, local verification and fixed-fixture integration qualification are satisfied. Owner semantic acceptance, merge and merged-revision verification remain separate. Current-head CI is reported in PR#10 after push; the qualification record does not assert an unobserved CI result. No signing, lifecycle or compliance product feature is marked complete.

### Acceptance map

| Gate | Evidence |
| --- | --- |
| Typed contracts and immutable digest semantics | Parser/model suite, P0 schema cross-checks and explicit unknown limitations |
| Idempotent append-only storage and migrations | Store restart/migration/fault/tamper suite, real repeated import |
| Malformed/oversized/scanner input | Decoder size/depth/row boundaries, malformed falsy values, date/offset/descriptor regressions |
| Deterministic CLI/JSON and exit codes | Subprocess suite and actual repeated query/restart comparisons |
| Actual pinned image scan and resolution | Clean c834c6b real acceptance, verified manifest/config, scanner/DB/report identities and normalized rows |
| Provenance and unknowns | Imported/executed separation, nullable scanner/DB context, no earned safety verdict |

P1 is qualified on its implementation branch for review; issue#2 remains linked for closure on integration. P2–P7 are not implemented by this PR.
