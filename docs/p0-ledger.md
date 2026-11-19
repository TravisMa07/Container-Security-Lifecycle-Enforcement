# P0 qualification ledger

Base: `8c5e95e661781f2810030ca6b89d6c0f7afd4f08`. Owner: root. Scope/expectations: [P0 design](p0-design.md). Phase tracker: [#1](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/1).

Current status: P0 qualified on the implementation branch. The owner retained the original source gate and supplied the publications; exact-source review and the source-aligned1.35.10 qualification passed. See the final closure section and artifact record below. Owner acceptance, merge and merged-commit verification remain separate.

## Pre-implementation discovery — 2026-11-19

Branch `phase/p0-compatibility`; working tree initially clean. Docker Engine 29.8.0 reachable; no running containers; kubectl has no current context. macOS ARM64, about 741 GiB filesystem free. Kind/Helm/Trivy/Cosign/AWS CLI absent from PATH. No cloud credentials read, no cluster mutation, no privileged installation.

Freeze the independent T1–F2 cases before tooling implementation. Tool absence is an environment result, not a behavioral-red test. P0 status: in progress, no runtime gate passed. Framework research delegated read-only to `p0_sources`; parent owns all tracked files and cluster/tool mutations.

## Provisioning and behavioral red → green

Expectation freeze: `9d420b25ca845541d66c931da652ea7d209a89e3` (design T1–F2), before executable tooling code. Scope remained P0 compatibility, not application feature delivery.

- Initial executable-copy harness: 7 offline installer tests ran, 6 failed for the intended missing checksum/archive/platform behavior (`.local/p0/tooling-red.log`). No downloaded code was executed by that deliberately incomplete test harness. Verified installer implementation made all 7 pass.
- Initial no-op lab guard harness: 3 tests ran, 2 failed for missing authorization and occupied-port rejection (`.local/p0/lab-red.log`). Guard implementation made all 3 pass.
- Review expanded the suite to 22 offline tests: malformed/incomplete/digest-mismatched/stale/future/unknown-severity scan evidence; remote host/context rejection; timeout and executable-error evidence retention. Final local suite passed. These synthetic cases qualify harness logic only, not third-party integrations.
- `make bootstrap` and a repeat invocation succeeded on Darwin ARM64: Kind 0.33.0, Cosign 3.1.4, Trivy 0.76.2, Helm 3.22.1; exact download/executable hashes and chart pin are in toolchain.lock.json and ignored bootstrap logs. boto3 1.44.6 and transitive packages are hash-locked in requirements-p0.lock, isolated under `.tools/venv` on Python 3.12.12.
- `make doctor` reports prerequisites available through project-local binaries and boto3; `integration_qualified` remains false by design. `make check`, Python compilation and whitespace checks passed. Ruff 0.17.6 was used as an exact-version development formatter; it is not a runtime dependency.

The checksum trust root is upstream HTTPS release metadata/checksum publication. Independent publisher-attestation verification and full component security-patch review are not established. Registry 2.8.3 was chosen to exercise Floci's documented Distribution-2 backing; do not mistake that compatibility choice for a current security qualification.

## Explicit owner decisions and isolation

The owner authorized both Kind's privileged node and Floci's Docker-socket access on local Docker Desktop during this P0 session. No sudo, real AWS or existing-resource deletion was authorized or performed. The owner selected Apache-2.0; LICENSE contains the official Apache text. Floci's repository license is MIT; main tool repositories use Apache-2.0, while image packages retain separate terms.

The lab uses dedicated `csle-p0` Docker network, `csle-p0-control-plane`, `csle-p0-floci` and Floci-created `floci-aws-csle-p0-ecr-registry`. Published ports are loopback: emulator 14566, backing registry 15100, and Kind's assigned API port. UI is disabled; no user kubeconfig context was set/changed. Kubectl 1.36.1 talks to node 1.37.0. The current harness rejects ambient remote endpoints/contexts and explicitly pins Docker operations to the local desktop-linux Unix endpoint.

## Real experiment results — bounded claims

See the committed [hash-attributed smoke summary](results/p0-smoke-summary.json). It links each public conclusion to retained ignored raw artifacts. Initial experiments ran from the freeze revision with a dirty implementation tree. Later Recorder entries also preserve per-source hashes; early discovery and Helm install logs are separately retained. No claim is made that earlier runs executed a later commit.

| Experiment | Observed result | Limit |
| --- | --- | --- |
| Kind + Kyverno | Node v1.37.0 Ready; chart 3.10.0 / Kyverno v1.20.0 controllers Ready | Single-replica ARM64 lab, not HA or other-platform qualification |
| Floci ECR and OCI | Create/describe/list succeeded; actual pushed manifest and fresh OCI pull match; both config/layer blobs hash-verified | Emulator only; the fresh store is a directory OCI pull, not a separate fresh Docker daemon |
| Unsupported ECR scanner calls | StartImageScan and DescribeImageScanFindings returned UnsupportedOperation | No Inspector/native scanner claim |
| Trivy | Real report schema 2; Alpine 3.24.4; 11 MEDIUM findings, no HIGH/CRITICAL in that run; DB version 2 updated 2026-11-19T13:02:29Z | Not CVE-free; no finding ingestion/product policy engine |
| Cosign | Local-key custom in-toto bundle signed and independently verified, directly stored through Floci OCI | Public tlog/TSA/Fulcio/OIDC explicitly disabled for local-only keys; no production identity claim |
| First admission | Actual pod admitted and Ready; runtime imageID contains the same manifest digest | One-assessment path, not repeated approval qualification |
| Active-policy change | Next server-side admission denied after policy version changed | Original rule restored; current code restores in finally |
| Initial negatives | Real unsigned artifact, alternate trust key and privileged configuration denied | Initial harness results are retained; stricter current positive controls supersede broad qualification claims |
| Initial expiry | Denial observed at 17:37 after 17:36 approval expiry, following earlier successful admission | Generic initial denial check was strengthened; strict causal expiry gate remains unqualified on current reissue path |
| Reissue | Independent fresh scan and second signature verification succeeded; positive admission FAILED with `P0 reject: expiry` | Older same-type attestation payload selected; current reassessment compatibility blocker |
| Strict repeat negative suite | STOPPED at required positive baseline after reissue | No earned negative pass from an already failing baseline |

Manifest identity throughout the initial path: `sha256:1829893486be257df5049ab3b7fc95afbd0fc09d89803cbc580bda1ba5386b29`. Host registry uses localhost:14566; node/pod verification uses the Floci Docker-network IP:4566 with the same repository path/digest. The node has an explicit endpoint-specific HTTP containerd trust entry. Index and selected ARM64 manifest identities remain separate in the lockfile.

Two early expiry runner attempts refused to execute because the approval had not yet expired; those are precondition failures, not denial evidence. Their logs were retained. The later failure on reissue is an actual admission result and is not relabeled as an environmental issue.

## Independent review and corrections

`p0_review` inspected the actual code/design and ran the initial 10 passing tests. It found five issues: mutable/incomplete scan acceptance, non-causal negative checks, ambient remote Docker access, lost timeout/error evidence and installer verify/use read races. Corrections: execute an independent scan before signing and validate supported shape/digest/freshness/severity; bind positive evidence to predicate/policy and require specific denial causes; reject remote engines; retain timeout/OSError logs and restore policy in finally; install/extract from one verified byte snapshot. Added focused offline cases and reran the real fresh-signing/admission path, exposing the older-payload blocker. No review finding is silently treated as owner acceptance.

## Source and architecture gates

[NIST source review](framework-sources.md) reviewed Rev.5 release 5.2.0 catalog and four grounded mapping directions. PCI full-standard retrieval remains HTTP 403. CIS edition 2.1.0 exact text/terms and Kubernetes applicability remain unreviewed; no registration/personal-data submission occurred. No approved framework mappings ship.

A full v1 application contract/schema freeze, security-patch review and complete negative suite (including wrong-subject/modified content/future-issued evidence) remain open. The observed multi-attestation behavior requires a grounded design decision and passing reassessment tests before the admission contract is accepted. Do not weaken expiry, delete old evidence, change clocks or invent per-run predicate types to manufacture success.

**P0 is in progress, not complete.** Product P1–P7 remain planned. Draft PR #9 references #1 and does not close it. All local resources/evidence are retained; no cleanup/reset has been implemented or performed.

Final reviewed-tree rerun: `make p0-ecr` passed after the review fixes/formatting; per-command records include source hashes. This refreshes only ECR/OCI/Trivy evidence, not the failed admission-reassessment gate. The committed smoke summary includes this separate result.

## Source-grounded compatibility correction and repeat qualification

Expectation amendment frozen separately in `19409bc` before correction, following independent pinned-source review by `attestation_selection`. The runtime cache can restore old verified payloads before a registry refetch; default TTL is 60m. The verifier's newest-selection logic recognizes `timestamp` but not `issued_at`, and requires a common timestamp source across same-type candidates. Missing timestamp behavior is a source conclusion, not a claim that the uncached v1 branch was separately run.

Corrected local profile: one fixed predicate URI `/p0-compatibility/v2`, schema version 2, required signed `timestamp == issued_at`, current signed assessment-ID validation, unchanged digest/trust/freshness/issue/expiry/active-policy checks, and `--imageVerifyCacheEnabled=false`. The Helm extraArgs uses string `"false"` because the chart omits boolean false; both rendered deployment and running controller configuration were inspected. All old v1 registry evidence remains intact. No per-run predicate type, evidence deletion or clock changes were used.

Real corrected runs at 17:50 UTC:

- First v2 independently scanned, signed and verified; actual pod admitted/Ready with matching runtime digest; active-policy revocation denied specifically, restored in finally.
- A second distinct v2 assessment for the same digest/key/type/policy was independently scanned, signed, verified and actually admitted/Ready. Its policy requires the second signed assessment ID, so accepting only the previous payload could not satisfy the positive oracle.
- Strict unsigned-artifact, alternate-trust-key and privileged-configuration admission negatives each passed with contemporaneous successful positive controls and specific policy/reason checks.
- Initial v1 failures and the stricter baseline-stop results remain in the earlier table/summary as superseded experimental results, not erased failures.

This bounds a local single-artifact reassessment feasibility result. It does not finalize multi-image policy-token/catalog design, production caching, all invalid-evidence cases, patch qualification or P0 acceptance. The final matching-positive/unchanged-policy expiry test is recorded below after the second v2 window elapses.

Final strict v2 expiry: after the second approval expired at 17:53:17 UTC, `make p0-expired` passed. It required the exact matching prior positive receipt/predicate hash, a positive timestamp within that predicate's window, unchanged observed policy, kubectl exit 1 and the specific `P0 reject: expiry` admission denial. The hash-attributed artifact is in the smoke summary. This closes the local repeated-assessment/expiry feasibility case, not the full P0/MVP gate. A subsequent ad-hoc summary path parse initially failed; attribution was corrected without rerunning or changing the successful runtime result.

Kubectl/server minor skew (1.36/1.37) is within the [official supported one-minor policy](https://kubernetes.io/releases/version-skew-policy/). Whole-stack patch status and benchmark applicability are still separate open gates.

## Closure continuation — technical qualification and exact-source blocker

Owner request: continue through P0 closure and commit to draft PR #9. Closure expectations/contracts frozen in `09e8f2f` before implementation. `closure_contracts` owned only schemas/tests/design; `closure_sources` and `closure_patch_review` performed read-only source/advisory work. Parent owns integration/pins/CI and serialized runtime tests. Existing concise threat model remains one shared checklist; no per-slice threat-model document or unrelated security infrastructure was added.

### Contracts and offline verification

Six application v1 JSON Schemas, shared definitions and explicitly synthetic fixtures are in contracts/v1. Independent C01–C16 cases and exact red/green hashes are in p0-contracts-design.md. A permissive-schema red run failed 72 invalid-input assertions before implementation; 17 contract tests now pass. Equality, chronology, actual evidence truth and cryptography remain explicit P1/P3/P5/P6 domain checks; structural validation alone cannot authorize anything.

Independent `closure_review` ran the then-42 tests and found one real malformed-input defect: falsy non-list Vulnerabilities values could normalize into a clean result. Four focused red failures reproduced that behavior; the corrected validator rejects them and explicitly supports absent/null/list clean results. The final suite has 27 unit +17 contract tests (44), all passing. Review's runtime-identity caution was addressed by verifying actual kubeletVersion and container.Image against the built-node record. Native/fallback referrers are both published; separate verifier-path coverage is not claimed.

### Patch and clean-clone qualification

Python upgraded to 3.12.16, registry to 3.1.2. Because no patched official Kind node tag was published, supported Kind release-file building uses hash-pinned Kubernetes 1.37.2 ARM64 archive and digest-pinned Kind base. Complete known-advisory applicability and residual limits are in dependencies.md; no vulnerability-free claim is made. OSV returned no matching advisories for the fifteen exact Python dependencies queried. Only URI/date-time validators actually used are installed, avoiding unrelated format extras.

Old project lab containers were stopped (not deleted), preserving their resources/data/history. No unrelated project resources were touched. A public GitHub clone under ignored `.local/p0/closure-clone` began with no copied .tools/.local state, at `93730f7`. It downloaded/verified tooling, installed hash-locked dependencies, ran tests, built a patched node, created separate `csle-p0-close` resources/loopback ports, installed Kyverno and passed the full initial/repeated-assessment, runtime identity, policy-revocation, unsigned/wrong-trust/privileged, six adversarial and expiry experiments. Docker's global content/build cache was available; cold-daemon/cache independence is not claimed.

After the review fix, the clean clone fast-forwarded to `ae3c009` and remained Git-clean. Dependencies were resynchronized and all 44 tests passed. Runtime version/config ID was asserted, and ECR/Trivy, two actual admission/runtime paths, active-policy revocation, initial negatives and all six adversarial cases passed again on that source revision. The final same-predicate expiry result is appended below after its actual clock window; earlier expiry success remains separately attributed.

Real adversarial cases: wrong outer subject, modified signed predicate, modified signature, future-issued signed predicate, stale scan time and stale DB time. Each has a contemporaneous valid admission control. Untampered fixture bundles are independently verified before mutation; malformed bundles/subject bindings fail independent verification and real admission. Stale/future fixtures retain valid cryptography and fail the intended content/time rule. Fixtures use only the ephemeral local key and distinct project-owned artifact digests; no old evidence index is overwritten.

[Closure summary](results/p0-closure-summary.json) attributes commands/artifact hashes to exact source revisions. Runtime results qualify those executed revisions, not an unexecuted later documentation commit. Builds record Docker config IDs separately from OCI manifest identity; build inputs/outcomes are repeatable, bit-for-bit generated metadata is not claimed.

### Acceptance map and remaining decision

| P0 requirement | Current evidence/status |
| --- | --- |
| Environment and exact local tool compatibility | Passed on documented ARM64 Mac/Docker Desktop; pinned tools, patched build inputs, actual runtime identity and clean-clone path recorded |
| ADRs, chosen license, dependency versions, risk register and test matrix | Implemented; Apache-2.0 owner-selected; source/advisory residuals explicit; no zero-CVE or production claim |
| User stories, initial schemas and immutable digest strategy | Handoff user stories plus six frozen v1 contracts and 17 offline contract tests; domain truth remains later implementation |
| Signed evidence and actual admission feasibility | Repeated allow/runtime identity, wrong-subject/tampered/future/stale/unsigned/wrong-trust/privileged/revoked denial passed; strict expiry separately time-qualified |
| Exact official selected PCI/CIS wording review | BLOCKED: publisher publication access unavailable; official FAQ-backed directions are not full text/testing/applicability review |
| Honest dependency/smoke failure/workaround record | Passed; initial cache/timestamp failure, patch changes, parser regression and their corrections retained |

HANDOFF.md section19 explicitly requires exact selected framework wording from official sources during P0. Official PCI catalog metadata marks the full standard protected/agreement-required; even unprotected ROC/SAQ template retrieval returned403. CIS exact text download is registration-gated/unavailable (404/403). No publisher agreement/account was created and no personal data supplied. Full source details/hashes are in framework-sources.md. An owner-supplied official publication or explicit phase-scope amendment is required before unqualified P0 closure; neither CI nor the threat-model checklist can substitute for those facts. All three expanded MVP features and P6 source/shipping tests remain mandatory.

Final reviewed-head expiry at `ae3c009`: `make p0-expired` passed after the actual second approval window, with matching positive receipt/predicate hash, unchanged policy and the specific expiry denial. An earlier invocation refused to execute before expiry; its separate precondition log is retained and is not denial evidence. Every implemented technical closure scenario now has passing evidence; exact-source wording is the sole P0 closure blocker. No issue/phase closure or merge is claimed.

## Final P0 closure — original source gate satisfied

The owner explicitly rejected deferring source review and supplied the official-publication copies. No requirement was waived or moved to P6. Root plus `pdf_pci_review` and `pdf_cis_review` inspected complete relevant pages and rendered tables; `p0_source_closure_review` independently verified the source metadata, clauses, manual classifications and version-scope handling. No blocking review findings remain.

[Source review](framework-sources.md) and its [metadata](results/p0-framework-source-review.json) identify the exact supplied bytes: PCI DSS4.0.1 June2024,397pages SHA-256 `5e6b9093b84007b973097d20126a3768ea2f0a1d4200255c849b0fb3bf04ebc7`; CIS2.1.0 dated2026-09-30,344pages SHA-256 `491849d6ede263ce9397afc89c102e00b9ce586a45c83c969f952df633afc495`. This binds the review to owner-supplied copies; publisher digital origin was not independently authenticated. Publications, full extracts and renders remain untracked.

Selected PCI6.3.1,6.3.3 and11.3.1 text, procedures, continuations and related applicability were reviewed. Final6.3.3 interpretation is entity-ranked critical patches within one month of release, other patches on entity timing. An early provisional misreading was withdrawn after visual comparison; no extraction defect or high-risk universal patch deadline is asserted. Organizational risk ranking, release dates, internal/CDE scope, cadence and personnel independence remain human/context facts. Source review is not a compliance assessment.

CIS5.2.2–5.2.7 exact IDs/audit/remediation/exception context and Manual classifications were reviewed. The publication's target1.34–1.35 and audience1.35–1.37 ranges conflict; patched1.35.10 is their conservative intersection. This avoids asserting benchmark-wide applicability for earlier1.37.2 experiments. The non-root strategy supports1.35 without relying on the1.36+ user-namespace alternative. P6 must preserve manual classification and implement/test technical evidence, not infer conformance from pod absence or this source review.

The source-aligned profile was frozen in0438c5f, pinned in59b870e, then qualified from a fresh public clone at exactly `59b870e7b9299284948793a303943eaea30dc31b` with a clean working tree and no copied tools/state. Docker image/build cache was available. Profile `csle-p0-cis` uses isolated loopback ports14586/15120 and dedicated kubeconfig/context. Earlier project lab containers were stopped but not deleted; their evidence remains. No unrelated resources changed.

[Final machine-readable qualification](results/p0-final-qualification.json) records actual inputs, build config identity, commands/log hashes and scenario outcomes. The actual node was Ready at1.35.10 and used Docker config ID `sha256:a2aa41a5f52ee9b68cebf4d4e8bfa107d7d5e831ad59433af0f924b96e5146fc`. All44 offline tests passed. Real Floci ECR/OCI byte identity, Trivy, two distinct approved/admitted/runtime-matching assessments, active-policy revocation, unsigned/wrong-key/privileged, wrong-subject/modified-content/modified-signature/future/stale-scan/stale-DB negatives and strict expiry passed. Each negative requires the intended reason and valid controls. The final expiry ran after19:09:00 UTC, with matching positive receipt and unchanged policy. No result is transferred to an unexecuted later documentation commit.

| P0 acceptance gate | Final result |
| --- | --- |
| Environment, compatible exact pins, runtime/identity smoke proof | Passed on the documented ARM64 local profile; known dependency limitations remain explicit |
| Architecture, license, risk register and phased test plan | Established; Apache-2.0 owner-selected; lean shared threat model and executable checks |
| User stories, initial canonical schemas and immutable identity strategy | Established; six schemas and17 contract tests, with domain-truth limits explicit |
| Exact official NIST/PCI/CIS selected-source review and applicability | Completed; source hashes/locators/interpretations and conservative1.35 scope recorded |
| Actual signed admission allow/deny, reassessment and freshness feasibility | Passed with original failures/corrections retained |
| Reproducible local setup and honest evidence attribution | Passed fresh checkout on supported host; no cold-cache, bit-for-bit, production or other-platform claim |

**P0 is qualified on branch `phase/p0-compatibility` for closure of phase tracker#1.** PR#9 remains draft/unmerged. This does not establish owner semantic acceptance, release authorization or verification on a merged commit. P1–P7 remain future work; no MVP completion, full compliance mapping implementation or organizational certification is claimed. All three expanded MVP features remain mandatory.
