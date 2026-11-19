# P0 qualification ledger

Base: `8c5e95e661781f2810030ca6b89d6c0f7afd4f08`. Owner: root. Scope/expectations: [P0 design](p0-design.md). Phase tracker: [#1](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/1).

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
