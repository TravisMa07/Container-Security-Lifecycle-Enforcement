# P0 compatibility spike: independent design and expectations

Base: `8c5e95e661781f2810030ca6b89d6c0f7afd4f08`. Tracking: [issue #1](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues/1). Status: expectation freeze before tooling implementation. Authority: HANDOFF.md sections 3–8, 12/P0, 15 and 17.

## Bounded outcome and exclusions

Establish an exact local ARM64 macOS toolchain and experimentally validate the registry → scan → signed custom predicate → Kind/Kyverno admission path. Produce reusable setup/check commands, a compatibility manifest and attributed evidence. This is feasibility qualification, not the P1–P7 product implementation. No production AWS, no user kubeconfig edits, no deletion, no new service framework and no committed credentials or downloaded artifacts.

The first implementation item owns local tool provisioning and isolated smoke experiments. P0 can remain incomplete if external compatibility/source/license gates remain open; retain failures and provide evidence-backed next work rather than weakening checks.

## Safety and reproducibility contracts

- Download only exact upstream HTTPS release artifacts to ignored `.tools/`; verify recorded SHA-256 before executing/extracting. Refuse unsupported platforms and traversal/symlink archive members. No sudo, global binary installation or unpinned shell installer.
- Immutable image refs are selected from actually fetched manifest digests, never guessed. Preserve platform/index identity separately. SQLite/Pydantic application dependencies are P1 work.
- Use dedicated `csle-p0` Docker resources and `.local/p0/kubeconfig`; pass kubeconfig/context explicitly. Refuse collisions rather than adopting/deleting existing resources. Loopback-only published ports. Preserve evidence and resources after the experiment; no automatic teardown.
- Registry and emulator traffic use explicit local endpoints and fixed test credentials. Do not inspect real AWS credentials or contact account APIs. Signing material lives only in ignored local storage with restrictive permissions.
- Each experiment records revision, command, UTC time, environment, return code, raw-output hash and bounded conclusion. Failed dependencies are infrastructure results, never behavioral-red evidence.

## Independent case matrix

Expected outcomes derive from the handoff and upstream OCI/in-toto/admission semantics, before code. Freeze this document in a separate commit; update expectations only with traceable source rationale.

| ID | Input/scenario | Expected outcome / oracle |
| --- | --- | --- |
| T1 | Supported host and correct downloaded artifact | Install only verified bytes under project-local tool directory; installed version matches manifest |
| T2 | Modified download or unsupported platform | Nonzero failure before execution, no partial executable installed |
| T3 | Archive path traversal or link entry | Reject before writing outside the staging directory |
| T4 | Existing cluster/resource or occupied local port | Fail explicitly; do not reuse, remove or overwrite unrelated resource |
| C1 | Dedicated pinned Kind node and Kyverno | Node/controllers Ready; exact versions and architecture recorded; user kubeconfig unchanged |
| R1 | ECR create/list/describe plus OCI push/fresh-store pull | Actual manifest/body hashes and ECR digest match the artifact; provenance `emulated_aws_ecr` |
| R2 | Unsupported ECR scanner APIs | Record actual unsupported response; never fabricate findings or call it native scanning |
| S1 | Trivy scan of exact pushed digest | Real schema-versioned JSON, same digest association, scanner version and DB metadata, raw report hash |
| A1 | Ephemeral trusted key signs custom in-toto predicate | Independent Cosign verification succeeds for exact subject and trusted public key |
| A2 | Wrong key, altered predicate/signature or different subject | Cryptographic/subject verification fails; valid signature on other content is insufficient |
| K1 | Trusted allow predicate, active policy, valid issue/expiry times | Real protected-namespace Kind admission allowed |
| K2 | Missing/unsigned, wrong signer/digest, modified evidence | Real admission denied and reason captured |
| K3 | Expired, future-issued, stale/revoked policy or scan evidence | Real admission denied, including after previous verification/cache population |
| K4 | Privileged configuration | Real admission denied independently of image CVE approval |
| F1 | Framework source reviewed | Exact official edition, requirement/testing applicability and bounded technical interpretation recorded; no certification claim |
| F2 | Source inaccessible or organization facts unknown | Explicit incomplete/review-required state; no approved mapping or false compliance claim |

## Contracts and decisions

Image identity: canonical SHA-256 manifest identity plus explicit optional index/platform relationship, registry/repository, source, first/last observation and resolution status. Runtime image IDs remain raw plus separately resolved identity. Contract schemas and their validation tests are finalized in P1; P0 must not replace unknown identity with string assumptions.

Attestation: use an actual Cosign-generated in-toto envelope, custom predicate URI, exact subject digest, explicit schema/policy identity/version, trusted scan hash, issued/expiry and signer trust configuration. Public key is configured independently. The smoke fixture is clearly labeled compatibility evidence and must not be represented as production-approved scan policy.

Admission: select current supported Kyverno API only after testing; verify cryptography before extracting predicate fields; test time/revocation/cache semantics. A separate OCI attestation store is allowed only if Floci fails direct compatibility and same-digest binding is proved. Missing expiry is not an acceptable workaround.

Architecture stays the accepted modular monolith; the spike adds no app backend. License remains an owner decision and framework catalogs remain source-reviewed proposals until authoritative review is complete.

## Qualification and ownership

Parent owns tooling/pins, shared contracts, cluster experiments and integration. `p0_sources` performs read-only official framework research from the base above, writing only ignored downloads. Heavy runs are serial. Final independent review inspects actual code, tests and evidence. PR references #1 without closing it unless every P0 gate is complete.
