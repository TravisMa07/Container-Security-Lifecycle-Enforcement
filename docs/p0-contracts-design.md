# P0 canonical contract freeze

Base: `d97d6c68aae3c310bc92ae7001c2bbca28cdf477`. Owner: `closure_contracts` for `contracts/v1/`, `tests/contract/` and this design only. Authority: HANDOFF.md sections 4–6, 9, 12/P0, 15 and 17. This defines application contract version 1; the earlier `/p0-compatibility/v2` predicate remains an explicitly separate experimental protocol.

## Scope and decisions

Freeze six JSON Schema Draft 2020-12 documents plus shared scalar definitions and synthetic contract fixtures: ImageArtifact, WorkloadObservation, VulnerabilityFinding, DerivedFindingState, SecurityAttestation predicate and ComplianceEvidence. Schemas validate structure and necessary evidence prerequisites, without implementing collectors, database storage, cryptography, policy evaluation or control mappings. P1 owns typed Pydantic models and executable domain logic consistent with these contracts.

- SHA-256 digests/hashes are lowercase `sha256:` plus exactly 64 hex characters. Tags are aliases, never artifact IDs. Canonical artifact identity is selected manifest digest; `index_digest` separately preserves its optional parent index and `platform_digest` preserves the selected platform manifest. `image_id`, selected manifest and platform equality when resolved is a domain invariant; schemas enforce digest shape/non-null resolution but do not pretend standard JSON Schema can compare property values.
- Unknown artifact resolution explicitly permits null identity/digests and requires source reference/reason rather than inventing a digest. Workload records retain desired references and raw runtime image ID independently; `resolved_digest` may remain null. Stable workload identity is `(cluster_id, uid)`, not namespace/name. Each observation is for a named container and container category, with opaque resourceVersion and idempotency key.
- Canonical application timestamps use RFC3339 UTC `Z`; fixture compatibility scripts may currently emit `+00:00` and must normalize at the future adapter boundary. JSON Schema format checks are enabled offline. Schemas do not claim to compare chronology across fields; first<=last, observation-window ordering and issued<expires remain explicit domain invariants for P1/P3/P5.
- Finding validity, exposure and remediation are separate enums. No rule turns disappearance/scale-zero into `not_affected` or `verified_in_scope`.
- `verified_in_scope` requires a bounded verification object: explicit scope/window, fresh complete inventory, zero remaining references, fixed scan evidence and observed replacement evidence; no coverage-gap IDs and historical_observed exposure (running/configured/unknown exposure cannot claim closure). These are required attestations of evidence, not proof that their supplied facts are true. Other remediation values cannot carry a verification claim.
- The security predicate is schema-validated content inside actual Cosign/in-toto, never a signature substitute. Require digest, assessment ID, policy ID/version/hash, raw scan hash, scanner/DB/scan timestamps, signer identity, issue/expiry, reason and evidence IDs. A passing structural validation does not authorize signing or admission. The application v1 predicate includes signed `timestamp` for the established verifier ordering compatibility; equality to issued_at is a domain invariant.
- Compliance assessment statuses are the handoff's five bounded states. Unknown applicability cannot earn pass or not-applicable. Not-applicable requires a recorded justification; pass/fail need applicable scope and nonempty evidence. Framework, version, source URL, mapping revision, technical procedure, limitations and reviewer field are retained. No organizational compliance verdict field is accepted.
- Objects reject undeclared properties. IDs are nonempty provider identifiers, not invented UUID requirements. Lists of evidence/reasons are unique. Shared definitions are resolved from a locally registered schema catalog, never the network.

## Independent expectations (freeze before schemas)

These cases derive from the handoff and safety invariants above, not from implementation output. Fixtures are synthetic and establish contract behavior only.

| Case | Input | Expected result and rationale |
| --- | --- | --- |
| C01 | Six complete canonical examples with UTC timestamps | Accept each; minimum contract shape usable for subsequent P1 work |
| C02 | Tag, uppercase digest, wrong hash length or malformed hex as artifact/finding/subject identity | Reject; immutable SHA-256 identity cannot be replaced by alias or malformed digest |
| C03 | Resolved artifact without a manifest; unknown artifact with fabricated digest | Reject; resolution uncertainty must be explicit |
| C04 | Index digest and selected platform digest retained separately | Accept; multi-architecture index is not silently collapsed into platform identity |
| C05 | Unknown workload runtime/digest, distinct UID with reused namespace/name | Accept; absence of runtime resolution and UID reuse do not fabricate identity/history |
| C06 | Missing UID/cluster/idempotency, numeric resourceVersion, unknown resource/container enum | Reject; durable identity, replay contract and source checkpoint semantics required |
| C07 | Naive/local-offset/malformed timestamps or invalid calendar date | Reject; canonical UTC and actual RFC3339 date validation required |
| C08 | Each orthogonal validity/exposure/remediation state, historical open finding | Accept valid combinations; no disappearance-based closure rule |
| C09 | verified_in_scope without scope/window, fresh/complete inventory, fixed scan, replacement or zero remaining references | Reject each missing or contrary prerequisite independently |
| C10 | verified_in_scope with coverage gaps or running/configured/unknown exposure | Reject; scope verification cannot coexist with unknown coverage or remaining exposure |
| C11 | Nonverified state carrying verification object | Reject; no misleading positive closure claim attached to open/unknown/regressed status |
| C12 | Predicate missing digest/policy/hash/signer/freshness/time evidence or decision outside allow/deny/review_required | Reject; structural trust context required, cryptography still separately mandatory |
| C13 | Finding with UNKNOWN severity and nullable DB/fixed version; malformed scanner/report hash | Accept honest unknowns, reject malformed source context |
| C14 | PCI evidence with not_determined applicability and requires_review | Accept; organizational facts cannot be inferred from technical evidence |
| C15 | Pass/fail with unknown applicability or absent evidence; not-applicable without justification | Reject; no earned pass or blanket not-applicable from unknown facts |
| C16 | Certification verdict, unknown enums, wrong contract version or arbitrary extension property | Reject; bounded semantics and versioned closed records |

## Validation and limits

The offline unittest contract suite uses `jsonschema` with FormatChecker and a locally registered schema catalog. Run schema self-checks and each positive/negative oracle; no Docker/network. A temporary empty schema may demonstrate meaningful red by incorrectly accepting the invalid cases; absence of a dependency/import is not behavioral red. Parent freezes this design before schema implementation, integrates the pinned dependency, and owns the project-wide test target/CI.

P1/P3/P5 must additionally enforce cross-record joins, equality/chronology, actual evidence referential integrity, freshness based on trusted clocks, scan provenance, scope completeness and cryptographic subject/signature verification. Schema-valid input is not trusted input and cannot alone establish remediation, authorization or compliance. No runtime feature or phase acceptance follows from these schema tests.
