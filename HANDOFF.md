# Container Security Lifecycle & Enforcement — Codex Engineering Handoff

**Status:** Implementation specification / MVP acceptance contract  
**Prepared:** 2026-11-19  
**Working name:** Container Security Lifecycle & Enforcement (CSLE; name can be changed)  
**Primary objective:** Build a local-first, security-first, cloud-native system that preserves evidence about ephemeral Kubernetes workloads, correlates container image vulnerabilities with live and historical deployment state, verifies remediation and regression, enforces trustworthy deployment policy, and exports narrowly scoped compliance evidence.

> **Instruction to Codex:** This document defines the target product and quality bar, **not** a mandate to implement everything in one PR. Inspect the environment and upstream APIs, write an implementation plan, build in bounded vertical slices, run acceptance tests, and accurately identify unimplemented or unverified features. Do not turn this into a full CSPM, CVE scanner, GRC system, or distributed event-processing platform. **The three previously “Later” features are explicitly MVP requirements:** (1) signed image security attestations, (2) functional Floci/ECR integration, and (3) selective PCI DSS 4.0.1 evidence mappings.

---

## 1. Why this project exists

Enterprise vulnerability-management queues are noisy for containers because deployments are ephemeral. A short-lived Job may run and disappear before the next scheduled scan; a Deployment may scale to zero but still reference a vulnerable image; a fixed image may be replaced with an old vulnerable digest; an apparently retired image may remain deployable in another namespace or registry. A vulnerability attached to an image is **not** necessarily a false positive when a pod stops running. Security teams need defensible answers to **what image**, **where observed**, **whether running or deployable**, **how the state changed**, **whether remediation was verified**, and **whether reintroduction is prevented**.

This project addresses that decision gap. Use existing security engines and platforms for their intended purposes:

- **Trivy** identifies OS/library vulnerabilities and selected image/Kubernetes configuration issues; our system does not reinvent package-to-CVE matching.
- **Kubernetes Kind** provides a real, local API and real workload lifecycle semantics.
- **Kyverno** enforces deployment guardrails and verifies appropriately signed image security attestations.
- **Cosign / in-toto** sign and verify an image-digest-bound policy assessment; signatures prove origin/integrity, **not perpetual safety**.
- **Floci** supplies an **emulated AWS ECR registry** and compatible AWS API surface for local integration; it is **not a real ECR vulnerability scanner**. Trivy remains the scan authority in local tests.
- **GitHub Actions** runs build/scan/policy checks and demonstrates secure delivery.
- **Selected CIS/NIST/PCI mappings** provide structured technical evidence, not legal-compliance certification.

Portfolio positioning: Unlike DetectBridge (detection pipeline) and ResponseForge (SOAR response), this system demonstrates **preventative cloud-native security**, Kubernetes engineering, OCI image identity, lifecycle reconciliation, security attestations, IaC, CI/CD, and evidence-backed vulnerability management.

### Product thesis

**Continuously reconcile image-vulnerability findings against both current and observed historical Kubernetes deployment state; verify fixes and regressions; prevent unapproved image/configuration deployments; export reproducible technical control evidence.**

### Primary user stories

1. As a vulnerability analyst, I can see which image digests with vulnerabilities are running, referenced but not running, historically observed, or unobserved/unknown, with timestamps and proof.
2. As a platform engineer, I can see why a specific image deployment was permitted or blocked, and reproduce the result.
3. As a remediation owner, I can verify that a patched digest replaced the vulnerable digest *across all inventory in scope*, not merely in one pod.
4. As a security reviewer, I can see an auditable sequence of scan, finding, workload event, decision, exception, and enforcement evidence.
5. As a DevSecOps engineer, I can clone the repository, stand up local infrastructure, push an image to an emulated ECR repository, scan it, create a signed attestation, and run a real Kyverno admission test.
6. As an auditor, I can export selected CIS, NIST SP 800-53, and PCI DSS 4.0.1 **technical evidence mappings**, including manual/unknown assessments, without false compliance claims.

---

## 2. Scope and non-goals

### Mandatory MVP outcomes

**M1. Live Kubernetes inventory and history:** real Kind cluster; list/watch Pods, Jobs, CronJobs, Deployments, ReplicaSets, StatefulSets, DaemonSets and owning controllers where applicable; persist first/last observed, observed state transitions, image identity, provenance, resource UIDs; periodically reconcile.

**M2. Vulnerability ingestion and correlation:** real Trivy image scan results with digest identity; deduplicate scans; correlate CVEs and configuration findings to running images and desired workload references; explain evidence and unknowns.

**M3. Lifecycle and remediation reasoning:** separate finding validity, deployment exposure, and remediation status; distinguish running, configured/not running, historical observed, and unknown; detect fixed/replaced/regressed digests; do **not** auto-mark non-running vulnerabilities false positive.

**M4. Security-first CI/CD and policy:** demonstrate a local and CI scan gate, Kyverno configuration policies (e.g. privilege restrictions) and real admission denial, not only a report.

**M5. Signed security attestations — REQUIRED IN MVP:** generate signed, digest-bound, versioned, time-bounded security decision predicates; cryptographically verify them and enforce with a supported Kyverno image verification policy in a real Kind cluster. Test rejection of missing/invalid/wrong-digest/expired-or-revoked-policy evidence. Expiration handling may use a trusted policy service or Kyverno policy expression if supported; verify the actual end-to-end behavior.

**M6. Floci/ECR integration — REQUIRED IN MVP:** bring up Floci, create ECR-compatible repo with AWS CLI/SDK, push/pull image bytes from real OCI registry backing, list/describe image metadata via its supported APIs, match digest identities against the registry, scan the actual image with Trivy, and exercise integration tests. Persist explicit provenance `emulated_aws_ecr`. A simple, separately tested Terraform provider configuration is desirable; do not hold up basic ECR correctness on incomplete Terraform API support.

**M7. Compliance/regulatory evidence — REQUIRED IN MVP:** selected **CIS Kubernetes Benchmark**, **NIST SP 800-53 Rev. 5** and **PCI DSS v4.0.1** mappings; evidence objects, mapping version, technical assessment status, limits and applicability; export JSON and readable HTML or Markdown. At least 2–3 grounded PCI technical mappings with authoritative citations and clearly bounded interpretations.

**M8. Evaluation:** reproducible positive/negative lifecycle scenarios, missed-event/reconciliation test, end-to-end denied/allowed admission tests, and baseline comparison against periodic-only inventory. CI includes unit and fixture integration tests; optional heavier local integration suite runs on capable development hosts.

### Explicit non-goals

- No new vulnerability database, package manager analyzer, CVSS standard replacement, or speculative exploitability engine.
- No real AWS production account or mandatory EKS cluster, real Inspector coverage, real PCI certification, or organizational compliance verdict.
- No multi-tenant SaaS, distributed Kafka/Flink architecture, enterprise GRC workflow, large React dashboard, Kubernetes operator/controller framework unless needed, eBPF runtime reachability, or autonomous AI decision-maker.
- No automated production remediation or image deletion; allow recommendations and safe test-only enforcement. No auto-suppression based solely on pods disappearing.
- No full AMI/EC2/GAMI assessment in MVP: AMI lifecycle is a separate future product surface, even if user’s VM experience motivates the problem.

### Explicit scope discipline

Use a **modular monolith** (one Python application / CLI plus one watcher worker or background process, one SQLite DB initially), not microservices. Prefer **Kind + local registry + Floci + Kyverno + Trivy + Cosign**, not EKS, Kafka, Redis, or Elasticsearch. Use Docker Compose / Makefiles / scripts to launch external services. A simple CLI, JSON, and HTML reports are sufficient. PostgreSQL, a UI, a live AWS account, and agentic AI are stretch goals only.

---

## 3. Verified upstream behavior and constraints

The following claims require implementation-time checking against the exact versions selected and should be recorded in `docs/dependencies.md`:

1. **Floci ECR**: supports a real OCI registry behind ECR APIs. Its own ECR docs explicitly list `StartImageScan` and `DescribeImageScanFindings` as **not implemented**; neither import nor invent Inspector CVE data as an ECR API success. Also note the emulator can store lifecycle rules without enforcing them. See <https://floci.io/floci/services/ecr/> and <https://github.com/floci-io/floci>.
2. **Cosign**: supports signed in-toto attestation predicates, image-digest verification, key-based local workflows and keyless options. See <https://docs.sigstore.dev/cosign/verifying/verify/> and <https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md>.
3. **Kyverno**: current documentation distinguishes policy types and versions. Confirm actual compatibility of chosen pinned Kyverno version, custom predicate types, signature identity, report semantics and image verification behavior. Prefer current upstream image-validating policy reference <https://kyverno.io/docs/policy-types/image-validating-policy/>. An old example is **not** proof that it works on the chosen version.
4. **Trivy**: built-in `--compliance` reporting is marked experimental and version-sensitive. Pin a version and inspect the exact JSON schema/benchmark IDs; do not silently treat compliance-check IDs as stable. <https://trivy.dev/docs/latest/guide/compliance/compliance/>.
5. **NIST**: use an explicit revision/catalog snapshot, currently SP 800-53 Rev. 5 with updates (including v5.2.0 where relevant); obtain identifiers/phrasing from authoritative NIST source. <https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final>.
6. **PCI DSS 4.0.1**: use the official PCI SSC text to verify the selected requirements, applicability, testing expectations, and effective dates before shipping mappings. A mapping from technical evidence is **not** an assertion of overall PCI DSS compliance. Start with 6.3.3 (security patching of applicable system components) and other *verified* technical requirements only if supported by scanner evidence.
7. **Kubernetes watches**: implement reconnect, `resourceVersion`, resource-version expiration handling, relist, periodic reconciliation, controller ownership tracking, and coverage-gap reporting. Kubernetes watches can miss a workload entirely during service downtime; never claim perfect reconstruction from a later list.

### Version policy

Codex must resolve **actual compatible versions** and pin image digests/CLI versions in a lockfile or documented manifest. Do not hard-code guessed versions in this handoff. Record date, architecture/platform (ARM64/AMD64), links and smoke-test results for Kind, Kubernetes, Kyverno, Trivy, Cosign, Floci, AWS CLI, Terraform if used, and Python dependencies. Security-patch status of components matters.

---

## 4. Architecture and boundaries

```text
       Kubernetes Kind                          Image/Registry sources
 Pods/Jobs/CronJobs/Controllers         Local OCI registry + Floci emulated ECR
            |                                          |
   list/watch/reconcile                         OCI digest inventory
            |                                          |
            +----------------+-------------------------+
                             |
                      Inventory Collector
               events + snapshots + coverage gaps
                             |
        Real Trivy scans ---->+----> Artifact/Finding Store (SQLite)
                             |
                      Correlation Engine
          digest identity + desired/runtime refs + history
                             |
           Lifecycle & Security Policy Decision Engine
             |                 |                   |
       Case/report          CI gate        Cosign sign attestation
        + evidence                               |
         mappings                          OCI Registry
       CIS/NIST/PCI                               |
                                           Kyverno verify/admit
                                           real Kind admission
```

### Module boundaries

- **Collectors:** Kubernetes API (watch/list), OCI registry/Floci ECR inventory, Trivy CLI/parser. Adapters transform raw provider payloads to canonical records with source/provenance.
- **Persistence:** SQLite with migrations, unique constraints and auditable history. Separate append-only observations from derived current state and current decisions. Avoid irreversible destructive overwrites of evidence.
- **Correlator:** Pure, unit-testable logic links image manifest digest to runtime and desired references; handles resolution uncertainty.
- **Lifecycle engine:** Pure, deterministic state machine/decision rules with complete reasoning codes; no generative model.
- **Policy evaluator:** Versioned organization rules, exception approvals, scan freshness, allowed registries, CVE policies, workload hardening requirements.
- **Attestation service:** Converts evaluated decision into canonical signed in-toto predicate, binds subject to immutable digest, stores signing identity and policy version; issues only when deterministic acceptance criteria pass.
- **Enforcement:** GitHub Actions/local CLI gate and Kyverno verified-admission; policy/config vulnerability checks separate from image attestation controls.
- **Evidence mapper:** Versioned CIS/NIST/PCI control registry and observable assessment outcomes; no GRC certification.
- **Reports & CLI:** `inspect image`, `inspect workload`, `findings`, `lifecycle`, `controls`, `export`, `demo`, `health` (exact syntax can be adapted, but keep stable help and tests).

### Trust boundaries

- Scanner output and registry metadata are untrusted inputs; validate schemas and constrain size/paths.
- Kubernetes API and emulated AWS credentials remain least-privileged.
- **Only CI/authorized policy service can sign**. Do not let arbitrary image publishers sign a passing security result without server-side validation.
- Signed predicate content must be verified against trusted key/identity, image digest, policy version, timestamp, validity, and expected predicate schema; an old legitimate signature must not bypass newer policy.
- Floci isn't AWS; its endpoint is local and may have permissive semantics. No claim of actual IAM, Inspector, or EKS security validation from emulator passing tests.
- Admission denial is the deployment barrier; existing running images are **not** automatically removed by admission policy installation.

---

## 5. Canonical data contracts (initial v1)

Use typed Pydantic models, version tags, schema fixtures, migrations and tests. Example field sets below are the minimum; adapt as needed.

### 5.1 ImageArtifact

```json
{
  "schema_version":"1",
  "image_id":"sha256:<manifest-digest>",
  "registry":"localhost:5000",
  "repository":"example/payment-api",
  "tags_observed":["v1"],
  "manifest_digest":"sha256:<digest>",
  "platform_digest":null,
  "platform":"linux/amd64",
  "source":"oci_registry",
  "first_seen":"2026-11-19T00:00:00Z",
  "last_seen":"2026-11-19T00:01:00Z",
  "resolution_status":"resolved"
}
```

**Image identity requirement:** image tags are aliases; don't use them as primary keys. Multi-architecture manifests may require a distinction between index digest and platform-specific manifest digest; preserve both when resolved. Runtime `imageID` formatting differs from repository manifest digest; do not blindly join by string equality or strip arbitrary prefixes. Record unresolved matches as `unknown`, with supporting data.

### 5.2 WorkloadObservation

```json
{
  "schema_version":"1",
  "cluster_id":"kind-csle",
  "namespace":"demo",
  "kind":"Pod",
  "name":"worker-xyz",
  "uid":"kubernetes-object-uid",
  "owner_refs":[{"kind":"Job","uid":"owner-uid"}],
  "desired_image_ref":"registry.local/worker:v1",
  "runtime_image_id":"registry.local/worker@sha256:...",
  "resolved_digest":"sha256:...",
  "phase":"Succeeded",
  "replicas_desired":null,
  "replicas_ready":null,
  "observed_at":"2026-11-19T00:00:00Z",
  "source":"kubernetes_watch",
  "event_type":"MODIFIED",
  "observation_id":"uuid"
}
```

Stable identity = `(cluster_id, object_uid)`; track namespace/name for presentation. Use idempotency keys for replayed/duplicated watch events; persist `resourceVersion`/collector checkpoint as operational metadata, not proof of full completeness.

### 5.3 VulnerabilityFinding

```json
{
  "finding_id":"stable-hash-of-source-image-package-vulnerability",
  "image_digest":"sha256:...",
  "scanner":"trivy",
  "scanner_version":"pinned-version",
  "vuln_id":"CVE-YYYY-NNNN",
  "package_name":"package",
  "installed_version":"x.y.z",
  "fixed_version":"x.y.z+1",
  "severity":"HIGH",
  "scan_timestamp":"2026-11-19T00:00:00Z",
  "scanner_db_updated_at":null,
  "source_document_hash":"sha256:...",
  "validity":"under_investigation",
  "evidence_ids":["evidence-id"]
}
```

Track package path/type, severity source, target OS/platform, and aliases where available. Maintain raw scan document hash and parser version. A finding is scoped to the artifact and scan context, not to a mutable container tag.

### 5.4 DerivedFindingState

```json
{
  "finding_id":"...",
  "assessment_at":"2026-11-19T00:05:00Z",
  "inventory_scope":"kind-csle/all-namespaces",
  "validity":"under_investigation",
  "exposure":"configured_not_running",
  "remediation":"open",
  "recommendation":"review_before_restart",
  "reason_codes":["DESIRED_REFERENCE_PRESENT","NO_RUNNING_POD_OBSERVED"],
  "confidence":"bounded",
  "coverage_gap_ids":[],
  "evidence_ids":["..."]
}
```

**Orthogonal states:**
- `validity`: `affected`, `not_affected`, `under_investigation`, `disputed` (use scanner result as evidence, not automatically authoritative VEX); explicitly retain provenance of VEX data if later supported.
- `exposure`: `running`, `configured_not_running`, `historical_observed`, `unknown`. Optional multiple simultaneous exposure categories across workloads; aggregate highest relevant exposure with rationale.
- `remediation`: `open`, `in_progress`, `verified_in_scope`, `regressed`, `unknown`.

`verified_in_scope` **must** carry inventory scope, observation window, freshness, coverage completeness and remaining references; never claim universal remediation. Historical absence is not proof that a finding is invalid.

### 5.5 SecurityAttestation predicate

Illustrative custom predicate; the outer signature/statement generated by Cosign must follow the *actual supported in-toto format*, not a homegrown signature scheme:

```json
{
  "schema_version":"1",
  "predicate_type":"https://example.org/csle/security-assessment/v1",
  "subject_image_digest":"sha256:...",
  "assessment_id":"uuid",
  "decision":"allow",
  "policy_id":"default-release-policy",
  "policy_version":"git-sha-or-semver",
  "scan_result_hash":"sha256:...",
  "scanner_version":"...",
  "issued_at":"2026-11-19T00:00:00Z",
  "expires_at":"2026-11-20T00:00:00Z",
  "signer_identity":"local-dev-public-key-id",
  "reason_codes":["SCANNED","POLICY_PASSED"]
}
```

Use deterministic canonical JSON for the stored predicate / policy hash. Signing key must not be committed to Git; `make demo-keys` creates **ephemeral local-only** test keys. A trusted public verification key or pinned signing identity is configured independently of the artifact. For GitHub-hosted CI, prefer identity-bound keyless signing where feasible and verified; local offline demo can use ephemeral key pairs.

### 5.6 ComplianceEvidence

```json
{
  "schema_version":"1",
  "framework":"PCI_DSS",
  "framework_version":"4.0.1",
  "control_id":"6.3.3",
  "mapping_version":"1.0.0",
  "technical_check_id":"container-vuln-remediation-timeliness",
  "assessment":"requires_review",
  "applicability":"not_determined",
  "asset_scope":"demo/payments",
  "observed_at":"2026-11-19T00:00:00Z",
  "evidence_ids":["..."],
  "limitations":["Cannot establish all organizational patch SLAs or entire CDE scope"],
  "reference_url":"official-requirement-link"
}
```

Assessment enumeration: `pass_technical_check`, `fail_technical_check`, `requires_review`, `insufficient_evidence`, `not_applicable_with_justification`. Never produce top-level `PCI compliant` labels.

---

## 6. Lifecycle observation and reconciliation

### Watch/list implementation

1. On startup, list each supported resource type/namespaces under approved RBAC scope and persist a checkpoint and snapshot.
2. Begin watches from supported resource versions. Persist events and derive current controller ownership and image refs; handle bookmarks if enabled.
3. On disconnect or expired resource version (`410 Gone`), record `coverage_gap_started`, relist authoritative current state, re-establish watch and record `coverage_gap_ended`; **never fabricate events inside the gap**.
4. Perform periodic full inventory reconciliation at configurable interval and reconcile drift in current derived state while preserving append-only observations.
5. Capture deletion events and controller scale transitions; watch workload templates to detect references when pod replica count is zero.
6. Constrain event retention, scan cadence and DB size with explicit limits; keep demonstration historical evidence available through test duration.
7. Persist timestamps: source event time (if present), ingestion time, and assessment time; make clock assumptions clear. Do not infer precise process execution times from Kubernetes list snapshots.

### Required edge cases

- `Job` completion and TTL deletion, `CronJob` scheduled child Jobs, `Deployment` scale-to-zero, duplicate names with different UID, rollout between two digests, same digest in multiple namespaces, mutable tag moved, missing runtime `imageID`, multi-architecture image identity, watch reconnect, short-lived workload entirely inside outage (unknown history), pods running but controller desired image differs.
- Image scan caching keyed on digest + scanner version + vulnerability DB identity/policy interval. New CVE DB updates can invalidate previous allow decisions without image change.
- Refuse unsafe extrapolation: registry deletion and Kubernetes workload deletion do **not** prove that an image never ran or cannot be restored.

### Minimum lifecycle classification decisions

| Condition | Exposure | Remediation interpretation |
|---|---|---|
| Running pod uses vulnerable resolved digest | `running` | open / investigate |
| No running pod but desired controller references digest | `configured_not_running` | open; may restart |
| Historically observed digest, no in-scope current desired/runtime refs, complete fresh snapshot | `historical_observed` | retirement candidate, manual confirmation |
| Source unavailable / unresolved digest / missing coverage | `unknown` | no automatic closure |
| Replacement digest is deployed but vulnerable digest still referenced elsewhere | running or configured elsewhere | not verified |
| No current in-scope refs, patched digest observed, coverage fresh, scan confirms fixed package | historical | `verified_in_scope` with scope/time caveat |
| Previously verified digest redeployed | running/configured | `regressed` |

---

## 7. Security policy, CI and admission enforcement

### Policy format

Version a repository-owned YAML or JSON ruleset (schema validated) with:
- Allowed registries, immutable digest requirement, minimum scan freshness, allowed scanner versions/database age.
- Disallowed vulnerability thresholds with a **documented exception** model. Consider fixed versions, VEX status, exploitation information, and workload scope where supported, but don't invent a universal numeric risk score.
- Required image attestation predicate type, signer trust anchor, policy ID/version, max age, and response on missing/unknown evidence.
- Kubernetes hardening policies: privileged containers, host namespaces/path mounts, unsafe capabilities, run-as-root, disallowed registries; these are distinct from vulnerability decision policies.

Policy evaluation must emit `allow`, `deny`, or `review_required` (fail closed where the configured protected namespace requires approval). Every decision needs stable reason codes and input evidence IDs.

### Security attestation flow (required end-to-end)

1. Build/push a real image digest to the **local OCI registry** or **Floci ECR-backed registry**.
2. Resolve immutable digest and run real Trivy image scan, record scanner DB/version and evidence hashes.
3. Evaluate policy and ensure only an authorized signer signs a **passing** assessment. Sign a custom in-toto predicate with Cosign, bound to the exact image digest and policy version. Document signature/attestation storage layout and registry capability.
4. Independently verify signature and trusted signer identity; check predicate subject, policy version, issue/expiry time, and scan freshness.
5. Configure a working Kyverno verification policy that validates the relevant attestation and rejects an unauthorized image in Kind. If Kyverno cannot express **all** freshness/expiry rules with the pinned version, pair it with a tested, fail-closed admission integration or a bounded policy-token mechanism; **do not silently omit expiration**.
6. Test: signed good digest allowed; unsigned digest denied; signed for other digest denied; modified predicate denied; stale policy version denied; expired approval denied; unsigned/missing scan denied; prohibited privileged pod denied; valid nonprivileged pod allowed.
7. Revocation/reassessment: after new vulnerability intelligence or policy change, mark prior verdict outdated and ensure the **next admission** is denied without a valid newly issued assessment. Clarify that Kyverno admission does not evict already-running pods.

### Operational security

Never permit arbitrary external images into signature trust scope simply because their owners published an attestation. Trust signing identity and provenance. Allow development keys only in a local test profile. Do not expose signing API publicly or give the watcher signing credentials. Prefer read-only Kubernetes watcher RBAC and separate narrowly scoped apply permissions for test harness. Any exceptions require owner, justification, expiry, approver and auditable linkage to a specific digest/policy.

---

## 8. Floci / ECR integration — mandatory MVP, bounded fidelity

**Important verified limitation:** Floci implements ECR API + real OCI backing, but ECR `StartImageScan` and `DescribeImageScanFindings` are **not implemented** (source: <https://floci.io/floci/services/ecr/>). Do **not** make successful ECR CVE findings calls a condition of a working integration or invent findings under Floci ECR. Any future Inspector adapter using fixtures must be explicitly marked `synthetic_contract_test`, not `real_aws_scanning`.

### MVP acceptance workflow

1. Start Floci locally under Docker Compose using a pinned image and ephemeral local AWS credentials. Document host network and container registry hostname resolution, Docker Desktop/ARM64 issues, and TLS/insecure-loopback **lab-only** operation.
2. Via AWS CLI or boto3 with `endpoint_url`, create ECR repository; list/describe repository and image metadata using supported Floci API actions.
3. Build a minimal pinned demo image, tag/push to Floci's OCI registry, pull it using a clean image store, resolve immutable digest and assert bytes/manifest identity.
4. Use Trivy to scan that **actual pushed image** (or a reproducibly pulled equivalent), produce vulnerability findings and associate them with digest via our ECR adapter. Do not pretend Floci itself scanned the image.
5. Use the same image in a Kind deployment; ensure Kind's container runtime can pull through network/CA setup or pre-load pinned image with an explicit digest mapping. Test network resolution from inside nodes; no silent fallback to unrelated local tag.
6. Run correlation and policy evaluation on the Floci ECR artifact and observed Kind workload. Generate signed attestation and demonstrate verification in an OCI registry compatible with Cosign/Kyverno. If Floci registry cannot support referrer/signature semantics reliably, use an **explicit separate local OCI registry for attestation storage**, and document two-repository trust and exact immutable binding; don't count unverified attestation storage as supported by Floci.
7. Keep a non-emulator registry adapter for portability and unit tests. Optional Terraform smoke test against supported emulated ECR creation; do not require real AWS account.
8. Maintain a compatibility ledger: AWS API operation, Floci version, status `works/unsupported/workaround`, test name and actual result.

### AWS future adapter

Design `RegistryInventoryProvider` interface and an optional `InspectorFindingProvider` interface, but do not implement full Inspector scanning, image-to-workload mapping, ECS, or EKS in MVP. If future fixtures simulate Inspector, preserve explicit fixture provenance and document what they **do not validate**.

---

## 9. Compliance and PCI DSS evidence mappings — mandatory MVP

### Intended result

For a small validated set of technical controls, show which image/workload/security assessments provide relevant evidence, whether the **technical condition** passed, failed, or needs review, and what the tool **cannot** determine. This is not a complete organization audit and not regulatory legal advice.

### Required coverage

- **CIS Kubernetes Benchmark**: at least 4–6 selected checks applicable to the *tested* Kind/Kubernetes/Trivy version; record benchmark version, applicability and evidence source. Separate cluster-level config tests from workload-only checks and account for managed-service-specific exclusions.
- **NIST SP 800-53 Rev. 5**: at least 4 validated mappings such as RA-5 (vulnerability monitoring/scanning), SI-2 (flaw remediation), CM-6 (configuration settings), AC-6 (least privilege) **where technical evidence genuinely supports them**. Version the control catalog and mapping.
- **PCI DSS v4.0.1**: at least 2–3 selected requirements (one starting candidate: 6.3.3); verify every ID and requirement text from PCI SSC's authoritative v4.0.1 publication before implementation. Candidate adjacent requirements might relate to vulnerability identification/risk ranking and security testing, but **do not claim a direct match without verification**. Record scoped assumption (e.g., fictional payment workload), evidence applicable to container image patching, missing manual elements such as CDE applicability, risk ranking/SLA, and human review. Regulatory mappings remain `requires_review` when organization-wide facts are absent.

### Explicit rules

- Compliance mapping is evidence-backed `technical_check -> framework requirement`, never `CVE -> organization noncompliant`.
- Include framework version, official URL/reference, mapping revision, technical assessment procedure, applicability, assets in scope, evidence IDs, timestamps, unsupported aspects, and human reviewer field.
- Distinguish `not_applicable` from `not_tested` and `insufficient_evidence`.
- Never calculate an unqualified “PCI compliant 92%” or “HIPAA certified” score.
- Preserve a frozen evidence package: selected raw scan outputs/hashes, policy version, workload observations, control results, signer identity, and report generation time.
- Add an example simulated audit export for a fictional PCI-relevant payment workload, clearly labeled as **demo**, not real audit attestation.
- Report stale/missing evidence as requiring reassessment. Handle benchmark ID drift explicitly.

### Minimal mapping format

```yaml
mapping_id: pci-4.0.1-6.3.3-container-patching
framework: PCI_DSS
framework_version: '4.0.1'
control_id: '6.3.3'
mapping_version: '1.0.0'
reference_url: 'VERIFY_OFFICIAL_REFERENCE_BEFORE_USE'
technical_check_ids:
  - image-vulnerability-inventory
  - remediation-verified-in-scope
required_evidence:
  - image_digest
  - scan_timestamp
  - workload_inventory_snapshot
  - remediation_history
assessment_limitations:
  - organizational_CDE_scope_not_determined
  - organization_patch_deadlines_require_review
```

The placeholder reference is a **required TODO for Codex to resolve**, not acceptable shipped output. Enforce a test that release mappings have real verified reference URLs and a source review record.

---

## 10. Local development / deployment experience

The ideal developer can run the platform from an IDE/coding-agent terminal on a capable Mac/Linux host with Docker. CI unit tests must not require nested virtualization or privileged cluster access.

### Expected scripts (proposed interface)

```bash
make doctor              # check Docker, CPU architecture, dependencies, ports
make bootstrap           # Python deps, external binaries pinned, local config
make up                  # start app + Floci + registries (no cloud credentials)
make kind-up             # create Kind cluster and install pinned Kyverno
make demo-images         # build/push pinned test images and resolve digests
make scan                # run real Trivy and ingest findings
make observe             # begin list/watch/reconciliation worker
make demo                # run the five-plus test scenarios and export evidence
make sign-demo           # issue local-only authorized assessment and Cosign attestation
make policy-test         # actually apply allow/deny workloads and assert admission responses
make controls            # export CIS/NIST/PCI evidence reports
make test                # fast unit + contract suite
make test-integration    # real Docker/Kind/Floci/Trivy/Kyverno suite
make down                # stop services without deleting persisted evidence
make reset-demo          # explicitly delete only labeled demo artifacts
```

These are targets to implement, **not** claims that they already exist. If tooling cannot be installed non-interactively on a host, provide `make doctor` with actionable errors and a verified manual prerequisite. Never write a bootstrap script that silently runs privileged commands or destroys existing clusters.

### Environment profiles

- `unit`: no Docker or network; test pure policy, fixtures, migration and mapping logic.
- `local`: Kind, SQLite, real Trivy, local OCI registry, Floci, Kyverno, Cosign; default.
- `offline`: preloaded fixtures and cached images/databases; transparently distinguish fixture scans from newly executed vulnerability scans.
- `aws-smoke` (post-MVP): optional real AWS, explicit credentials and budget guardrails, never default.

### Docker networking

Handle multi-network registry addresses, Docker Desktop and Kind containerd pulls and trust of local TLS roots, ARM64 vs AMD64 platform manifests. **End-to-end proof must use the same image digest** in registry, Trivy scan, signed attestation, and running/admitted workload. Record the resolved identities in the demo report.

---

## 11. Repository layout (recommended)

```text
csle/
  README.md
  AGENTS.md
  HANDOFF.md
  Makefile
  pyproject.toml
  uv.lock
  .github/workflows/{ci.yml,integration.yml}
  app/
    cli.py
    config.py
    models/{artifacts.py,workloads.py,findings.py,decisions.py,controls.py}
    collectors/{kubernetes.py,trivy.py,oci_registry.py,floci_ecr.py}
    store/{db.py,migrations/,repositories.py}
    engine/{correlate.py,lifecycle.py,policy.py,remediation.py}
    supply_chain/{attest.py,verify.py}
    compliance/{mapping_loader.py,evaluate.py,export.py}
    reports/{json.py,html.py}
  policy/{release-policy.yaml,exceptions.schema.json,kyverno/}
  compliance/{cis/,nist/,pci/}
  contracts/{v1/,fixtures/}
  infra/{compose.yaml,kind.yaml,floci/,terraform-ecr/}
  demos/{images/,workloads/,scenarios/,expected/}
  scripts/{doctor.sh,bootstrap.sh,teardown.sh}
  tests/{unit/,contract/,integration/,e2e/}
  docs/{architecture.md,threat-model.md,decisions/,dependency-matrix.md,
        floci-compatibility.md,controls-methodology.md,test-methodology.md,
        performance.md,limitations.md,demo-runbook.md,results/}
```

Do not create empty directories solely for appearance. Use `AGENTS.md` for concise durable repo guidance. Never modify other user repositories (including DetectBridge/ResponseForge); this is fully standalone.

---

## 12. Implementation milestones and acceptance gates

Build vertical slices with realistic, tested checkpoints. **All eight milestones below collectively define the MVP**; order may be optimized for dependencies. Only claim a phase complete after verifiable tests pass.

### P0 — Discovery, compatibility and threat model

- Inspect local OS/architecture, Docker and repo state. Select versions based on current docs; prove Kind + Kyverno + Floci + OCI registry + Trivy + Cosign compatibility using minimal smoke experiments.
- Write architecture ADRs, exact chosen license/dependency versions, risk register and test matrix.
- Define user stories, schemas and immutable digest strategy. Verify PCI mappings against official requirements.
- **Gate:** documented dependency matrix and successful/failed smoke tests, with identified workarounds; no fabricated integrations.

### P1 — Data model, CLI, Trivy ingestion

- Implement migrations and model validation; scan one pinned real image; persist raw report hash, normalized findings, scan metadata, image identity; include fixtures for fast tests.
- **Gate:** reimport idempotency, malformed scanner input handling, deterministic CLI/JSON output, image digest resolution evidence.

### P2 — Kubernetes lifecycle collector and reconciler

- Real Kind cluster, watched workload kinds, snapshot/relist, owner references, event persistence, restart checkpoint, coverage gap signaling; events and snapshots visible through CLI.
- **Gate:** short-lived job observed then deleted remains in historical store; scale-to-zero still references desired image; outage yields explicit unknown coverage; no false invented history.

### P3 — Correlation and remediation decision engine

- Pure deterministic classification, finding-to-digest-to-workload join, remediation/regression inference, stable reason codes, scoped verification and unknowns.
- **Gate:** state matrix unit tests, multiple namespaces, image tag mutation, unresolvable runtime IDs, partial inventory, patched replacement and regression cases all behave as specified.

### P4 — Floci ECR integration (MANDATORY)

- Deploy Floci with real OCI-backed ECR; push/pull test image, boto3/CLI list/describe images, scan with Trivy, join Floci inventory to Kind workloads, log unsupported scanner APIs and workarounds.
- **Gate:** command-driven integration test proving same digest across Floci registry, scan, observation; compatibility ledger; no claims of native Floci CVE scanning.

### P5 — Security policy and signed attestations (MANDATORY)

- Versioned release policy, scan freshness, exceptions; Cosign signed predicate with immutable image digest; independent verification; CI security gate and Kyverno admission policies.
- **Gate:** real allow/deny Kind admission test suite covers trust identity, wrong digest, modified content, expired/stale policy, unsigned image and privileged workload. **Do not mark complete with mock verification only.**

### P6 — CIS/NIST/PCI technical evidence (MANDATORY)

- Implement versioned control mapping catalogs, selected technical checks, official-source verification, JSON + HTML/Markdown export with provenance, limitations and manual-review states.
- **Gate:** CIS and NIST results plus **at least 2–3 authoritative PCI DSS 4.0.1 mappings** in the exported sample, evidence hashes reproducible, explicit no-certification disclaimer, failing evidence or unknown applicability shows review rather than spurious pass.

### P7 — Demo evaluation, recovery and polish

- Run all scenarios, negative controls, periodic-scan baseline, integration/restart tests, metrics, resource consumption checks, docs/diagrams and GitHub Actions.
- **Gate:** fully reproducible demo on supported host; clean CI, no false claims; known gaps listed; metrics derived from recorded runs. Include documented reset/cleanup.

### Optional future work (excluded from MVP)

Real EKS/ECR/Inspector, ECS, cloud identity analysis, multiple clusters, Postgres, dashboard, eBPF/running package reachability, AMI security, multi-tenant GRC, AI investigation, continuous production response automation. All should remain optional adapters, not core dependencies.

---

## 13. Required demonstration scenarios and acceptance tests

Each scenario must have a setup command, input images/digests, expected events/observations/decisions, negative control, measured timing, and recorded artifacts. Use intentionally vulnerable **non-sensitive** demo images/fixtures, sandbox namespaces, resource labels and deterministic teardown.

| ID | Scenario | Mandatory assertion |
|---|---|---|
| S1 | Job starts, finishes quickly, TTL deletes | Previously captured UID, digest and observed history persist; scan-only baseline may miss it |
| S2 | Deployment scales to zero | No running pods, but desired reference remains; finding not marked fixed/false positive |
| S3 | Vulnerable digest replaced with patched digest | Only `verified_in_scope` after all observed current references and scan evidence support conclusion |
| S4 | Previously removed digest reintroduced in new namespace | Regression identified, affected workload and original remediation linked |
| S5 | Kubernetes watcher stopped, workloads mutate, watcher restarts | Current snapshot converges; missing history explicitly marked as coverage gap/unknown |
| S6 | Deployment attempts unsigned/wrong-digest/stale-attestation image | Real Kyverno admission denial; audit reason captured |
| S7 | Signed, policy-approved digest with valid time window | Real Kyverno admission success; runtime image digest verified where available |
| S8 | Privileged container configuration | Real Kyverno policy denial independent of CVE scan |
| S9 | Floci-backed ECR image pushed, pulled and scanned | Byte/manifest/digest association verified; no Inspector scanning claim |
| S10 | CIS/NIST/PCI evidence export | Accurate technical assessment and limitations; source/version present |
| S11 | Duplicate watch events / repeated scan imports | Idempotent storage and stable decisions |
| S12 | Benign image and workload without prohibited condition | No invented CVEs, no gratuitous denial; accurate clean/unknown status |
| S13 | Mutable tag points to new digest | New artifact identity; no stale vulnerability or attestation inheritance |
| S14 | Scanner unavailable or CVE DB too old | Evaluation yields `review_required`/deny according to policy, not an unearned allow |

### Baseline evaluation

Run same repeatable test suite under:

**Baseline:** periodic inventory + Trivy image scanning, no persisted watch history.
**System:** watch observations + periodic reconciliation + historical evidence + policy/enforcement.

Measure:
- Observed ephemeral workload capture proportion (among workloads created under known observation coverage).
- Exposure classification precision/recall against manually labeled scenario truth; report support and denominators.
- Remediation verification and regression detection accuracy, including false closure count.
- Detection/inventory update latency distribution; p50/p95 where sample size warrants.
- Reconciliation completion after interruptions; number/duration of unknown coverage gaps.
- False allow/deny rate for attestation and policy controls across allow/deny fixtures.
- CPU, memory, API request frequency, duplicate scan avoidance, storage growth.
- Report mapping provenance and evidence coverage by selected technical control.

Never predeclare “reduced false positives by 70%” or invented MTTR metrics. Produce actual measurement scripts and raw results, with environment/platform and limitations.

---

## 14. API/CLI expectations

Prefer a stable CLI instead of writing a web application. Recommended commands (names may change after ADR, but features must exist):

```text
csle doctor
csle scan image <ref> --format json
csle inventory workloads --cluster kind-csle
csle findings list --exposure running
csle findings explain <finding-id>
csle lifecycle image <digest>
csle remediation verify <finding-id> --scope kind-csle
csle policy evaluate image <digest> --policy policy/release-policy.yaml
csle attest issue <digest> --policy ... --local-dev-key
csle attest verify <digest> --trusted-key ...
csle registry sync --provider floci-ecr
csle compliance report --framework pci-dss --format html
csle demo run --all
```

A simple API may be useful for future adapters, but **not required** unless it reduces complexity. Every command must have help/exit code semantics and machine-readable output. Security enforcement errors must return nonzero status. Evidence `explain` should return exact observation IDs, timestamps, policy, and result reason codes.

---

## 15. Security engineering / threat model requirements

Document assets, adversaries, threat boundaries, abuse scenarios and controls:

- **False trust:** forged Trivy result, forged attestation, wrong digest, mutable tag, attacker-signed policy passing with wrong identity; sign only after trusted independent scan and verify signer identity.
- **Replay attacks:** previously valid attestations reused after expiry, CVE DB update, policy change; freshness and policy revocation checks.
- **Data integrity:** corrupt/missing observation DB, tampered local reports, invalid evidence references; hashes, migration tests, append-only observation model where feasible.
- **Availability:** Kubernetes API/watch failure, Floci outage, Trivy database unavailable, registry unresponsive, Kyverno unavailable. State failures explicitly; admission failure behavior should align with protected-namespace fail-closed policy while preserving a documented rescue procedure for a broken lab.
- **Least privilege:** watcher is read-only, signing key separate from collector, policy-admin privileges separate from runtime, GitHub Actions permissions minimal, credentials never logged/committed.
- **Supply chain:** pin dependencies, verify downloads and OCI image digests, avoid unsafe shell interpolation, scan own images, no untrusted PR use of signing credentials.
- **Local test safety:** only project-labeled namespace and resources deleted, never scan or mutate third-party clusters by default, no public exposure of Floci admin endpoints or registry signing keys, no `terraform destroy` outside explicit emulator/test state.

Document explicit residual risks: unobserved ephemeral workloads in downtime, imperfect package applicability, limited runtime reachability, scan freshness, regulator applicability, emulator fidelity, policy bypasses through privileged cluster administrators or alternate admission paths.

---

## 16. Development standards for Codex

1. **Plan first**: Read this document, inspect existing repo and host constraints; produce prioritized issue list and phased plan with concrete acceptance tests. If starting from scratch, initialize new standalone repository.
2. **Test-driven and evidence-driven**: tests alongside each implementation slice, fixture coverage for negative cases, real external integration tests before claiming tool support.
3. **Small changes**: bounded PR/commit series, document architecture decisions and tradeoffs, prefer simple solutions over speculative extensibility.
4. **No fake completion**: mock tests may demonstrate contract logic, not real Kubernetes admission, scan, Floci OCI behavior or Cosign verification. Mark implementation status `implemented / integration-tested / environment-blocked / deferred` independently.
5. **No hidden services**: don't add Redis, Kafka, Elasticsearch, SaaS APIs, or extra message brokers without proof of necessity.
6. **Do not ask for ongoing hand-holding** for routine implementation choices; select and document sensible defaults. Ask before privileged/destructive actions, connecting actual AWS accounts, or exposing private credentials.
7. **Maintain docs**: release notes, setup, dependencies matrix, threat model, limitations, control evidence methodology, demo results, and reproducible commands.
8. **Preserve source and reproducibility**: pin external datasets/images and references; cite license and origin of any third-party fixtures. Do not embed secret keys or scan private assets.
9. **Platform portability**: ensure at least one fully supported local developer configuration; detect unsupported ARM64/AMD64 or Docker limitations rather than pretending success.
10. **Resume claims**: do not publish quantitative improvements unless measured; separate local/emulated integration from real AWS validation.

---

## 17. Definition of done

The **MVP is complete only if all are true**:

- A fresh clone on a documented supported environment can bootstrap dependencies, create Kind, start Floci-backed ECR and a registry, run real Trivy scans and install a pinned Kyverno.
- A short-lived Kubernetes Job is captured, stored, and later explained even after deletion; unknown coverage gaps are handled without fabricated history.
- Findings are linked to immutable image identities and classified along validity / exposure / remediation dimensions; scale-zero and tag-reuse cases do not yield false closure.
- Remediation replacement and regression are demonstrated with exact image digests and a reproducible scenario suite.
- A genuine Floci ECR repository accepts a pushed OCI image that can be pulled back and enumerated through supported AWS APIs; scan association is done by **Trivy**, never a fictional ECR scanner.
- **Cosign creates and verifies a signed digest-bound attestation, and real Kyverno admits a valid image and denies missing/invalid/stale/unauthorized evidence in Kind**. Demonstrate cryptographic, content, version and freshness controls with tests.
- GitHub Actions/local CI fails correctly for a disallowed image/configuration, without granting untrusted builds signing privileges.
- Exported evidence includes selected CIS, NIST and **PCI DSS 4.0.1** mappings with official references, scope, evidence and limitations; there are no organizational certification claims.
- A documented baseline evaluation and negative controls demonstrate strengths and blind spots; metrics are reproducible, not invented.
- Setup/teardown is documented and constrained to project-owned resources. No real AWS account or paid service is required for the MVP.
- README includes architecture, one-page demo, tests, sample report screenshots, observed results and known limitations.

If a critical external tool cannot meet an acceptance gate, **do not mask the gap**. Provide a compatibility proof, an alternative grounded design that preserves security properties, tests of the workaround, and mark the gate incomplete until validated. A single fully demonstrated end-to-end path is more important than many superficial integrations.

---

## 18. Codex first instruction (copy/paste)

> Read `HANDOFF.md` completely and treat it as the authoritative scope and acceptance contract. Build a local-first, security-first Container Vulnerability Lifecycle & Enforcement project using a real Kind cluster, Trivy, Kyverno, Cosign, an OCI registry, Floci emulated ECR, and selected CIS/NIST/PCI DSS v4.0.1 technical evidence mappings. **Signed image security attestations, Floci/ECR integration and PCI DSS mappings are mandatory MVP features, not later enhancements.**
>
> First inspect the host and upstream tooling, verify compatibility constraints, and propose a phased implementation plan with tests and clear non-goals. Then implement in small validated slices. Prioritize real evidence, immutable image digests, workload event history/reconciliation, orthogonal lifecycle states, correct remediation/regression decisions, trusted admission enforcement and reproducible local testing. Never fabricate scanner results, AWS support, historical events, compliance claims, or performance metrics. Keep architecture significantly smaller than DetectBridge; no Kafka, distributed event processing, large UI or AI. Only call a milestone complete after its specified real tests pass; document blockers and limitations honestly. Do not perform destructive/privileged operations or use a real AWS account without explicit authorization.

---

## 19. Primary upstream references for implementation

- Kubernetes API concepts and watch/list semantics: <https://kubernetes.io/docs/reference/using-api/api-concepts/>
- Kind: <https://kind.sigs.k8s.io/>
- Kubernetes workload resources: <https://kubernetes.io/docs/concepts/workloads/>
- Trivy documentation and experimental compliance mode: <https://trivy.dev/docs/latest/guide/compliance/compliance/>
- Floci repository: <https://github.com/floci-io/floci>
- **Floci ECR behavior and unsupported scanning APIs**: <https://floci.io/floci/services/ecr/>
- Floci ECR quick start: <https://github.com/floci-io/floci/blob/main/docs/getting-started/quick-start.md>
- Cosign attest: <https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md>
- Cosign verify: <https://docs.sigstore.dev/cosign/verifying/verify/>
- Kyverno image validating policies: <https://kyverno.io/docs/policy-types/image-validating-policy/>
- NIST SP 800-53 Rev. 5: <https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final>
- PCI Security Standards Council (official standards and document library): <https://www.pcisecuritystandards.org/document_library/>
- CIS Kubernetes Benchmark: obtain the benchmark edition applicable to chosen Kubernetes version from CIS official source, record exact version.

**Reference policy:** Verify versions and exact framework requirement wording against official sources as part of P0. This handoff intentionally avoids guessing CLI details or implying ECR image scanning exists in Floci. Changes to upstream APIs are tracked through documented ADRs and integration tests, not silently assumed.
