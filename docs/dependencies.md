# Dependency research and environment

Observed 2026-11-19. Documentation/release discovery is distinct from a runtime smoke result. P0 tool/image pins are now in toolchain.lock.json and SDK dependencies in requirements-p0.lock. Application dependencies are P1 work. P0 remains open; initial candidates below are retained as research history.

## Host evidence

Read-only commands: `uname -sm`, `sw_vers`, `command -v`, `docker version`, `docker info`, `docker context show`, `kubectl version --client -o json`, `uv python list --only-installed`, and authenticated GitHub identity/repository lookup.

| Component | Observed | Qualification |
| --- | --- | --- |
| Host | Darwin ARM64, macOS 26.5.1 build 25F80 | Host discovery only |
| Docker | Desktop 4.92.0; Engine 29.8.0; desktop-linux; linux/aarch64; containerd 2.3.5 | Client/server contact passed; no image/cluster smoke |
| Docker resources | 15 CPUs; 8,318,844,928 bytes memory | Full stack capacity unmeasured |
| kubectl | v1.36.1 darwin/arm64 | Client only; cluster-version skew not tested |
| uv | 0.13.6 | Discovery only |
| Python | system 3.9.6; uv-managed 3.12.12, 3.13.15, 3.14.10 installed | Select 3.12 baseline; app dependencies not resolved |
| Git/GitHub | Git installed; gh authenticated as TravisMa07; requested repository absent (404) | Initial creation/push authorized |
| Kind, Helm, Trivy, Cosign, AWS CLI, Terraform | Not found on PATH | Missing tooling; no integration claim |

## Official source review

- [Kind quick start](https://kind.sigs.k8s.io/docs/user/quick-start/) documents v0.33.0 and ARM64 binaries; choose an explicitly supported Kubernetes node digest, not an assumed latest tag.
- [Kyverno image validating policy](https://kyverno.io/docs/policy-types/image-validating-policy/) provides custom attestation and attestor APIs. API existence does not prove our time, revocation, registry or signature-format behavior.
- [Floci ECR](https://floci.io/floci/services/ecr/) documents ECR APIs and OCI backing, with scanning and signing limitations. Prove direct OCI attachment compatibility separately; use a documented separate attestation registry only if necessary.
- [Cosign verification](https://docs.sigstore.dev/cosign/verifying/verify/) and [attest CLI](https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md) are the signature-contract sources. Review current storage/bundle defaults against Kyverno.
- [Trivy compliance](https://trivy.dev/docs/latest/guide/compliance/compliance/) requires exact schema and benchmark-version review; do not rely on experimental IDs as stable contracts.
- [Kubernetes API semantics](https://kubernetes.io/docs/reference/using-api/api-concepts/) govern opaque resource versions, relist and watch gaps.
- [NIST source](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final), [PCI library](https://www.pcisecuritystandards.org/document_library/) and [CIS benchmark](https://www.cisecurity.org/benchmark/kubernetes) require exact catalog/version review before mappings ship.

## Compatibility experiment register

| Experiment | Expected proof | Actual result |
| --- | --- | --- |
| Docker contact | Engine reachable, architecture/resources recorded | Passed read-only discovery |
| Kind node + Kyverno | Pinned node/images, supported skew, ready controllers | Not run; tools absent |
| Floci ECR + OCI | Create/list/describe, real push/pull/manifest identity | Not run |
| Trivy | Actual digest-bound image scan + DB/version/raw hash | Not run; tool absent |
| Cosign + registry | Custom predicate signed and independently verified | Not run; tool absent |
| Kyverno admission | Valid allow; all trust/time/version/config negatives denied | Not run |
| Framework sources | Exact official editions, reviewed requirement IDs and bounded interpretations | Pending; no release mappings |

Pin versions, download checksums, OCI index/platform digests, licenses and source URLs in a machine-readable manifest after selection. Record installed versions separately from candidates. Security-patch review and compatibility qualification remain release gates.

## Candidate version matrix (not an installation lock)

Read-only research on 2026-11-19 identified the following official releases. This initial candidate list is superseded by the selected pins and bounded runtime evidence in the P0 ledger. Release discovery alone does not establish patch status or support.

| Tool | Candidate | Official source |
| --- | --- | --- |
| Kind | v0.33.0 | <https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0> |
| Kubernetes | v1.37.0, node digest `sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5` | Same Kind release; verify fetched manifest before use |
| Kyverno | v1.20.0; Helm chart 3.10.0 | <https://kyverno.io/docs/installation/releases/> and <https://kyverno.io/docs/installation/installation/>; documented Kubernetes 1.34–1.37 support |
| Cosign | v3.1.4 | <https://github.com/sigstore/cosign/releases/tag/v3.1.4> |
| Trivy | v0.76.2 | <https://github.com/aquasecurity/trivy/releases/tag/v0.76.2> |
| Floci | 2.5.0 | <https://github.com/floci-io/floci/releases/tag/2.5.0> |

Cosign 3 storage/bundle defaults require a joint Kyverno retrieval experiment. Current ImageValidatingPolicy documents `policies.kyverno.io/v1`, explicit per-policy registry credentials and extraction of the entire in-toto statement (custom fields under `.predicate`). Verify signatures before extraction. Do not assume time checks remain correct under verification caches.

### Historical PCI source-access result (resolved by owner-supplied publications)

The official library links the v4.0.1 standard to <https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0_1.pdf>; the research fetch returned HTTP 403. Full source/testing-procedure review was pending at discovery; the completed owner-supplied review in [framework sources](framework-sources.md) supersedes that state. [Official FAQ 1597](https://www.pcisecuritystandards.org/faqs/1597/) supports candidate 6.3.1, 6.3.3 and 11.3.1 investigation, but does not replace full review. Scans alone do not establish entity risk ranking, vendor patch-release dates, patch deadlines, independent personnel or full CDE coverage. No approved mappings are included.

## Selected P0 toolchain and actual status

[Machine-readable pins](../toolchain.lock.json) record upstream artifact SHA-256, chart hash, OCI index/ARM64 manifests and tool licenses. [Hash-locked SDK requirements](../requirements-p0.lock) isolate boto3 1.44.6 under Python 3.12.12. Kind 0.33.0, Cosign 3.1.4, Trivy 0.76.2 and Helm 3.22.1 were actually provisioned and their version commands executed on Darwin ARM64. AWS CLI/Terraform remain absent; the real ECR experiment uses boto3, so neither is implied installed. Development formatting used exact Ruff 0.17.6.

The initial host/experiment tables above are discovery-time records. Current [P0 results](p0-ledger.md) supersede their Not-run entries: real Kind/Kyverno readiness, Floci OCI/ECR identity, Trivy scan, one-assessment Cosign/admission/runtime path and specific initial negatives were observed. Initial reassessment failed closed on cached older payload expiry. The corrected fixed v2/uncached profile now passes successive admissions and strict initial negatives without removing old evidence. That initial qualification state is superseded by the final P0 ledger/source-aligned results.

Official pinned repository license review: Kind, Helm, Trivy, Kyverno and Distribution use Apache-2.0; Cosign's exact LICENSE text is Apache-2.0 although GitHub's detector returned NOASSERTION; Floci 2.5.0 uses MIT. Component repository licenses do not relicense complete image packages. Owner selected Apache-2.0 for CSLE. Checksums are rooted in upstream HTTPS metadata; independent publisher-attestation verification, complete component security-patch status, supported benchmark applicability and fresh-clone full-stack acceptance remain open.

## P0 closure dependency review — 2026-11-19

The initial Python/registry/node pins were compatibility experiments, not a security clearance. Current qualification upgrades Python to [3.12.16](https://www.python.org/downloads/release/python-31216/) and the backing registry to [Distribution 3.1.2](https://github.com/distribution/distribution/releases/tag/v3.1.2), addressing upstream published fixes. Registry 2.8.3 is affected by [digest verification](https://github.com/distribution/distribution/security/advisories/GHSA-685w-q87j-wqw3) and [tag deletion](https://github.com/distribution/distribution/security/advisories/GHSA-6pjf-3r9x-m592) advisories. Floci's core ECR/OCI path was retested with 3.1.2; its Distribution-2-specific garbage-collection helper remains unqualified and unused.

The official Kind node catalog had no patched 1.37.2 image. Instead, `make p0-node` uses Kind's supported release-file builder with checksum-pinned [Kubernetes 1.37.2 ARM64 archive](https://dl.k8s.io/v1.37.2/kubernetes-server-linux-arm64.tar.gz) and digest-pinned Kind base. This addresses the [StatefulSet/ControllerRevision fix](https://github.com/kubernetes/kubernetes/issues/142097); the separate [Windows UNC issue](https://github.com/kubernetes/kubernetes/issues/142098) does not apply to this Linux profile. The built node's Docker config ID is recorded and compared to the actual created container; it is not mislabeled an OCI manifest digest. Build inputs/outcomes are reproducible, but bit-for-bit output identity is not claimed: generated Docker metadata can differ per build.

Independent official-release review found the selected Kind 0.33.0, Kyverno 1.20.0, Cosign 3.1.4, Trivy 0.76.2 and Floci 2.5.0 current stable. Helm 3.22.1 is current in its supported 3.x line; Helm 4 is not needed for the tested Kubernetes libraries/profile. Latest does not mean vulnerability-free.

Embedded Go metadata (571 unique module/version pairs queried against OSV) still has matching advisories. Bounded applicability review:

| Advisory family | P0 exposure and limits |
| --- | --- |
| [Go CA distrust](https://vuln.go.dev/ID/GO-2026-6809.json) in Kind/Helm build versions | Kind uses the explicit local Unix engine; Helm uses a checksum-pinned local chart and project-loopback Kubernetes CA. Arbitrary external TLS usage is not qualified. |
| [HTTP/1 server race](https://vuln.go.dev/ID/GO-2026-6859.json) | These tested CLI paths do not expose that HTTP server API. No general reachability proof is claimed. |
| [compress malformed-input panic](https://vuln.go.dev/ID/GO-2026-6865.json) | Scanning/signing is restricted to the exact verified pinned fixture. Arbitrary-image resilience is a future adapter/release gate; a scanner failure cannot earn an allow. |
| [OpenTelemetry truncation](https://github.com/advisories/GHSA-q7gw-24fr-5p69) | No external telemetry collector is configured. Do not claim a full upstream module clearance. |
| [OpenPGP](https://vuln.go.dev/ID/GO-2026-5932.json), HTML parsers, Windows-only syscalls | Local ECDSA signing, pinned-chart installation and Linux/macOS profile exclude those intended paths; future feature use needs renewed review. |
| [Azure credential helper](https://vuln.go.dev/ID/GO-2026-6225.json) | Only explicit local registry endpoints/ephemeral keys are qualified; Azure credentials and registries are excluded. |

Fifteen exact Python SDK/schema/format dependencies were queried against OSV; no matching advisory was returned on this date. The lock now installs only the URI/date-time format validators actually used by the schemas, avoiding unrelated format extras. This is a version-feed result, not a claim of no vulnerabilities. Repository licenses and source origins remain recorded; OS/image transitive packages retain their own terms.

Raw official release, Kubernetes CVE feed, Go metadata and OSV responses are retained in ignored `.local/p0-sources/patch-review/` and `.local/p0/closure-python-audit.json`. Known upstream findings are explicit scoped limitations; P0 qualifies this local fixed-fixture path and does not approve production or arbitrary-image use.

## Final source-aligned selection

Source review of the supplied CIS2.1.0 publication found target1.34–1.35 versus audience1.35–1.37. The selected supported profile therefore uses the shared1.35 minor, with official stable1.35.10 release bytes SHA-256 `337982e3d5825f60d989b440c5ef441051ffec54659e9b11a7cdcaf218270157`. This is above the1.35.9 fix boundary for the previously reviewed controller issue. The pinned Kind release-file build, actual node/config identity and full scenario suite passed on that version; prior1.37.2 build inputs remain historical in the lock. Kubectl1.36.1 is within supported one-minor skew. Kyverno1.20 supports1.34–1.37. No new external service or source-gate waiver was introduced.

## P1 application dependencies and scanner boundary

P0 is merged at eb54a6d. P1 uses strict Pydantic2.14.4/core2.50.5 and a setuptools84.2.1 editable build. [Runtime lock](../requirements-app.lock) and [development lock](../requirements-dev.lock) contain exact package hashes; the development lock preserves all original P0 pins using constraints. Twenty packages returned no matching OSV advisory in the P1 point-in-time query (ignored .local/p1/osv.json), not a general security assurance. Python3.12.16 remains the locally qualified runtime.

The existing Trivy/Go malformed-compression advisory boundary is enforced by P1: independent loopback resolution must select the exact pinned demo manifest before invoking Trivy. Import/parser functionality can ingest other digest-bound reports but never upgrades them to executed evidence. Broad arbitrary-image execution is deferred until a patched pinned scanner or a renewed bounded applicability review supports it; no default-earned policy approval exists. No runtime/tool image pins changed during P1.
