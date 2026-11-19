# Dependency research and environment

Observed 2026-11-19. Documentation/release discovery is distinct from a runtime smoke result. Exact app dependencies and OCI digests are not locked yet; P0 remains open. Do not use these candidates as an install lockfile.

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

Read-only research on 2026-11-19 identified the following official releases. None has been installed or tested together here. Release discovery alone does not establish patch status or support.

| Tool | Candidate | Official source |
| --- | --- | --- |
| Kind | v0.33.0 | <https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0> |
| Kubernetes | v1.37.0, node digest `sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5` | Same Kind release; verify fetched manifest before use |
| Kyverno | v1.20.0; Helm chart 3.10.0 | <https://kyverno.io/docs/installation/releases/> and <https://kyverno.io/docs/installation/installation/>; documented Kubernetes 1.34–1.37 support |
| Cosign | v3.1.4 | <https://github.com/sigstore/cosign/releases/tag/v3.1.4> |
| Trivy | v0.76.2 | <https://github.com/aquasecurity/trivy/releases/tag/v0.76.2> |
| Floci | 2.5.0 | <https://github.com/floci-io/floci/releases/tag/2.5.0> |

Cosign 3 storage/bundle defaults require a joint Kyverno retrieval experiment. Current ImageValidatingPolicy documents `policies.kyverno.io/v1`, explicit per-policy registry credentials and extraction of the entire in-toto statement (custom fields under `.predicate`). Verify signatures before extraction. Do not assume time checks remain correct under verification caches.

### PCI source-access result

The official library links the v4.0.1 standard to <https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0_1.pdf>; the research fetch returned HTTP 403. Full source/testing-procedure review is pending. [Official FAQ 1597](https://www.pcisecuritystandards.org/faqs/1597/) supports candidate 6.3.1, 6.3.3 and 11.3.1 investigation, but does not replace full review. Scans alone do not establish entity risk ranking, vendor patch-release dates, patch deadlines, independent personnel or full CDE coverage. No approved mappings are included.
