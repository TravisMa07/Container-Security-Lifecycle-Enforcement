# Current limitations

P0 provides pinned local tooling, an isolated compatibility lab and real experiments; no application inventory, persistence, lifecycle engine, production policy service, compliance export or complete demo exists. No P0–P7 gate is complete.

A single-assessment path demonstrated Floci OCI bytes/ECR metadata → Trivy → Cosign → Kyverno admission and a matching runtime digest. The initial v1 reassessment failed closed on cached older evidence. A source-grounded fixed v2 schema plus disabled verification cache now passes two successive admissions and strict initial negatives while retaining old evidence. This profile is a narrow single-artifact compatibility prototype; the six canonical schemas, real wrong-subject/tampered/future/stale negatives and a fresh-clone qualification now pass. Exact official PCI/CIS source wording is the remaining P0 closure gate. See the [P0 ledger](p0-ledger.md); do not infer a complete signed-attestation product from a one-time smoke result.

Only ARM64 macOS provisioning was exercised. Linux/AMD64, offline setup, production TLS and AWS security fidelity remain unqualified. Known dependency/advisory applicability was reviewed for the fixed-fixture local profile; no blanket vulnerability-free or arbitrary-image assurance is claimed. No performance/baseline improvement claims exist.

Project license is owner-selected Apache-2.0. NIST source review is recorded; full authoritative PCI/CIS source review remains open and no approved compliance mappings ship. All containers/resources and evidence remain retained; the older project lab containers are stopped and the patched qualification profile is running. No resources were deleted. Cleanup is not implemented or implicitly authorized.
