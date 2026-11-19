# Current limitations

P0 provides pinned local tooling, an isolated compatibility lab and real experiments; no application inventory, persistence, lifecycle engine, production policy service, compliance export or complete demo exists. No P0–P7 gate is complete.

A single-assessment path demonstrated Floci OCI bytes/ECR metadata → Trivy → Cosign → Kyverno admission and a matching runtime digest. The initial v1 reassessment failed closed on cached older evidence. A source-grounded fixed v2 schema plus disabled verification cache now passes two successive admissions and strict initial negatives while retaining old evidence. This profile is a narrow single-artifact compatibility prototype; the full negative matrix, final contracts and fresh-clone qualification remain open. See the [P0 ledger](p0-ledger.md); do not infer a complete signed-attestation product from a one-time smoke result.

Only ARM64 macOS provisioning was exercised. Linux/AMD64, fresh-clone full-stack success, offline setup, production TLS, AWS security fidelity and full component security-patch qualification remain open. No performance/baseline improvement claims exist.

Project license is owner-selected Apache-2.0. NIST source review is recorded; full authoritative PCI/CIS source review remains open and no approved compliance mappings ship. All containers/resources and evidence remain retained; cleanup is not implemented or implicitly authorized.
