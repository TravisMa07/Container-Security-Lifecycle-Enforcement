# Container Security Lifecycle & Enforcement

CSLE is a planned local-first container vulnerability lifecycle and deployment enforcement tool. It will correlate immutable image identities with Kubernetes workload history, verify scoped remediation and regression, and export bounded technical evidence.

**Current status: P0 qualified on the implementation branch; P1–P7 remain planned and the MVP is incomplete.** [HANDOFF.md](HANDOFF.md) is the authoritative specification. Signed security attestations, functional Floci/ECR integration, and PCI DSS 4.0.1 evidence mappings are mandatory MVP gates.

The implementation stays small: one Python CLI/application, one watcher process, SQLite, and external Kind, Trivy, Kyverno, Cosign and Floci services. No distributed pipeline, large UI or real AWS account is required.

The repository is public. [Implementation issues](https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/issues) track P0–P7. Each implementation item will use a linked PR when work begins; future-phase PRs are not created in advance. See [contributing](CONTRIBUTING.md).

## Start here

- [Architecture and decisions](docs/architecture.md)
- [Phased implementation and acceptance plan](docs/roadmap.md)
- [Development workflow](docs/sdlc.md)
- [Dependency research and host observations](docs/dependencies.md)
- [Threat model](docs/threat-model.md)
- [Qualification ledger](docs/implementation-ledger.md)
- [Limitations](docs/limitations.md)

Run `make bootstrap` for project-local pinned P0 tools, `make test` for offline safety tests, `make check` for document integrity, and `make doctor` for read-only prerequisite discovery. See the [P0 runbook](docs/p0-runbook.md) and [P0 results](docs/p0-ledger.md). P0 source review, contracts, negative cases and a clean-clone Kubernetes1.35.10 qualification passed. [Final evidence](docs/results/p0-final-qualification.json) records the source revision and tested scope; PR#9 remains draft/unmerged. No product application or full demo command exists.

Development host observed: macOS 26.5.1 ARM64, Docker Desktop 4.92.0 / Engine 29.8.0, 15 Docker CPUs and about 7.75 GiB Docker memory. Linux and AMD64 support remain unqualified.

Licensed under [Apache-2.0](LICENSE), selected by the owner during P0. External tools, datasets and images retain their own licenses and usage terms.
