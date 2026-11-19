# Working on CSLE

Read HANDOFF.md completely. It is the authoritative product and acceptance contract. Then read README.md, docs/architecture.md, docs/sdlc.md, docs/roadmap.md, and the owning design/ledger before implementation.

- Preserve the modular monolith, SQLite and CLI scope. Do not modify other repositories.
- Signed security attestations, Floci/ECR and PCI DSS mappings are mandatory MVP work, never stretch goals.
- Freeze independent expectations before evidence-sensitive implementation. Record behavioral red, green, revision, commands, evidence and limitations. Mocks cannot qualify real integrations.
- Never infer fixed/false-positive status from pod deletion, scale-zero or missing observations. Retain coverage gaps and unknown identities.
- Trust immutable digests, validated scanner provenance and independently configured signer identity. Never sign an arbitrary imported passing report.
- Keep keys, credentials, raw private evidence, databases and downloaded tools out of Git. Use explicit local endpoints; do not use real AWS credentials.
- Use short-lived branches and bounded PRs after the authorized initial foundation push. Do not merge or release without owner authorization. The initial repo creation/push is explicitly authorized in this session.
- The owner authorizes subagents: assign read-only review or nonoverlapping file ownership, explicit expectations and a base revision. Parent owns integration, contracts, dependency pins, CI and status. No concurrent cluster qualification.
- Record implemented, locally verified, integration-qualified, owner-accepted and merged separately. Keep failed checks and changed expectations traceable.
- Ask only for privileged/destructive/external-account actions outside existing authorization. Never delete an existing cluster or modify another kube context by default.
