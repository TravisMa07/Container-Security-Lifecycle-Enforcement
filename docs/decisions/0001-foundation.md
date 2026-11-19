# ADR 0001: Small local-first foundation

Date: 2026-11-19. Status: accepted initial engineering direction within the handoff; compatibility is not yet qualified.

## Context and decision

Use a Python modular monolith with typed Pydantic contracts, SQLite migrations, a CLI and a read-only Kubernetes watcher. Keep collectors, pure decision logic, signing and evidence export as modules. Prefer Python 3.12 initially: 3.12.12 is already installed through uv on this host; lock application dependencies when P1 starts. Do not use the host system Python 3.9 for the application.

Use external Kind, Kyverno, Trivy, Cosign and Floci rather than reproducing their engines. Select precise versions only after reviewing official sources and validating their combined behavior. Latest individual releases are research candidates, not a compatible stack.

Use an ephemeral local signer with independent public-key trust for the local profile. Signing requires a fresh trusted scan and policy decision. Investigate current Kyverno image-verification APIs and time/policy-revocation expressions before choosing the final admission contract.

Start the explicitly requested GitHub repository private, with the current folder name, no license assumption and no remote protection changes. The user authorized creation and initial push; subsequent implementation uses branches/PRs and explicit merges.

## Alternatives and consequences

A distributed service stack increases operational and evidence complexity without helping this MVP. A large dashboard is unnecessary for the CLI/report acceptance contract. Keyless production signing remains an optional future profile; local keys do not establish production identity assurance.

Floci signing/referrer behavior and container-to-host registry networking are integration risks. A separate OCI attestation store is permitted only with explicit same-digest proof and documented trust binding. Expiry and policy revocation may not be dropped to accommodate tooling.

## Validation

Foundation checks establish document integrity only. P0 must prove the precise tool chain, architecture support, registry transport, signature format, custom predicate, freshness and fail-closed admission behavior. P1 freezes contract expectations before implementing storage/ingestion.
