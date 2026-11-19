# Development and qualification

HANDOFF.md governs scope. The Agentic SDLC skill supplies the evidence workflow, not a copied DetectBridge architecture. Keep files and implementation proportional to this project.

## Delivery policy

After the authorized initial foundation seed/push, use bounded branches and PRs. Normally use 1–3 cohesive commits: independent design/expectation freeze, implementation with tests/docs, and qualification evidence where needed. Do not rewrite published history. Owner authorization is required for merges and releases; ordinary implementation and review are already authorized.

Before each slice, record behavior, exclusions, dependencies, input/output contracts, invariants and acceptance oracles derived independently from requirements. Use a separate expectation-freeze commit for semantic, contract, stateful and evidence-sensitive changes. Demonstrate meaningful behavioral red before green; dependency failure is not behavioral red.

## Evidence and gates

Record revision, environment, artifact identity, command, outcome, evidence path and limitations. Preserve failed checks. Distinguish planned, implemented, locally verified, runtime-qualified, owner-accepted, merged and verified-on-merged-commit. Documentation checks are never runtime evidence.

Fast tests run without Docker/network; fixture provenance is explicit. Real integration tests use project-owned local resources, explicit context/endpoint and recorded digests. Heavy cluster suites run serially. CI must not give untrusted PRs signing credentials or elevated write permissions. Add CI gates only when there is meaningful behavior to check.

Subagents may research, review independent expectations and implement nonoverlapping slices. Record ownership/base/dependencies in the ledger. Parent integrates contracts, pins, CI and status; reviewers inspect actual artifacts. Agent review does not imply owner acceptance.

No hidden privileged commands or cleanup. Preserve evidence by default; deletion is separately authorized and constrained to project-owned resources. No real AWS or paid service is part of local acceptance.
