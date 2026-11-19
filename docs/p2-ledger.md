# P2 implementation ledger

Base: merged P1 `2bffd97b325e53817f9cd9c2263564a40019b785`. Owner explicitly authorized PR#10 merge and next roadmap PR, not P2 merge. PR#10 readied and merged with exact head5ed28fd. On merged main,96 tests, documentation checks and actual P1 scan acceptance passed; .local/p1/merged-tests.log and merged-real.json retain exact attribution.

P2 expectations in p2-design.md frozen before production implementation. Parent owns shared contracts/migration, adapter/collector/CLI, RBAC, integration and status. Bounded agents own normalization and persistence separately; reviews read-only. No concurrent cluster qualification. Status: planned; no P2 feature qualified yet.

## Implementation / preliminary checks

Freeze5ab817b. p2_normalizer owned app/workloads.py and focused tests; p2_store owned InventoryStore/tests. Parent owns migration2, REST/coordinator/CLI, RBAC and integration script. Normalizer runnable skeleton recorded7 intended failures; store skeleton4 intended failures. Green15 normalization and13 store tests pass. Parent adapter/coordinator suites cover pagination, 410, bookmarks, relist failure, gaps, scope binding and worker/lease failure. P1 migration tests were updated to expect len(DEFAULT_MIGRATIONS) and the next version, preserving migration-failure and edited-applied-content assertions; migration1 bytes remain unchanged.

A real read-only API probe showed PodList items omit TypeMeta (kind/apiVersion). Adapter must supply these from the typed endpoint/list, never guess a differing type. Focused test first failed with missing kind, then passed after endpoint-bound metadata completion; contradictory supplied types reject. Raw object hashes describe this documented canonical decoded representation rather than exact wire JSON bytes. Source: actual retained .local/p2/list-probe.json and Kubernetes API concepts documentation.137 offline tests pass (120 unit +17 contract), document/compile/whitespace checks pass. No P2 real integration claim yet.

Added opt-in tests/integration/p2_real.py: creates only a new labeled project namespace and namespaced read-only SA/Role, runs TTL/history, scale-zero, reconnect/reconcile/restart/unseen-workload and actual old-RV410 scenarios, retains raw evidence and performs no existing-resource deletion. Admin setup uses the explicit existing project kubeconfig/context; collector receives only owner-readable SA token and CA files. Any failed scenario remains an open gate; no mock410 can qualify the real410 claim.
