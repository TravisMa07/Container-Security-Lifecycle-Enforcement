# P2 implementation ledger

Base: merged P1 `2bffd97b325e53817f9cd9c2263564a40019b785`. Owner explicitly authorized PR#10 merge and next roadmap PR, not P2 merge. PR#10 readied and merged with exact head5ed28fd. On merged main,96 tests, documentation checks and actual P1 scan acceptance passed; .local/p1/merged-tests.log and merged-real.json retain exact attribution.

P2 expectations in p2-design.md frozen before production implementation. Parent owns shared contracts/migration, adapter/collector/CLI, RBAC, integration and status. Bounded agents own normalization and persistence separately; reviews read-only. No concurrent cluster qualification. Status: planned; no P2 feature qualified yet.

## Implementation / preliminary checks

Freeze5ab817b. p2_normalizer owned app/workloads.py and focused tests; p2_store owned InventoryStore/tests. Parent owns migration2, REST/coordinator/CLI, RBAC and integration script. Normalizer runnable skeleton recorded7 intended failures; store skeleton4 intended failures. Green15 normalization and13 store tests pass. Parent adapter/coordinator suites cover pagination, 410, bookmarks, relist failure, gaps, scope binding and worker/lease failure. P1 migration tests were updated to expect len(DEFAULT_MIGRATIONS) and the next version, preserving migration-failure and edited-applied-content assertions; migration1 bytes remain unchanged.

A real read-only API probe showed PodList items omit TypeMeta (kind/apiVersion). Adapter must supply these from the typed endpoint/list, never guess a differing type. Focused test first failed with missing kind, then passed after endpoint-bound metadata completion; contradictory supplied types reject. Raw object hashes describe this documented canonical decoded representation rather than exact wire JSON bytes. Source: actual retained .local/p2/list-probe.json and Kubernetes API concepts documentation.137 offline tests pass (120 unit +17 contract), document/compile/whitespace checks pass. No P2 real integration claim yet.

Added opt-in tests/integration/p2_real.py: creates only a new labeled project namespace and namespaced read-only SA/Role, runs TTL/history, scale-zero, reconnect/reconcile/restart/unseen-workload and actual old-RV410 scenarios, retains raw evidence and performs no existing-resource deletion. Admin setup uses the explicit existing project kubeconfig/context; collector receives only owner-readable SA token and CA files. Any failed scenario remains an open gate; no mock410 can qualify the real410 claim.

## Initial real run and independent review

First real setup at8a060f8 failed in the test harness after successful RBAC creation: kubectl create List emits multiple JSON documents, while harness expected one. No collector claim follows; retained namespace csle-p2-20261119230957339996 was not deleted. Changed harness to create each RBAC item separately. Second working-tree run at8a060f8 passed all actual scenarios: Job TTL/history/name reuse, scale-zero reference, seven-kind list/watch and reconnect, periodic reconciliation, watcher downtime/restart/unseen Job, read-only token403 controls, replay, deterministic CLI, and actual API410/relist. Exact source and dirty state are preserved in .local/p2/real-second.json; namespace csle-p2-20261119231015933204 remains retained. Final committed-source qualification still pending.

Independent p2_review inspected8a060f8 and139 tests (including parent CLI additions). Two reproduced blockers: one cluster ID could bind different servers in different namespaces; complete/empty snapshots had no immutable membership receipt, losing observed absence history after later reappearance. Regression logs binding-red.log and snapshot-history-red.log show intended assertion failures (the first history-test attempt only showed missing API; replaced by a runnable empty-result skeleton before recording meaningful red). Corrections enforce cluster-wide server binding and append immutable scope/kind/RV/time/member receipts, including empty snapshots. Migration3 adds receipts without editing executed migration2. No past absence is reconstructed on upgrade. SQL fault at gap-close proves receipt/event/current/checkpoint rollback together; append-only/tamper tests validate receipts.

Review also noted aggregate pagination memory; cumulative20MiB snapshot cap was reproduced red and fixed. Log snapshot-limit-red.log/green.log retained. Corrected suites144 pass (127 unit +17 contract), including all P1/P0 tests. Parent owns final source/runtime/CI attribution; no P2 merge authorized.

## Final P2 qualification

Clean executed source `1ef3ed1f4b26d2942555ef53757b1d938ba164d5`. `make test`:144 passed (127 unit +17 contract). Document checks, compileall and whitespace checks pass. A newly created Python3.12.16 environment installed the same20 hash-locked development packages and editable CLI; all144 tests pass there. No dependency/tool pin changed.

Actual `tests/integration/p2_real.py` passed on Kubernetes1.35.10: all seven resource list/watch paths using read-only namespaced token; secrets/create/delete/other-namespace403; short-lived Job captured before TTL deletion and retained after restart; name reused with new UID; scale-zero desired image retained; repeated actual watches; periodic reconciliation; observer downtime with an entirely unseen Job never invented; actual API410 from old RV1 followed by closed expiry gap/relist; real-event duplicate idempotency; immutable complete/empty snapshot receipts and deterministic CLI queries. Recovery summary deliberately contains exactly the exercised RESOURCE_VERSION_EXPIRED error; it is not mislabeled a no-error run. The observer was stopped during the unseen Job scenario; no API-server outage or live storage corruption is claimed. Offline tests own those transport/SQL fault assertions.

[Qualification record](results/p2-qualification.json) owns exact UID/run/server identity, counts, log/raw-artifact hashes and limitations. The earlier setup failure and working-tree success remain traceable. Three newly created project namespaces are retained; new Job TTL cleanup was intentional, no pre-existing resource/cluster/context was deleted or changed. Raw objects, owner-only tokens, databases and tools are outside Git. Migration3 preserves earlier applied migrations and creates no fictional prior receipts.

Independent final review inspected corrected1ef3ed1, verified discovered tests/atomicity/identity/bounds and found no remaining blockers. Implementation, local verification and bounded real integration qualification are satisfied. Owner semantic acceptance, P2 merge authorization and merged-revision verification remain separate. Final documentation commits do not imply runtime execution at another source revision. Current-head CI is reported in PR#11 after push. P3–P7 remain mandatory and unimplemented here.

| Acceptance | Evidence |
| --- | --- |
| Seven-kind typed UID/owner/container refs |15 normalizer cases/P0 schema checks plus seven actual API watches |
| Immutable events/checkpoints and duplicate/name reuse | Store faults/restart/replay suites and actual captured Job UID reuse |
| History after TTL and zero replicas | Actual raw DELETED Job observations and scale-zero desired reference |
| Reconnect/410/reconcile/restart/gaps | Actual watch connections and410/relist; offline failed-list/early-EOF/fault cases |
| No invented unseen history / observed absence preserved | Actual downtime Job absent from events/receipts; empty/reappearance regression; atomic receipt history |
| CLI and provenance | Actual deterministic events/observations/snapshots/current/gaps queries and exact source/artifact record |

Issue#3 remains linked for closure on integration; draft PR#11 is unmerged.
