## Behavior and scope

Describe the concrete problem, trigger, resulting behavior and exclusions.

## Tracking and dependencies

- Phase and tracking issue:
- Implementation item issue, if separate:
- Required base/dependencies:

Use `Refs #N` for partial phase work. Close a phase issue only when all of its acceptance gates have recorded passing evidence.

## Independent expectations

Link the owning design and expectation-freeze commit. Describe expected outcomes and their requirements/source rationale, including negative and unknown cases.

## Validation and evidence

Record actual commands, revision, environment/platform, artifact/digest identity, results and evidence/ledger links. For behavior changes, record meaningful red then green. Distinguish fast fixture tests from real integration qualification; mark unrun or failed gates explicitly. Documentation-only changes need document checks, not invented runtime tests.

## Risks and remaining gates

Record limitations, unresolved findings, compatibility/recovery concerns and any owner decision still needed. CI success does not authorize merge or establish runtime qualification.

- [ ] The PR references its phase/implementation issue and has bounded scope.
- [ ] Expected behavior was established independently of implementation output.
- [ ] Actual tests/evidence and failed/unavailable checks are recorded.
- [ ] Design, roadmap, ledger and user-facing claims match the evidence.
- [ ] No keys, credentials, private evidence or unrelated resources are included.
