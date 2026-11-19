# Contributing

Read [HANDOFF.md](HANDOFF.md), [AGENTS.md](AGENTS.md), the [architecture](docs/architecture.md), [workflow](docs/sdlc.md) and [roadmap](docs/roadmap.md) before implementation. The handoff is the authoritative acceptance contract.

Pick the dependency-ready phase issue, then create a short-lived branch for one bounded implementation item. Record independent behavior/acceptance expectations before implementation and preserve the separate expectation-freeze commit where required. Open a linked draft PR when real work exists; each implementation item gets a PR. Keep incomplete phase issues open and record actual evidence rather than claiming completion from code alone.

Run `make check` for foundation integrity and `make doctor` for read-only prerequisite discovery. Missing tools intentionally cause doctor to fail. Product test and integration commands will be introduced with their implementation; no application capability is qualified yet. Use the PR template to record the tests that actually ran, exact artifact identities, limitations and remaining gates.

Do not commit keys, credentials, local databases, private scan data or downloaded binaries. Use only project-scoped local clusters/registries and explicit emulator endpoints. Do not connect real AWS accounts or perform privileged/destructive work without authorization. Merge and release require owner authorization.

The repository is public; a license has not been selected. Do not assume an open-source license or add third-party material without recording its source and usage terms.
