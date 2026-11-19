# P1 local scan evidence

Prerequisites: supported P0 macOS ARM64 checkout, Python3.12.16/uv, `make bootstrap`. This installs hash-locked development dependencies and the editable `csle` entry point in `.tools/venv`. `python -m app` under that interpreter is equivalent. Editable local checkout is the supported distribution; no published wheel or cross-platform scanner qualification is claimed.

## Offline workflow

```sh
make test
make check
.tools/venv/bin/csle --help
.tools/venv/bin/csle --db .local/example.sqlite3 db init
.tools/venv/bin/csle --db .local/example.sqlite3 scan import tests/fixtures/p1/trivy-synthetic.json --image localhost:15120/demo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
.tools/venv/bin/csle --db .local/example.sqlite3 scans list
.tools/venv/bin/csle --db .local/example.sqlite3 findings list
```

Use `scans show SCAN_ID` and `findings explain FINDING_ID` with IDs from the output. Repeating the exact import returns the same scan ID with `inserted:false`. All query JSON is deterministic for unchanged stored evidence; finding display picks newest scan timestamp then document hash and retains evidence links. Exact raw bytes and optional supplied DB metadata are retained in SQLite. Imported versions/DB timestamps remain assertions, and unavailable facts stay null/unknown. No import can claim executed provenance through CLI flags.

## Real local scan

Use the [P0 runbook](p0-runbook.md) to create the authorized isolated local profile and push its pinned artifact. P1 qualification uses the retained `csle-p0-cis` backing OCI registry, exposed only on loopback port15120. Floci ECR inventory is still P4 work; this command directly reads OCI bytes without claiming AWS scanning.

```sh
.tools/venv/bin/csle doctor
.tools/venv/bin/csle --db .local/real.sqlite3 scan image 127.0.0.1:15120/000000000000/us-east-1/csle-p0/demo@sha256:1829893486be257df5049ab3b7fc95afbd0fc09d89803cbc580bda1ba5386b29 --registry-url http://127.0.0.1:15120 --platform linux/arm64
.tools/venv/bin/csle --db .local/real.sqlite3 scans list
```

The endpoint must exactly match the image reference authority and be an explicit loopback HTTP host/port. No redirects, proxy routing, registry credentials, mutable tags or arbitrary external endpoints are accepted by this bounded P1 resolver. Public/authenticated registry adapters belong to P4. A supplied index is resolved to exactly one platform descriptor; selected manifest/config hashes and config platform are checked independently. Generic `linux/arm64` retains a resolved `v8` variant. The report's config identity must match the verified config; config IDs never substitute for manifest identity.

The runner verifies Trivy against its checksum-pinned downloaded archive and exact version. It removes TRIVY environment overrides, disables implicit config/ignore files, includes all severities/unfixed findings and uses a private run directory. It serializes CSLE users of each cache; do not modify the cache with other tools during a scan. Trivy can fetch its public CVE DB; this is not an offline integration command. DB bytes and metadata are hashed; report, command and logs remain under ignored `.local/p1/runs/`, with raw bytes also in the database. Default cache is `.local/trivy-cache`; `--cache-dir` overrides it.

## Errors and recovery

Success is0. Invalid input, unknown record and invalid/incompatible evidence/schema are2; file/storage/scanner failures are1. Errors are JSON on stderr with empty stdout. Help is human-readable and exits0. `make` propagates target failures using its own exit convention. An empty finding set is not an approval; P1 emits no policy or remediation verdict.

Migrations and ingestion are all-or-nothing. Incompatible/newer/edited migration ledgers refuse to open; do not reset a database to make validation pass. Preserve the database and raw logs for diagnosis. SQLite append-only guards and hashes detect common accidental changes but cannot defend against its local owner rewriting evidence and hashes together. There is no automatic deletion/retention or signing command. Keep databases, keys and raw private reports out of Git. P2–P7 capabilities remain pending.
