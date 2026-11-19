# P0 local compatibility runbook

Profile: macOS ARM64, local Docker Desktop, Python 3.12.16 and uv. Other profiles remain unsupported by provisioning. P0 is an experimental compatibility slice; no product CLI or full MVP feature is implemented. Read the [design](p0-design.md) and [results](p0-ledger.md) first.

## Setup and safety

`make bootstrap` installs checksum-pinned Kind, Cosign, Trivy and Helm only under `.tools/`, verifies the pinned Kyverno chart, and synchronizes the hash-locked boto3 tooling environment. It does not use sudo or change a global tool installation. The checksum trust root is the upstream HTTPS release metadata; independent publisher-attestation verification is not claimed.

Run `make test`, `make check` and `make doctor`. Doctor discovers local binaries and uses the isolated boto3 SDK when AWS CLI is absent. `prerequisites_available` means commands responded, not that versions or integrations are qualified. The `integration_qualified` field remains false; consult the ledger for bounded real evidence.

Before lab creation, obtain owner authorization for Kind's privileged container and Floci's Docker socket. For this development session the owner explicitly authorized both on local Docker Desktop. That permission does not cover a remote Docker engine, sudo or deletion. Only the explicit desktop-linux Unix endpoint is allowed; ambient remote contexts/hosts are rejected.

Build the patched node first with `make p0-node`: Kind builds Kubernetes 1.37.2 from a checksum-pinned official release and pinned base image. The resulting local Docker config ID is recorded separately from OCI manifest digests. Then start a **fresh** lab with `make p0-up P0_PRIVILEGE_FLAG=--allow-privileged-local`. The default `make p0-up` refuses privileged work. Existing project resources/kubeconfig or occupied ports fail rather than being reused or deleted. Resources: network `csle-p0`, node `csle-p0-control-plane`, emulator `csle-p0-floci` and Floci-created `floci-aws-csle-p0-ecr-registry`. Published API/registry ports bind 127.0.0.1. UI is disabled. User kubeconfig is not edited; all API commands explicitly use `.local/p0/kubeconfig` and `kind-csle-p0`.

## Experiments

1. `make p0-kyverno`: install the pinned chart and pinned images in the dedicated Kind cluster. Single replicas are intentional for the lab; no availability claim.
2. `make p0-ecr`: create/describe the dedicated ECR repo, push a pinned single-platform Alpine image, verify a clean OCI pull's manifest and blob bytes, enumerate via boto3, record unsupported scanner API results, and perform a real Trivy scan.
3. `make p0-attest`: independently execute another real scan before signing, reject incomplete/unbound/stale/prohibited scan evidence, use an ephemeral local key and explicit signing config with no public Fulcio/Rekor/TSA/OIDC services, verify the signature, and apply a scoped ImageValidatingPolicy. This gate is a deliberately narrow P0 compatibility rule, not the P5 policy engine. Its approval lasts at most three minutes and cannot outlive scan/DB freshness.
4. `make p0-admission`: require valid real admission, create a pod, verify runtime digest and test active-policy-version revocation with restoration in finally. Record a positive receipt binding predicate hash, observed policy, UID and runtime identity.
5. `make p0-negatives`: require a positive admission control before testing a real unsigned OCI artifact, a different configured trust key and privileged configuration. Expected policy-specific denial messages must be present.
6. After the recorded approval expiry, `make p0-expired`: require the matching positive receipt and unchanged observed policy, then require the specific expiry denial. An early invocation refuses the test; it is not evidence of an expiry denial.

**Corrected compatibility profile:** the initial v1 reassessment failed on an older cached payload. The fixed v2 schema adds required signed `timestamp == issued_at`; the controller explicitly uses `--imageVerifyCacheEnabled=false`. This is a one-time schema migration, with all old v1 evidence retained. Two successive v2 approvals for the same image/key/type were admitted with distinct current assessment IDs, and strict unsigned/wrong-trust/privileged tests passed with positive controls. The policy pins the current signed assessment ID as an oracle that the newest payload was selected. This prototype protects one compatibility artifact, not a multi-image production authorization catalog. Do not restore caching without repeated freshness/revocation tests. The full fresh-clone and negative matrix remains open; see the ledger for exact results.

Host and cluster registry addresses differ. The host uses localhost:14566 and the pod uses the explicitly discovered Floci Docker-network IP on port 4566; identical manifest digest binds both. The node-local containerd hosts entry permits plain HTTP for only that lab endpoint. This transport profile is local-only; no production TLS or AWS IAM assurance is claimed.

## Evidence and retained resources

Ignored `.local/p0/runs/<UTC>-<id>/` contains per-command logs and JSONL records: source revision/dirty state, source hashes for current runs, actual command, time/duration, exit/failure kind and raw log hash. SDK/OCI results and raw scans remain ignored. Public summaries contain hashes and bounded outcomes. Tests explicitly cover timeout/error retention. Earlier discovery commands and initial Helm install were separately logged and are identified as manual discovery in the ledger.

No teardown/reset command exists in this slice. Resources, images, keys and evidence are retained; the demo pod sleeps for one hour and then exits. Do not run a generic prune or delete an existing cluster. Any later cleanup must be explicitly authorized and target only these identified project resources. If the lab policy blocks protected workloads, inspect the scoped policy with the explicit project kubeconfig; recovery changes/removal must be recorded and must not be represented as an enforcement pass.

For independent clean-clone qualification, select a separate profile before any command: `export CSLE_P0_PROFILE=csle-p0-close CSLE_P0_API_PORT=14576 CSLE_P0_REGISTRY_PORT=15110`. These validated parameters isolate Docker resources and loopback ports; the clone owns its own ignored state/kubeconfig. Defaults retain the original lab profile. `make p0-adversarial` publishes isolated malformed/future/stale fixtures using only the ephemeral lab key and requires independent verification and causal admission denial, with valid controls. No existing evidence index is replaced.
