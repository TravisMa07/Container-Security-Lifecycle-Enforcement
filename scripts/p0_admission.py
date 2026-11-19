"""Real P0 admission checks against the dedicated Kind context only."""

import argparse
import copy
from datetime import datetime, timezone
import ipaddress
import hashlib
import json
from pathlib import Path
from p0_lab import CONTEXT, NODE_CONTAINER, LOCAL, KUBECONFIG, Recorder


def main(expired=False):
    rec = Recorder()
    result = json.loads((LOCAL / "attestation-result.json").read_text())
    image = result["image"]
    kubectl = ["kubectl", "--kubeconfig", KUBECONFIG, "--context", CONTEXT]
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "csle-p0-valid-" + rec.directory.name[-8:],
            "namespace": "csle-p0",
            "labels": {"io.csle.scope": "p0"},
        },
        "spec": {
            "restartPolicy": "Never",
            "containers": [
                {
                    "name": "demo",
                    "image": image,
                    "command": ["sh", "-c", "echo csle-p0; sleep 3600"],
                }
            ],
        },
    }
    path = rec.directory / "pod.json"
    path.write_text(json.dumps(pod))
    if expired:
        if not datetime.now(timezone.utc) > datetime.fromisoformat(
            result["expires_at"]
        ):
            raise ValueError("approval not expired yet")
        proof = json.loads((LOCAL / "admission-positive.json").read_text())
        if (
            proof["image"] != image
            or proof["predicate_sha256"]
            != hashlib.sha256(Path(result["predicate_file"]).read_bytes()).hexdigest()
        ):
            raise ValueError("matching prior positive admission evidence required")
        predicate = json.loads(Path(result["predicate_file"]).read_text())
        observed_at = datetime.fromisoformat(proof["observed_at"])
        if (
            not datetime.fromisoformat(predicate["issued_at"])
            <= observed_at
            < datetime.fromisoformat(predicate["expires_at"])
        ):
            raise ValueError(
                "positive admission was outside the predicate validity window"
            )
        current = rec.run(
            [
                *kubectl,
                "get",
                "imagevalidatingpolicy",
                "csle-p0-attestation",
                "-o",
                "json",
            ]
        )
        if json.loads(current.stdout)["spec"] != proof["observed_policy_spec"]:
            raise ValueError(
                "policy changed since positive admission; expiry cause not isolated"
            )
        outcome = rec.run(
            [*kubectl, "create", "--dry-run=server", "-f", path], check=False
        )
        if not (
            outcome.returncode == 1
            and b"denied" in outcome.stderr.lower()
            and b"csle-p0-attestation" in outcome.stderr
            and b"P0 reject: expiry" in outcome.stderr
        ):
            raise ValueError(outcome.stderr.decode())
        print(
            "PASS: admission denied after previously valid approval expired:",
            rec.directory,
        )
        return
    outcome = rec.run([*kubectl, "create", "--dry-run=server", "-f", path], check=False)
    if not outcome.returncode == 0:
        raise ValueError(outcome.stderr.decode())
    host = image.split("/")[0]
    ipaddress.IPv4Address(host.split(":")[0])
    hosts = rec.directory / "hosts.toml"
    hosts.write_text(
        'server = "http://'
        + host
        + '"\n[host."http://'
        + host
        + '"]\n  capabilities = ["pull", "resolve"]\n'
    )
    destination = "/etc/containerd/certs.d/" + host
    rec.run(["docker", "exec", NODE_CONTAINER, "mkdir", "-p", destination])
    rec.run(["docker", "cp", hosts, NODE_CONTAINER + ":" + destination + "/hosts.toml"])
    rec.run([*kubectl, "create", "-f", path])
    rec.run(
        [
            *kubectl,
            "-n",
            "csle-p0",
            "wait",
            "--for=condition=Ready",
            "pod/" + pod["metadata"]["name"],
            "--timeout=90s",
        ]
    )
    observed = rec.run(
        [*kubectl, "-n", "csle-p0", "get", "pod", pod["metadata"]["name"], "-o", "json"]
    )
    state = json.loads(observed.stdout)
    runtime = state["status"]["containerStatuses"][0]["imageID"]
    if not image.split("@")[1] in runtime:
        raise ValueError(runtime)
    current = rec.run(
        [*kubectl, "get", "imagevalidatingpolicy", "csle-p0-attestation", "-o", "json"]
    )
    proof = {
        "image": image,
        "predicate_sha256": hashlib.sha256(
            Path(result["predicate_file"]).read_bytes()
        ).hexdigest(),
        "observed_policy_spec": json.loads(current.stdout)["spec"],
        "positive_run": str(rec.directory),
        "pod_uid": state["metadata"]["uid"],
        "runtime_image_id": runtime,
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }
    (LOCAL / "admission-positive.json").write_text(json.dumps(proof, indent=2))
    policy = json.loads(Path(result["policy_file"]).read_text())
    stale = copy.deepcopy(policy)
    for validation in stale["spec"]["validations"]:
        validation["expression"] = validation["expression"].replace(
            "== 'p0-v3'", "== 'p0-revoked'"
        )
    stale_path = rec.directory / "revoked-policy.json"
    stale_path.write_text(json.dumps(stale))
    try:
        rec.run([*kubectl, "apply", "-f", stale_path])
        outcome = rec.run(
            [*kubectl, "create", "--dry-run=server", "-f", path], check=False
        )
        if not (
            outcome.returncode == 1
            and b"denied" in outcome.stderr.lower()
            and b"P0 reject: policy-version" in outcome.stderr
        ):
            raise ValueError(outcome.stderr.decode())
    finally:
        rec.run([*kubectl, "apply", "-f", result["policy_file"]])
    print(
        "PASS: valid admission/runtime digest and active-policy revocation denial:",
        rec.directory,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expired", action="store_true")
    main(parser.parse_args().expired)
