"""Independent real registry/admission negatives for the P0 compatibility spike."""

import copy
import hashlib
import json
from pathlib import Path
import urllib.parse
import urllib.request
from p0_ecr import fetch
from p0_lab import ROOT, LOCAL, KUBECONFIG, Recorder


def request(url, method, data=b"", content_type="application/octet-stream"):
    req = urllib.request.Request(
        url, data=data, method=method, headers={"Content-Type": content_type}
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        return (response.read(), response.headers)


def main():
    rec = Recorder()
    result = json.loads((LOCAL / "attestation-result.json").read_text())
    policy = json.loads(Path(result["policy_file"]).read_text())
    kubectl = ["kubectl", "--kubeconfig", KUBECONFIG, "--context", "kind-csle-p0"]
    host_image = result["host_image"]
    (repository, subject) = host_image.split("@")
    origin = "http://" + repository.split("/")[0]
    base = origin + "/v2/" + repository.split("/", 1)[1]
    (raw, _) = fetch(base + "/manifests/" + subject)
    manifest = json.loads(raw)
    (config_raw, _) = fetch(base + "/blobs/" + manifest["config"]["digest"])
    config = json.loads(config_raw)
    config.setdefault("config", {}).setdefault("Labels", {})["io.csle.p0.case"] = (
        "unsigned-" + rec.directory.name
    )
    blob = json.dumps(config, sort_keys=True).encode()
    digest = "sha256:" + hashlib.sha256(blob).hexdigest()
    (_, headers) = request(base + "/blobs/uploads/", "POST")
    location = urllib.parse.urlsplit(headers["Location"])
    target = origin + location.path + "?" + location.query
    target += ("&" if location.query else "") + urllib.parse.urlencode(
        {"digest": digest}
    )
    request(target, "PUT", blob)
    manifest["config"]["digest"] = digest
    manifest["config"]["size"] = len(blob)
    content = json.dumps(manifest, sort_keys=True).encode()
    unsigned_digest = "sha256:" + hashlib.sha256(content).hexdigest()
    request(base + "/manifests/unsigned-p0", "PUT", content, manifest["mediaType"])
    (pulled, _) = fetch(base + "/manifests/" + unsigned_digest)
    if not pulled == content:
        raise ValueError("compatibility expectation failed")
    unsigned_image = result["image"].split("@")[0] + "@" + unsigned_digest
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "csle-p0-negative-" + rec.directory.name[-8:],
            "namespace": "csle-p0",
        },
        "spec": {
            "containers": [
                {"name": "demo", "image": unsigned_image, "command": ["sleep", "3600"]}
            ]
        },
    }

    def denied(name, obj, reason):
        file = rec.directory / (name + ".json")
        file.write_text(json.dumps(obj))
        outcome = rec.run(
            [*kubectl, "create", "--dry-run=server", "-f", file], check=False
        )
        if not (
            outcome.returncode == 1
            and b"denied" in outcome.stderr.lower()
            and (reason.encode() in outcome.stderr)
        ):
            raise ValueError(outcome.stderr.decode())
        print("PASS:", name, flush=True)

    positive = copy.deepcopy(pod)
    positive["spec"]["containers"][0]["image"] = result["image"]
    baseline_file = rec.directory / "positive-baseline.json"
    baseline_file.write_text(json.dumps(positive))
    rec.run([*kubectl, "create", "--dry-run=server", "-f", baseline_file])
    denied("unsigned-real-image", pod, "P0 reject: signature")
    cosign = ROOT / ".tools/bin/cosign"
    import os

    env = dict(os.environ, COSIGN_PASSWORD="")
    wrong = rec.directory / "wrong-signer"
    rec.run([cosign, "generate-key-pair", "--output-key-prefix", wrong], env=env)
    wrong.with_suffix(".key").chmod(384)
    other = copy.deepcopy(policy)
    other["spec"]["attestors"][0]["cosign"]["key"]["data"] = wrong.with_suffix(
        ".pub"
    ).read_text()
    other_file = rec.directory / "wrong-trust.json"
    other_file.write_text(json.dumps(other))
    try:
        rec.run([*kubectl, "create", "--dry-run=server", "-f", baseline_file])
        rec.run([*kubectl, "apply", "-f", other_file])
        pod["spec"]["containers"][0]["image"] = result["image"]
        denied("unauthorized-signer", pod, "P0 reject: signature")
    finally:
        rec.run([*kubectl, "apply", "-f", result["policy_file"]])
    hardening = {
        "apiVersion": "policies.kyverno.io/v1",
        "kind": "ValidatingPolicy",
        "metadata": {"name": "csle-p0-hardening", "labels": {"io.csle.scope": "p0"}},
        "spec": {
            "validationActions": ["Deny"],
            "failurePolicy": "Fail",
            "evaluation": {"background": {"enabled": False}},
            "matchConstraints": policy["spec"]["matchConstraints"],
            "variables": [
                {
                    "name": "containers",
                    "expression": "object.spec.containers + object.spec.?initContainers.orValue([]) + object.spec.?ephemeralContainers.orValue([])",
                }
            ],
            "validations": [
                {
                    "expression": "variables.containers.all(c, !has(c.securityContext) || !has(c.securityContext.privileged) || !c.securityContext.privileged)",
                    "message": "P0 privileged containers are prohibited",
                }
            ],
        },
    }
    hardening_file = rec.directory / "hardening-policy.json"
    hardening_file.write_text(json.dumps(hardening))
    rec.run([*kubectl, "apply", "-f", hardening_file])
    rec.run([*kubectl, "create", "--dry-run=server", "-f", baseline_file])
    pod["spec"]["containers"][0]["securityContext"] = {"privileged": True}
    denied("privileged-configuration", pod, "csle-p0-hardening")
    (rec.directory / "negative-result.json").write_text(
        json.dumps(
            {
                "unsigned_image": unsigned_image,
                "original_subject": subject,
                "cases_passed": [
                    "unsigned-real-image",
                    "unauthorized-signer",
                    "privileged-configuration",
                ],
            },
            indent=2,
        )
    )
    print("Evidence:", rec.directory, flush=True)


if __name__ == "__main__":
    main()
