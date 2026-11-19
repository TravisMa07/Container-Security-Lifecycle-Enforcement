"""Real cryptographic/admission negatives using explicit ephemeral lab fixtures."""

import base64
import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path

from p0_attestation import TYPE
from p0_ecr import fetch
from p0_lab import ROOT, LOCAL, KUBECONFIG, CONTEXT, Recorder
from p0_oci import digest, variant, publish_bundle


def main():
    rec = Recorder()
    result = json.loads((LOCAL / "attestation-result.json").read_text())
    original = json.loads(Path(result["predicate_file"]).read_text())
    host_repository, subject = result["host_image"].split("@")
    cluster_repository = result["image"].split("@")[0]
    base = (
        "http://"
        + host_repository.split("/")[0]
        + "/v2/"
        + host_repository.split("/", 1)[1]
    )
    manifest_bytes, _ = fetch(base + "/manifests/" + subject)
    source = json.loads(manifest_bytes)
    kubectl = ["kubectl", "--kubeconfig", KUBECONFIG, "--context", CONTEXT]
    cosign = ROOT / ".tools/bin/cosign"
    public = LOCAL / "keys/trusted.pub"
    private = LOCAL / "keys/trusted.key"
    env = dict(os.environ, COSIGN_PASSWORD="")
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "p0-adversarial-" + rec.directory.name[-8:],
            "namespace": "csle-p0",
        },
        "spec": {
            "containers": [
                {"name": "demo", "image": result["image"], "command": ["sleep", "60"]}
            ]
        },
    }
    baseline = rec.directory / "positive.json"
    baseline.write_text(json.dumps(pod))
    outcomes = []
    cases = [
        ("wrong-outer-subject", "signature"),
        ("modified-predicate", "signature"),
        ("modified-signature", "signature"),
        ("future-issued", "issued-at"),
        ("stale-scan", "scan-freshness"),
        ("stale-db", "db-freshness"),
    ]
    for case, reason in cases:
        # A valid control rules out expired baseline, verifier outage and namespace errors.
        rec.run([*kubectl, "create", "--dry-run=server", "-f", baseline])
        label = case + "-" + rec.directory.name[-8:]
        image_bytes = variant(base, source, label)
        image_digest = digest(image_bytes)
        image = host_repository + "@" + image_digest
        predicate = copy.deepcopy(original)
        predicate["purpose"] = "p0-adversarial-fixture-only"
        predicate["subject_image_digest"] = image_digest
        if case == "future-issued":
            future = datetime.now(timezone.utc) + timedelta(hours=1)
            predicate.update(
                issued_at=future.isoformat(),
                timestamp=future.isoformat(),
                expires_at=(future + timedelta(minutes=1)).isoformat(),
            )
        elif case == "stale-scan":
            predicate["scan_timestamp"] = (
                datetime.now(timezone.utc) - timedelta(hours=25)
            ).isoformat()
        elif case == "stale-db":
            predicate["scanner_db_updated_at"] = (
                datetime.now(timezone.utc) - timedelta(hours=25)
            ).isoformat()
        if case == "wrong-outer-subject":
            bundle = json.loads(Path(result["bundle_file"]).read_text())
        else:
            predicate_path = rec.directory / (case + "-predicate.json")
            predicate_path.write_text(json.dumps(predicate, sort_keys=True))
            bundle_path = rec.directory / (case + "-valid-bundle.json")
            rec.run(
                [
                    cosign,
                    "attest",
                    "--yes",
                    "--no-upload",
                    "--key",
                    private,
                    "--signing-config",
                    LOCAL / "signing-config.json",
                    "--predicate",
                    predicate_path,
                    "--type",
                    TYPE,
                    "--bundle",
                    bundle_path,
                    "--allow-http-registry",
                    image,
                ],
                env=env,
            )
            bundle = json.loads(bundle_path.read_text())
            # Prove the fixture is correctly signed/subject-bound before the mutation.
            rec.run(
                [
                    cosign,
                    "verify-blob-attestation",
                    "--key",
                    public,
                    "--bundle",
                    bundle_path,
                    "--type",
                    TYPE,
                    "--insecure-ignore-tlog",
                    "--digest",
                    image_digest.split(":")[1],
                    "--digestAlg",
                    "sha256",
                ]
            )
            if case == "modified-predicate":
                payload = json.loads(
                    base64.b64decode(bundle["dsseEnvelope"]["payload"])
                )
                payload["predicate"]["reason_codes"].append("UNSIGNED_MODIFICATION")
                bundle["dsseEnvelope"]["payload"] = base64.b64encode(
                    json.dumps(payload, sort_keys=True).encode()
                ).decode()
            elif case == "modified-signature":
                signature = bytearray(
                    base64.b64decode(bundle["dsseEnvelope"]["signatures"][0]["sig"])
                )
                signature[-1] ^= 1
                bundle["dsseEnvelope"]["signatures"][0]["sig"] = base64.b64encode(
                    signature
                ).decode()
        bundle_path = rec.directory / (case + "-tested-bundle.json")
        bundle_path.write_text(json.dumps(bundle, sort_keys=True))
        if reason == "signature":
            verified = rec.run(
                [
                    cosign,
                    "verify-blob-attestation",
                    "--key",
                    public,
                    "--bundle",
                    bundle_path,
                    "--type",
                    TYPE,
                    "--insecure-ignore-tlog",
                    "--digest",
                    image_digest.split(":")[1],
                    "--digestAlg",
                    "sha256",
                ],
                check=False,
            )
            if verified.returncode != 1:
                raise ValueError(
                    "cryptographic/subject negative did not fail as expected: " + case
                )
        artifact = publish_bundle(base, bundle, image_bytes, label, TYPE)
        negative = copy.deepcopy(pod)
        negative["spec"]["containers"][0]["image"] = (
            cluster_repository + "@" + image_digest
        )
        path = rec.directory / (case + "-pod.json")
        path.write_text(json.dumps(negative))
        rec.run([*kubectl, "create", "--dry-run=server", "-f", baseline])
        denied = rec.run(
            [*kubectl, "create", "--dry-run=server", "-f", path], check=False
        )
        message = "P0 reject: " + reason
        if (
            denied.returncode != 1
            or b"denied" not in denied.stderr.lower()
            or message.encode() not in denied.stderr
        ):
            raise ValueError(
                "expected causal admission denial missing: "
                + case
                + ": "
                + denied.stderr.decode()
            )
        outcomes.append(
            {"case": case, "expected_reason": message, "result": "passed", **artifact}
        )
        (rec.directory / "adversarial-result.json").write_text(
            json.dumps(outcomes, indent=2)
        )
        print("PASS:", case, flush=True)
    print("Adversarial evidence:", rec.directory, flush=True)


if __name__ == "__main__":
    main()
