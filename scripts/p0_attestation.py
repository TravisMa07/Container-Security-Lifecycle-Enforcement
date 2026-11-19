"""P0 Cosign/current Kyverno feasibility experiment, explicitly nonproduction."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import uuid
from pathlib import Path
import subprocess
from p0_lab import (
    CONTEXT,
    PROFILE,
    API_PORT,
    FLOCI_CONTAINER,
    ROOT,
    LOCAL,
    KUBECONFIG,
    Recorder,
    local_docker,
)

TYPE = "https://github.com/TravisMa07/Container-Security-Lifecycle-Enforcement/attestations/p0-compatibility/v2"


def validate_scan(report, db, digest, now):
    if (
        report.get("SchemaVersion") != 2
        or not isinstance(report.get("Results"), list)
        or not report["Results"]
    ):
        raise ValueError("complete supported Trivy report required")
    refs = report.get("Metadata", {}).get("RepoDigests", [])
    if not isinstance(refs, list) or not any(
        isinstance(ref, str) and ref.rsplit("@", 1)[-1] == digest for ref in refs
    ):
        raise ValueError("scan digest binding required")
    for result in report["Results"]:
        if result.get("Class") not in {"os-pkgs", "lang-pkgs"} or not result.get(
            "Type"
        ):
            raise ValueError("unsupported scanner result")
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise ValueError("malformed vulnerability list")
        for finding in vulnerabilities:
            if not isinstance(finding, dict) or finding.get("Severity") not in {
                "LOW",
                "MEDIUM",
            }:
                raise ValueError("scan severity gate failed")
    for value in [report.get("CreatedAt"), db.get("UpdatedAt")]:
        if not isinstance(value, str):
            raise ValueError("scan and DB timestamps required")
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if timestamp.tzinfo is None or not timedelta(0) <= now - timestamp <= timedelta(
            hours=24
        ):
            raise ValueError("fresh scan and DB required")


def main():
    rec = Recorder()
    ecr_path = Path((LOCAL / "ecr-result-path.txt").read_text())
    ecr = json.loads(ecr_path.read_text())
    report_path = rec.directory / "trusted-trivy.json"
    if not ecr["image"].startswith(
        f"localhost:{API_PORT}/000000000000/us-east-1/csle-p0/demo@sha256:"
    ):
        raise ValueError(
            "only the explicit local compatibility repository can be signed"
        )
    # Execute an independent fresh scan here; never sign a merely imported passing report.
    rec.run(
        [
            ROOT / ".tools/bin/trivy",
            "image",
            "--image-src",
            "remote",
            "--scanners",
            "vuln",
            "--format",
            "json",
            "--output",
            report_path,
            "--cache-dir",
            LOCAL / "trivy-cache",
            "--insecure",
            ecr["image"],
        ]
    )
    report = json.loads(report_path.read_text())
    now = datetime.now(timezone.utc)
    db = json.loads((LOCAL / "trivy-cache/db/metadata.json").read_text())
    validate_scan(report, db, ecr["manifest_digest"], now)
    keys = LOCAL / "keys"
    keys.mkdir(mode=448, exist_ok=True)
    keys.chmod(448)
    env = dict(os.environ, COSIGN_PASSWORD="")
    cosign = ROOT / ".tools/bin/cosign"
    if not (keys / "trusted.key").exists():
        rec.run(
            [cosign, "generate-key-pair", "--output-key-prefix", keys / "trusted"],
            env=env,
        )
    (keys / "trusted.key").chmod(384)
    config = LOCAL / "signing-config.json"
    rec.run(
        [
            cosign,
            "signing-config",
            "create",
            "--no-default-fulcio",
            "--no-default-oidc",
            "--no-default-rekor",
            "--no-default-tsa",
            "--out",
            config,
        ]
    )
    predicate = {
        "schema_version": "2",
        "assessment_id": uuid.uuid4().hex,
        "decision": "allow",
        "purpose": "p0-compatibility-nonproduction",
        "subject_image_digest": ecr["manifest_digest"],
        "policy_id": "p0-scan-gate",
        "policy_version": "p0-v3",
        "scan_result_hash": "sha256:"
        + hashlib.sha256(report_path.read_bytes()).hexdigest(),
        "scanner_version": "0.76.2",
        "scanner_db_updated_at": db["UpdatedAt"],
        "scan_timestamp": report["CreatedAt"],
        "issued_at": now.isoformat(),
        "timestamp": now.isoformat(),
        "expires_at": min(
            now + timedelta(minutes=3),
            datetime.fromisoformat(report["CreatedAt"]) + timedelta(hours=24),
            datetime.fromisoformat(db["UpdatedAt"].replace("Z", "+00:00"))
            + timedelta(hours=24),
        ).isoformat(),
        "reason_codes": [
            "REAL_TRIVY_SCAN",
            "NO_HIGH_CRITICAL_UNKNOWN",
            "FRESH_DB",
            "LOCAL_COMPATIBILITY_ONLY",
        ],
    }
    pred = rec.directory / "predicate.json"
    pred.write_text(json.dumps(predicate, sort_keys=True) + "\n")
    rec.run(
        [
            cosign,
            "attest",
            "--yes",
            "--key",
            keys / "trusted.key",
            "--signing-config",
            config,
            "--predicate",
            pred,
            "--type",
            TYPE,
            "--bundle",
            rec.directory / "bundle.json",
            "--allow-http-registry",
            ecr["image"],
        ],
        env=env,
    )
    rec.run(
        [
            cosign,
            "verify-attestation",
            "--key",
            keys / "trusted.pub",
            "--type",
            TYPE,
            "--insecure-ignore-tlog",
            "--allow-http-registry",
            ecr["image"],
        ]
    )
    ip = subprocess.check_output(
        [
            *local_docker(),
            "inspect",
            FLOCI_CONTAINER,
            "--format",
            '{{(index .NetworkSettings.Networks "' + PROFILE + '").IPAddress}}',
        ],
        text=True,
    ).strip()
    image = ip + ":4566/" + ecr["image"].split("/", 1)[1]
    kubectl = ["kubectl", "--kubeconfig", KUBECONFIG, "--context", CONTEXT]
    ns = {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": "csle-p0", "labels": {"io.csle.scope": "p0"}},
    }
    ns_file = rec.directory / "namespace.json"
    ns_file.write_text(json.dumps(ns))
    rec.run([*kubectl, "apply", "-f", ns_file])
    match = {
        "namespaceSelector": {"matchLabels": {"io.csle.scope": "p0"}},
        "resourceRules": [
            {
                "apiGroups": [""],
                "apiVersions": ["v1"],
                "operations": ["CREATE", "UPDATE"],
                "resources": ["pods"],
            }
        ],
    }
    crypto = "verifyAttestationSignatures(image, attestations.assessment, [attestors.trusted]) > 0"
    payload = "extractPayload(image, attestations.assessment).predicate."
    clauses = [
        ("signature", crypto),
        ("schema", crypto + " && " + payload + "schema_version == '2'"),
        ("decision", crypto + " && " + payload + "decision == 'allow'"),
        ("policy-version", crypto + " && " + payload + "policy_version == 'p0-v3'"),
        ("issued-at", crypto + " && timestamp(" + payload + "issued_at) <= time.now()"),
        ("expiry", crypto + " && timestamp(" + payload + "expires_at) > time.now()"),
    ]
    for name, field in [
        ("scan-freshness", "scan_timestamp"),
        ("db-freshness", "scanner_db_updated_at"),
    ]:
        value = "timestamp(" + payload + field + ")"
        clauses.append(
            (
                name,
                crypto
                + " && "
                + value
                + " <= time.now() && time.now() - "
                + value
                + ' <= duration("24h")',
            )
        )
    clauses.extend(
        [
            (
                "timestamp",
                crypto + " && " + payload + "timestamp == " + payload + "issued_at",
            ),
            (
                "assessment-id",
                crypto
                + " && "
                + payload
                + "assessment_id == '"
                + predicate["assessment_id"]
                + "'",
            ),
            (
                "subject",
                crypto
                + ' && image.endsWith("@" + '
                + payload
                + "subject_image_digest)",
            ),
        ]
    )
    policy = {
        "apiVersion": "policies.kyverno.io/v1",
        "kind": "ImageValidatingPolicy",
        "metadata": {"name": "csle-p0-attestation", "labels": {"io.csle.scope": "p0"}},
        "spec": {
            "validationActions": ["Deny"],
            "failurePolicy": "Fail",
            "evaluation": {"background": {"enabled": False}},
            "matchConstraints": match,
            "credentials": {"allowInsecureRegistry": True, "providers": []},
            "validationConfigurations": {
                "mutateDigest": False,
                "verifyDigest": True,
                "required": True,
            },
            "attestors": [
                {
                    "name": "trusted",
                    "cosign": {
                        "key": {"data": (keys / "trusted.pub").read_text()},
                        "ctlog": {
                            "insecureIgnoreTlog": True,
                            "insecureIgnoreSCT": True,
                        },
                    },
                }
            ],
            "attestations": [{"name": "assessment", "intoto": {"type": TYPE}}],
            "validations": [
                {
                    "expression": "images.containers.all(image, " + expression + ")",
                    "message": "P0 reject: " + name,
                }
                for name, expression in clauses
            ],
        },
    }
    policy_file = rec.directory / "image-policy.json"
    policy_file.write_text(json.dumps(policy, indent=2))
    rec.run([*kubectl, "apply", "-f", policy_file])
    result = {
        "image": image,
        "host_image": ecr["image"],
        "expires_at": predicate["expires_at"],
        "policy_file": str(policy_file),
        "bundle_file": str(rec.directory / "bundle.json"),
        "predicate_file": str(pred),
        "run_directory": str(rec.directory),
    }
    (LOCAL / "attestation-result.json").write_text(json.dumps(result, indent=2))
    print("Signature verified; policy applied:", rec.directory, flush=True)


if __name__ == "__main__":
    main()
