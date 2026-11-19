"""Real P0 ECR/OCI compatibility experiment; explicit emulator credentials only."""

import base64
import hashlib
import json
import urllib.request
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from p0_lab import API_PORT, ROOT, LOCAL, Recorder, local_docker


def fetch(url):
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json",
            "Authorization": "Basic " + base64.b64encode(b"AWS:floci").decode(),
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return (response.read(), dict(response.headers))


def main():
    rec = Recorder()
    manifest = json.loads((ROOT / "toolchain.lock.json").read_text())
    client = boto3.client(
        "ecr",
        endpoint_url=f"http://127.0.0.1:{API_PORT}",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(connect_timeout=5, read_timeout=30, retries={"max_attempts": 0}),
    )
    try:
        repository = client.create_repository(repositoryName="csle-p0/demo")[
            "repository"
        ]
    except client.exceptions.RepositoryAlreadyExistsException:
        repository = client.describe_repositories(repositoryNames=["csle-p0/demo"])[
            "repositories"
        ][0]
    ref = repository["repositoryUri"] + ":p0"
    if not ref.startswith(f"localhost:{API_PORT}/000000000000/us-east-1/csle-p0/demo:"):
        raise ValueError("compatibility expectation failed")
    docker_config = LOCAL / "docker-config"
    docker_config.mkdir(exist_ok=True)
    (docker_config / "config.json").write_text(
        json.dumps(
            {
                "auths": {
                    f"localhost:{API_PORT}": {
                        "auth": base64.b64encode(b"AWS:floci").decode()
                    }
                }
            }
        )
    )
    endpoint = local_docker()[2]
    docker = ["docker", "--host", endpoint, "--config", docker_config]
    demo = manifest["images"]["demo"]
    source = "alpine@" + demo["linux_arm64_digest"]
    rec.run([*docker, "pull", source])
    rec.run([*docker, "tag", source, ref])
    rec.run([*docker, "push", ref])
    path = "000000000000/us-east-1/csle-p0/demo"
    origin = f"http://127.0.0.1:{API_PORT}/v2/" + path
    (raw, headers) = fetch(origin + "/manifests/p0")
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if not digest == demo["linux_arm64_digest"]:
        raise ValueError((digest, demo["linux_arm64_digest"]))
    listing = client.list_images(repositoryName="csle-p0/demo")
    details = client.describe_images(repositoryName="csle-p0/demo")
    if not digest in {image["imageDigest"] for image in listing["imageIds"]}:
        raise ValueError("compatibility expectation failed")
    if not digest in {image["imageDigest"] for image in details["imageDetails"]}:
        raise ValueError("compatibility expectation failed")
    store = rec.directory / "oci-pull"
    store.mkdir()
    (pulled, _) = fetch(origin + "/manifests/" + digest)
    if not pulled == raw:
        raise ValueError("compatibility expectation failed")
    (store / "manifest.json").write_bytes(pulled)
    obj = json.loads(pulled)
    for descriptor in [obj["config"], *obj["layers"]]:
        (blob, _) = fetch(origin + "/blobs/" + descriptor["digest"])
        if not descriptor["digest"] == "sha256:" + hashlib.sha256(blob).hexdigest():
            raise ValueError("compatibility expectation failed")
        if not len(blob) == descriptor["size"]:
            raise ValueError("compatibility expectation failed")
        (store / descriptor["digest"].replace(":", "-")).write_bytes(blob)
    unsupported = {}
    for operation in ["start_image_scan", "describe_image_scan_findings"]:
        try:
            getattr(client, operation)(
                repositoryName="csle-p0/demo", imageId={"imageDigest": digest}
            )
            raise AssertionError("unexpected scanner API success: " + operation)
        except ClientError as error:
            if error.response["Error"]["Code"] != "UnsupportedOperation":
                raise
            unsupported[operation] = error.response["Error"]
    result = {
        "provenance": "emulated_aws_ecr",
        "image": ref.split(":p0")[0] + "@" + digest,
        "source": source,
        "manifest_digest": digest,
        "fresh_oci_store": str(store.relative_to(ROOT)),
        "verified_blobs": len(obj["layers"]) + 1,
        "list_images": listing,
        "describe_images": details,
        "unsupported_scanner_apis": unsupported,
        "registry_manifest_headers": headers,
        "revision": rec.revision,
        "dirty_working_tree": rec.dirty,
    }
    (rec.directory / "ecr-result.json").write_text(
        json.dumps(result, indent=2, default=str) + "\n"
    )
    (LOCAL / "ecr-result-path.txt").write_text(str(rec.directory / "ecr-result.json"))
    print(
        json.dumps(
            {
                k: result[k]
                for k in [
                    "provenance",
                    "image",
                    "manifest_digest",
                    "verified_blobs",
                    "unsupported_scanner_apis",
                ]
            },
            indent=2,
        )
    )
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
            rec.directory / "trivy.json",
            "--cache-dir",
            LOCAL / "trivy-cache",
            "--insecure",
            result["image"],
        ],
        timeout=600,
    )
    report = json.loads((rec.directory / "trivy.json").read_text())
    if not report["SchemaVersion"] == 2:
        raise ValueError("compatibility expectation failed")
    if not any((digest in item for item in report["Metadata"]["RepoDigests"])):
        raise ValueError("compatibility expectation failed")
    rec.run([ROOT / ".tools/bin/trivy", "--version", "--format", "json"])
    print("ECR/OCI and real Trivy proof:", rec.directory, flush=True)


if __name__ == "__main__":
    main()
