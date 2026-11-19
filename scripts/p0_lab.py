"""Create only a fresh, explicitly authorized local compatibility lab; no cleanup."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import socket
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
LOCAL = ROOT / ".local" / "p0"


def profile_values(name, api_port, registry_port):
    if not re.fullmatch(r"csle-p0(?:-[a-z0-9]{1,16})?", name):
        raise ValueError("invalid project-scoped P0 profile")
    ports = [int(api_port), int(registry_port)]
    if any(port < 1024 or port > 65535 for port in ports) or len(set(ports)) != 2:
        raise ValueError("invalid or overlapping loopback ports")
    return name, *ports


PROFILE, API_PORT, REGISTRY_PORT = profile_values(
    os.environ.get("CSLE_P0_PROFILE", "csle-p0"),
    os.environ.get("CSLE_P0_API_PORT", "14566"),
    os.environ.get("CSLE_P0_REGISTRY_PORT", "15100"),
)
NETWORK = PROFILE
CONTEXT = "kind-" + PROFILE
FLOCI_CONTAINER = PROFILE + "-floci"
NODE_CONTAINER = PROFILE + "-control-plane"
REGISTRY_CONTAINER = "floci-aws-" + PROFILE + "-ecr-registry"
KUBECONFIG = LOCAL / "kubeconfig"


def check_ports(ports):
    for port in ports:
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError as error:
                raise ValueError("local port unavailable: " + str(port)) from error


def require_privilege_authorization(authorized):
    if not authorized:
        raise ValueError(
            "explicit owner authorization required for Kind privilege and Floci Docker socket"
        )


def local_docker():
    # Explicit local context plus Unix endpoint; never honor an ambient remote engine.
    env = dict(os.environ)
    context = env.pop("DOCKER_CONTEXT", None)
    ambient = env.pop("DOCKER_HOST", None)
    if context and context != "desktop-linux":
        raise ValueError("local Docker Desktop context required")
    endpoint = subprocess.check_output(
        [
            "docker",
            "context",
            "inspect",
            "desktop-linux",
            "--format",
            "{{.Endpoints.docker.Host}}",
        ],
        text=True,
        env=env,
    ).strip()
    if not endpoint.startswith("unix://") or (ambient and ambient != endpoint):
        raise ValueError("remote Docker endpoint is outside local authorization")
    return ["docker", "--host", endpoint]


class Recorder:
    def __init__(self):
        self.directory = (
            LOCAL
            / "runs"
            / (
                datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                + "-"
                + uuid.uuid4().hex[:8]
            )
        )
        self.directory.mkdir(parents=True)
        self.revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        self.dirty = bool(
            subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)
        )
        self.source_hashes = {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in [
                ROOT / "toolchain.lock.json",
                *sorted((ROOT / "scripts").glob("*.py")),
            ]
        }
        self.count = 0

    def run(self, args, *, env=None, check=True, timeout=600):
        self.count += 1
        start = datetime.now(timezone.utc).isoformat()
        before = time.monotonic()
        print("Running:", " ".join(map(str, args)), flush=True)
        command = [str(arg) for arg in args]
        child_env = dict(os.environ if env is None else env)
        if command[0] == "docker":
            docker = local_docker()
            if "--host" in command:
                if command[command.index("--host") + 1] != docker[2]:
                    raise ValueError(
                        "Docker endpoint differs from authorized local engine"
                    )
            else:
                command = docker + command[1:]
            child_env.pop("DOCKER_HOST", None)
            child_env.pop("DOCKER_CONTEXT", None)
        failure = None
        try:
            result = subprocess.run(
                command, cwd=ROOT, env=child_env, capture_output=True, timeout=timeout
            )
        except subprocess.TimeoutExpired as error:
            failure = "timeout"
            result = subprocess.CompletedProcess(
                command, 124, error.stdout or b"", error.stderr or b""
            )
        except OSError as error:
            failure = "os_error"
            result = subprocess.CompletedProcess(command, 127, b"", str(error).encode())
        output = result.stdout + b"\nSTDERR:\n" + result.stderr
        path = self.directory / (str(self.count).zfill(3) + ".log")
        path.write_bytes(output)
        record = {
            "command": command,
            "at": start,
            "failure": failure,
            "seconds": round(time.monotonic() - before, 3),
            "exit_code": result.returncode,
            "revision": self.revision,
            "dirty_working_tree": self.dirty,
            "source_hashes": self.source_hashes,
            "profile": {
                "name": PROFILE,
                "api_port": API_PORT,
                "registry_port": REGISTRY_PORT,
                "context": CONTEXT,
            },
            "log": path.name,
            "output_sha256": hashlib.sha256(output).hexdigest(),
        }
        with (self.directory / "commands.jsonl").open("a") as stream:
            stream.write(json.dumps(record) + "\n")
        if check and result.returncode:
            raise RuntimeError("command failed; preserved evidence: " + str(path))
        return result


def up(authorized):
    require_privilege_authorization(authorized)
    check_ports([API_PORT, REGISTRY_PORT])
    docker = local_docker()
    manifest = json.loads((ROOT / "toolchain.lock.json").read_text())
    node = json.loads((LOCAL / "node-image.json").read_text())
    current_node = json.loads(
        subprocess.check_output([*docker, "image", "inspect", node["tag"]], text=True)
    )[0]
    if (
        current_node["Id"] != node["docker_config_id"]
        or node["version"] != manifest["node_build"]["version"]
    ):
        raise ValueError("local node build identity changed or version mismatched")
    rec = Recorder()
    for resource, name in [
        ("network", NETWORK),
        ("container", FLOCI_CONTAINER),
        ("container", REGISTRY_CONTAINER),
        ("container", NODE_CONTAINER),
    ]:
        if rec.run(["docker", resource, "inspect", name], check=False).returncode == 0:
            raise ValueError("existing resource collision: " + name)
    if KUBECONFIG.exists():
        raise ValueError(
            "existing project kubeconfig; refusing overwrite: " + str(KUBECONFIG)
        )
    rec.run(["docker", "info", "--format", "{{.ServerVersion}}"])
    # Floci may start only its explicitly named ECR sidecar. UI and unsolicited services stay unexposed.
    rec.run(["docker", "network", "create", "--label", "io.csle.scope=p0", NETWORK])
    image = manifest["images"]
    data = LOCAL / "floci-data"
    data.mkdir(exist_ok=True)
    rec.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            FLOCI_CONTAINER,
            "--label",
            "io.csle.scope=p0",
            "--network",
            NETWORK,
            "--memory",
            "1536m",
            "-p",
            f"127.0.0.1:{API_PORT}:4566",
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock",
            "-v",
            str(data) + ":" + str(data),
            "-e",
            "FLOCI_SERVICES_UI_ENABLED=false",
            "-e",
            "FLOCI_SERVICES_ECR_REGISTRY_IMAGE=" + image["registry"]["reference"],
            "-e",
            "FLOCI_SERVICES_ECR_REGISTRY_CONTAINER_NAME=" + PROFILE + "-ecr-registry",
            "-e",
            "FLOCI_SERVICES_ECR_REGISTRY_BASE_PORT=" + str(REGISTRY_PORT),
            "-e",
            "FLOCI_SERVICES_ECR_REGISTRY_MAX_PORT=" + str(REGISTRY_PORT),
            "-e",
            "FLOCI_SERVICES_ECR_DOCKER_NETWORK=" + NETWORK,
            "-e",
            "FLOCI_SERVICES_ECR_DATA_PATH=" + str(data),
            "-e",
            "FLOCI_SERVICES_ECR_URI_STYLE=path",
            image["floci"]["reference"],
        ]
    )
    env = dict(
        os.environ, KIND_EXPERIMENTAL_DOCKER_NETWORK=NETWORK, DOCKER_HOST=docker[2]
    )
    env.pop("DOCKER_CONTEXT", None)
    rec.run(
        [
            ROOT / ".tools/bin/kind",
            "create",
            "cluster",
            "--name",
            PROFILE,
            "--kubeconfig",
            KUBECONFIG,
            "--config",
            ROOT / "infra/p0/kind.yaml",
            "--image",
            node["tag"],
            "--wait",
            "180s",
        ],
        env=env,
    )
    rec.run(
        [
            "kubectl",
            "--kubeconfig",
            KUBECONFIG,
            "--context",
            CONTEXT,
            "get",
            "nodes",
            "-o",
            "json",
        ]
    )
    print("Lab created; evidence:", rec.directory, flush=True)
    print("Resources retained. No cleanup performed.", flush=True)


def build_node():
    from bootstrap_tools import download

    manifest = json.loads((ROOT / "toolchain.lock.json").read_text())
    spec = manifest["node_build"]
    rec = Recorder()
    archive = ROOT / ".tools/downloads" / spec["sha256"]
    archive.parent.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        download(spec["url"], archive, max_bytes=512 * 1024 * 1024)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != spec["sha256"]:
        raise ValueError("Kubernetes release archive checksum mismatch")
    env = dict(os.environ, DOCKER_HOST=local_docker()[2])
    env.pop("DOCKER_CONTEXT", None)
    rec.run(
        [
            ROOT / ".tools/bin/kind",
            "build",
            "node-image",
            "--type",
            "file",
            archive,
            "--arch",
            spec["architecture"],
            "--base-image",
            spec["base_reference"],
            "--image",
            spec["output_tag"],
        ],
        env=env,
        timeout=900,
    )
    inspected = rec.run(["docker", "image", "inspect", spec["output_tag"]])
    image = json.loads(inspected.stdout)[0]
    result = {
        "version": spec["version"],
        "tag": spec["output_tag"],
        "docker_config_id": image["Id"],
        "architecture": image["Architecture"],
        "source_archive_sha256": spec["sha256"],
        "base_reference": spec["base_reference"],
        "evidence_directory": str(rec.directory),
    }
    (LOCAL / "node-image.json").write_text(json.dumps(result, indent=2))
    print("Patched node build:", result, flush=True)


def install_kyverno():
    manifest = json.loads((ROOT / "toolchain.lock.json").read_text())
    chart = (
        ROOT
        / ".tools/charts"
        / ("kyverno-" + manifest["kyverno_chart"]["version"] + ".tgz")
    )
    if (
        hashlib.sha256(chart.read_bytes()).hexdigest()
        != manifest["kyverno_chart"]["sha256"]
    ):
        raise ValueError("chart checksum mismatch")
    rec = Recorder()
    rec.run(
        [
            ROOT / ".tools/bin/helm",
            "install",
            "kyverno",
            chart,
            "--kubeconfig",
            KUBECONFIG,
            "--kube-context",
            CONTEXT,
            "-n",
            "kyverno",
            "--create-namespace",
            "-f",
            ROOT / "infra/p0/kyverno-values.json",
            "--wait",
            "--timeout",
            "180s",
        ]
    )
    rec.run(
        [
            "kubectl",
            "--kubeconfig",
            KUBECONFIG,
            "--context",
            CONTEXT,
            "-n",
            "kyverno",
            "get",
            "pods",
            "-o",
            "json",
        ]
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["up", "kyverno", "node"])
    parser.add_argument(
        "--allow-privileged-local",
        action="store_true",
        help="Use only after owner authorizes Kind privilege and Floci socket access",
    )
    args = parser.parse_args()
    if args.action == "up":
        up(args.allow_privileged_local)
    elif args.action == "kyverno":
        install_kyverno()
    else:
        build_node()
