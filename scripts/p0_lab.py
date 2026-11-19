"""Create only a fresh, explicitly authorized local compatibility lab; no cleanup."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
LOCAL = ROOT / ".local" / "p0"
NETWORK = "csle-p0"
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
    check_ports([14566, 15100])
    docker = local_docker()
    manifest = json.loads((ROOT / "toolchain.lock.json").read_text())
    rec = Recorder()
    for resource, name in [
        ("network", NETWORK),
        ("container", "csle-p0-floci"),
        ("container", "floci-aws-csle-p0-ecr-registry"),
        ("container", "csle-p0-control-plane"),
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
            "csle-p0-floci",
            "--label",
            "io.csle.scope=p0",
            "--network",
            NETWORK,
            "--memory",
            "1536m",
            "-p",
            "127.0.0.1:14566:4566",
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock",
            "-v",
            str(data) + ":" + str(data),
            "-e",
            "FLOCI_SERVICES_UI_ENABLED=false",
            "-e",
            "FLOCI_SERVICES_ECR_REGISTRY_IMAGE=" + image["registry"]["reference"],
            "-e",
            "FLOCI_SERVICES_ECR_REGISTRY_CONTAINER_NAME=csle-p0-ecr-registry",
            "-e",
            "FLOCI_SERVICES_ECR_REGISTRY_BASE_PORT=15100",
            "-e",
            "FLOCI_SERVICES_ECR_REGISTRY_MAX_PORT=15100",
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
            "csle-p0",
            "--kubeconfig",
            KUBECONFIG,
            "--config",
            ROOT / "infra/p0/kind.yaml",
            "--image",
            image["kind_node"]["reference"],
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
            "kind-csle-p0",
            "get",
            "nodes",
            "-o",
            "json",
        ]
    )
    print("Lab created; evidence:", rec.directory, flush=True)
    print("Resources retained. No cleanup performed.", flush=True)


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
            "kind-csle-p0",
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
            "kind-csle-p0",
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
    parser.add_argument("action", choices=["up", "kyverno"])
    parser.add_argument(
        "--allow-privileged-local",
        action="store_true",
        help="Use only after owner authorizes Kind privilege and Floci socket access",
    )
    args = parser.parse_args()
    if args.action == "up":
        up(args.allow_privileged_local)
    else:
        install_kyverno()
