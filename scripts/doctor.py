"""Read-only host discovery. No installs, cloud requests or kube API operations."""

import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent

TOOLS = {
    "git": ["--version"],
    "docker": ["version", "--format", "{{json .}}"],
    "uv": ["--version"],
    "kind": ["version"],
    "kubectl": ["version", "--client", "-o", "json"],
    "helm": ["version", "--short"],
    "trivy": ["--version"],
    "cosign": ["version"],
    "aws": ["--version"],
}


def main():
    results = {}
    for name, args in TOOLS.items():
        local = ROOT / ".tools/bin" / name
        executable = str(local) if local.is_file() else shutil.which(name)
        if (
            name == "aws"
            and executable is None
            and (ROOT / ".tools/venv/bin/python").is_file()
        ):
            executable = str(ROOT / ".tools/venv/bin/python")
            args = ["-c", 'import boto3; print("boto3 " + boto3.__version__)']
        if executable is None:
            results[name] = {"status": "missing"}
            continue
        try:
            run = subprocess.run(
                [executable, *args],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            results[name] = {
                "status": "available" if run.returncode == 0 else "failed",
                "path": executable,
                "exit_code": run.returncode,
                "output": (run.stdout + run.stderr).strip(),
            }
        except (OSError, subprocess.TimeoutExpired) as error:
            results[name] = {"status": "failed", "error": str(error)}
    ready = all(result["status"] == "available" for result in results.values())
    print(
        json.dumps(
            {
                "schema_version": "1",
                "system": platform.system(),
                "architecture": platform.machine(),
                "prerequisites_available": ready,
                "integration_qualified": False,
                "tools": results,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if ready else 1


if __name__ == "__main__":
    sys.exit(main())
