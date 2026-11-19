"""Read-only host discovery. No installs, cloud requests or kube API operations."""
import json
import platform
import shutil
import subprocess
import sys

TOOLS = {
    "git": ["--version"], "docker": ["version", "--format", "{{json .}}"],
    "uv": ["--version"], "kind": ["version"],
    "kubectl": ["version", "--client", "-o", "json"],
    "helm": ["version", "--short"], "trivy": ["--version"],
    "cosign": ["version"], "aws": ["--version"],
}

def main():
    results = {}
    for name, args in TOOLS.items():
        executable = shutil.which(name)
        if executable is None:
            results[name] = {"status": "missing"}
            continue
        try:
            run = subprocess.run([executable, *args], capture_output=True,
                                 text=True, timeout=15, check=False)
            results[name] = {"status": "available" if run.returncode == 0 else "failed",
                             "path": executable, "exit_code": run.returncode,
                             "output": (run.stdout + run.stderr).strip()}
        except (OSError, subprocess.TimeoutExpired) as error:
            results[name] = {"status": "failed", "error": str(error)}
    ready = all(result["status"] == "available" for result in results.values())
    print(json.dumps({"schema_version": "1", "system": platform.system(),
                      "architecture": platform.machine(), "prerequisites_available": ready,
                      "integration_qualified": False, "tools": results}, indent=2, sort_keys=True))
    return 0 if ready else 1

if __name__ == "__main__":
    sys.exit(main())
