"""Install checksum-pinned upstream tools locally; no sudo or shell installers."""

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import tempfile
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
MAX_BYTES = 256 * 1024 * 1024


def platform_key(system, machine):
    key = system.lower() + "-" + {"aarch64": "arm64"}.get(machine, machine)
    if key != "darwin-arm64":
        raise ValueError(
            "unsupported tool profile: "
            + key
            + "; currently qualified for provisioning: darwin-arm64 only"
        )
    return key


def install_verified(source, destination, digest, member=None):
    """Validate all input before atomically replacing an installed executable."""
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("invalid checksum")
    with source.open("rb") as stream:
        verified = stream.read(MAX_BYTES + 1)
    if len(verified) > MAX_BYTES:
        raise ValueError("download exceeds size limit")
    if hashlib.sha256(verified).hexdigest() != digest:
        raise ValueError("download checksum mismatch")
    if member is None:
        payload = verified
    else:
        with tarfile.open(fileobj=io.BytesIO(verified), mode="r:gz") as archive:
            members = []
            unpacked_size = 0
            for entry in archive:
                members.append(entry)
                unpacked_size += entry.size
                if len(members) > 1024 or unpacked_size > MAX_BYTES:
                    raise ValueError("archive exceeds size/member limit")
                path = PurePosixPath(entry.name)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or not (entry.isfile() or entry.isdir())
                ):
                    raise ValueError("unsafe archive entry: " + entry.name)
            selected = [
                entry for entry in members if entry.name == member and entry.isfile()
            ]
            if len(selected) != 1 or selected[0].size > MAX_BYTES:
                raise ValueError(
                    "missing, duplicate or oversized archive member: " + member
                )
            with archive.extractfile(selected[0]) as stream:
                payload = stream.read(MAX_BYTES + 1)
    if not payload or len(payload) > MAX_BYTES:
        raise ValueError("empty or oversized executable")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as stream:
        staged = Path(stream.name)
        try:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            staged.chmod(0o755)
            os.replace(staged, destination)
        finally:
            staged.unlink(missing_ok=True)
    return hashlib.sha256(payload).hexdigest()


def download(url, target, max_bytes=MAX_BYTES):
    if not url.startswith("https://"):
        raise ValueError("upstream downloads require HTTPS")
    with urllib.request.urlopen(url, timeout=60) as response:
        if not response.url.startswith("https://"):
            raise ValueError("insecure download redirect")
        with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as stream:
            staged = Path(stream.name)
            try:
                total = 0
                while True:
                    data = response.read(1024 * 1024)
                    if not data:
                        break
                    total += len(data)
                    if total > max_bytes:
                        raise ValueError("download exceeds size limit")
                    stream.write(data)
                stream.close()
                os.replace(staged, target)
            finally:
                staged.unlink(missing_ok=True)


def main():
    profile = platform_key(platform.system(), platform.machine())
    manifest = json.loads((ROOT / "toolchain.lock.json").read_text())
    downloads = ROOT / ".tools" / "downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    for name, tool in manifest["profiles"][profile].items():
        cached = downloads / tool["sha256"]
        if not cached.exists():
            download(tool["url"], cached)
        identity = install_verified(
            cached, ROOT / ".tools" / "bin" / name, tool["sha256"], tool.get("member")
        )
        print(
            json.dumps(
                {
                    "tool": name,
                    "version": tool["version"],
                    "executable_sha256": identity,
                    "profile": profile,
                }
            )
        )
    chart = manifest["kyverno_chart"]
    cached = downloads / chart["sha256"]
    if not cached.exists():
        download(chart["url"], cached)
    if hashlib.sha256(cached.read_bytes()).hexdigest() != chart["sha256"]:
        raise ValueError("chart checksum mismatch")
    charts = ROOT / ".tools/charts"
    charts.mkdir(exist_ok=True)
    (charts / ("kyverno-" + chart["version"] + ".tgz")).write_bytes(cached.read_bytes())


if __name__ == "__main__":
    main()
