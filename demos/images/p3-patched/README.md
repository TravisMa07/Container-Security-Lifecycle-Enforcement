# Vetted P3 patched fixture

This fixture changes only the reviewed Alpine base's libcrypto3/libssl3 packages to the exact original finding's fixed version3.5.9-r1. `recipe.json` pins the selected base manifest, official Alpine package URLs/SHA-256, Dockerfile, platform, fixed timestamp and loopback output repository. The build requests linux/arm64/v8; the exporter may omit the default v8 config variant. Raw platform values remain recorded; P3 applies only the exact containerd arm64/arm64-v8 default alias, not arbitrary platform equivalence. APK signatures are still checked by the base image's package manager; `--allow-untrusted` is prohibited.

From the supported P0 checkout with its existing loopback registry running:

```sh
.tools/venv/bin/python scripts/p3_fixtures.py
.tools/venv/bin/python scripts/p3_fixtures.py --no-cache
```

The helper uses the explicitly validated local Docker Desktop Unix endpoint. Downloads/cached packages, build contexts, command logs and result receipts remain under ignored `.local/p3/`. Corrupt cached input rejects rather than silently repairing it. The helper never accepts an arbitrary endpoint, source URL, build recipe or image reference.

Build runs with network disabled, provenance/SBOM generation disabled and a fixed SOURCE_DATE_EPOCH. Parent-owned no-cache layer comparison identified the package installer timestamp in /var/log/apk.log as the only differing file; the Dockerfile removes that installation log after signature-verified installation. Package database and installed binaries remain intact for independent scanner evidence. Docker exports to an ignored image.tar with timestamp rewriting, then an explicit local docker load imports it (avoiding the Docker driver implicit-unpack/export conflict). The output is pushed only to `127.0.0.1:15120/csle-p3/patched:fixed`, then selected manifest/config bytes are verified. If the parent adds `images.p3_patched.linux_arm64_digest` (or manifest_digest/selected_digest) to the repository toolchain lock, any differing output rejects. The mutable fixture tag is only transport convenience; consumers use the recorded immutable image_ref. A successful build is not a scan, fixed-package proof, policy verdict or signing authorization.

Parent-owned actual builds/scans and a no-cache digest comparison must qualify this fixture before claiming bit-for-bit reproduction or extending the scanner's fixed-fixture allowlist. Official package/image components retain their own licenses; the repository Apache-2.0 license does not relicense package payloads. Raw package bytes are not committed.
