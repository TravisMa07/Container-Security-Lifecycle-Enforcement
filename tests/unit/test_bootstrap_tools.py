"""Independent security cases T1–T3 from the frozen P0 design; offline."""

import hashlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from bootstrap_tools import install_verified, platform_key


class VerifiedToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "download"
        self.destination = self.root / "bin" / "tool"

    def install(self, data, member=None, digest=None):
        self.source.write_bytes(data)
        return install_verified(
            self.source,
            self.destination,
            digest or hashlib.sha256(data).hexdigest(),
            member,
        )

    def archive(self, name, kind=tarfile.REGTYPE):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.linkname = "../../escape"
            info.size = 4 if kind == tarfile.REGTYPE else 0
            archive.addfile(info, io.BytesIO(b"tool") if info.size else None)
        return stream.getvalue()

    def test_verified_raw_bytes_are_installed_executable(self):
        self.install(b"verified tool")
        self.assertEqual(self.destination.read_bytes(), b"verified tool")
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o755)

    def test_tampered_download_never_replaces_previous_tool(self):
        self.destination.parent.mkdir()
        self.destination.write_bytes(b"previous")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.install(b"altered bytes", digest="0" * 64)
        self.assertEqual(self.destination.read_bytes(), b"previous")

    def test_verified_archive_member_installs(self):
        self.install(self.archive("darwin-arm64/tool"), member="darwin-arm64/tool")
        self.assertEqual(self.destination.read_bytes(), b"tool")

    def test_archive_escape_is_rejected_without_install(self):
        with self.assertRaisesRegex(ValueError, "archive"):
            self.install(self.archive("../../escape"), member="../../escape")
        self.assertFalse(self.destination.exists())
        self.assertFalse((self.root.parent / "escape").exists())

    def test_archive_link_is_rejected_without_install(self):
        with self.assertRaisesRegex(ValueError, "archive"):
            self.install(self.archive("tool", tarfile.SYMTYPE), member="tool")
        self.assertFalse(self.destination.exists())

    def test_missing_member_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "member"):
            self.install(self.archive("other"), member="tool")
        self.assertFalse(self.destination.exists())

    def test_unsupported_platform_is_explicit(self):
        with self.assertRaisesRegex(ValueError, "unsupported"):
            platform_key("Windows", "arm64")


if __name__ == "__main__":
    unittest.main()
