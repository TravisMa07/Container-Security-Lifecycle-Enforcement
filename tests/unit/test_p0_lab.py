"""P0 isolation expectations from frozen T4; no Docker/network dependency."""

from pathlib import Path
import socket
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from p0_lab import check_ports, require_privilege_authorization


class LabSafetyTests(unittest.TestCase):
    def test_privileged_start_requires_explicit_authorization(self):
        with self.assertRaisesRegex(ValueError, "authorization"):
            require_privilege_authorization(False)

    def test_explicit_authorization_is_accepted(self):
        require_privilege_authorization(True)

    def test_occupied_port_is_rejected(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            with self.assertRaisesRegex(ValueError, "port"):
                check_ports([listener.getsockname()[1]])


class DockerIsolationTests(unittest.TestCase):
    def test_remote_host_is_rejected(self):
        from unittest.mock import patch
        from p0_lab import local_docker

        with (
            patch.dict("os.environ", {"DOCKER_HOST": "ssh://remote"}, clear=True),
            patch(
                "p0_lab.subprocess.check_output",
                return_value="unix:///local/docker.sock",
            ),
        ):
            with self.assertRaisesRegex(ValueError, "remote"):
                local_docker()

    def test_remote_context_is_rejected(self):
        from unittest.mock import patch
        from p0_lab import local_docker

        with patch.dict("os.environ", {"DOCKER_CONTEXT": "remote"}, clear=True):
            with self.assertRaisesRegex(ValueError, "context"):
                local_docker()

    def test_nonlocal_context_endpoint_is_rejected(self):
        from unittest.mock import patch
        from p0_lab import local_docker

        with (
            patch.dict("os.environ", {}, clear=True),
            patch("p0_lab.subprocess.check_output", return_value="tcp://remote:2376"),
        ):
            with self.assertRaisesRegex(ValueError, "remote"):
                local_docker()

    def test_local_engine_is_explicit(self):
        from unittest.mock import patch
        from p0_lab import local_docker

        with (
            patch.dict("os.environ", {}, clear=True),
            patch(
                "p0_lab.subprocess.check_output",
                return_value="unix:///local/docker.sock",
            ),
        ):
            self.assertEqual(
                local_docker(), ["docker", "--host", "unix:///local/docker.sock"]
            )


class EvidenceFailureTests(unittest.TestCase):
    def test_timeout_retains_partial_output_and_failure_record(self):
        import json
        import tempfile
        from unittest.mock import patch
        from p0_lab import Recorder

        with tempfile.TemporaryDirectory() as tmp, patch("p0_lab.LOCAL", Path(tmp)):
            recorder = Recorder()
            with self.assertRaises(RuntimeError):
                recorder.run(
                    [
                        sys.executable,
                        "-c",
                        'import time; print("before timeout", flush=True); time.sleep(10)',
                    ],
                    timeout=0.2,
                )
            entry = json.loads((recorder.directory / "commands.jsonl").read_text())
            self.assertEqual(entry["failure"], "timeout")
            self.assertEqual(entry["exit_code"], 124)
            self.assertIn(
                "before timeout", (recorder.directory / entry["log"]).read_text()
            )

    def test_missing_executable_retains_error_record(self):
        import json
        import tempfile
        from unittest.mock import patch
        from p0_lab import Recorder

        with tempfile.TemporaryDirectory() as tmp, patch("p0_lab.LOCAL", Path(tmp)):
            recorder = Recorder()
            with self.assertRaises(RuntimeError):
                recorder.run([str(Path(tmp) / "not-installed")])
            entry = json.loads((recorder.directory / "commands.jsonl").read_text())
            self.assertEqual(entry["failure"], "os_error")
            self.assertEqual(entry["exit_code"], 127)


class ProfileIsolationTests(unittest.TestCase):
    def test_project_scoped_profile_and_distinct_ports(self):
        from p0_lab import profile_values

        self.assertEqual(
            profile_values("csle-p0-close", "14576", "15110"),
            ("csle-p0-close", 14576, 15110),
        )

    def test_unscoped_or_shell_like_profile_is_rejected(self):
        from p0_lab import profile_values

        for name in ["production", "csle-p0-../escape", "csle-p0;echo", "csle-p0-"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                profile_values(name, 14576, 15110)

    def test_privileged_or_colliding_ports_are_rejected(self):
        from p0_lab import profile_values

        for pair in [(80, 15110), (14576, 14576), (65536, 15110)]:
            with self.subTest(pair=pair), self.assertRaises(ValueError):
                profile_values("csle-p0-close", *pair)
