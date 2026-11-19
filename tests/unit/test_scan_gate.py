"""Synthetic policy input oracles; these do not qualify a real scanner."""

import copy
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from p0_attestation import validate_scan


class ScanGateTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 19, 17, tzinfo=timezone.utc)
        self.digest = "sha256:" + "a" * 64
        self.report = {
            "SchemaVersion": 2,
            "CreatedAt": "2026-11-19T16:00:00Z",
            "Metadata": {"RepoDigests": ["localhost/demo@" + self.digest]},
            "Results": [{"Class": "os-pkgs", "Type": "alpine", "Vulnerabilities": []}],
        }
        self.db = {"UpdatedAt": "2026-11-19T15:00:00Z"}

    def test_supported_complete_clean_result_allows(self):
        validate_scan(self.report, self.db, self.digest, self.now)

    def test_missing_results_rejects(self):
        del self.report["Results"]
        with self.assertRaises(ValueError):
            validate_scan(self.report, self.db, self.digest, self.now)

    def test_unrecognized_or_prohibited_severity_rejects(self):
        for severity in ["CRITICAL", "HIGH", "UNKNOWN", "typo", None]:
            with self.subTest(severity=severity):
                report = copy.deepcopy(self.report)
                report["Results"][0]["Vulnerabilities"] = [{"Severity": severity}]
                with self.assertRaisesRegex(ValueError, "severity"):
                    validate_scan(report, self.db, self.digest, self.now)

    def test_wrong_digest_and_schema_reject(self):
        for change in [
            {"SchemaVersion": 99},
            {"Metadata": {"RepoDigests": ["localhost/demo:tag"]}},
        ]:
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    validate_scan(
                        {**self.report, **change}, self.db, self.digest, self.now
                    )

    def test_stale_future_or_naive_timestamps_reject(self):
        for stamp in [
            "2026-11-18T16:59:59Z",
            "2026-11-19T18:00:00Z",
            "2026-11-19T16:00:00",
        ]:
            with self.subTest(stamp=stamp):
                with self.assertRaises(ValueError):
                    validate_scan(
                        self.report, {"UpdatedAt": stamp}, self.digest, self.now
                    )

    def test_empty_or_unsupported_result_rejects(self):
        for results in [[], [{}], [{"Class": "config", "Type": "yaml"}]]:
            with self.subTest(results=results):
                with self.assertRaises(ValueError):
                    validate_scan(
                        {**self.report, "Results": results},
                        self.db,
                        self.digest,
                        self.now,
                    )

    def test_malformed_falsy_vulnerability_values_reject(self):
        for value in [{}, "", False, 0]:
            with self.subTest(value=value):
                report = copy.deepcopy(self.report)
                report["Results"][0]["Vulnerabilities"] = value
                with self.assertRaisesRegex(ValueError, "malformed"):
                    validate_scan(report, self.db, self.digest, self.now)

    def test_supported_absent_or_null_clean_list_accepts(self):
        for value in [None, []]:
            report = copy.deepcopy(self.report)
            report["Results"][0]["Vulnerabilities"] = value
            validate_scan(report, self.db, self.digest, self.now)
        del self.report["Results"][0]["Vulnerabilities"]
        validate_scan(self.report, self.db, self.digest, self.now)
