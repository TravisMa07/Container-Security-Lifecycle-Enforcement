"""Requirement-derived synthetic contract oracles; no runtime/integration claim."""

import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[2]
DIRECTORY = ROOT / "contracts/v1"
KINDS = [
    "image-artifact",
    "workload-observation",
    "vulnerability-finding",
    "derived-finding-state",
    "security-predicate",
    "compliance-evidence",
]


class CanonicalContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schemas = {
            path.stem: json.loads(path.read_text())
            for path in DIRECTORY.glob("*.schema.json")
        }
        registry = Registry().with_resources(
            (schema["$id"], Resource.from_contents(schema))
            for schema in cls.schemas.values()
        )
        cls.validators = {
            name: Draft202012Validator(
                cls.schemas[name + ".schema"],
                registry=registry,
                format_checker=FormatChecker(),
            )
            for name in KINDS
        }
        fixture = json.loads((DIRECTORY / "synthetic-examples.json").read_text())
        if fixture["provenance"] != "synthetic_contract_test":
            raise ValueError("contract fixtures must retain synthetic provenance")
        cls.examples = fixture["records"]

    def valid(self, kind, value):
        self.validators[kind].validate(value)

    def invalid(self, kind, value):
        self.assertTrue(list(self.validators[kind].iter_errors(value)), (kind, value))

    def test_schemas_are_valid_and_minimum_examples_accept(self):
        for schema in self.schemas.values():
            Draft202012Validator.check_schema(schema)
        for kind in KINDS:
            with self.subTest(kind=kind):
                self.valid(kind, self.examples[kind])

    def test_immutable_identity_rejects_tags_and_malformed_digests(self):
        for kind, field in [
            ("image-artifact", "image_id"),
            ("vulnerability-finding", "image_digest"),
            ("security-predicate", "subject_image_digest"),
        ]:
            for digest in [
                "demo:latest",
                "sha256:" + "A" * 64,
                "sha256:" + "a" * 63,
                "sha256:" + "g" * 64,
            ]:
                with self.subTest(kind=kind, digest=digest):
                    value = copy.deepcopy(self.examples[kind])
                    value[field] = digest
                    self.invalid(kind, value)

    def test_resolution_uncertainty_is_explicit(self):
        artifact = copy.deepcopy(self.examples["image-artifact"])
        artifact["manifest_digest"] = None
        self.invalid("image-artifact", artifact)
        artifact.update(
            resolution_status="unknown",
            image_id=None,
            index_digest=None,
            platform_digest=None,
            resolution_reason="Registry unavailable",
        )
        self.valid("image-artifact", artifact)
        artifact["manifest_digest"] = "sha256:" + "b" * 64
        self.invalid("image-artifact", artifact)

    def test_index_and_platform_identities_are_preserved(self):
        artifact = copy.deepcopy(self.examples["image-artifact"])
        artifact["index_digest"] = "sha256:" + "b" * 64
        self.valid("image-artifact", artifact)
        self.assertNotEqual(artifact["index_digest"], artifact["platform_digest"])

    def test_workload_unknown_runtime_and_reused_name_new_uid_accept(self):
        record = copy.deepcopy(self.examples["workload-observation"])
        record.update(
            runtime_image_id=None, resolved_digest=None, resolution_status="unknown"
        )
        self.valid("workload-observation", record)
        record["uid"] = "replacement-resource-uid"
        self.valid("workload-observation", record)

    def test_workload_identity_checkpoint_and_kind_are_required(self):
        for field in ["uid", "cluster_id", "idempotency_key"]:
            value = copy.deepcopy(self.examples["workload-observation"])
            del value[field]
            with self.subTest(field=field):
                self.invalid("workload-observation", value)
        for field, bad in [
            ("resource_version", 123),
            ("kind", "UnknownKind"),
            ("container_type", "mystery"),
        ]:
            value = copy.deepcopy(self.examples["workload-observation"])
            value[field] = bad
            self.invalid("workload-observation", value)

    def test_timestamps_are_actual_canonical_utc_dates(self):
        for kind, field in [
            ("image-artifact", "first_seen"),
            ("workload-observation", "observed_at"),
            ("vulnerability-finding", "scan_timestamp"),
            ("derived-finding-state", "assessment_at"),
            ("security-predicate", "issued_at"),
            ("compliance-evidence", "observed_at"),
        ]:
            for stamp in [
                "2026-11-19T12:00:00",
                "2026-11-19T12:00:00-05:00",
                "2026-02-30T12:00:00Z",
                "today",
            ]:
                value = copy.deepcopy(self.examples[kind])
                value[field] = stamp
                with self.subTest(kind=kind, stamp=stamp):
                    self.invalid(kind, value)

    def test_orthogonal_states_do_not_imply_false_closure(self):
        record = copy.deepcopy(self.examples["derived-finding-state"])
        for validity in ["affected", "not_affected", "under_investigation", "disputed"]:
            for exposure in [
                "running",
                "configured_not_running",
                "historical_observed",
                "unknown",
            ]:
                for remediation in ["open", "in_progress", "regressed", "unknown"]:
                    record.update(
                        validity=validity, exposure=exposure, remediation=remediation
                    )
                    self.valid("derived-finding-state", record)

    def verified(self):
        record = copy.deepcopy(self.examples["derived-finding-state"])
        record.update(exposure="historical_observed", remediation="verified_in_scope")
        record["verification"] = {
            "scope": "kind-csle/all-namespaces",
            "window_start": "2026-11-19T12:00:00Z",
            "window_end": "2026-11-19T12:05:00Z",
            "inventory_fresh": True,
            "coverage_complete": True,
            "remaining_references": 0,
            "fixed_scan_evidence_ids": ["fixed-scan"],
            "replacement_observation_ids": ["replacement"],
        }
        return record

    def test_scoped_verification_requires_every_positive_prerequisite(self):
        record = self.verified()
        self.valid("derived-finding-state", record)
        missing = copy.deepcopy(record)
        del missing["verification"]
        self.invalid("derived-finding-state", missing)
        for field in record["verification"]:
            value = copy.deepcopy(record)
            del value["verification"][field]
            with self.subTest(missing=field):
                self.invalid("derived-finding-state", value)
        for field, bad in [
            ("inventory_fresh", False),
            ("coverage_complete", False),
            ("remaining_references", 1),
            ("fixed_scan_evidence_ids", []),
            ("replacement_observation_ids", []),
        ]:
            value = copy.deepcopy(record)
            value["verification"][field] = bad
            self.invalid("derived-finding-state", value)

    def test_scoped_verification_rejects_gaps_current_or_unknown_exposure(self):
        for exposure in ["running", "configured_not_running", "unknown"]:
            value = self.verified()
            value["exposure"] = exposure
            self.invalid("derived-finding-state", value)
        value = self.verified()
        value["coverage_gap_ids"] = ["gap"]
        self.invalid("derived-finding-state", value)

    def test_nonverified_states_cannot_carry_a_verification_claim(self):
        value = self.verified()
        value["remediation"] = "open"
        self.invalid("derived-finding-state", value)

    def test_predicate_requires_trust_context_and_policy_outcomes(self):
        for field in [
            "subject_image_digest",
            "policy_id",
            "policy_version",
            "policy_hash",
            "scan_result_hash",
            "signer_identity",
            "issued_at",
            "expires_at",
            "scan_timestamp",
            "scanner_db_updated_at",
            "timestamp",
        ]:
            value = copy.deepcopy(self.examples["security-predicate"])
            del value[field]
            with self.subTest(field=field):
                self.invalid("security-predicate", value)
        for decision in ["allow", "deny", "review_required"]:
            value = copy.deepcopy(self.examples["security-predicate"])
            value["decision"] = decision
            self.valid("security-predicate", value)
        value["decision"] = "safe"
        self.invalid("security-predicate", value)

    def test_finding_unknowns_accept_but_malformed_provenance_rejects(self):
        value = copy.deepcopy(self.examples["vulnerability-finding"])
        value.update(severity="UNKNOWN", scanner_db_updated_at=None, fixed_version=None)
        self.valid("vulnerability-finding", value)
        for field, bad in [
            ("source_document_hash", "unsigned-report"),
            ("scanner_version", ""),
            ("parser_version", ""),
        ]:
            record = copy.deepcopy(value)
            record[field] = bad
            self.invalid("vulnerability-finding", record)

    def test_unknown_compliance_applicability_stays_review(self):
        record = copy.deepcopy(self.examples["compliance-evidence"])
        self.valid("compliance-evidence", record)
        for assessment in [
            "pass_technical_check",
            "fail_technical_check",
            "not_applicable_with_justification",
        ]:
            value = copy.deepcopy(record)
            value["assessment"] = assessment
            self.invalid("compliance-evidence", value)

    def test_compliance_pass_needs_applicability_and_evidence(self):
        record = copy.deepcopy(self.examples["compliance-evidence"])
        record.update(assessment="pass_technical_check", applicability="applicable")
        self.valid("compliance-evidence", record)
        record["evidence_ids"] = []
        self.invalid("compliance-evidence", record)

    def test_not_applicable_needs_explicit_justification(self):
        record = copy.deepcopy(self.examples["compliance-evidence"])
        record.update(
            assessment="not_applicable_with_justification",
            applicability="not_applicable",
        )
        self.invalid("compliance-evidence", record)
        record["applicability_justification"] = (
            "Fictional demo is outside the declared evaluation scope"
        )
        self.valid("compliance-evidence", record)

    def test_unknown_version_enum_and_extension_fields_reject(self):
        for kind in KINDS:
            for field, bad in [
                ("schema_version", "99"),
                ("organizational_certification", "compliant"),
            ]:
                record = copy.deepcopy(self.examples[kind])
                record[field] = bad
                with self.subTest(kind=kind, field=field):
                    self.invalid(kind, record)
