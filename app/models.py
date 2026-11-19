"""Strict v1 records consumed by P1; raw provider assertions are not trust."""
from datetime import datetime
import hashlib
import json
import re
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def sha256_bytes(raw: bytes) -> str:
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def nonblank(value: str) -> str:
    if not value.strip():
        raise ValueError('nonblank text required')
    return value


def utc(value: str) -> str:
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z', value):
        raise ValueError('canonical UTC timestamp required')
    datetime.fromisoformat(value.replace('Z', '+00:00'))
    return value


def unique(value: list) -> list:
    if len(value) != len(set(value)):
        raise ValueError('unique list required')
    return value


Text = Annotated[str, Field(min_length=1, max_length=4096), AfterValidator(nonblank)]
Identifier = Annotated[str, Field(min_length=1, max_length=512), AfterValidator(nonblank)]
Digest = Annotated[str, Field(pattern=r'^sha256:[0-9a-f]{64}$')]
Timestamp = Annotated[str, AfterValidator(utc)]
Platform = Annotated[str, Field(pattern=r'^[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)?$')]
Texts = Annotated[list[Text], Field(max_length=1000), AfterValidator(unique)]
Identifiers = Annotated[list[Identifier], Field(max_length=1000), AfterValidator(unique)]


class Record(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class ImageArtifact(Record):
    schema_version: Literal['1'] = '1'
    image_id: Digest | None
    registry: Text
    repository: Text
    tags_observed: Texts
    manifest_digest: Digest | None
    index_digest: Digest | None
    platform_digest: Digest | None
    platform: Platform | None
    source: Literal['oci_registry', 'emulated_aws_ecr', 'kubernetes', 'synthetic_contract_test']
    source_reference: Text
    first_seen: Timestamp
    last_seen: Timestamp
    resolution_status: Literal['resolved', 'unknown']
    resolution_reason: Text | None

    @model_validator(mode='after')
    def relationships(self):
        if datetime.fromisoformat(self.first_seen.replace('Z', '+00:00')) > datetime.fromisoformat(self.last_seen.replace('Z', '+00:00')):
            raise ValueError('first_seen must not follow last_seen')
        if self.resolution_status == 'resolved':
            if self.image_id is None or self.image_id != self.manifest_digest:
                raise ValueError('resolved image_id must equal selected manifest digest')
            if self.platform_digest is not None and self.platform_digest != self.manifest_digest:
                raise ValueError('platform digest must equal selected manifest digest')
        elif any(value is not None for value in [self.image_id, self.manifest_digest, self.index_digest, self.platform_digest]) or not self.resolution_reason:
            raise ValueError('unknown resolution needs null digests and reason')
        return self


class VulnerabilityFinding(Record):
    schema_version: Literal['1'] = '1'
    finding_id: Identifier
    image_digest: Digest
    scanner: Literal['trivy'] = 'trivy'
    scanner_version: Identifier
    parser_version: Identifier
    vuln_id: Identifier
    package_name: Text
    package_type: Identifier
    package_path: Text | None
    installed_version: Text
    fixed_version: Text | None
    severity: Literal['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    severity_source: Text | None
    target_os: Text | None
    platform: Platform | None
    aliases: Identifiers
    scan_timestamp: Timestamp
    scanner_db_updated_at: Timestamp | None
    source_document_hash: Digest
    validity: Literal['affected', 'not_affected', 'under_investigation', 'disputed']
    evidence_ids: Annotated[Identifiers, Field(min_length=1)]


class ParsedScan(Record):
    image: ImageArtifact
    findings: list[VulnerabilityFinding]
    source_document_hash: Digest
    parser_version: Identifier
    scanner_version: Identifier | None
    scan_timestamp: Timestamp
    scanner_db_updated_at: Timestamp | None
    db_document_hash: Digest | None
    limitations: Annotated[list[Identifier], AfterValidator(unique)]

    @model_validator(mode='after')
    def coherent_evidence(self):
        seen = set()
        for finding in self.findings:
            if finding.finding_id in seen:
                raise ValueError('duplicate canonical finding identity')
            seen.add(finding.finding_id)
            if (finding.image_digest != self.image.image_id
                or finding.source_document_hash != self.source_document_hash
                or finding.parser_version != self.parser_version
                or finding.scan_timestamp != self.scan_timestamp
                or finding.scanner_db_updated_at != self.scanner_db_updated_at
                or finding.scanner_version != (self.scanner_version or 'unknown')
                or self.source_document_hash not in finding.evidence_ids):
                raise ValueError('finding evidence does not match scan context')
        if self.limitations != sorted(self.limitations):
            raise ValueError('limitations must be sorted')
        return self
