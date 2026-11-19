"""Bounded Trivy schema-2 vulnerability normalization; never execution trust."""
from datetime import datetime, timezone
import json
import math
import re
from urllib.parse import urlsplit

from app.models import ImageArtifact, ParsedScan, VulnerabilityFinding, canonical_json, sha256_bytes

PARSER_VERSION = 'trivy-v2/1'
MAX_REPORT_BYTES = 20 * 1024 * 1024
MAX_DB_BYTES = 1024 * 1024
MAX_RESULTS = 10_000
MAX_FINDINGS = 100_000
MAX_DEPTH = 64
DIGEST = r'sha256:[0-9a-f]{64}'


def parse_image_ref(value: str) -> tuple[str, str, str]:
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError('digest-qualified image reference required')
    match = re.fullmatch(r'([a-z0-9][a-z0-9.:-]*)/([a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*)@(' + DIGEST + ')', value)
    if not match:
        raise ValueError('explicit registry/repository@sha256 digest required; tags unsupported')
    registry, repository, digest = match.groups()
    try:
        authority = urlsplit("//" + registry)
        port = authority.port
        if not authority.hostname or (port is not None and not 1 <= port <= 65535):
            raise ValueError("invalid registry authority")
    except ValueError as error:
        raise ValueError("invalid registry authority") from error
    return registry, repository, digest


def normalize_timestamp(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})', value):
        raise ValueError('timezone-aware RFC3339 timestamp required')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (ValueError, OverflowError) as error:
        raise ValueError('invalid timestamp') from error
    return parsed.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def _pairs(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ValueError('duplicate JSON key')
        output[key] = value
    return output


def _float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("nonfinite JSON number")
    return result


def _unicode(value):
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError("invalid Unicode scalar") from error
    elif isinstance(value, list):
        for item in value:
            _unicode(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _unicode(key)
            _unicode(item)


def load_json(raw: bytes, limit: int = MAX_REPORT_BYTES):
    if not isinstance(raw, bytes) or len(raw) > limit:
        raise ValueError('JSON input exceeds byte limit or is not bytes')
    # Bound nesting before JSON decoding; quoted braces do not count.
    depth = 0
    quoted = False
    escaped = False
    for char in raw:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
        elif char == 34:
            quoted = True
        elif char in (123, 91):
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError('JSON nesting exceeds limit')
        elif char in (125, 93):
            depth -= 1
    try:
        result = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs, parse_float=_float, parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON number')))
        _unicode(result)
        return result
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('malformed JSON document') from error


# Shared bounded decoder for the runner and OCI resolver.
load_document = load_json


def _object(value, name):
    if not isinstance(value, dict):
        raise ValueError(name + ' must be an object')
    return value


def _text(value, name, optional=False):
    if optional and (value is None or value == ''):
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise ValueError(name + ' must be nonblank text')
    return value


def parse_report(raw: bytes, image_ref: str, scanner_version: str | None = None, db_metadata: bytes | None = None) -> ParsedScan:
    registry, repository, digest = parse_image_ref(image_ref)
    obj = _object(load_json(raw), 'report')
    if type(obj.get('SchemaVersion')) is not int or obj['SchemaVersion'] != 2 or obj.get('ArtifactType') != 'container_image':
        raise ValueError('supported schema-2 container image report required')
    timestamp = normalize_timestamp(obj.get('CreatedAt'))
    metadata = _object(obj.get('Metadata'), 'Metadata')
    if 'ImageID' in metadata and metadata['ImageID'] is not None:
        if not isinstance(metadata['ImageID'], str) or not re.fullmatch(DIGEST, metadata['ImageID']):
            raise ValueError('invalid config ImageID')
    refs = metadata.get('RepoDigests')
    if not isinstance(refs, list) or not refs:
        raise ValueError('report repository digest identity required')
    for ref in refs:
        parse_image_ref(ref)
    if image_ref not in refs:
        raise ValueError('report does not bind the exact requested repository and digest')
    limitations = {'REPORT_CONTENT_UNVERIFIED', 'MANIFEST_KIND_UNVERIFIED', 'REGISTRY_RESOLUTION_UNVERIFIED'}
    reported = None
    if 'Trivy' in obj:
        trivy = _object(obj['Trivy'], 'Trivy')
        reported = _text(trivy.get('Version'), 'Trivy.Version', optional=True)
    if scanner_version is not None:
        _text(scanner_version, 'scanner_version')
    if reported and scanner_version and reported != scanner_version:
        raise ValueError('conflicting scanner versions')
    version = reported or scanner_version
    if version is None:
        limitations.add('SCANNER_VERSION_UNKNOWN')
    db_time = None
    db_hash = None
    if db_metadata is not None:
        db = _object(load_json(db_metadata, MAX_DB_BYTES), 'DB metadata')
        db_hash = sha256_bytes(db_metadata)
        if db.get('UpdatedAt') is not None:
            db_time = normalize_timestamp(db['UpdatedAt'])
    if db_time is None:
        limitations.add('SCANNER_DB_TIMESTAMP_UNKNOWN')
    if db_hash is None:
        limitations.add('SCANNER_DB_IDENTITY_UNKNOWN')
    config = metadata.get('ImageConfig')
    platform = None
    if config is not None:
        config = _object(config, 'ImageConfig')
        os_name = _text(config.get('os'), 'ImageConfig.os', optional=True)
        arch = _text(config.get('architecture'), 'ImageConfig.architecture', optional=True)
        variant = _text(config.get('variant'), 'ImageConfig.variant', optional=True)
        if os_name and arch:
            platform = os_name + '/' + arch + (('/' + variant) if variant else '')
    if platform is None:
        limitations.add('PLATFORM_UNKNOWN')
    os_info = metadata.get('OS')
    target_os = None
    if os_info is not None:
        os_info = _object(os_info, 'OS')
        family = _text(os_info.get('Family'), 'OS.Family', optional=True)
        name = _text(os_info.get('Name'), 'OS.Name', optional=True)
        if family:
            target_os = family + ((' ' + name) if name else '')
    image = ImageArtifact(image_id=digest, registry=registry, repository=repository, tags_observed=[], manifest_digest=digest, index_digest=None, platform_digest=digest if platform else None, platform=platform, source='oci_registry', source_reference=image_ref, first_seen=timestamp, last_seen=timestamp, resolution_status='resolved', resolution_reason=None)
    results = obj.get('Results')
    if results is None:
        results = []
    if not isinstance(results, list) or len(results) > MAX_RESULTS:
        raise ValueError('unsupported result collection or limit exceeded')
    if not results:
        limitations.add('NO_SCAN_RESULTS')
    document_hash = sha256_bytes(raw)
    findings = {}
    count = 0
    for result in results:
        result = _object(result, 'result')
        if _text(result.get('Class'), 'Class') not in {'os-pkgs', 'lang-pkgs'}:
            raise ValueError('unsupported non-vulnerability result class')
        target = _text(result.get('Target'), 'Target')
        package_type = _text(result.get('Type'), 'Type')
        rows = result.get('Vulnerabilities')
        if rows is None:
            rows = []
        if not isinstance(rows, list):
            raise ValueError('Vulnerabilities must be an array or null')
        count += len(rows)
        if count > MAX_FINDINGS:
            raise ValueError('finding limit exceeded')
        for row in rows:
            row = _object(row, 'vulnerability')
            vuln = _text(row.get('VulnerabilityID'), 'VulnerabilityID')
            package = _text(row.get('PkgName'), 'PkgName')
            installed = _text(row.get('InstalledVersion'), 'InstalledVersion')
            path = _text(row.get('PkgPath'), 'PkgPath', optional=True)
            fixed = _text(row.get('FixedVersion'), 'FixedVersion', optional=True)
            source = _text(row.get('SeveritySource'), 'SeveritySource', optional=True)
            severity = row.get('Severity')
            if severity is None:
                severity = 'UNKNOWN'
                limitations.add('FINDING_SEVERITY_UNKNOWN')
            aliases = row.get('Aliases', [])
            if not isinstance(aliases, list) or any(not isinstance(alias, str) for alias in aliases):
                raise ValueError('Aliases must be a string array')
            identity = ['trivy', digest, target, package_type, path, package, installed, vuln]
            finding_id = sha256_bytes(canonical_json(identity).encode())
            finding = VulnerabilityFinding(finding_id=finding_id, image_digest=digest, scanner_version=version or 'unknown', parser_version=PARSER_VERSION, vuln_id=vuln, package_name=package, package_type=package_type, package_path=path, installed_version=installed, fixed_version=fixed, severity=severity, severity_source=source, target_os=target_os, platform=platform, aliases=sorted(set(aliases)), scan_timestamp=timestamp, scanner_db_updated_at=db_time, source_document_hash=document_hash, validity='under_investigation', evidence_ids=[document_hash])
            if finding_id in findings and findings[finding_id] != finding:
                raise ValueError('conflicting duplicate vulnerability identity')
            findings[finding_id] = finding
    return ParsedScan(image=image, findings=[findings[key] for key in sorted(findings)], source_document_hash=document_hash, parser_version=PARSER_VERSION, scanner_version=version, scan_timestamp=timestamp, scanner_db_updated_at=db_time, db_document_hash=db_hash, limitations=sorted(limitations))
