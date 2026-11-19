"""Requirement-derived P1 parser expectations; synthetic inputs, no network."""
import copy
import json
from pathlib import Path
import unittest

from app.collectors.trivy import parse_report

FIXTURE = Path(__file__).resolve().parents[1] / 'fixtures/p1/trivy-synthetic.json'
REF = 'localhost:15120/demo@sha256:' + 'a' * 64

def report():
    return json.loads(FIXTURE.read_bytes())

def parse(obj, **kwargs):
    return parse_report(json.dumps(obj).encode(), REF, **kwargs)

class ParserRedTests(unittest.TestCase):
    def test_reject_wrong_schema_and_identity(self):
        for mutate in [lambda x: x.update(SchemaVersion=3), lambda x: x['Metadata'].update(RepoDigests=[]), lambda x: x.update(ArtifactType='filesystem'), lambda x: x['Results'][0].update(Class={})]:
            obj=report(); mutate(obj)
            with self.assertRaises(ValueError): parse(obj)

    def test_falsy_malformed_collections(self):
        for value in [{}, '', False, 0]:
            with self.subTest(value=value):
                obj=report(); obj['Results'][0]['Vulnerabilities']=value
                with self.assertRaises(ValueError): parse(obj)
                obj=report(); obj['Results']=value
                with self.assertRaises(ValueError): parse(obj)

    def test_invalid_required_fields_and_timestamp(self):
        for name,value in [('PkgName', ''), ('InstalledVersion', False), ('VulnerabilityID', 0), ('Severity','EXTREME')]:
            obj=report(); obj['Results'][0]['Vulnerabilities'][0][name]=value
            with self.assertRaises(ValueError): parse(obj)
        obj=report(); obj['CreatedAt']='2026-02-30T00:00:00Z'
        with self.assertRaises(ValueError): parse(obj)

    def test_duplicate_json_key_nonfinite_and_tag(self):
        for raw in [b'{"SchemaVersion":2,"SchemaVersion":3}', b'{"x":NaN}']:
            with self.assertRaises(ValueError): parse_report(raw, REF)
        with self.assertRaises(ValueError): parse_report(FIXTURE.read_bytes(), 'localhost:15120/demo:tag')

class ParserBehaviorTests(unittest.TestCase):
    def test_normalization_and_stable_ids(self):
        obj=report()
        obj['Results'][0]['Vulnerabilities'].append(copy.deepcopy(obj['Results'][0]['Vulnerabilities'][0]))
        first=parse(obj)
        self.assertEqual(len(first.findings), 2)
        self.assertEqual(first.image.image_id, 'sha256:'+'a'*64)
        self.assertEqual(first.image.platform, 'linux/arm64')
        self.assertEqual(first.scanner_version, '0.76.2')
        self.assertIn('REPORT_CONTENT_UNVERIFIED', first.limitations)
        for result in first.findings:
            self.assertEqual(result.validity, 'under_investigation')
        obj['Results'][0]['Vulnerabilities']=obj['Results'][0]['Vulnerabilities'][:2]
        obj['Results'][0]['Vulnerabilities'][0]['Severity']='LOW'
        obj['Results'][0]['Vulnerabilities'][0]['FixedVersion']='3'
        obj['CreatedAt']='2026-11-20T12:00:00+02:00'
        second=parse(obj)
        self.assertEqual([x.finding_id for x in first.findings], [x.finding_id for x in second.findings])
        self.assertEqual(second.scan_timestamp, '2026-11-20T10:00:00Z')
        self.assertNotEqual(first.source_document_hash, second.source_document_hash)

    def test_target_path_type_digest_are_identity(self):
        obj=report(); base=parse(obj)
        original=obj['Results'][0]['Vulnerabilities'][0]
        other=copy.deepcopy(original); other['PkgPath']='/different'
        obj['Results'][0]['Vulnerabilities'].append(other)
        result=copy.deepcopy(obj['Results'][0]); result['Target']='other target'; result['Type']='other'
        obj['Results'].append(result)
        self.assertEqual(len(parse(obj).findings), 6)
        raw=json.dumps(obj).replace('sha256:'+'a'*64,'sha256:'+'b'*64).encode()
        other=parse_report(raw,REF.replace('a'*64,'b'*64))
        self.assertTrue(set(x.finding_id for x in base.findings).isdisjoint(x.finding_id for x in other.findings))

    def test_unknowns_empty_results_are_not_safety(self):
        for value in [None, []]:
            obj=report(); obj['Results']=value; del obj['Trivy']; del obj['Metadata']['ImageConfig']
            parsed=parse(obj)
            self.assertIsNone(parsed.scanner_version)
            self.assertIsNone(parsed.scanner_db_updated_at)
            self.assertIsNone(parsed.db_document_hash)
            self.assertEqual(parsed.findings, [])
            self.assertIn('NO_SCAN_RESULTS', parsed.limitations)
            self.assertIn('SCANNER_VERSION_UNKNOWN', parsed.limitations)
            self.assertIsNone(parsed.image.platform)
        obj=report(); obj['Results'][0]['Vulnerabilities'][0].pop('Severity')
        parsed=parse(obj)
        self.assertIn('FINDING_SEVERITY_UNKNOWN',parsed.limitations)
        self.assertTrue(all(x.severity == 'UNKNOWN' for x in parsed.findings))

    def test_conflicting_duplicate_and_versions(self):
        obj=report(); duplicate=copy.deepcopy(obj['Results'][0]['Vulnerabilities'][0]); duplicate['Severity']='LOW'
        obj['Results'][0]['Vulnerabilities'].append(duplicate)
        with self.assertRaises(ValueError): parse(obj)
        with self.assertRaises(ValueError): parse(report(),scanner_version='wrong')

    def test_database_context(self):
        from app.models import sha256_bytes
        metadata=b'{"Version":2,"UpdatedAt":"2026-11-19T09:00:00+00:00"}'
        parsed=parse(report(),db_metadata=metadata)
        self.assertEqual(parsed.scanner_db_updated_at,'2026-11-19T09:00:00Z')
        self.assertEqual(parsed.db_document_hash,sha256_bytes(metadata))
        self.assertTrue(all(x.scanner_db_updated_at == parsed.scanner_db_updated_at for x in parsed.findings))
        for raw in [b'false', b'{"UpdatedAt":false}', b'{"UpdatedAt":"2026-11-19"}']:
            with self.assertRaises(ValueError): parse(report(),db_metadata=raw)

    def test_bounds_and_unicode(self):
        from app.collectors.trivy import load_json, MAX_DEPTH, MAX_REPORT_BYTES, MAX_DB_BYTES
        self.assertEqual(load_json(b'{}'+b' '*8,10),{})
        with self.assertRaises(ValueError): load_json(b'{}'+b' '*9,10)
        self.assertEqual(load_json(b'['*MAX_DEPTH+b'0'+b']'*MAX_DEPTH),self._nested(MAX_DEPTH))
        for raw in [b'['*(MAX_DEPTH+1)+b'0'+b']'*(MAX_DEPTH+1), b'{"n":1e999}',b'{"a":"\\ud800"}',b'\xff']:
            with self.assertRaises(ValueError): load_json(raw)
        valid=FIXTURE.read_bytes()
        self.assertIsNotNone(parse_report(valid+b' '*(MAX_REPORT_BYTES-len(valid)),REF))
        with self.assertRaises(ValueError): parse_report(valid+b' '*(MAX_REPORT_BYTES-len(valid)+1),REF)
        with self.assertRaises(ValueError): parse(report(),db_metadata=b' '*(MAX_DB_BYTES+1))

    def _nested(self,depth):
        value=0
        for _ in range(depth): value=[value]
        return value

    def test_row_limits(self):
        from app.collectors.trivy import MAX_RESULTS, MAX_FINDINGS
        obj=report(); empty=copy.deepcopy(obj['Results'][0]); empty['Vulnerabilities']=[]
        obj['Results']=[empty]*MAX_RESULTS
        self.assertEqual(parse(obj).findings,[])
        obj['Results'].append(empty)
        with self.assertRaises(ValueError): parse(obj)
        obj=report(); item={'VulnerabilityID':'C','PkgName':'p','InstalledVersion':'1'}
        obj['Results'][0]['Vulnerabilities']=[item]*MAX_FINDINGS
        self.assertEqual(len(parse(obj).findings),1)
        obj['Results'][0]['Vulnerabilities'].append(item)
        with self.assertRaises(ValueError): parse(obj)

class ModelContractTests(unittest.TestCase):
    def test_producers_match_frozen_schemas(self):
        from jsonschema import Draft202012Validator, FormatChecker
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT202012
        root=Path(__file__).resolve().parents[2]/'contracts/v1'
        schemas=[json.loads(x.read_text()) for x in root.glob('*.schema.json')]
        registry=Registry().with_resources((x['$id'],Resource.from_contents(x,default_specification=DRAFT202012)) for x in schemas)
        parsed=parse(report())
        for name,records in [('image-artifact',[parsed.image]),('vulnerability-finding',parsed.findings)]:
            schema=json.loads((root/(name+'.schema.json')).read_text())
            validator=Draft202012Validator(schema,registry=registry,format_checker=FormatChecker())
            for record in records: validator.validate(record.model_dump())

    def test_domain_invariants_and_strict_types(self):
        from app.models import ImageArtifact,VulnerabilityFinding
        image=parse(report()).image.model_dump()
        for key,value in [('image_id','sha256:'+'b'*64),('platform_digest','sha256:'+'b'*64),('first_seen','2026-11-20T00:00:00Z'),('registry',False),('last_seen','2026-02-30T00:00:00Z'),('tags_observed',['x','x'])]:
            bad=copy.deepcopy(image); bad[key]=value
            with self.assertRaises(ValueError): ImageArtifact.model_validate(bad)
        finding=parse(report()).findings[0].model_dump()
        for key,value in [('scanner_version',1),('severity','EXTREME'),('evidence_ids',[]),('scan_timestamp','2026-11-19T00:00:00+00:00'),('aliases',['x','x'])]:
            bad=copy.deepcopy(finding); bad[key]=value
            with self.assertRaises(ValueError): VulnerabilityFinding.model_validate(bad)
        image.update(resolution_status='unknown',image_id=None,manifest_digest=None,platform_digest=None,resolution_reason='unresolved')
        self.assertIsNone(ImageArtifact.model_validate(image).image_id)

    def test_scan_context_references(self):
        from app.models import ParsedScan
        scan=parse(report()).model_dump()
        for key,value in [('image_digest','sha256:'+'c'*64),('source_document_hash','sha256:'+'c'*64),('parser_version','other'),('scanner_version','other'),('scan_timestamp','2026-11-20T00:00:00Z'),('scanner_db_updated_at','2026-11-18T00:00:00Z')]:
            changed=copy.deepcopy(scan)
            changed['findings'][0][key]=value
            with self.assertRaises(ValueError): ParsedScan.model_validate(changed)
        changed=copy.deepcopy(scan); changed['findings'].append(changed['findings'][0])
        with self.assertRaises(ValueError): ParsedScan.model_validate(changed)

class TimestampRegressionTests(unittest.TestCase):
    def test_invalid_offset_components_rejected(self):
        from app.collectors.trivy import normalize_timestamp
        for value in ['2026-11-19T00:00:00+00:99', '2026-11-19T00:00:00-01:60', '2026-11-19T00:00:00+24:00']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_timestamp(value)
