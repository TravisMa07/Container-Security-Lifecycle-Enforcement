"""Requirement-derived P3 matrix; all scanner/Kubernetes data is synthetic."""
import copy
import json
from pathlib import Path
import unittest

from app.collectors.trivy import parse_report
from app.models import canonical_json, sha256_bytes
from app.workloads import normalize_object
from app.engine.lifecycle import evaluate

A='sha256:'+'a'*64
B='sha256:'+'b'*64
C='sha256:'+'c'*64
HASH='sha256:'+'d'*64
T0='2026-11-19T00:00:00Z'
T1='2026-11-19T00:00:01Z'
T10='2026-11-19T00:00:10Z'
AT='2026-11-19T00:00:20Z'
KINDS=('Pod','Job','CronJob','Deployment','ReplicaSet','StatefulSet','DaemonSet')


def ref(digest):return 'localhost:15120/demo@'+digest


def scan(digest,patched=False):
    result={'Target':'alpine 3.24','Class':'os-pkgs','Type':'alpine',
            'Packages':[{'Name':'crypto','Version':'2.0-r1' if patched else '2.0-r0'}],
            'Vulnerabilities':[] if patched else [{'VulnerabilityID':'CVE-2026-10000','PkgName':'crypto','InstalledVersion':'2.0-r0','FixedVersion':'2.0-r1','Severity':'HIGH'}]}
    report={'SchemaVersion':2,'ArtifactType':'container_image','CreatedAt':T1,'Trivy':{'Version':'0.76.2'},
            'Metadata':{'RepoDigests':[ref(digest)],'ImageID':C,'OS':{'Family':'alpine','Name':'3.24'},'ImageConfig':{'os':'linux','architecture':'arm64'}},'Results':[result]}
    raw=canonical_json(report).encode();db=b'{"UpdatedAt":"2026-11-19T00:00:00Z","Version":2}'
    parsed=parse_report(raw,ref(digest),'0.76.2',db).model_dump(mode='json')
    return dict(parsed,scan_id=sha256_bytes((digest+'scan').encode()),report=report,
                provenance='executed_local_trivy',resolution={'manifest_digest':digest,'platform_digest':digest,'index_digest':None,'platform':'linux/arm64','config_digest':C},
                execution={'scanner_version':'0.76.2','executable_hash':HASH,'db_content_hash':HASH,'started_at':T0,'finished_at':T1})


def event(kind,uid,digest,version='one',at=T0,namespace='one',owner=None,running=True):
    obj={'kind':kind,'metadata':{'namespace':namespace,'name':uid,'uid':uid,'resourceVersion':version},'spec':{},'status':{}}
    if owner:obj['metadata']['ownerReferences']=[{'kind':owner[0],'uid':owner[1],'name':owner[1],'controller':True}]
    containers=[{'name':'worker','image':ref(digest)}]
    if kind=='Pod':
        obj['spec']['containers']=containers
        obj['status']={'phase':'Running' if running else 'Succeeded','containerStatuses':[{'name':'worker','imageID':ref(digest),'state':{'running':{'startedAt':T0}} if running else {'terminated':{'exitCode':0}}}]}
    else:obj['spec']={'replicas':1,'template':{'spec':{'containers':containers}}}
    return normalize_object('cluster',namespace,kind,obj,'MODIFIED','kubernetes_watch',at).model_dump(mode='json')


def current(record,last_seen=T10):
    return {k:record[k] for k in ('cluster_id','namespace','kind','name','uid','event_id','observations')} | {'present':True,'absence_reason':None,'last_seen':last_seen}


def facts(patched=True):
    old_scan=scan(A);new_scan=scan(B,True)
    history=[event('Deployment','deploy',A),event('ReplicaSet','old-rs',A,owner=('Deployment','deploy')),event('Pod','old-pod',A,owner=('ReplicaSet','old-rs'))]
    records=([event('Deployment','deploy',B,version='two',at=T10),event('ReplicaSet','new-rs',B,at=T10,owner=('Deployment','deploy')),event('Pod','new-pod',B,at=T10,owner=('ReplicaSet','new-rs'))] if patched else history)
    return {'finding':old_scan['findings'][0],'scope':{'cluster_id':'cluster','namespaces':['one']},'assessment_at':AT,
            'inventory_max_age_seconds':30,'scan_max_age_seconds':86400,'db_max_age_seconds':86400,
            'current':[current(r) for r in records],'events':history+([r for r in records if r not in history]),
            'snapshots':[{'snapshot_id':'snapshot-'+kind,'cluster_id':'cluster','namespace':'one','kind':kind,'resource_version':'list-'+kind,'observed_at':T10,'source':'kubernetes_list','members':[]} for kind in KINDS],
            'checkpoints':[{'namespace':'one','kind':kind,'resource_version':'checkpoint-'+kind,'observed_at':T10} for kind in KINDS],
            'gaps':[],'scans':[old_scan,new_scan],'trusted_scanner_hashes':[HASH],'replacement_digest':B if patched else None,'previous':[]}


class FalseClosureRedTests(unittest.TestCase):
    def test_running_and_scale_zero_never_verify(self):
        value=facts(False)
        result=evaluate(value)['state']
        self.assertEqual(result['exposure'],'running')
        self.assertEqual(result['remediation'],'open')
        value['current']=[current(value['events'][0])]
        value['current'][0]['observations'][0]['replicas_desired']=0
        result=evaluate(value)['state']
        self.assertEqual(result['exposure'],'configured_not_running')
        self.assertEqual(result['remediation'],'open')

    def test_disappearance_does_not_verify(self):
        value=facts(False);value['current']=[]
        result=evaluate(value)['state']
        self.assertEqual(result['exposure'],'historical_observed')
        self.assertEqual(result['remediation'],'open')

    def test_partial_gapped_unknown_identity_blocks(self):
        for change in ['missing','gap','tag','runtime']:
            value=facts()
            if change=='missing':value['snapshots'].pop()
            if change=='gap':value['gaps']=[{'gap_id':'gap','cluster_id':'cluster','namespace':'one','kind':'Pod','started_at':T10,'ended_at':None,'reason':'OUTAGE'}]
            if change=='tag':value['current'][0]['observations'][0]['desired_image_ref']='localhost:15120/demo:tag'
            if change=='runtime':value['current'][-1]['observations'][0].update(runtime_image_id='containerd://sha256:'+'f'*64,resolved_digest=None,resolution_status='unknown')
            with self.subTest(change=change):self.assertNotEqual(evaluate(value)['state']['remediation'],'verified_in_scope')

    def test_untrusted_or_package_absence_is_not_fix(self):
        for change in ['import','packages','version','lineage']:
            value=facts()
            if change=='import':value['scans'][1]['provenance']='imported'
            if change=='packages':value['scans'][1]['report']['Results'][0].pop('Packages')
            if change=='version':value['scans'][1]['report']['Results'][0]['Packages'][0]['Version']='different'
            if change=='lineage':value['current'][-1]['observations'][0]['owner_refs']=[]
            with self.subTest(change=change):self.assertNotEqual(evaluate(value)['state']['remediation'],'verified_in_scope')


class EngineMatrixTests(unittest.TestCase):
    def test_positive_verification_and_schema(self):
        from jsonschema import Draft202012Validator, FormatChecker
        from referencing import Registry, Resource
        value=facts();before=canonical_json(value)
        result=evaluate(value)
        self.assertEqual(canonical_json(value),before)
        self.assertEqual(result,evaluate(copy.deepcopy(value)))
        state=result['state']
        self.assertEqual(state['remediation'],'verified_in_scope')
        self.assertEqual(state['exposure'],'historical_observed')
        self.assertEqual(state['validity'],'under_investigation')
        self.assertEqual(state['verification']['remaining_references'],0)
        self.assertEqual(state['verification']['window_start'],T10)
        root=Path(__file__).resolve().parents[2]/'contracts/v1'
        schemas=[json.loads(path.read_text()) for path in root.glob('*.schema.json')]
        registry=Registry().with_resources((schema['$id'],Resource.from_contents(schema)) for schema in schemas)
        schema=json.loads((root/'derived-finding-state.schema.json').read_text())
        Draft202012Validator(schema,registry=registry,format_checker=FormatChecker()).validate(state)

    def test_no_history_no_verification(self):
        value=facts();value['events']=[e for e in value['events'] if e['observed_at']!=T0]
        result=evaluate(value)['state']
        self.assertEqual(result['remediation'],'unknown')
        self.assertEqual(result['exposure'],'unknown')
        self.assertIn('NO_OBSERVATION',result['reason_codes'])

    def test_cross_namespace_remaining_reference(self):
        value=facts();value['scope']['namespaces'].append('two')
        for field in ['snapshots','checkpoints']:
            for row in copy.deepcopy(value[field]):row['namespace']='two';value[field].append(row)
        extra=event('Deployment','other-deploy',A,at=T10,namespace='two')
        value['events'].append(extra);value['current'].append(current(extra))
        state=evaluate(value)['state']
        self.assertEqual(state['remediation'],'open')
        self.assertEqual(state['exposure'],'configured_not_running')
        self.assertIn('REMAINING_REFERENCES',state['reason_codes'])

    def test_freshness_boundaries_and_future_dates(self):
        for field in ['snapshots','checkpoints','current']:
            for timestamp in ['2026-11-18T00:00:00Z','2026-11-19T00:00:21Z']:
                value=facts()
                for row in value[field]:row['last_seen' if field=='current' else 'observed_at']=timestamp
                with self.subTest(field=field,timestamp=timestamp):
                    state=evaluate(value)['state'];self.assertEqual(state['remediation'],'unknown')
                    self.assertIn('INVENTORY_STALE',state['reason_codes'])
        value=facts();value['inventory_max_age_seconds']=10
        self.assertEqual(evaluate(value)['state']['remediation'],'verified_in_scope')
        value['inventory_max_age_seconds']=9
        self.assertEqual(evaluate(value)['state']['remediation'],'unknown')

    def test_closed_gap_boundary_and_intersection(self):
        value=facts();value['gaps']=[{'gap_id':'old-gap','cluster_id':'cluster','namespace':'one','kind':'Pod','started_at':T0,'ended_at':T10}]
        self.assertEqual(evaluate(value)['state']['remediation'],'verified_in_scope')
        value['gaps'][0]['ended_at']='2026-11-19T00:00:11Z'
        state=evaluate(value)['state']
        self.assertEqual(state['remediation'],'unknown');self.assertEqual(state['coverage_gap_ids'],['old-gap'])

    def test_untrusted_fixed_version_cannot_borrow_executed_provenance(self):
        value=facts();value['finding']['fixed_version']='malicious'
        self.assertEqual(evaluate(value)['state']['remediation'],'unknown')
        # Even a forged normalized row must agree with the original raw scanner result.
        value['scans'][0]['findings'][0]['fixed_version']='malicious'
        self.assertEqual(evaluate(value)['state']['remediation'],'unknown')
        value=facts();value['scans'][0]['execution']['executable_hash']=C
        self.assertEqual(evaluate(value)['state']['remediation'],'unknown')

    def test_package_proof_negative_matrix(self):
        changes=['removed','path','type','platform','os','range','vuln','alias']
        for change in changes:
            value=facts();replacement=value['scans'][1];result=replacement['report']['Results'][0]
            if change=='removed':result['Packages']=[]
            if change=='path':result['Packages'][0]['PkgPath']='/elsewhere'
            if change=='type':result['Type']='debian'
            if change=='platform':replacement['image']['platform']='linux/amd64'
            if change=='os':replacement['report']['Metadata']['OS']['Family']='debian'
            if change=='range':
                value['finding']['fixed_version']='2.0-r1,2.1-r0'
                value['scans'][0]['findings'][0]['fixed_version']='2.0-r1,2.1-r0'
                value['scans'][0]['report']['Results'][0]['Vulnerabilities'][0]['FixedVersion']='2.0-r1,2.1-r0'
            if change=='vuln':result['Vulnerabilities']=copy.deepcopy(value['scans'][0]['report']['Results'][0]['Vulnerabilities'])
            if change=='alias':result['Vulnerabilities']=[{'VulnerabilityID':'OTHER','Aliases':['CVE-2026-10000'],'PkgName':'crypto'}]
            with self.subTest(change=change):self.assertNotEqual(evaluate(value)['state']['remediation'],'verified_in_scope')

    def test_unknown_or_auxiliary_owner_cannot_establish_replacement(self):
        for controller in [True,False]:
            value=facts()
            for row in value['current']:
                for observation in row['observations']:
                    observation['owner_refs']=[{'kind':'Deployment','uid':'not-captured','controller':controller}]
            for event_row in value['events']:
                for observation in event_row['observations']:
                    observation['owner_refs']=[{'kind':'Deployment','uid':'not-captured','controller':controller}]
            state=evaluate(value)['state']
            self.assertNotEqual(state['remediation'],'verified_in_scope')
            self.assertIn('REPLACEMENT_LINEAGE_UNKNOWN',state['reason_codes'])

    def test_regression_links_equal_or_expanded_scope_only(self):
        prior=evaluate(facts())['state']
        for change,expected in [('same','regressed'),('expanded','regressed'),('other_cluster','open'),('other_finding','open'),('narrower','open')]:
            value=facts(False);value['assessment_at']='2026-11-19T00:00:30Z'
            for row in value['current']:row['last_seen']='2026-11-19T00:00:25Z'
            old={'assessment_id':'prior-assessment','finding_id':value['finding']['finding_id'],'scope':copy.deepcopy(value['scope']),'state':prior}
            if change=='expanded':
                value['scope']['namespaces'].append('two')
                for field in ['snapshots','checkpoints']:
                    for row in copy.deepcopy(value[field]):row['namespace']='two';value[field].append(row)
            if change=='other_cluster':old['scope']['cluster_id']='other'
            if change=='other_finding':old['finding_id']='other'
            if change=='narrower':old['scope']['namespaces'].append('two')
            value['previous']=[old];result=evaluate(value)
            with self.subTest(change=change):
                self.assertEqual(result['state']['remediation'],expected)
                self.assertEqual(result['regression_of'],'prior-assessment' if expected=='regressed' else None)
                self.assertEqual(result['state']['validity'],'under_investigation')

    def test_index_relationship_is_positive_reference_not_absence_proof(self):
        value=facts();index='sha256:'+'e'*64
        value['scans'][0]['image']['index_digest']=index
        value['scans'][0]['resolution']['index_digest']=index
        value['current'][0]['observations'][0]['desired_image_ref']=ref(index)
        result=evaluate(value)
        self.assertIn('REMAINING_REFERENCES',result['state']['reason_codes'])
        self.assertNotEqual(result['state']['remediation'],'verified_in_scope')
        value=facts();value['current'][0]['observations'][0]['desired_image_ref']=ref(index)
        self.assertIn('IDENTITY_UNRESOLVED',evaluate(value)['state']['reason_codes'])

    def test_scanner_db_freshness_and_terminal_status(self):
        for change in ['scan','db','future_db']:
            value=facts()
            if change=='scan':value['scan_max_age_seconds']=1
            if change=='db':value['db_max_age_seconds']=1
            if change=='future_db':value['scans'][1]['scanner_db_updated_at']='2026-11-19T00:00:25Z'
            with self.subTest(change=change):self.assertEqual(evaluate(value)['state']['remediation'],'unknown')
        value=facts(False)
        pod_record=event('Pod','old-pod',A,running=False,owner=('ReplicaSet','old-rs'))
        value['current']=[current(pod_record)];value['events'].append(pod_record)
        self.assertEqual(evaluate(value)['state']['exposure'],'configured_not_running')

    def test_containerd_arm64_default_v8_platform_equivalence(self):
        value=facts()
        value['scans'][0]['image']['platform']='linux/arm64/v8'
        value['scans'][0]['resolution']['platform']='linux/arm64/v8'
        value['scans'][0]['report']['Metadata']['ImageConfig']['variant']='v8'
        self.assertEqual(evaluate(value)['state']['remediation'],'verified_in_scope')
        for platform,architecture,variant in [('linux/amd64','amd64',None),('linux/arm64/v9','arm64','v9')]:
            candidate=copy.deepcopy(value)
            candidate['scans'][1]['image']['platform']=platform
            candidate['scans'][1]['resolution']['platform']=platform
            candidate['scans'][1]['report']['Metadata']['ImageConfig']['architecture']=architecture
            if variant:candidate['scans'][1]['report']['Metadata']['ImageConfig']['variant']=variant
            with self.subTest(platform=platform):self.assertNotEqual(evaluate(candidate)['state']['remediation'],'verified_in_scope')

    def test_invalid_scope_and_malformed_nested_evidence_reject(self):
        for change in ['empty_scope','duplicate_scope','bad_time','missing_receipt_field','bad_current_row']:
            value=facts()
            if change=='empty_scope':value['scope']['namespaces']=[]
            if change=='duplicate_scope':value['scope']['namespaces']=['one','one']
            if change=='bad_time':value['assessment_at']='2026-02-30T00:00:00Z'
            if change=='missing_receipt_field':del value['snapshots'][0]['observed_at']
            if change=='bad_current_row':del value['current'][0]['event_id']
            with self.subTest(change=change),self.assertRaises(ValueError):evaluate(value)

    def test_all_matching_package_instances_must_prove_fixed(self):
        for extra in [{'Name':'crypto','Version':'2.0-r0'},{'Name':'crypto'}]:
            value=facts()
            value['scans'][1]['report']['Results'][0]['Packages'].append(extra)
            with self.subTest(extra=extra):
                self.assertNotEqual(evaluate(value)['state']['remediation'],'verified_in_scope')
        value=facts()
        value['scans'][1]['report']['Results'][0]['Packages'].append({'Name':'crypto','Version':'2.0-r1'})
        self.assertEqual(evaluate(value)['state']['remediation'],'verified_in_scope')

    def test_every_relevant_target_needs_complete_package_inventory(self):
        variants=[None,False,0,{},'', [None],[{}],[{'Version':'2.0-r1'}],[{'Name':'crypto','Version':'2.0-r1','PkgPath':False}]]
        for packages in variants:
            value=facts()
            value['scans'][1]['report']['Results'].append({'Type':'alpine','Class':'os-pkgs','Target':'second','Packages':packages,'Vulnerabilities':[]})
            with self.subTest(packages=packages):self.assertNotEqual(evaluate(value)['state']['remediation'],'verified_in_scope')
        value=facts()
        value['scans'][1]['report']['Results'].append({'Type':'alpine','Class':'os-pkgs','Target':'second','Vulnerabilities':[]})
        self.assertNotEqual(evaluate(value)['state']['remediation'],'verified_in_scope')
        value=facts()
        value['scans'][1]['report']['Results'].append({'Type':'alpine','Class':'os-pkgs','Target':'second','Packages':[],'Vulnerabilities':[]})
        self.assertEqual(evaluate(value)['state']['remediation'],'verified_in_scope')

    def test_expanded_scope_does_not_invent_reintroduction_of_old_unseen_workload(self):
        prior=evaluate(facts())['state']
        for created,expected in [(None,'open'),('2026-11-19T00:00:00Z','open'),('2026-11-19T00:00:25Z','regressed')]:
            value=facts();value['scope']['namespaces'].append('two');value['assessment_at']='2026-11-19T00:00:30Z'
            for field in ('snapshots','checkpoints'):
                for row in copy.deepcopy(value[field]):row['namespace']='two';value[field].append(row)
            outsider=event('Pod','outside-old',A,at='2026-11-19T00:00:26Z',namespace='two')
            if created:
                outsider['raw_object']['metadata']['creationTimestamp']=created
                outsider['raw_object_hash']=sha256_bytes(canonical_json(outsider['raw_object']).encode())
            value['events'].append(outsider);value['current'].append(current(outsider,last_seen='2026-11-19T00:00:26Z'))
            value['previous']=[{'assessment_id':'prior','finding_id':value['finding']['finding_id'],'scope':{'cluster_id':'cluster','namespaces':['one']},'state':prior}]
            with self.subTest(created=created):self.assertEqual(evaluate(value)['state']['remediation'],expected)
