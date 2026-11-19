"""Opt-in P3 real rollout/remaining-reference/regression acceptance in new scopes."""
from datetime import datetime, timezone
import base64
import ipaddress
import json
from pathlib import Path
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'scripts'))
from p0_lab import local_docker
from app.collectors.kubernetes import KubeAPI,RESOURCES
from app.collectors.lifecycle import Collector
from app.store.db import Store
from app.store.inventory import InventoryStore
from app.store.assessments import AssessmentStore

CLUSTER='kind-csle-p0-cis'
ADMIN=ROOT/'.local/p0/source-clone/.local/p0/kubeconfig'
ORIGINAL='sha256:1829893486be257df5049ab3b7fc95afbd0fc09d89803cbc580bda1ba5386b29'


def main():
    stamp=datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')
    namespaces=['csle-p3-'+stamp+'-a','csle-p3-'+stamp+'-b']
    run=ROOT/'.local/p3/qualification'/stamp;run.mkdir(parents=True,mode=0o700);run.chmod(0o700)
    db=run/'evidence.sqlite3';commands=[]
    kubectl=['kubectl','--kubeconfig',str(ADMIN),'--context',CLUSTER]
    def command(argv,input=None,check=True):
        result=subprocess.run([str(x) for x in argv],input=input,capture_output=True,text=True,timeout=180)
        commands.append({'argv':[str(x).replace(str(ROOT),'${CHECKOUT}') for x in argv],'exit_code':result.returncode})
        (run/'commands.json').write_text(json.dumps(commands,indent=2))
        if check and result.returncode:
            (run/'failure.log').write_text(result.stderr)
            raise AssertionError('command failed; inspect '+str(run/'failure.log'))
        return result
    def kube(*args,input=None):return command([*kubectl,*args],input).stdout
    def create(obj):return json.loads(kube('create','-f','-','-o','json',input=json.dumps(obj)))
    config=json.loads(kube('config','view','--minify','--raw','-o','json'))
    server=config['clusters'][0]['cluster']['server']
    ca=run/'ca.crt';ca.write_bytes(base64.b64decode(config['clusters'][0]['cluster']['certificate-authority-data']))
    lock=json.loads((ROOT/'toolchain.lock.json').read_text());patched=lock['images']['p3_patched']['linux_arm64_digest']
    scanrefs=['127.0.0.1:15120/000000000000/us-east-1/csle-p0/demo@'+ORIGINAL,'127.0.0.1:15120/csle-p3/patched@'+patched]
    for ref in scanrefs:
        command([sys.executable,'-m','app','--db',db,'scan','image',ref,'--registry-url','http://127.0.0.1:15120'])
    with Store(db) as store:
        scans=store.list_scans()
        old=next(s for s in scans if s['image']['manifest_digest']==ORIGINAL)
        finding=next(f for f in old['findings'] if f['package_name']=='libcrypto3' and f['fixed_version']=='3.5.9-r1')
        finding_id=finding['finding_id']
    docker=local_docker()
    node='csle-p0-cis-control-plane'
    registry=json.loads(command([*docker,'inspect','floci-aws-csle-p0-cis-ecr-registry']).stdout)[0]
    address=registry['NetworkSettings']['Networks']['csle-p0-cis']['IPAddress'];ipaddress.IPv4Address(address)
    host=address+':5000';destination='/etc/containerd/certs.d/'+host
    content='server = "http://'+host+'"\n[host."http://'+host+'"]\n  capabilities = ["pull", "resolve"]\n'
    existing=command([*docker,'exec',node,'cat',destination+'/hosts.toml'],check=False)
    if existing.returncode==0:
        assert existing.stdout==content,'existing runtime registry config differs'
    else:
        hosts=run/'hosts.toml';hosts.write_text(content)
        command([*docker,'exec',node,'mkdir','-p',destination])
        command([*docker,'cp',hosts,node+':'+destination+'/hosts.toml'])
    original_ref='docker.io/library/alpine@'+ORIGINAL
    patched_ref=host+'/csle-p3/patched@'+patched
    apis=[]
    for index,ns in enumerate(namespaces):
        create({'apiVersion':'v1','kind':'Namespace','metadata':{'name':ns,'labels':{'io.csle.scope':'p3'}}})
        rbac=json.loads((ROOT/'infra/p2-rbac.json').read_text())
        for item in rbac['items']:
            item['metadata']['namespace']=ns
            for subject in item.get('subjects',[]):subject['namespace']=ns
            create(item)
        token=run/('observer-'+str(index)+'.token');token.touch(mode=0o600)
        token.write_text(kube('-n',ns,'create','token','csle-observer','--duration=1h').strip())
        apis.append(KubeAPI(server,ca,token,ns))
    collectors=[Collector(api,db,CLUSTER,ns,reconcile_seconds=5,watch_seconds=2) for api,ns in zip(apis,namespaces)]
    summaries=[];failures=[]
    def target(collector):
        try:summaries.append(collector.run())
        except BaseException as error:failures.append(type(error).__name__)
    threads=[threading.Thread(target=target,args=(c,)) for c in collectors]
    for thread in threads:thread.start()
    def wait(condition,timeout=90):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            if condition():return
            time.sleep(.3)
        raise AssertionError('scenario timed out; inspect '+str(run))
    def ready():
        with InventoryStore(db) as store:return all(store.checkpoint(CLUSTER,ns,kind) for ns in namespaces for kind in RESOURCES)
    expected=[]
    def assess(replacement=False):
        with AssessmentStore(db) as store:
            result=store.assess(finding_id,CLUSTER,namespaces,patched if replacement else None)
        (run/'latest-assessment.json').write_text(json.dumps(result,sort_keys=True,indent=2))
        return result
    def expect(name,remediation,exposure=None,replacement=False):
        result=None
        def condition():
            nonlocal result
            result=assess(replacement)
            return result['state']['remediation']==remediation and (exposure is None or result['state']['exposure']==exposure)
        wait(condition)
        expected.append({'scenario':name,'expected_remediation':remediation,'expected_exposure':exposure,
                         'assessment_id':result['assessment_id'],'actual':result['state']})
        return result
    def template(ref):
        return {'metadata':{'labels':{'app':'csle-p3'}},'spec':{'automountServiceAccountToken':False,
            'containers':[{'name':'worker','image':ref,'imagePullPolicy':'IfNotPresent','command':['sh','-c','sleep 3600'],
             'resources':{'requests':{'cpu':'10m','memory':'16Mi'},'limits':{'cpu':'100m','memory':'32Mi'}},
             'securityContext':{'allowPrivilegeEscalation':False,'runAsUser':65532,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}}}]}}
    try:
        wait(ready)
        deployment=create({'apiVersion':'apps/v1','kind':'Deployment','metadata':{'name':'service','namespace':namespaces[0]},
           'spec':{'replicas':1,'revisionHistoryLimit':1,'selector':{'matchLabels':{'app':'csle-p3'}},'template':template(original_ref)}})
        kube('-n',namespaces[0],'rollout','status','deployment/service','--timeout=90s')
        baseline=expect('original_running','open','running')
        patch={'spec':{'template':template(patched_ref)}}
        kube('-n',namespaces[0],'patch','deployment/service','--type=merge','-p',json.dumps(patch))
        kube('-n',namespaces[0],'rollout','status','deployment/service','--timeout=90s')
        def old_pods_gone():
            return not any(c['image']==original_ref for p in json.loads(kube('-n',namespaces[0],'get','pods','-o','json'))['items'] for c in p['spec']['containers'])
        wait(old_pods_gone)
        retained=expect('old_scale_zero_replicaset_remains','open','configured_not_running',replacement=True)
        # Kubernetes retires only this newly created demo Deployment's old ReplicaSet.
        kube('-n',namespaces[0],'patch','deployment/service','--type=merge','-p','{"spec":{"revisionHistoryLimit":0}}')
        def old_rs_gone():
            return not any(c['image']==original_ref for r in json.loads(kube('-n',namespaces[0],'get','replicasets','-o','json'))['items'] for c in r['spec']['template']['spec']['containers'])
        wait(old_rs_gone)
        verified=expect('fixed_package_replacement_verified','verified_in_scope','historical_observed',replacement=True)
        assert verified['state']['validity']==finding['validity']=='under_investigation'
        pod=template(original_ref);pod['apiVersion']='v1';pod['kind']='Pod';pod['metadata']={'name':'regression','namespace':namespaces[1],'labels':{'io.csle.scope':'p3'}}
        create(pod);kube('-n',namespaces[1],'wait','--for=condition=Ready','pod/regression','--timeout=90s')
        regressed=expect('old_digest_reintroduced_other_namespace','regressed','running',replacement=True)
        assert regressed['regression_of']==verified['assessment_id']
        # One explicit frozen time/facts re-evaluates idempotently while producers are stopped below.
    finally:
        for collector in collectors:collector.stop.set()
        for thread in threads:thread.join(30)
    assert not failures and all(not t.is_alive() for t in threads),failures
    assert all(s['errors']==0 for s in summaries),summaries
    with AssessmentStore(db) as store:
        before=store.get_assessment(verified['assessment_id'])
        assert before==verified
        assert store.list_assessments(ORIGINAL)
    argv=[sys.executable,'-m','app','--db',str(db),'lifecycle','image',ORIGINAL]
    assert command(argv).stdout==command(argv).stdout
    assert all(not (r['actual']['remediation']=='verified_in_scope' and r['expected_remediation']!='verified_in_scope') for r in expected)
    result={'executed_revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'dirty_working_tree':bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT)),
        'cluster_id':CLUSTER,'namespaces':namespaces,'local_directory':str(run.relative_to(ROOT)),
        'original_digest':ORIGINAL,'replacement_digest':patched,'selected_finding_id':finding_id,'selected_vulnerability':finding['vuln_id'],
        'selected_package':finding['package_name'],'installed_version':finding['installed_version'],'fixed_version':finding['fixed_version'],
        'scenarios':expected,'false_closures':0,'scenario_count':len(expected),'collector_summaries':summaries,
        'deployment_uid':deployment['metadata']['uid'],'verified_assessment_id':verified['assessment_id'],'regression_assessment_id':regressed['assessment_id']}
    (run/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps(result,sort_keys=True,indent=2))


if __name__=='__main__':main()
