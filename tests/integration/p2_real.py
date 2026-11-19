"""Opt-in P2 Kind qualification: new labeled namespace, no existing-resource deletion."""
from datetime import datetime, timezone
import base64
import json
from pathlib import Path
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from app.collectors.kubernetes import KubeAPI, KubeError, RESOURCES
from app.collectors.lifecycle import Collector
from app.store.inventory import InventoryStore

ADMIN = ROOT / '.local/p0/source-clone/.local/p0/kubeconfig'
CONTEXT = 'kind-csle-p0-cis'
IMAGE = 'docker.io/library/alpine@sha256:1829893486be257df5049ab3b7fc95afbd0fc09d89803cbc580bda1ba5386b29'


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')
    ns = 'csle-p2-' + stamp
    run = ROOT / '.local/p2/qualification' / stamp
    run.mkdir(parents=True, mode=0o700)
    run.chmod(0o700)
    db = run / 'evidence.sqlite3'
    commands=[]
    kubectl=['kubectl','--kubeconfig',str(ADMIN),'--context',CONTEXT]
    def command(args, input=None):
        result=subprocess.run([*kubectl,*args],input=input,capture_output=True,text=True,timeout=60)
        commands.append({'argv':args,'exit_code':result.returncode})
        (run/'commands.json').write_text(json.dumps(commands,indent=2))
        if result.returncode:
            (run/'failed-command.log').write_text(result.stderr)
            raise AssertionError('kubectl failed; inspect '+str(run/'failed-command.log'))
        return result.stdout
    def apply(obj):
        if obj.get('kind')=='List':
            return {'items':[apply(item) for item in obj['items']]}
        return json.loads(command(['create','-f','-','-o','json'],json.dumps(obj)))
    config=json.loads(command(['config','view','--minify','--raw','-o','json']))
    server=config['clusters'][0]['cluster']['server']
    versions=json.loads(command(['version','-o','json']))
    (run/'ca.crt').write_bytes(base64.b64decode(config['clusters'][0]['cluster']['certificate-authority-data']))
    apply({'apiVersion':'v1','kind':'Namespace','metadata':{'name':ns,'labels':{'io.csle.scope':'p2'}}})
    rbac=json.loads((ROOT/'infra/p2-rbac.json').read_text())
    for item in rbac['items']:
        item['metadata']['namespace']=ns
        for subject in item.get('subjects',[]):subject['namespace']=ns
    apply(rbac)
    token=command(['-n',ns,'create','token','csle-observer','--duration=1h']).strip()
    token_path=run/'observer.token'
    token_path.touch(mode=0o600);token_path.write_text(token)
    api=KubeAPI(server,run/'ca.crt',token_path,ns)
    denials={}
    for name,method,path in [('secrets','GET','/api/v1/namespaces/'+ns+'/secrets'),('create_pod','POST','/api/v1/namespaces/'+ns+'/pods'),('delete_pod','DELETE','/api/v1/namespaces/'+ns+'/pods/not-existing'),('other_namespace','GET','/api/v1/namespaces/default/pods')]:
        req=urllib.request.Request(server+path,method=method,headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'},data=b'{}' if method=='POST' else None)
        try:
            with api.opener.open(req,timeout=15):pass
            raise AssertionError('unexpected RBAC permission: '+name)
        except urllib.error.HTTPError as error:
            denials[name]=error.code;error.close()
            assert denials[name]==403
    token=None
    observed_calls={k:0 for k in RESOURCES}
    original_watch=api.watch
    def watch(kind,version,timeout):
        observed_calls[kind]+=1
        yield from original_watch(kind,version,timeout)
    api.watch=watch
    summaries=[]
    def start(client):
        collector=Collector(client,db,'kind-csle-p0-cis',ns,reconcile_seconds=8,watch_seconds=2)
        errors=[]
        def target():
            try:summaries.append(collector.run())
            except BaseException as error:errors.append(type(error).__name__)
        thread=threading.Thread(target=target);thread.start()
        return collector,thread,errors
    def stop(handle):
        collector,thread,errors=handle;collector.stop.set();thread.join(30)
        assert not thread.is_alive() and not errors, errors
    def wait(assertion,timeout=60):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            if assertion():return
            time.sleep(.2)
        raise AssertionError('scenario timeout; evidence retained at '+str(run))
    def query(method):
        with InventoryStore(db) as store:return getattr(store,method)('kind-csle-p0-cis',ns)
    def ready():
        with InventoryStore(db) as store:return all(store.checkpoint('kind-csle-p0-cis',ns,k) is not None for k in RESOURCES)
    def template(commandline):
        return {'metadata':{'labels':{'app':'csle-p2'}},'spec':{'automountServiceAccountToken':False,'restartPolicy':'Never','containers':[{'name':'worker','image':IMAGE,'command':['sh','-c',commandline],'resources':{'requests':{'cpu':'10m','memory':'16Mi'},'limits':{'cpu':'100m','memory':'32Mi'}},'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']},'runAsUser':65532}}]}}
    def job(name):
        return apply({'apiVersion':'batch/v1','kind':'Job','metadata':{'name':name,'namespace':ns},'spec':{'ttlSecondsAfterFinished':3,'template':template('echo observed; sleep 1')}})
    def deleted(uid):return any(e['uid']==uid and e['event_type']=='DELETED' for e in query('events'))
    handle=start(api)
    try:
        wait(ready)
        first=job('short')
        wait(lambda:deleted(first['metadata']['uid']))
        first_uid=first['metadata']['uid']
        second=job('short')
        second_uid=second['metadata']['uid'];assert first_uid!=second_uid
        wait(lambda:deleted(second_uid))
        pod_template=template('sleep 600');pod_template['spec']['restartPolicy']='Always'
        deployment=apply({'apiVersion':'apps/v1','kind':'Deployment','metadata':{'name':'scale','namespace':ns},'spec':{'replicas':1,'selector':{'matchLabels':{'app':'csle-p2'}},'template':pod_template}})
        command(['-n',ns,'scale','deployment/scale','--replicas=0'])
        wait(lambda:any(r['kind']=='Deployment' and r['present'] and any(o['replicas_desired']==0 and o['desired_image_ref']==IMAGE for o in r['observations']) for r in query('current')))
        # Give every real watch a normal timeout/reconnect and periodic reconciliation.
        wait(lambda:all(count>=2 for count in observed_calls.values()),30)
        wait(lambda:any(e['source']=='kubernetes_reconcile' for e in query('events')),30)
    finally:stop(handle)
    assert summaries[-1]['errors']==0,summaries
    # Entire lifecycle during observer downtime: later list must not invent it.
    unseen=job('unseen');unseen_uid=unseen['metadata']['uid']
    def unseen_gone():
        listed=json.loads(command(['-n',ns,'get','jobs','-o','json']))
        return all(j['metadata']['uid']!=unseen_uid for j in listed['items'])
    wait(unseen_gone)
    class ExpiredOnce(KubeAPI):
        injected=False
        observed_code=None
        def watch(self,kind,version,timeout):
            if kind=='Pod' and not self.injected:
                self.injected=True
                try:yield from super().watch(kind,'1',timeout)
                except KubeError as error:
                    self.observed_code=error.code
                    raise
            else:yield from super().watch(kind,version,timeout)
    recovered=ExpiredOnce(server,run/'ca.crt',token_path,ns)
    handle=start(recovered)
    try:
        wait(lambda:recovered.observed_code==410,30)
        wait(lambda:any(g['reason']=='RESOURCE_VERSION_EXPIRED' and g['ended_at'] is not None for g in query('gaps')),30)
        wait(lambda:any(g['reason']=='COLLECTOR_STOPPED' and g['ended_at'] is not None for g in query('gaps')),30)
    finally:stop(handle)
    events=query('events');observations=query('observations');current=query('current');gaps=query('gaps');snapshots=query('snapshots')
    assert snapshots and any(s['members']==[] for s in snapshots)
    assert all(m['uid']!=unseen_uid for s in snapshots for m in s['members'])
    assert not any(e['uid']==unseen_uid for e in events)
    assert any(o['uid']==first_uid for o in observations) and any(o['uid']==second_uid for o in observations)
    # Replay a real captured event without changing checkpoints/current/history.
    event=next(e for e in events if e['source']=='kubernetes_watch' and e['event_type']=='DELETED' and e['uid']==first_uid)
    with InventoryStore(db) as store:
        before=store.checkpoint('kind-csle-p0-cis',ns,event['kind'])
        receipt=store.apply_event('kind-csle-p0-cis',ns,event['kind'],event['event_type'],event['raw_object'],datetime.now(timezone.utc).isoformat().replace('+00:00','Z'))
        assert receipt['inserted'] is False
        assert store.checkpoint('kind-csle-p0-cis',ns,event['kind'])==before
    for method,value in [('events',events),('observations',observations),('current',current),('gaps',gaps),('snapshots',snapshots)]:
        (run/(method+'.json')).write_text(json.dumps(value,sort_keys=True,indent=2))
    for operation in ('workloads','events','observations','snapshots','gaps'):
        argv=[sys.executable,'-m','app','--db',str(db),'inventory',operation,'--cluster','kind-csle-p0-cis','--namespace',ns]
        first_output=subprocess.check_output(argv,cwd=ROOT)
        assert first_output==subprocess.check_output(argv,cwd=ROOT)
    result={'executed_revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'dirty_working_tree':bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT)),
            'namespace':ns,'cluster_id':'kind-csle-p0-cis','server_id':api.server_id,'local_directory':str(run.relative_to(ROOT)),
            'first_job_uid':first_uid,'reused_name_job_uid':second_uid,'unobserved_job_uid':unseen_uid,
            'rbac_denials':denials,'actual_expired_resource_version_status':recovered.observed_code,'watch_connections':observed_calls,
            'kubernetes_server_version':versions['serverVersion']['gitVersion'],'snapshot_receipts':len(snapshots),'events':len(events),'observations':len(observations),'gaps':len(gaps),'collector_summaries':summaries,
            'passed':['all_seven_resource_list_watch','read_only_namespaced_rbac','ttl_job_history','scale_zero_reference','same_name_new_uid','real_watch_reconnect','periodic_reconciliation','restart_checkpoint_and_gaps','unseen_downtime_job_not_invented','actual_api_410_and_relist','replay_idempotency','deterministic_cli','immutable_complete_snapshot_receipts']}
    (run/'result.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
