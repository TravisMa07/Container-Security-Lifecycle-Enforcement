"""Append-only workload evidence with transactional derived inventory/checkpoints."""
from contextlib import contextmanager
from datetime import datetime
import json
import uuid
from pydantic import TypeAdapter

from app.models import Identifier, Timestamp, canonical_json, sha256_bytes
from app.store.db import Store

KINDS = ('Pod','Job','CronJob','Deployment','ReplicaSet','StatefulSet','DaemonSet')
_ID = TypeAdapter(Identifier)
_TIME = TypeAdapter(Timestamp)


def _hash(value):
    return sha256_bytes(canonical_json(value).encode())


def _pack(value):
    return canonical_json({'record': value, 'content_hash': _hash(value)})


def _unpack(payload):
    try:
        envelope=json.loads(payload)
        value=envelope['record']
        if not isinstance(value,dict) or _hash(value)!=envelope['content_hash']:
            raise ValueError('inventory evidence integrity check failed')
        return value
    except (KeyError,TypeError,json.JSONDecodeError) as error:
        raise ValueError('inventory evidence integrity check failed') from error


def _scope(cluster_id,namespace,kind=None):
    _ID.validate_python(cluster_id, strict=True)
    _ID.validate_python(namespace, strict=True)
    if kind is not None and kind not in KINDS:
        raise ValueError('unsupported workload kind')


def _time(value):
    return _TIME.validate_python(value,strict=True)


def _instant(value):
    return datetime.fromisoformat(value.replace('Z','+00:00'))


class InventoryStore:
    def __init__(self,path):
        self.store=Store(path)
        self.connection=self.store.connection

    def __enter__(self):
        self.store.__enter__()
        return self

    def __exit__(self,*args):
        self.store.__exit__(*args)

    @contextmanager
    def _transaction(self):
        self.store._ensure_ready()
        self.connection.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.connection.execute('COMMIT')
        except BaseException:
            self.connection.execute('ROLLBACK')
            raise

    def bind_scope(self,cluster_id,namespace,server_id):
        _scope(cluster_id,namespace)
        _ID.validate_python(server_id,strict=True)
        with self._transaction():
            bindings=self.connection.execute('SELECT server_id FROM inventory_scopes WHERE cluster_id=?',
                                             (cluster_id,)).fetchall()
            if any(row['server_id']!=server_id for row in bindings):
                raise ValueError('inventory scope is bound to a different Kubernetes server')
            self.connection.execute('INSERT OR IGNORE INTO inventory_scopes(cluster_id,namespace,server_id) VALUES(?,?,?)',
                                    (cluster_id,namespace,server_id))

    def checkpoint(self,cluster_id,namespace,kind):
        _scope(cluster_id,namespace,kind)
        self.store._ensure_ready()
        row=self.connection.execute('SELECT resource_version,observed_at FROM inventory_checkpoints WHERE cluster_id=? AND namespace=? AND kind=?',
                                    (cluster_id,namespace,kind)).fetchone()
        if row is None: return None
        _ID.validate_python(row['resource_version'],strict=True)
        _time(row['observed_at'])
        return dict(row)

    def _checkpoint(self,cluster_id,namespace,kind,resource_version,observed_at):
        _ID.validate_python(resource_version,strict=True); _time(observed_at)
        self.connection.execute('INSERT INTO inventory_checkpoints(cluster_id,namespace,kind,resource_version,observed_at) VALUES(?,?,?,?,?) '
                                'ON CONFLICT(cluster_id,namespace,kind) DO UPDATE SET resource_version=excluded.resource_version,observed_at=excluded.observed_at',
                                (cluster_id,namespace,kind,resource_version,observed_at))

    def bookmark(self,cluster_id,namespace,kind,resource_version,observed_at):
        _scope(cluster_id,namespace,kind)
        with self._transaction():
            self._checkpoint(cluster_id,namespace,kind,resource_version,observed_at)

    def _gap_rows(self,cluster_id,namespace=None):
        sql='SELECT * FROM inventory_gap_events WHERE cluster_id=?'
        params=[cluster_id]
        if namespace is not None: sql+=' AND namespace=?';params.append(namespace)
        rows=[]
        for row in self.connection.execute(sql,params):
            value=dict(row); event_id=value.pop('gap_event_id')
            if _hash(value)!=event_id:
                raise ValueError('inventory gap evidence integrity check failed')
            _scope(value['cluster_id'],value['namespace'],value['kind'])
            _time(value['observed_at']);_time(value['started_at'])
            if value['event_type'] not in ('START','END'):
                raise ValueError('invalid inventory gap event')
            rows.append(value)
        return rows

    def _gaps(self,cluster_id,namespace=None):
        groups={}
        for row in self._gap_rows(cluster_id,namespace):
            groups.setdefault(row['gap_id'],[]).append(row)
        result=[]
        for gap_id in sorted(groups):
            rows=groups[gap_id];starts=[r for r in rows if r['event_type']=='START'];ends=[r for r in rows if r['event_type']=='END']
            if len(starts)!=1 or len(ends)>1:
                raise ValueError('invalid inventory gap sequence')
            start=starts[0]
            for end in ends:
                if any(end[key]!=start[key] for key in ('cluster_id','namespace','kind','reason','started_at')) or _instant(end['observed_at'])<_instant(start['observed_at']):
                    raise ValueError('conflicting inventory gap evidence')
            result.append({key:start[key] for key in ('gap_id','cluster_id','namespace','kind','reason','started_at')} |
                          {'ended_at':ends[0]['observed_at'] if ends else None})
        # More than one unresolved gap for a scope/kind is corruption, never coverage.
        open_keys=[(r['namespace'],r['kind']) for r in result if r['ended_at'] is None]
        if len(open_keys)!=len(set(open_keys)): raise ValueError('multiple open inventory gaps')
        return result

    def gaps(self,cluster_id,namespace=None):
        _ID.validate_python(cluster_id,strict=True)
        if namespace is not None: _scope(cluster_id,namespace)
        self.store._ensure_ready()
        return self._gaps(cluster_id,namespace)

    def _append_gap(self,value):
        self.connection.execute('INSERT INTO inventory_gap_events(gap_event_id,gap_id,cluster_id,namespace,kind,event_type,reason,observed_at,started_at) VALUES(?,?,?,?,?,?,?,?,?)',
                                (_hash(value),value['gap_id'],value['cluster_id'],value['namespace'],value['kind'],value['event_type'],value['reason'],value['observed_at'],value['started_at']))

    def begin_gap(self,cluster_id,namespace,kind,reason,observed_at,started_at=None):
        _scope(cluster_id,namespace,kind);_ID.validate_python(reason,strict=True);_time(observed_at)
        started_at=observed_at if started_at is None else _time(started_at)
        if _instant(started_at)>_instant(observed_at): raise ValueError('gap start follows observation')
        with self._transaction():
            existing=[g for g in self._gaps(cluster_id,namespace) if g['kind']==kind and g['ended_at'] is None]
            if existing: return existing[0]['gap_id']
            gap_id='gap:'+uuid.uuid4().hex
            self._append_gap({'gap_id':gap_id,'cluster_id':cluster_id,'namespace':namespace,'kind':kind,'event_type':'START',
                              'reason':reason,'observed_at':observed_at,'started_at':started_at})
            return gap_id

    def _close_gap(self,cluster_id,namespace,kind,observed_at):
        for gap in self._gaps(cluster_id,namespace):
            if gap['kind']==kind and gap['ended_at'] is None:
                start_event=next(row for row in self._gap_rows(cluster_id,namespace) if row['gap_id']==gap['gap_id'] and row['event_type']=='START')
                if _instant(observed_at)<_instant(start_event['observed_at']): raise ValueError('gap end precedes gap observation')
                self._append_gap({key:gap[key] for key in ('gap_id','cluster_id','namespace','kind','reason','started_at')} |
                                 {'event_type':'END','observed_at':observed_at})

    def _read_event(self,event_id):
        from app.workloads import NormalizedResource
        row=self.connection.execute('SELECT payload FROM inventory_events WHERE event_id=?',(event_id,)).fetchone()
        if row is None: raise ValueError('missing inventory event reference')
        value=_unpack(row['payload'])
        try:
            record=NormalizedResource.model_validate(value)
            if record.event_id!=event_id or _hash(record.raw_object)!=record.raw_object_hash:
                raise ValueError('inventory raw event integrity check failed')
            from app.workloads import normalize_object
            expected=normalize_object(record.cluster_id,record.namespace,record.kind,record.raw_object,record.event_type,record.source,record.observed_at)
            if expected.model_dump(mode='json')!=value:
                raise ValueError('inventory normalized event integrity check failed')
            rows=self.connection.execute('SELECT observation_id,payload FROM inventory_observations WHERE event_id=? ORDER BY observation_id',(event_id,)).fetchall()
            observations=[]
            for row in rows:
                observation=_unpack(row['payload'])
                if observation.get('observation_id')!=row['observation_id']:
                    raise ValueError('inventory observation identity mismatch')
                observations.append(observation)
            if observations!=sorted(value['observations'],key=lambda r:r['observation_id']):
                raise ValueError('inventory observation/event association failed')
            return value
        except (KeyError,TypeError) as error:
            raise ValueError('inventory normalized evidence integrity check failed') from error

    def _append_resource(self,record):
        value=record.model_dump(mode='json')
        existing=self.connection.execute('SELECT 1 FROM inventory_events WHERE event_id=?',(record.event_id,)).fetchone()
        if existing is not None:
            prior=self._read_event(record.event_id)
            if prior['raw_object_hash']!=record.raw_object_hash or prior['raw_object']!=record.raw_object:
                raise ValueError('conflicting replayed inventory event')
            return prior,False
        self.connection.execute('INSERT INTO inventory_events(event_id,payload) VALUES(?,?)',(record.event_id,_pack(value)))
        for observation in value['observations']:
            self.connection.execute('INSERT INTO inventory_observations(observation_id,event_id,payload) VALUES(?,?,?)',
                                    (observation['observation_id'],record.event_id,_pack(observation)))
        return value,True

    def _membership(self,value,present,absence_reason,observed_at):
        self.connection.execute('INSERT INTO inventory_current(cluster_id,namespace,kind,uid,event_id,present,absence_reason,last_seen) VALUES(?,?,?,?,?,?,?,?) '
                                'ON CONFLICT(cluster_id,namespace,kind,uid) DO UPDATE SET event_id=excluded.event_id,present=excluded.present,absence_reason=excluded.absence_reason,last_seen=excluded.last_seen',
                                (value['cluster_id'],value['namespace'],value['kind'],value['uid'],value['event_id'],int(present),absence_reason,observed_at))

    def apply_event(self,cluster_id,namespace,kind,event_type,obj,observed_at):
        from app.workloads import normalize_object
        if event_type not in ('ADDED','MODIFIED','DELETED'): raise ValueError('unsupported watch event type')
        record=normalize_object(cluster_id,namespace,kind,obj,event_type,'kubernetes_watch',observed_at)
        with self._transaction():
            value,inserted=self._append_resource(record)
            # Exact replays never regress a more recent derived membership/checkpoint.
            if inserted:
                self._membership(value,event_type!='DELETED','WATCH_DELETED' if event_type=='DELETED' else None,observed_at)
                self._checkpoint(cluster_id,namespace,kind,record.resource_version,observed_at)
            return {'event_id':record.event_id,'inserted':inserted}

    def apply_snapshot(self,cluster_id,namespace,kind,objects,resource_version,observed_at,source='kubernetes_list'):
        from app.workloads import normalize_object
        _scope(cluster_id,namespace,kind);_ID.validate_python(resource_version,strict=True);_time(observed_at)
        if source not in ('kubernetes_list','kubernetes_reconcile'): raise ValueError('unsupported snapshot source')
        if not isinstance(objects,list) or len(objects)>10000: raise ValueError('complete bounded object list required')
        records=[normalize_object(cluster_id,namespace,kind,obj,'SNAPSHOT',source,observed_at) for obj in objects]
        uids=[r.uid for r in records]
        if len(uids)!=len(set(uids)): raise ValueError('duplicate resource UID in snapshot')
        with self._transaction():
            inserted=0
            for record in records:
                value,new=self._append_resource(record);inserted+=int(new)
                self._membership(value,True,None,observed_at)
            for row in self.connection.execute('SELECT uid FROM inventory_current WHERE cluster_id=? AND namespace=? AND kind=? AND present=1',
                                               (cluster_id,namespace,kind)).fetchall():
                if row['uid'] not in uids:
                    self.connection.execute('UPDATE inventory_current SET present=0,absence_reason=? WHERE cluster_id=? AND namespace=? AND kind=? AND uid=?',
                                            ('RECONCILED_ABSENT',cluster_id,namespace,kind,row['uid']))
            receipt={'cluster_id':cluster_id,'namespace':namespace,'kind':kind,
                     'resource_version':resource_version,'observed_at':observed_at,'source':source,
                     'members':sorted([{'uid':r.uid,'event_id':r.event_id} for r in records],key=lambda r:r['uid'])}
            snapshot_id=_hash(receipt)
            self.connection.execute('INSERT OR IGNORE INTO inventory_snapshots(snapshot_id,payload) VALUES(?,?)',
                                    (snapshot_id,_pack(receipt)))
            self._checkpoint(cluster_id,namespace,kind,resource_version,observed_at)
            self._close_gap(cluster_id,namespace,kind,observed_at)
            return {'inserted':inserted,'objects':len(records),'resource_version':resource_version,'snapshot_id':snapshot_id}

    def snapshots(self,cluster_id,namespace=None):
        _ID.validate_python(cluster_id,strict=True)
        if namespace is not None: _scope(cluster_id,namespace)
        self.store._ensure_ready()
        result=[]
        try:
            for row in self.connection.execute('SELECT snapshot_id,payload FROM inventory_snapshots ORDER BY snapshot_id'):
                receipt=_unpack(row['payload'])
                if _hash(receipt)!=row['snapshot_id']:
                    raise ValueError('inventory snapshot identity check failed')
                _scope(receipt['cluster_id'],receipt['namespace'],receipt['kind'])
                _time(receipt['observed_at']);_ID.validate_python(receipt['resource_version'],strict=True)
                if receipt['source'] not in ('kubernetes_list','kubernetes_reconcile') or not isinstance(receipt['members'],list):
                    raise ValueError('invalid inventory snapshot evidence')
                seen=set()
                for member in receipt['members']:
                    event=self._read_event(member['event_id'])
                    if member['uid'] in seen or member['uid']!=event['uid'] or any(receipt[k]!=event[k] for k in ('cluster_id','namespace','kind','source')) or event['event_type']!='SNAPSHOT':
                        raise ValueError('inventory snapshot membership association failed')
                    seen.add(member['uid'])
                if receipt['cluster_id']==cluster_id and (namespace is None or receipt['namespace']==namespace):
                    result.append(dict(receipt,snapshot_id=row['snapshot_id']))
            return result
        except (KeyError,TypeError) as error:
            raise ValueError('inventory snapshot integrity check failed') from error

    def events(self,cluster_id,namespace=None):
        _ID.validate_python(cluster_id,strict=True)
        if namespace is not None: _scope(cluster_id,namespace)
        self.store._ensure_ready()
        result=[]
        for row in self.connection.execute('SELECT event_id FROM inventory_events ORDER BY event_id'):
            event=self._read_event(row['event_id'])
            if event['cluster_id']==cluster_id and (namespace is None or event['namespace']==namespace): result.append(event)
        return result

    def observations(self,cluster_id,namespace=None):
        return sorted([observation for event in self.events(cluster_id,namespace) for observation in event['observations']],key=lambda r:r['observation_id'])

    def current(self,cluster_id,namespace=None):
        _ID.validate_python(cluster_id,strict=True)
        if namespace is not None: _scope(cluster_id,namespace)
        self.store._ensure_ready()
        sql='SELECT * FROM inventory_current WHERE cluster_id=?';params=[cluster_id]
        if namespace is not None: sql+=' AND namespace=?';params.append(namespace)
        sql+=' ORDER BY namespace,kind,uid'
        result=[]
        for row in self.connection.execute(sql,params):
            event=self._read_event(row['event_id'])
            if any(row[key]!=event[key] for key in ('cluster_id','namespace','kind','uid')) or row['present'] not in (0,1):
                raise ValueError('inventory membership association failed')
            _time(row['last_seen'])
            if (row['present'] and (row['absence_reason'] is not None or event['event_type']=='DELETED')) or (not row['present'] and row['absence_reason'] not in ('WATCH_DELETED','RECONCILED_ABSENT')) or (row['absence_reason']=='WATCH_DELETED' and event['event_type']!='DELETED'):
                raise ValueError('inventory membership state is inconsistent')
            result.append({key:event[key] for key in ('cluster_id','namespace','kind','name','uid','event_id','observations')} |
                          {'present':bool(row['present']),'absence_reason':row['absence_reason'],'last_seen':row['last_seen']})
        return result
