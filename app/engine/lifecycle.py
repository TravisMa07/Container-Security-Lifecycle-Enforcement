"""Pure scoped lifecycle reasoning. An evidence result is never authorization."""
from datetime import datetime
import re
from typing import Annotated, Any, Literal
from urllib.parse import quote

from pydantic import Field, TypeAdapter, model_validator

from app.collectors.trivy import normalize_timestamp, parse_image_ref
from app.models import Digest, Identifier, Identifiers, Record, Text, Timestamp, VulnerabilityFinding

ENGINE_VERSION = 'p3/1'
KINDS = ('Pod','Job','CronJob','Deployment','ReplicaSet','StatefulSet','DaemonSet')
Positive = Annotated[int, Field(ge=1, le=86400)]
_ID = TypeAdapter(Identifier)
_TIME = TypeAdapter(Timestamp)


def instant(value):
    return datetime.fromisoformat(_TIME.validate_python(value, strict=True).replace('Z','+00:00'))


class Verification(Record):
    scope: Text
    window_start: Timestamp
    window_end: Timestamp
    inventory_fresh: Literal[True]
    coverage_complete: Literal[True]
    remaining_references: Literal[0]
    fixed_scan_evidence_ids: Annotated[Identifiers, Field(min_length=1)]
    replacement_observation_ids: Annotated[Identifiers, Field(min_length=1)]

    @model_validator(mode='after')
    def coherent(self):
        if instant(self.window_start)>instant(self.window_end):
            raise ValueError('verification window is inverted')
        return self


class DerivedFindingState(Record):
    schema_version: Literal['1']='1'
    finding_id: Identifier
    assessment_at: Timestamp
    inventory_scope: Text
    validity: Literal['affected','not_affected','under_investigation','disputed']
    exposure: Literal['running','configured_not_running','historical_observed','unknown']
    remediation: Literal['open','in_progress','verified_in_scope','regressed','unknown']
    recommendation: Text
    reason_codes: Annotated[Identifiers,Field(min_length=1,max_length=100)]
    confidence: Literal['bounded','unknown']
    coverage_gap_ids: Identifiers
    evidence_ids: Identifiers
    verification: Verification | None=None

    @model_validator(mode='after')
    def coherent(self):
        if any(not re.fullmatch(r'[A-Z][A-Z0-9_]*',reason) for reason in self.reason_codes):
            raise ValueError('stable uppercase reason required')
        if self.remediation=='verified_in_scope':
            if (self.verification is None or self.exposure!='historical_observed' or self.coverage_gap_ids
                    or not self.evidence_ids or self.verification.scope!=self.inventory_scope
                    or self.verification.window_end!=self.assessment_at):
                raise ValueError('verification prerequisites missing')
        elif self.verification is not None:
            raise ValueError('nonverified result cannot carry verification')
        return self


class Scope(Record):
    cluster_id: Identifier
    namespaces: Annotated[list[Identifier],Field(min_length=1,max_length=32)]

    @model_validator(mode='after')
    def coherent(self):
        if self.namespaces!=sorted(set(self.namespaces)):
            raise ValueError('scope namespaces must be sorted and unique')
        return self


class Facts(Record):
    finding: VulnerabilityFinding
    scope: Scope
    assessment_at: Timestamp
    inventory_max_age_seconds: Positive
    scan_max_age_seconds: Positive
    db_max_age_seconds: Positive
    current: list[dict[str,Any]]
    events: list[dict[str,Any]]
    snapshots: list[dict[str,Any]]
    checkpoints: list[dict[str,Any]]
    gaps: list[dict[str,Any]]
    scans: list[dict[str,Any]]
    trusted_scanner_hashes: list[Digest]
    replacement_digest: Digest | None
    previous: list[dict[str,Any]]


def _digest(reference):
    if not isinstance(reference,str):return None
    if reference.startswith('docker-pullable://'):
        reference=reference[len('docker-pullable://'):]
    try:return parse_image_ref(reference)[2]
    except ValueError:return None


def _fresh(value,at,age):
    try:return 0<=(at-instant(value)).total_seconds()<=age
    except (ValueError,TypeError,OverflowError):return False


def _scan_reasons(scan,facts):
    reasons=set()
    try:
        image,execution,report=scan['image'],scan.get('execution') or {},scan['report']
        resolution=scan.get('resolution') or {}
        manifest=TypeAdapter(Digest).validate_python(image['manifest_digest'],strict=True)
        TypeAdapter(Digest).validate_python(resolution.get('config_digest'),strict=True)
        metadata=report.get('Metadata') or {}
        claimed=report.get('Trivy') or {}
        if (scan.get('provenance')!='executed_local_trivy'
            or execution.get('executable_hash') not in facts.trusted_scanner_hashes
            or not scan.get('scanner_version')
            or execution.get('scanner_version')!=scan['scanner_version']
            or claimed.get('Version')!=scan['scanner_version']
            or report.get('SchemaVersion')!=2 or report.get('ArtifactType')!='container_image'
            or image.get('image_id')!=manifest or image.get('resolution_status')!='resolved'
            or resolution.get('manifest_digest')!=manifest or resolution.get('platform_digest')!=manifest
            or resolution.get('platform')!=image.get('platform') or not image.get('platform')
            or resolution.get('index_digest')!=image.get('index_digest')
            or metadata.get('ImageID')!=resolution.get('config_digest')
            or _digest(image.get('source_reference'))!=manifest
            or image.get('source_reference') not in metadata.get('RepoDigests',[])
            or normalize_timestamp(report.get('CreatedAt'))!=scan['scan_timestamp']
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',scan.get('source_document_hash') or '')
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',scan.get('db_document_hash') or '')
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',execution.get('db_content_hash') or '')):
            reasons.add('TRUSTED_SCAN_REQUIRED')
        if instant(execution['started_at'])>instant(scan['scan_timestamp']) or instant(execution['finished_at'])<instant(scan['scan_timestamp']) or instant(execution['finished_at'])>instant(facts.assessment_at):
            reasons.add('TRUSTED_SCAN_REQUIRED')
        at=instant(facts.assessment_at)
        if not _fresh(scan.get('scan_timestamp'),at,facts.scan_max_age_seconds):reasons.add('SCAN_STALE')
        if not _fresh(scan.get('scanner_db_updated_at'),at,facts.db_max_age_seconds):reasons.add('DB_STALE')
        if scan.get('scanner_db_updated_at') and instant(scan['scanner_db_updated_at'])>instant(scan['scan_timestamp']):reasons.add('DB_STALE')
        config=metadata.get('ImageConfig') or {}
        declared='/'.join([config.get('os',''),config.get('architecture','')]+([config['variant']] if config.get('variant') else []))
        if declared!=image.get('platform'):reasons.add('TRUSTED_SCAN_REQUIRED')
    except (KeyError,TypeError,ValueError,AttributeError,OverflowError):
        reasons.add('TRUSTED_SCAN_REQUIRED')
    return reasons


def _latest(scans):
    def key(scan):
        try:time=instant(scan.get('scan_timestamp'))
        except (ValueError,TypeError):time=instant('0001-01-01T00:00:00Z')
        return time,scan.get('source_document_hash',''),scan.get('provenance')=='executed_local_trivy',scan.get('scan_id','')
    return max(scans,key=key) if scans else None


def _raw_finding_matches(scan,finding):
    for result in (scan.get('report') or {}).get('Results') or []:
        if not isinstance(result,dict) or result.get('Type')!=finding['package_type']:continue
        for row in result.get('Vulnerabilities') or []:
            if not isinstance(row,dict):continue
            if (row.get('VulnerabilityID')==finding['vuln_id'] and row.get('PkgName')==finding['package_name']
                and row.get('InstalledVersion')==finding['installed_version'] and (row.get('FixedVersion') or None)==finding['fixed_version']
                and (row.get('PkgPath') or None)==finding['package_path']
                and row.get('Severity','UNKNOWN')==finding['severity']
                and (row.get('SeveritySource') or None)==finding['severity_source']
                and sorted(set(row.get('Aliases') or []))==finding['aliases']):return True
    return False


def _original_scan(facts):
    finding=facts.finding.model_dump(mode='json')
    candidates=[]
    for scan in facts.scans:
        if scan.get('source_document_hash')!=finding['source_document_hash']:continue
        if (scan.get('image') or {}).get('manifest_digest')!=finding['image_digest']:continue
        if any(row==finding for row in scan.get('findings',[])) and _raw_finding_matches(scan,finding):
            candidates.append(scan)
    valid=[scan for scan in candidates if not _scan_reasons(scan,facts)]
    return _latest(valid or candidates)


def _running(observation,event):
    if observation.get('kind')!='Pod' or observation.get('phase')!='Running':return False
    field={'regular':'containerStatuses','init':'initContainerStatuses','ephemeral':'ephemeralContainerStatuses'}.get(observation.get('container_type'))
    if field is None:return False
    rows=((event or {}).get('raw_object') or {}).get('status',{}).get(field,[])
    return any(isinstance(row,dict) and row.get('name')==observation.get('container_name')
               and isinstance(row.get('state'),dict) and isinstance(row['state'].get('running'),dict)
               for row in rows)


def _lineage(observation,events,current):
    namespace=observation['namespace']
    scoped_events=[event for event in events if event.get('namespace')==namespace]
    nodes={event['uid']:(event['kind'],event['name']) for event in scoped_events}
    def parents(item):
        result=set()
        for owner in item.get('owner_refs',[]):
            identity=nodes.get(owner.get('uid'))
            if (owner.get('controller') is True and identity and identity[0]==owner.get('kind')
                and (not owner.get('name') or identity[1]==owner['name'])):result.add(owner['uid'])
        return result
    owners={}
    for event in scoped_events:
        for item in event.get('observations',[]):owners.setdefault(item['uid'],set()).update(parents(item))
    for row in current:
        if row.get('namespace')==namespace and row.get('present'):
            owners[row['uid']]=set().union(*(parents(item) for item in row.get('observations',[])))
    uid=observation['uid'];reachable={uid};pending=list(parents(observation))
    while pending:
        parent=pending.pop()
        if parent in reachable:continue
        reachable.add(parent);pending.extend(owners.get(parent,()))
        if len(reachable)>10000:raise ValueError('owner ancestry exceeds limit')
    return reachable


def _same_platform(left,right):
    # containerd/platforms normalizes arm64's default v8 variant to empty.
    # Keep stored evidence unchanged and do not extrapolate to v9/other OS/arch.
    if left==right:return True
    return {left,right}=={'linux/arm64','linux/arm64/v8'}


def _package_fixed(original,replacement,finding):
    fixed=finding.fixed_version
    if not fixed or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.+_~:-]*',fixed):return False
    old_image,new_image=original['image'],replacement['image']
    old_metadata=original['report'].get('Metadata') or {};new_metadata=replacement['report'].get('Metadata') or {}
    old_os=(old_metadata.get('OS') or {}).get('Family');new_os=(new_metadata.get('OS') or {}).get('Family')
    if not old_os or old_os!=new_os or not _same_platform(old_image.get('platform'),new_image.get('platform')):return False
    names={finding.vuln_id,*finding.aliases};matched=False
    for result in replacement['report'].get('Results') or []:
        if not isinstance(result,dict) or result.get('Type')!=finding.package_type:continue
        packages=result.get('Packages')
        if isinstance(packages,list):
            for package in packages:
                if not isinstance(package,dict):continue
                path=package.get('PkgPath') or None
                if package.get('Name')==finding.package_name and path==finding.package_path and package.get('Version')==fixed:matched=True
        vulnerabilities=result.get('Vulnerabilities')
        if vulnerabilities is not None and not isinstance(vulnerabilities,list):return False
        for vulnerability in vulnerabilities or []:
            if not isinstance(vulnerability,dict):return False
            ids={vulnerability.get('VulnerabilityID'),*(vulnerability.get('Aliases') or [])}
            if vulnerability.get('PkgName')==finding.package_name and (vulnerability.get('PkgPath') or None)==finding.package_path and names.intersection(ids):return False
    return matched


def _evaluate(facts:dict)->dict:
    """Evaluate bounded truth over frozen input; never perform I/O or mutate input."""
    f=Facts.model_validate(facts)
    cluster=f.scope.cluster_id;namespaces=set(f.scope.namespaces);at=instant(f.assessment_at)
    scope_text='cluster/'+quote(cluster,safe='')+'/namespaces/'+','.join(quote(ns,safe='') for ns in f.scope.namespaces)
    finding=f.finding;digest=finding.image_digest
    def scoped(row):return row.get('cluster_id')==cluster and row.get('namespace') in namespaces
    events=[row for row in f.events if scoped(row)];event_map={row['event_id']:row for row in events}
    currents=[row for row in f.current if scoped(row) and row.get('present')]
    reasons=set();evidence={finding.source_document_hash};gap_ids=[]
    latest_receipts={};checkpoints={}
    for row in f.snapshots:
        if scoped(row) and row.get('kind') in KINDS:
            key=(row['namespace'],row['kind'])
            if key not in latest_receipts or instant(row['observed_at'])>instant(latest_receipts[key]['observed_at']):latest_receipts[key]=row
    for row in f.checkpoints:
        if row.get('namespace') in namespaces and row.get('kind') in KINDS:
            key=(row['namespace'],row['kind'])
            if key in checkpoints:raise ValueError('duplicate inventory checkpoint')
            checkpoints[key]=row
    required={(ns,kind) for ns in namespaces for kind in KINDS}
    if set(latest_receipts)!=required or set(checkpoints)!=required:reasons.add('INVENTORY_INCOMPLETE')
    times=[instant(row['observed_at']) for row in latest_receipts.values()]
    window_start=max(times) if times else at
    for key,row in latest_receipts.items():
        evidence.add(row['snapshot_id'])
        if not _fresh(row['observed_at'],at,f.inventory_max_age_seconds):reasons.add('INVENTORY_STALE')
        checkpoint=checkpoints.get(key)
        if checkpoint is not None and (not _fresh(checkpoint['observed_at'],at,f.inventory_max_age_seconds) or instant(checkpoint['observed_at'])<instant(row['observed_at'])):reasons.add('INVENTORY_STALE')
    for gap in f.gaps:
        if not scoped(gap):continue
        start=instant(gap['started_at']);end=instant(gap['ended_at']) if gap.get('ended_at') else None
        if end is not None and end<start:raise ValueError('inverted coverage gap')
        if start>at:reasons.add('INVENTORY_STALE')
        if start<=at and (end is None or end>window_start):
            gap_ids.append(gap['gap_id']);reasons.add('COVERAGE_GAP');evidence.add(gap['gap_id'])
    original=_original_scan(f)
    scan_reasons=_scan_reasons(original,f) if original else {'TRUSTED_SCAN_REQUIRED'}
    reasons.update(scan_reasons)
    if original:evidence.add(original['scan_id'])
    known=set();index_links={}
    for scan in f.scans:
        status=_scan_reasons(scan,f)
        if status-{'SCAN_STALE','DB_STALE'}:continue
        image=scan['image'];known.add(image['manifest_digest'])
        if image.get('index_digest'):
            index_links.setdefault(image['index_digest'],set()).add(image['manifest_digest'])
    links={'running':set(),'configured':set(),'historical':set(),'unknown':set()};uncertain=False
    old_observations=[];replacement_observations=[];current_old=[]
    def old_reference(value):return value==digest or digest in index_links.get(value,set())
    for event in events:
        if instant(event['observed_at'])>at:
            reasons.add('INVENTORY_STALE');continue
        for observation in event.get('observations',[]):
            if old_reference(_digest(observation.get('desired_image_ref'))) or old_reference(_digest(observation.get('runtime_image_id'))):
                links['historical'].add(observation['observation_id']);old_observations.append(observation)
    for row in currents:
        key=(row['namespace'],row['kind']);receipt=latest_receipts.get(key)
        if not _fresh(row.get('last_seen'),at,f.inventory_max_age_seconds) or (receipt and instant(row['last_seen'])<instant(receipt['observed_at'])):reasons.add('INVENTORY_STALE')
        event=event_map.get(row['event_id'])
        if event is None or any(event.get(key)!=row.get(key) for key in ('cluster_id','namespace','kind','uid')):
            uncertain=True;evidence.add(row['event_id'])
        if not row.get('observations'):
            uncertain=True;evidence.add(row['event_id'])
        for observation in row.get('observations',[]):
            oid=observation['observation_id'];desired=_digest(observation.get('desired_image_ref'));runtime=_digest(observation.get('runtime_image_id'))
            if old_reference(desired):links['configured'].add(oid);current_old.append((row,observation))
            elif desired not in known:
                links['unknown'].add(oid);uncertain=True
            if observation.get('kind')=='Pod':
                active=observation.get('phase') not in ('Succeeded','Failed')
                if active and (runtime is None or runtime not in known):links['unknown'].add(oid);uncertain=True
                if runtime==digest and _running(observation,event):links['running'].add(oid);current_old.append((row,observation))
                if runtime==f.replacement_digest and _running(observation,event):replacement_observations.append(observation)
                # A known old runtime in a nonrunning/uncertain status is still a remaining reference.
                if runtime==digest and not _running(observation,event):links['configured'].add(oid);current_old.append((row,observation))
    if links['running']:reasons.add('RUNNING_REFERENCE_PRESENT')
    if links['configured']:reasons.add('DESIRED_REFERENCE_PRESENT')
    if links['historical']:reasons.add('HISTORICAL_OBSERVATION_PRESENT')
    else:reasons.add('NO_OBSERVATION')
    if uncertain:reasons.add('IDENTITY_UNRESOLVED')
    remaining=bool(links['running'] or links['configured'])
    if remaining:reasons.add('REMAINING_REFERENCES')
    inventory_bad=bool(reasons.intersection({'INVENTORY_INCOMPLETE','INVENTORY_STALE','COVERAGE_GAP','IDENTITY_UNRESOLVED'}))
    exposure=('unknown' if inventory_bad else 'running' if links['running'] else 'configured_not_running' if links['configured'] else 'historical_observed' if links['historical'] else 'unknown')
    remediation='unknown' if inventory_bad or scan_reasons or not links['historical'] else 'open'
    verification=None;regression_of=None
    predecessors=[]
    for previous in f.previous:
        prior_scope=previous.get('scope') or {};state=previous.get('state') or {}
        if (previous.get('finding_id')==finding.finding_id and prior_scope.get('cluster_id')==cluster
            and set(prior_scope.get('namespaces') or []) and set(prior_scope['namespaces']).issubset(namespaces)
            and state.get('remediation')=='verified_in_scope' and instant(state['assessment_at'])<at
            and any(_fresh(row['last_seen'],at,f.inventory_max_age_seconds) and instant(row['last_seen'])>instant(state['assessment_at']) for row,_ in current_old)):
            predecessors.append(previous)
    if predecessors:
        previous=max(predecessors,key=lambda row:(instant(row['state']['assessment_at']),row['assessment_id']))
        regression_of=previous['assessment_id'];remediation='regressed';reasons.add('REGRESSION_OBSERVED');evidence.add(regression_of)
    elif f.replacement_digest:
        replacement=_latest([scan for scan in f.scans if (scan.get('image') or {}).get('manifest_digest')==f.replacement_digest])
        replacement_status=_scan_reasons(replacement,f) if replacement else {'TRUSTED_SCAN_REQUIRED'}
        reasons.update(replacement_status)
        if replacement:evidence.add(replacement['scan_id'])
        if not replacement_observations:reasons.add('REPLACEMENT_NOT_OBSERVED')
        matched=[]
        for candidate in replacement_observations:
            ancestors=_lineage(candidate,events,currents)
            if any(old['namespace']==candidate['namespace'] and old['container_name']==candidate['container_name'] and old['container_type']==candidate['container_type'] and ancestors.intersection(_lineage(old,events,[])) for old in old_observations):matched.append(candidate)
        if replacement_observations and not matched:reasons.add('REPLACEMENT_LINEAGE_UNKNOWN')
        fixed=bool(original and replacement and not scan_reasons and not replacement_status and _package_fixed(original,replacement,finding))
        if not fixed:reasons.add('PACKAGE_FIX_UNCONFIRMED')
        if remediation!='unknown' and not remaining and replacement_observations:remediation='in_progress'
        if replacement_status:remediation='unknown'
        if (not inventory_bad and not scan_reasons and not replacement_status and not remaining
            and links['historical'] and matched and fixed):
            remediation='verified_in_scope';reasons.add('VERIFIED_SCOPED_REPLACEMENT')
            verification=Verification(scope=scope_text,window_start=window_start.isoformat().replace('+00:00','Z'),window_end=f.assessment_at,
                                      inventory_fresh=True,coverage_complete=True,remaining_references=0,
                                      fixed_scan_evidence_ids=[replacement['scan_id']],replacement_observation_ids=sorted({o['observation_id'] for o in matched}))
    for values in links.values():evidence.update(values)
    recommendation={'verified_in_scope':'retain_scoped_evidence_and_monitor','regressed':'investigate_reintroduced_digest','open':'remediate_remaining_references' if remaining else 'manual_retirement_review','in_progress':'complete_replacement_verification','unknown':'collect_missing_evidence'}[remediation]
    state=DerivedFindingState(finding_id=finding.finding_id,assessment_at=f.assessment_at,inventory_scope=scope_text,validity=finding.validity,
                              exposure=exposure,remediation=remediation,recommendation=recommendation,reason_codes=sorted(reasons),
                              confidence='unknown' if inventory_bad or scan_reasons else 'bounded',coverage_gap_ids=sorted(set(gap_ids)),evidence_ids=sorted(evidence),verification=verification)
    return {'state':state.model_dump(mode='json',exclude_none=True),'links':{key:sorted(value) for key,value in links.items()},
            'regression_of':regression_of,'replacement_digest':f.replacement_digest}


def evaluate(facts:dict)->dict:
    """Public input boundary: malformed evidence fails explicitly, never as approval."""
    try:
        return _evaluate(facts)
    except (KeyError,TypeError,AttributeError,IndexError,OverflowError) as error:
        raise ValueError('invalid lifecycle evidence envelope') from error
