"""BOM-declared CVEs and product-bound ICSA context -> source analysis.

V1/V2 collect source context, V3 records asset-key values and V4
evaluates source-scoped operating conditions and generates VEX documents.
"""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
import re
import threading
import uuid
from datetime import datetime, timezone

from src.item4.assets import asset_classification_inference as asset_model
from src.item4.decision import scoped_vex_review as descriptions
from src.item4.decision import population_condition_rules as population
from src.item4.assets import asset_observations
from src.common.data import analysis_job_store as store
from src.item4.analysis import exploitation_prerequisites as vep
from src.item4.analysis import product_advisory_evidence as advisory_context
from src.item4.analysis import cve_reference_sources as references
from src.item4.analysis import prerequisite_automation,operational_evidence_catalogue,condition_automation
from src.item4.web.saved_review_translations import english_message

VERSION = asset_observations.VERSION
PRESENTATION_VERSION = 'item4-english-ui/1'
RETRIEVAL_VERSION = 'item4-component-context/4-selected-product'
WORKFLOW_VERSION = 'item4-condition-workflow/3-selected-product'
CVERE = re.compile(r'CVE-\d{4}-\d{4,}', re.I)
# Only jobs currently admitted to this service process occupy RAM. Finished
# jobs and operator inputs use the same expiring, durable SQLite snapshots.
MAX_ACTIVE_JOBS = 3
JOBS = {}
ASSESSING = set()
LOCK = threading.RLock()
QUEUE = ThreadPoolExecutor(max_workers=2, thread_name_prefix='item4-questionnaire')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def inventory(bom):
    """Keep BOM pointers, all declared CVEs and their component associations."""
    if not isinstance(bom, dict):
        raise ValueError('A BOM JSON object is required.')
    components = []

    def component(item, pointer, spdx=False):
        if not isinstance(item,dict) or not isinstance(item.get('name'),str) or not item['name'].strip():
            raise ValueError('Each component requires a nonempty name.')
        ref=item.get('SPDXID') if spdx else item.get('bom-ref',pointer)
        if not isinstance(ref,str) or not ref.strip():
            raise ValueError('Component references must be nonempty strings.')
        for key in ('version','versionInfo'):
            if item.get(key) is not None and not isinstance(item[key],str):
                raise ValueError('Component versions must be strings.')
        if len(components)>=10000:
            raise ValueError('A maximum of 10,000 components can be processed at once.')
        components.append(dict(ref=ref,name=item['name'],pointer=pointer,value=item))

    def walk(items, path, depth=0):
        if not isinstance(items, list):
            raise ValueError('components must be an array.')
        if depth>32:raise ValueError('Component nesting must not exceed 32 levels.')
        for i, item in enumerate(items):
            pointer = path+'/'+str(i)
            component(item,pointer)
            walk(item.get('components', []), pointer+'/components',depth+1)

    if bom.get('bomFormat') == 'CycloneDX':
        if not isinstance(bom.get('metadata',{}),dict):
            raise ValueError('metadata must be a JSON object.')
        representative = (bom.get('metadata') or {}).get('component')
        if representative is not None:
            component(representative,'/metadata/component')
            walk(representative.get('components', []), '/metadata/component/components')
        walk(bom.get('components', []), '/components')
    elif str(bom.get('spdxVersion', '')).startswith('SPDX-2.'):
        packages=bom.get('packages',[])
        if not isinstance(packages,list):raise ValueError('packages must be an array.')
        describes=bom.get('documentDescribes',[])
        if not isinstance(describes,list) or any(not isinstance(ref,str) for ref in describes):
            raise ValueError('documentDescribes must be an array of component references.')
        for i, item in enumerate(packages):
            component(item,'/packages/'+str(i),spdx=True)
    else:
        raise ValueError('Choose a CycloneDX or SPDX 2.x BOM JSON file.')
    if not components or len({c['ref'] for c in components}) != len(components):
        raise ValueError('Components are missing or component references are duplicated.')
    declared = {}

    def collect(rows, pointer, default_ref=None):
        if not isinstance(rows, list):
            raise ValueError('The CVE list must be an array.')
        for i, row in enumerate(rows):
            if isinstance(row,dict):
                affects=row.get('affects',[])
                if not isinstance(affects,list) or any(not isinstance(a,dict) or not isinstance(a.get('ref'),str) or not a['ref'].strip() for a in affects):
                    raise ValueError('Vulnerability affects must be an array of component references.')
            value = row if isinstance(row, str) else row.get('id') or row.get('cve') or row.get('cve_id') if isinstance(row, dict) else None
            if not isinstance(value, str) or not CVERE.fullmatch(value):
                # Non-CVE identifiers can coexist in a CycloneDX vulnerability list.
                continue
            cve = value.upper()
            entry = declared.setdefault(cve, dict(cve=cve, pointers=[], component_refs=[],declaration_bindings=[]))
            entry['pointers'].append(pointer+'/'+str(i))
            refs = [a.get('ref') for a in row.get('affects', []) if isinstance(a, dict)] if isinstance(row, dict) else []
            if default_ref:
                refs.append(default_ref)
            entry['declaration_bindings'].append(dict(pointer=pointer+'/'+str(i),component_refs=sorted(set(refs))))
            entry['component_refs'] = sorted(set(entry['component_refs']) | {r for r in refs if isinstance(r, str)})

    collect(bom.get('vulnerabilities', []), '/vulnerabilities')
    collect(bom.get('cves', []), '/cves')
    for c in components:
        collect(c['value'].get('vulnerabilities', []), c['pointer']+'/vulnerabilities', c['ref'])
        collect(c['value'].get('cves', []), c['pointer']+'/cves', c['ref'])
    if len(declared)>2000:
        raise ValueError('A maximum of 2,000 CVEs can be processed at once. Split the BOM.')
    by_ref={c['ref']:c for c in components}
    for entry in declared.values():
        entry['components']=[dict(ref=ref,name=by_ref[ref]['name'],
            version=by_ref[ref]['value'].get('version') or by_ref[ref]['value'].get('versionInfo'),
            cpes=advisory_context.cpes(by_ref[ref]['value']))
            for ref in entry['component_refs'] if ref in by_ref]
        entry['unresolved_refs']=[ref for ref in entry['component_refs'] if ref not in by_ref]
    return components, sorted(declared.values(), key=lambda d:d['cve'])


def is_collection(component):
    return (str(component['ref']).startswith('collection:')
            or component['value'].get('type')=='data')


def selected_inventory(bom, selected_ref):
    """Preserve the original BOM; scope analysis to explicit product/CVE links."""
    components,declared=inventory(bom)
    selected=next((c for c in components if c['ref']==selected_ref),None)
    if selected is None or is_collection(selected):
        raise ValueError('Select an actual product and version range from the BOM.')
    scoped=[]
    for original in declared:
        if selected_ref not in original['component_refs']:continue
        row=deepcopy(original)
        row['component_refs']=[selected_ref]
        row['components']=[c for c in row['components'] if c['ref']==selected_ref]
        row['unresolved_refs']=[]
        row['declaration_bindings']=[dict(b,component_refs=[selected_ref])
            for b in row['declaration_bindings'] if selected_ref in b['component_refs']]
        row['pointers']=[b['pointer'] for b in row['declaration_bindings']]
        scoped.append(row)
    scope=dict(version='item4-selected-product-scope/1',mode='selected_product',
        selected_ref=selected_ref,product_name=selected['name'],
        version_range=selected['value'].get('version') or selected['value'].get('versionInfo') or 'unknown',
        component_refs=[selected_ref],cve_ids=[d['cve'] for d in scoped],
        excluded_cve_ids=[d['cve'] for d in declared if d['cve'] not in {r['cve'] for r in scoped}],
        unassigned_cve_ids=[d['cve'] for d in declared if not d['component_refs']],
        binding='Explicit BOM component references only; advisory ranges are not installed-version observations.')
    return [selected],scoped,scope


def scope_job(job,selected):
    components,declared,scope=selected_inventory(job['input_bom'],selected['ref'])
    if not declared:
        raise ValueError('No CVEs are explicitly linked to the selected product. Review its SBOM-to-CVE mappings; unassigned CVEs are not assumed to apply.')
    job.update(components=[dict(advisory_context.component_identity(c),type=c['value'].get('type')) for c in components],
        representative=dict(ref=selected['ref'],name=selected['name'],pointer=selected['pointer'],version=scope['version_range']),
        declared_cves=declared,cves_total=len(declared),analysis_scope=scope)
    job['conditions']=[r for r in job.get('conditions',[]) if r['cve'] in scope['cve_ids']]
    job['cves_done']=len(job['conditions'])
    return components,declared


def representative_candidates(bom, components):
    if bom.get('bomFormat')=='CycloneDX':
        top=[c for c in components if c['pointer']=='/metadata/component' and not is_collection(c)]
        return top or [c for c in components if not is_collection(c) and
            (re.fullmatch(r'/components/\d+',c['pointer']) or
             re.fullmatch(r'/metadata/component/components/\d+',c['pointer']))]
    describes=bom.get('documentDescribes',[])
    return [c for c in components if not is_collection(c) and (not describes or c['ref'] in describes)]


def classify(bom, selected):
    if is_collection(selected):raise ValueError('Asset classification requires one selected product.')
    candidates=[selected]
    results=[dict(_classify_component(bom,c),component_ref=c['ref']) for c in candidates]
    if len(results)==1:
        result=results[0]
    else:
        types={r.get('asset_type_id') for r in results}
        if results and all(r['status']=='classified' for r in results) and len(types)==1:
            result=deepcopy(results[0])
            result['evidence']=[e for r in results for e in r.get('evidence',[])]
        else:
            result=dict(status='unresolved',asset_type_id=None,
                evidence=[e for r in results for e in r.get('evidence',[])],
                reason='Component asset types are unresolved or disagree; no single asset type is assumed.')
    result['component_classifications']=deepcopy(results)
    result['retrieval_version']=RETRIEVAL_VERSION
    result['classification_version']=asset_model.VERSION
    result.update(run_id=uuid.uuid4().hex,created_at=datetime.now(timezone.utc).isoformat(),
        input_sha256=digest(dict(bom=bom,selected_ref=selected['ref'])),
        model=dict(version=asset_model.VERSION),validation='provisional_asset_type_not_operating_truth')
    result['sha256']=digest(result)
    return result


def _classify_component(bom, selected):
    """Classify BOM text with the frozen TF-IDF/SVD/K-means model."""
    name=selected['name']
    description=selected['value'].get('description') or ''
    try:
        prediction=asset_model.predict(name, [], description=description)
    except (OSError,ValueError,ImportError) as error:
        prediction=dict(status='unresolved',asset_type_id=None,reason='Asset K-means model unavailable: '+str(error))
    aid=prediction.get('asset_type_id')
    valid={aid:dict(id=aid,name=rows[0]['asset_name'])
           for aid,rows in asset_observations.catalogue()['asset_types'].items()}
    classified=prediction.get('status')!='unresolved' and aid in valid
    return dict(status='classified' if classified else 'unresolved',
        asset_type_id=aid if classified else None,asset=valid.get(aid),prediction=prediction,
        representative=dict(name=name,pointer=selected['pointer']),evidence=[],
        feature_evidence=[dict(source='BOM component name',text=name),
                          dict(source='BOM component description',text=description)],
        reason=prediction.get('reason'),classification_version=asset_model.VERSION,
        provisional=True,supplies_operating_truth=False)


def description_packet(cve):
    """Use only the local CVE description, not advisory mitigation paragraphs."""
    try:
        detail = descriptions.detail(cve)
    except KeyError:
        detail = None
    if detail and detail.get('original_nvd_status')=='Rejected':
        return dict(cve=cve, status='unresolved', cve_record_state='REJECTED',reason='This CVE has been rejected.')
    record = population.get(cve)
    sources = [deepcopy(s) for s in (record or {}).get('sources', []) if s['id']=='nvd:'+cve]
    if not sources:
        if detail is None:
            return dict(cve=cve, status='unresolved', reason='No local CVE description is available.')
        text = detail.get('description')
        if not text:
            return dict(cve=cve, status='unresolved', reason='The local CVE description is unavailable.')
        sources = [dict(id='nvd:'+cve, text=text, text_sha256=hashlib.sha256(text.encode()).hexdigest(),
                        url='https://nvd.nist.gov/vuln/detail/'+cve, product_keys=[], scope_binding='unresolved')]
    # This branch extracts description conditions only. It must not bind the
    # source scenario to a deployed product merely because the BOM declares it.
    packet = dict(cve=cve, products=[], sources=sources)
    return packet


def extract_description(cve, *, asset_context=None):
    packet,collection=evidence_packet(cve)
    if packet.get('status')=='unresolved':return packet
    if asset_context is not None:packet['asset_type_context']=deepcopy(asset_context)
    try:artifact = vep.resolve(packet)
    except Exception as exc:
        return dict(cve=cve,status='unresolved',extraction_state='extraction_failed',
            source_kind='CVE description',sources=packet['sources'],evidence_packet=packet,
            source_collection=collection,evidence_scope='CVE description and CVE-scoped primary references',
            extraction_automation=dict(execution_history=deepcopy(getattr(exc,'execution_history',[])),
                failure=deepcopy(getattr(exc,'failure',None))),
            reason='CVE source extraction incomplete: '+type(exc).__name__+': '+str(exc)[:500])
    review_failed=(artifact.get('coverage_review') or {}).get('status')=='failed'
    result=dict(cve=cve, status='unresolved' if review_failed else 'extracted',
                extraction_state='coverage_review_failed' if review_failed else 'conditions_extracted' if artifact['draft']['prerequisites'] else 'no_operating_conditions',
                source_kind='CVE description', sources=packet['sources'],
                prerequisite=artifact,evidence_packet=packet,source_collection=collection,
                evidence_scope='CVE description and CVE-scoped primary references')
    if review_failed:result['reason']='Automated source-condition review exhausted: '+artifact['coverage_review']['error']
    return result


def evidence_packet(cve):
    """Every declared CVE follows the same local/CNA/advisory collection path.

    The historical source_kind string remains for wire compatibility. The
    evidence_packet and source_collection record the actual selected documents.
    Product/version applicability remains a separate supplier-evidence gate.
    """
    base=description_packet(cve)
    if base.get('cve_record_state')=='REJECTED':return base,dict(cve=cve,attempts=[],source_count=0)
    try:detail=descriptions.detail(cve)
    except KeyError:detail={}
    extra,collection=references.collect(cve,detail.get('advisory_ids',[]))
    if collection.get('cve_record_state')=='REJECTED':
        return dict(cve=cve,status='unresolved',cve_record_state='REJECTED',
            reason='The public CVE record is rejected.',source_collection=collection),collection
    sources=deepcopy(base.get('sources',[]));seen={s['text_sha256'] for s in sources}
    for source in extra:
        if source['text_sha256'] not in seen:sources.append(source);seen.add(source['text_sha256'])
    if not sources:
        return dict(cve=cve,status='unresolved',reason='No CVE-scoped source passage is available after primary-reference collection.',source_collection=collection),collection
    return dict(cve=cve,products=[],sources=sources),collection


def extract_declared(cve, components, *, asset_context=None):
    """Extract scoped CVE/reference conditions and separately retain product context."""
    _,context=advisory_context.packet(cve,components)
    try:
        result=extract_description(cve,asset_context=asset_context) if asset_context is not None else extract_description(cve)
    except Exception as exc:
        result=dict(cve=cve,status='unresolved',source_kind='CVE description',
                    reason='CVE description extraction incomplete: '+type(exc).__name__+': '+str(exc)[:250])
    result.update(source_kind='CVE description',source_policy='cve-description-special/1',
                  advisory_context=context,source_components=deepcopy(components),description_fallback=True)
    return result


def revalidate_previous(previous,components, *, asset_context=None):
    """Reuse pinned hypotheses only after fresh collection matches exactly.

    New/changed sources take the normal full extraction path. This migration
    never copies old questions, operating answers, or Boolean conclusions.
    """
    artifact=previous.get('prerequisite') or {}
    if not artifact or artifact.get('version')!=vep.VERSION:return None
    histories=artifact.get('execution_history',[])+artifact.get('prior_execution_history',[])
    if not any(h.get('llm_used') is True for h in histories):return None
    for role in ('exploitation-prerequisites',vep.COVERAGE.ROLE):
        entries=[h for h in histories if h.get('role')==role and h.get('llm_used') is True]
        if not entries:continue
        current=vep.L.identity(role)
        if any(any(h.get('model',{}).get(k)!=current.get(k) for k in ('provider','model','adapter')) for h in entries):return None
    packet,collection=evidence_packet(previous['cve'])
    if asset_context is not None:packet['asset_type_context']=deepcopy(asset_context)
    if packet.get('status')=='unresolved' or artifact.get('source_record_sha256')!=vep.digest(packet):return None
    extra=[]
    for candidate in previous.get('source_condition_candidates',[]):
        entries=candidate.get('execution_history',[])+candidate.get('prior_execution_history',[])
        if not any(h.get('llm_used') is True for h in entries):continue
        if any(any(h.get('model',{}).get(k)!=vep.L.identity(h['role']).get(k) for k in ('provider','model','adapter'))
               for h in entries if h.get('llm_used') is True):continue
        extra.append(candidate)
    try:updated=prerequisite_automation.revalidate(packet,artifact,extra_artifacts=extra)
    except prerequisite_automation.CheckpointRejected:return None
    _,context=advisory_context.packet(previous['cve'],components)
    result=deepcopy(previous)
    result.pop('source_condition_candidates',None)
    failed=(updated.get('coverage_review') or {}).get('status')=='failed'
    result.update(prerequisite=updated,evidence_packet=packet,sources=packet['sources'],source_collection=collection,
        advisory_context=context,source_components=deepcopy(components),status='unresolved' if failed else 'extracted',
        extraction_state='partial_conditions_revalidated' if failed else 'conditions_extracted')
    result.pop('reason',None)
    if failed:result['reason']='Source-supported atoms recovered; complete conditions or relations remain unresolved.'
    return result



def _save(job):
    store.put('item4_questionnaire', job['id'], job, 7*86400)

def _commit(job):
    """Under LOCK, publish a snapshot only after the durable write succeeds."""
    _save(job)
    if job['status'] in ('queued', 'running'):
        JOBS[job['id']] = job
    else:
        JOBS.pop(job['id'], None)


class QueueFullError(ValueError):
    """The client can retry the same request after another job finishes."""


def _enqueue(job, selected):
    """Admission for new and recovered jobs. Caller holds LOCK through submit."""
    if sum(j['status'] in ('queued', 'running') for j in JOBS.values()) >= MAX_ACTIVE_JOBS:
        raise QueueFullError('The BOM queue is full. Retry the same request after a job completes.')
    scope_job(job,selected)
    _prepare_analysis(job)
    _commit(job)
    try:
        QUEUE.submit(_run, job['id'], job['input_bom'], selected, job['declared_cves'])
    except RuntimeError:
        # A closing executor rejected submission. Leave the durable checkpoint
        # queued for recovery, but do not count a worker which never started.
        JOBS.pop(job['id'], None)
        raise
    return deepcopy(job)


def _prepare_analysis(job):
    from src.item4.workflow.analysis_job_state import prepare
    return prepare(job,digest)


def extraction_identity():
    from src.item4.assets.question_record_context import signature as record_context_signature
    try:model=vep.L.identity('exploitation-prerequisites')
    except Exception as exc:model=dict(unavailable=type(exc).__name__+': '+str(exc))
    return digest(dict(policy=vep.VERSION,operator_policy=vep.OP.POLICY,
                       workflow=WORKFLOW_VERSION,
                       asset_record_context=record_context_signature(),
                       condition_types=vep.TAXONOMY.condition_types(),
                       automation=[prerequisite_automation.VERSION,operational_evidence_catalogue.VERSION,condition_automation.VERSION],
                       reference_collection=references.VERSION,
                       coverage_review=vep.digest(dict(version=vep.COVERAGE.VERSION,prompt=vep.COVERAGE.SYSTEM)),
                       extraction_prompt=vep.digest(vep.SYSTEM),
                       retrieval=RETRIEVAL_VERSION,product_status=advisory_context.STATUS_POLICY,model=model))



def _update(jid, **changes):
    with LOCK:
        _commit(dict(JOBS[jid], **changes))


def _run(jid, bom, selected, declared):
    try:
        with LOCK:saved=deepcopy(JOBS[jid])
        recovery_rows={}
        for row in saved.get('source_recovery_checkpoints',[])+saved.get('conditions',[]):
            previous=recovery_rows.get(row['cve']);current=deepcopy(row)
            if previous:
                candidates=previous.get('source_condition_candidates',[])+([previous['prerequisite']] if previous.get('prerequisite') else [])+current.get('source_condition_candidates',[])
                current['source_condition_candidates']=list({a['sha256']:a for a in candidates if a.get('sha256')}.values())
            recovery_rows[row['cve']]=current
        saved_rows=list(recovery_rows.values())
        run_identity=extraction_identity()
        _update(jid, status='running',extraction_identity=run_identity,
                cves_done=0,questions_done=0,question_state='queued',source_recovery_checkpoints=saved_rows)
        components,declared=scope_job(saved,selected)
        _update(jid,components=saved['components'],representative=saved['representative'],declared_cves=declared,cves_total=len(declared),analysis_scope=saved['analysis_scope'])
        def asset_branch():
            previous=saved.get('asset_classification') or {}
            if saved.get('asset_state')=='completed' and previous.get('retrieval_version')==RETRIEVAL_VERSION and previous.get('classification_version')==asset_model.VERSION:
                return previous
            _update(jid, asset_state='running')
            try:
                result = classify(bom, selected)
            except Exception as exc:
                result = dict(status='unresolved', asset_type_id=None, evidence=[], reason=type(exc).__name__+': '+str(exc)[:250])
            result['classification_version']=asset_model.VERSION
            _update(jid, asset_classification=result, asset_state='completed')
            return result

        def condition_branch(classification):
            results = []
            checkpoint={r['cve']:r for r in saved_rows
                        if r.get('status') in ('extracted','unresolved') and r.get('source_kind')=='CVE description'
                        and r.get('source_policy')=='cve-description-special/1' and r.get('extraction_policy')==vep.VERSION
                        and r.get('extraction_identity')==run_identity}
            _update(jid, condition_state='running')
            for declared_cve in declared:
                cve = declared_cve['cve']
                linked = [c for c in components if c['ref'] in declared_cve['component_refs']]
                from src.item4.assets.question_record_context import extraction_context
                asset_context=extraction_context(dict(asset_classification=classification,
                    representative=dict(ref=selected['ref'])),linked)
                previous=checkpoint.get(cve)
                if (previous and previous.get('bom_declaration')==declared_cve
                    and previous.get('asset_type_context_sha256')==digest(asset_context)):
                    results.append(previous)
                    _update(jid,conditions=deepcopy(results),cves_done=len(results))
                    continue
                try:
                    prior=next((r for r in saved_rows if r['cve']==cve and r.get('bom_declaration')==declared_cve),None)
                    result = revalidate_previous(prior,linked,asset_context=asset_context) if prior else None
                    if result is None:result = extract_declared(cve, linked,asset_context=asset_context)
                except Exception as exc:
                    result = dict(cve=cve, status='unresolved', reason=type(exc).__name__+': '+str(exc)[:250],
                        extraction_automation=dict(execution_history=deepcopy(getattr(exc,'execution_history',[])),
                            failure=deepcopy(getattr(exc,'failure',None))))
                result['bom_declaration'] = declared_cve
                result['extraction_policy']=vep.VERSION
                result['extraction_identity']=run_identity
                result['asset_type_context_sha256']=digest(asset_context)
                results.append(result)
                _update(jid, conditions=deepcopy(results), cves_done=len(results))
            _update(jid, condition_state='completed',source_recovery_checkpoints=[])
            return results

        # IC extraction must receive the completed V1 context, including an
        # explicit unresolved result. Unknown asset types never block V2.
        classification=asset_branch()
        results=condition_branch(classification)
        from src.item4.analysis import asset_operating_question_generation as V3
        _update(jid,question_state='running')
        with LOCK:question_job=deepcopy(JOBS[jid])
        question_identity=V3.plan_identity(question_job)
        generated=V3.run_job(question_job,lambda artifacts,done,total:
            _update(jid,question_generations=artifacts,questions_done=done,questions_total=total))
        _update(jid,question_generations=generated,question_attempted_identity=question_identity,
            question_output_identity=V3.digest(generated),question_state=(
            'incomplete' if any(a['status'] in ('failed','partial') for a in generated.values()) else 'completed'))
        with LOCK:
            job = dict(JOBS[jid], status='completed', revision=JOBS[jid].get('revision',0)+1)
            job['plan_sha256'] = digest(dict(bom_sha256=job['bom_sha256'],
                asset_classification=classification, conditions=results))
            _prepare_analysis(job)
            _commit(job)
    except Exception as exc:
        with LOCK:
            try:
                _update(jid, status='failed', error=type(exc).__name__+': '+str(exc)[:300])
            finally:
                # A disk failure can also prevent recording the error. Release
                # the worker slot; recovery reads the last committed checkpoint.
                JOBS.pop(jid, None)


def start(bom, representative_ref=None, request_id=None):
    components, declared = inventory(bom)
    if not declared:
        raise ValueError('The BOM has no declared CVEs. This workflow analyzes CVEs already identified in the BOM.')
    eligible=representative_candidates(bom,components)
    # Accept an older collection-root selection only when its actual product is unambiguous.
    if representative_ref and any(c['ref']==representative_ref and is_collection(c) for c in components) and len(eligible)==1:
        representative_ref=eligible[0]['ref']
    chosen = next((c for c in eligible if c['ref']==representative_ref), None) if representative_ref else None
    if representative_ref and not chosen:
        raise ValueError('The selected top-level component is not in the BOM.')
    if chosen is None and len(eligible)==1:
        chosen = eligible[0]
    if chosen is None:
        raise ValueError('Select a top-level component from the list.')
    with LOCK:
        if request_id is not None:
            if not isinstance(request_id,str) or not re.fullmatch(r'[a-f0-9]{32}',request_id):
                raise ValueError('request_id must be a 32-character hexadecimal identifier.')
            existing=JOBS.get(request_id) or store.get('item4_questionnaire',request_id)
            if existing:
                if existing['bom_sha256']!=digest(bom) or existing['representative']['ref']!=chosen['ref']:
                    raise ValueError('This request_id belongs to another BOM or component selection.')
                return get(request_id)
        jid = request_id or uuid.uuid4().hex
        job = dict(id=jid, version=VERSION, status='queued', bom_sha256=digest(bom),
                   input_bom=deepcopy(bom),
                   components=[dict(advisory_context.component_identity(c),type=c['value'].get('type')) for c in components],
                   representative=dict(ref=chosen['ref'], name=chosen['name'], pointer=chosen['pointer']),
                   declared_cves=declared, cves_total=len(declared), cves_done=0,
                   asset_state='queued', condition_state='queued', conditions=[],
                   asset_classification=None, unresolved=[], revision=0,
                   product_vex_status='under_investigation',
                   policy='CVE-scoped primary-source operating conditions; no CVSS common-question gate.')
        return _enqueue(job, deepcopy(chosen))


class StaleInputError(ValueError):
    """The caller must reload the current plan/revision instead of overwriting it."""


def retry(jid,payload):
    """Explicitly retry source failures using the same BOM and successful CVEs."""
    if not isinstance(payload,dict) or set(payload)!={'revision','plan_sha256'}:
        raise ValueError('Supply revision and plan_sha256 to retry source analysis.')
    with LOCK:
        job=get(jid)
        if type(payload['revision']) is not int or payload['revision']!=job['revision'] or payload['plan_sha256']!=job['plan_sha256']:
            raise StaleInputError('The analysis changed. Reload before retrying.')
        if job['status'] in ('queued','running'):return job
        failed=[r for r in job['conditions'] if r.get('status')!='extracted']
        if job['status']=='completed' and not failed and not job.get('special_source_refresh_required') and not job.get('question_generation_required') and (job.get('asset_classification') or {}).get('status')=='classified':
            raise ValueError('There are no failed source or classification stages to retry.')
        bom=job.get('input_bom')
        if not bom or digest(bom)!=job['bom_sha256']:
            raise ValueError('Cannot retry: the original BOM snapshot is missing or changed.')
        components,_=inventory(bom)
        selected=next((c for c in components if c['ref']==job['representative']['ref']),None)
        if selected is None:raise ValueError('Cannot retry: the selected component is missing.')
        job.update(status='queued',conditions=[r for r in job['conditions'] if r.get('status')=='extracted'],
                   retry_count=job.get('retry_count',0)+1)
        job['cves_done']=len(job['conditions'])
        if (job.get('asset_classification') or {}).get('status')!='classified':job['asset_state']='queued'
        job.pop('error',None)
        return _enqueue(job,selected)


def _current(jid,payload,allowed):
    if not isinstance(payload,dict) or set(payload)-allowed:
        raise ValueError('Only registered answers, context choices, revision and plan_sha256 are accepted.')
    job=get(jid)
    if job['status']!='completed':raise ValueError('Wait for source analysis to complete.')
    if type(payload.get('revision')) is not int or payload['revision']!=job['revision'] or payload.get('plan_sha256')!=job['plan_sha256']:
        raise StaleInputError('The inputs or source plan changed. Reload the current analysis.')
    return job


def save_answers(jid,payload):
    from datetime import datetime,timezone
    with LOCK:
        job=_current(jid,payload,{'answers','context_answers','answer_records','asked_question_ids','revision','plan_sha256'})
        answers=payload.get('answers',{});context=payload.get('context_answers',{})
        if not isinstance(answers,dict) or not isinstance(context,dict):
            raise ValueError('Answers and context_answers must be objects.')
        questions={q['id']:q for q in job['asset_questions']}
        asked=payload.get('asked_question_ids',job.get('asked_question_ids',[]))
        if not isinstance(asked,list) or any(not isinstance(qid,str) or qid not in questions for qid in asked) or len(asked)!=len(set(asked)):
            raise ValueError('asked_question_ids must contain unique current question IDs.')
        records=payload.get('answer_records',{})
        if not isinstance(records,dict) or any(qid not in answers for qid in records):
            raise ValueError('answer_records must map submitted question IDs to operating record metadata.')
        for record in records.values():
            if not isinstance(record,dict) or set(record)-{'references','observed_at','recorded_by'}:
                raise ValueError('Operating records accept references, observed_at and recorded_by only.')
            refs=record.get('references',[])
            if not isinstance(refs,list) or len(refs)>20 or any(not isinstance(r,str) or not r.strip() or len(r)>2000 for r in refs):
                raise ValueError('Operating record references must be nonempty strings (at most 20).')
            if not isinstance(record.get('recorded_by',''),str) or len(record.get('recorded_by',''))>300:
                raise ValueError('Invalid operating record attribution.')
            at=record.get('observed_at')
            if at is not None:
                try:
                    if not isinstance(at,str) or datetime.fromisoformat(at.replace('Z','+00:00')).utcoffset() is None:raise ValueError()
                except (ValueError,TypeError):raise ValueError('observed_at requires an ISO timestamp with timezone.')
        if any(k not in questions or not isinstance(v,str) or v not in {o['code'] for o in questions[k]['options']} for k,v in answers.items()):
            raise ValueError('Only registered question IDs and their declared answer choices are accepted.')
        controls={q['id']:{o['code'] for o in q['options']} for q in job['context_questions']}
        if any(k not in controls or not isinstance(v,str) or v not in controls[k] for k,v in context.items()):
            raise ValueError('Only registered assessment context choices are accepted.')
        effective={**job['context_answers'],**context}
        for q in job['context_questions']:
            condition=q.get('visible_when')
            if condition and effective.get(condition['question_id'],'unknown')!=condition['value']:
                context[q['id']]='unknown'
        changed=asked!=job.get('asked_question_ids',[]) or any(job['answers'].get(k,'unknown')!=v for k,v in answers.items()) or any(job['context_answers'].get(k,'unknown')!=v for k,v in context.items()) or any(job.get('answer_provenance',{}).get(k,{}).get('operating_records',{})!=v for k,v in records.items())
        if changed:
            stamp=datetime.now(timezone.utc).isoformat()
            # A changed mode/origin/target/version cannot silently reuse saved
            # observations. Explicit answers in this request are re-attestations.
            if any(job['context_answers'].get(k,'unknown')!=v for k,v in context.items()):
                job['answers']={};job['answer_provenance']={}
                if 'asked_question_ids' not in payload:asked=[]
                for case in job['assessment_cases']:
                    prefix = case['prefix']
                    if any(k in context and job['context_answers'].get(k, 'unknown') != context[k]
                           for k in ('scope', prefix+'target', prefix+'deployment')):
                        job['context_answers'].pop(prefix+'inventory_coverage', None)
            job['answers'].update(answers);job['context_answers'].update(context)
            job['asked_question_ids']=list(asked)
            for qid,value in answers.items():
                q=questions[qid]
                job['answer_provenance'][qid]=dict(value=value,recorded_at=stamp,
                    condition_id=q['condition_id'],question_generation_sha256=q.get('question_generation_sha256'),
                    extraction_confidence=q.get('extraction_confidence'),question_confidence=q.get('question_confidence'),
                    operating_records=deepcopy(records.get(qid,job.get('answer_provenance',{}).get(qid,{}).get('operating_records',{}))),
                    component_ref=q['component_ref'],scope_id=q['scope_id'],key=q['key'],
                    basis='operator_attestation',independent_evidence_verified=False)
            from src.item4.assets.condition_coverage import coverage
            job['condition_coverage']=coverage(job,job['assessment_cases'],job['asset_questions'],job.get('extraction_confidence_rejections',[]),job.get('question_confidence_rejections',[]))
            job.update(revision=job['revision']+1,assessment=None,assessment_state='inputs_saved',product_vex_status='under_investigation')
            job['agents'][-1]['state']='inputs_saved'
            _commit(job)
        return deepcopy(job)


def assess(jid,payload):
    from src.item4.decision import asset_vex_assessment as evaluator
    with LOCK:
        job=_current(jid,payload,{'revision','plan_sha256'})
        if jid in ASSESSING or len(ASSESSING)>=2:
            raise QueueFullError('A VEX assessment is already running. Retry shortly.')
        job.update(assessment=None,assessment_state='running',product_vex_status='under_investigation')
        job.pop('assessment_error',None)
        job['agents'][-1]['state']='running'
        _commit(job)
        ASSESSING.add(jid)
    try:
        report=evaluator.evaluate(job)
        with LOCK:
            latest=get(jid)
            if latest['revision']!=job['revision'] or latest['plan_sha256']!=job['plan_sha256']:
                raise StaleInputError('Inputs changed during assessment. Assess the latest revision again.')
            latest.update(assessment=report,assessment_state='completed')
            statuses={r['status'] for r in report['decisions']}
            latest['product_vex_status']=next(iter(statuses)) if len(statuses)==1 else 'under_investigation'
            latest['agents'][-1]['state']='completed'
            _commit(latest)
            return deepcopy(latest)
    except Exception as exc:
        with LOCK:
            latest=JOBS.get(jid) or store.get('item4_questionnaire',jid)
            if latest and latest['revision']==job['revision'] and latest['plan_sha256']==job['plan_sha256']:
                latest.update(assessment=None,assessment_state='failed',
                              assessment_error=type(exc).__name__+': '+str(exc)[:300],
                              product_vex_status='under_investigation')
                latest['agents'][-1]['state']='failed'
                _commit(latest)
        raise
    finally:
        with LOCK:ASSESSING.discard(jid)


def export(jid,kind):
    from src.item4.decision import asset_vex_assessment as evaluator
    snapshot=get(jid)
    if kind=='analysis':return snapshot
    document=evaluator.export(snapshot,kind)
    with LOCK:
        latest=get(jid)
        if latest['revision']!=snapshot['revision'] or latest['plan_sha256']!=snapshot['plan_sha256']:
            raise StaleInputError('Inputs changed during export. Assess the latest revision again.')
    return document


def get(jid):
    with LOCK:
        in_memory=jid in JOBS
        job=JOBS.get(jid) or store.get('item4_questionnaire',jid)
        if not job:raise KeyError('The analysis job was not found.')
        identity=extraction_identity()
        interrupted=(not in_memory and (job['status'] in ('queued','running') or
            (job['status']=='failed' and str(job.get('error','')).startswith('The server restarted before completion.'))))
        outdated=(job['status'] in ('completed','failed') and job.get('extraction_identity')!=identity)
        if interrupted or outdated:
            bom=job.get('input_bom')
            if not bom or digest(bom)!=job['bom_sha256']:
                raise ValueError('Cannot resume: the original BOM snapshot is missing or changed.')
            components,declared=inventory(bom)
            selected=next((c for c in components if c['ref']==job['representative']['ref']),None)
            if selected is None:raise ValueError('Cannot resume: the selected component is missing.')
            eligible=representative_candidates(bom,components)
            if is_collection(selected) and len(eligible)==1:
                selected=eligible[0]
                job['representative']={k:selected[k] for k in ('ref','name','pointer')}
            job.update(status='queued',recovery_count=job.get('recovery_count',0)+1,
                recovery_notice='Source analysis resumed with the current extraction policy and adapter.' if outdated else 'Analysis resumed from saved CVE checkpoints after a server restart.')
            job.pop('error',None)
            return _enqueue(job, selected)
        else:
            classification_changed=False
            if job['status']=='completed' and (job.get('asset_classification') or {}).get('classification_version')!=asset_model.VERSION:
                components,_=inventory(job['input_bom'])
                selected=next(c for c in components if c['ref']==job['representative']['ref'])
                job['asset_classification']=classify(job['input_bom'],selected)
                job['asset_state']='completed'
                classification_changed=True
            if job['status']=='completed':
                from src.item4.assets.question_record_context import extraction_context
                declarations={d['cve']:d for d in job['declared_cves']}
                stale_context=any(r.get('asset_type_context_sha256') and
                    r['asset_type_context_sha256']!=digest(extraction_context(job,
                        [c for c in job['components'] if c['ref'] in declarations.get(r['cve'],{}).get('component_refs',[])]))
                    for r in job.get('conditions',[]))
                if stale_context:
                    components,_=inventory(job['input_bom'])
                    selected=next(c for c in components if c['ref']==job['representative']['ref'])
                    job.update(status='queued',condition_state='queued',
                        recovery_notice='Refreshing IC extraction for the current asset type and record context.')
                    return _enqueue(job,selected)
            if job.get('error'):job['error']=english_message(job['error'])
            changed=_prepare_analysis(job) or classification_changed
            if job['status']=='completed':
                from src.item4.analysis import asset_operating_question_generation as V3
                if V3.requires_generation(job):
                    components,_=inventory(job['input_bom'])
                    selected=next(c for c in components if c['ref']==job['representative']['ref'])
                    job.update(status='queued',recovery_notice='Generating missing operating questions from the validated source conditions.')
                    return _enqueue(job,selected)
            if job.get('assessment_state')=='running' and jid not in ASSESSING:
                job.update(assessment=None,assessment_state='failed',
                           assessment_error='The server restarted during assessment. Evaluate the saved inputs again.',
                           product_vex_status='under_investigation')
                job['agents'][-1]['state']='failed'
                changed=True
            if changed:_save(job)
        return deepcopy(job)






