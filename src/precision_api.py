"""Current precision reports and source-free operational assessment endpoints."""
from copy import deepcopy
from datetime import datetime,timezone
import json
import hashlib
import re
from pathlib import Path
import uuid
from fastapi import APIRouter,HTTPException,Request
from fastapi.responses import HTMLResponse,JSONResponse
from . import operational_assessment as O,review_store

ROOT=Path(__file__).resolve().parents[1]
router=APIRouter(tags=['precision-workbench'])


def read_report(path):
    return json.loads(path.read_text(encoding='utf-8')) if path.is_file() else None


@router.get('/api/precision/metrics')
def metrics():
    return dict(population_basis=read_report(ROOT/'results/cve_population_12418_v1/coverage_report.json'),
        population_validation=read_report(ROOT/'results/cve_population_precision_v1/validation_report.json'),
        item4_source_simulation=read_report(ROOT/'results/item4_source_context_v1/precision_report.json'),
        item4_source_progress=read_report(ROOT/'results/item4_source_context_v1/status.json'),
        item4_source_CVE_progress=read_report(ROOT/'results/item4_source_context_v1/cve_progress.json'),
        item4_source_training=read_report(ROOT/'models/item4_source_context_qwen25_14b_v1/status.json'),
        primary_metric_scope='Fixed real-CVE population of 12418; legacy benchmark scores are separate',
        item3_trained=read_report(ROOT/'results/item3_precision_v11/trained_evaluation/precision_report.json'),
        item3_rules=read_report(ROOT/'results/item3_precision_v11/rules_evaluation/precision_report.json'),
        item4_synthetic=read_report(ROOT/'results/item4_operational_v2/precision_report.json'),
        item4_trained=read_report(ROOT/'results/item4_operational_v2/trained_precision_report.json'),
        training=read_report(ROOT/'models/precision_roles_qwen25_14b_v1/status.json'),
        item3_progress=read_report(ROOT/'results/item3_precision_v11/trained_evaluation/status.json'),
        real_asset_precision=None,thresholds=dict(item3_strictly_greater_than=.8,item4_strictly_greater_than=.85))


@router.get('/api/precision/standards/attack')
def attack(asset:str='',technique:str=''):
    from .operational_standards import attack_context
    try:return attack_context([asset] if asset else [],[technique] if technique else [])
    except ValueError as exc:raise HTTPException(422,str(exc)) from exc


@router.get('/api/precision/item4/source-simulation/cves/{cve}')
def simulation_cases(cve:str):
    from .asset_vulntology import detail
    from .item4_source_simulation import DATA
    import sqlite3
    try:record=detail(cve)
    except (ValueError,KeyError) as exc:raise HTTPException(404,str(exc)) from exc
    index=next((r for r in map(json.loads,(DATA/'cve_index.jsonl').open(encoding='utf-8')) if r['cve']==cve),None)
    if index is None:raise HTTPException(404,'CVE not in the sealed simulation population')
    wanted=set(index['cases']);rows=[]
    for row in map(json.loads,(DATA/index['fold']/'inputs.jsonl').open(encoding='utf-8')):
        if row['id'] in wanted:rows.append(row)
        if len(rows)==len(wanted):break
    path=ROOT/'results/item4_source_context_v1/predictions.sqlite3'
    if path.is_file():
        with sqlite3.connect('file:'+path.as_posix()+'?mode=ro',uri=True) as db:
            for row in rows:
                found=db.execute('SELECT prediction FROM predictions WHERE id=?',(row['id'],)).fetchone()
                row['sealed_prediction']=json.loads(found[0]) if found else None
    return dict(cve=cve,index=index,cases=rows,source_record_digest=record['record_digest'],
        sources=record['sources'],products=record['products'],
        gold_included=False,is_production_VEX=False,export_allowed=False,
        meaning='Real source/product/path, explicit hypothetical world assumptions; not a real installation assessment')


@router.post('/api/precision/item4/source-simulation/assess')
async def simulation_assess(request:Request):
    from .item4_source_simulation import assess_live_simulation
    from starlette.concurrency import run_in_threadpool
    def run(packet):
        result=assess_live_simulation(packet)
        if result.get('raw',{}).get('llm_used'):
            from .precision_role_runtime import get_precision_runtime
            runtime=get_precision_runtime()
            with runtime.lock:
                result['identification_adapter_restored']=runtime.model.active_adapter=='default'
            if not result['identification_adapter_restored']:raise RuntimeError('Identification adapter restoration failed')
        return result
    try:
        payload=await body(request)
        return await run_in_threadpool(run,payload['packet'])
    except (ValueError,KeyError,TypeError) as exc:raise HTTPException(422,str(exc)) from exc
    except (RuntimeError,OSError) as exc:raise HTTPException(503,str(exc)) from exc


@router.post('/api/precision/standards/vulntology/validate')
async def native(request:Request):
    from .operational_standards import validate_native
    try:return validate_native(await body(request))
    except (ValueError,TypeError) as exc:raise HTTPException(422,str(exc)) from exc


async def body(request,limit=2*1024*1024):
    raw=await request.body()
    if len(raw)>limit:raise HTTPException(413,'Request too large')
    value=json.loads(raw)
    if not isinstance(value,dict):raise ValueError('JSON object required')
    return value


def evaluated_packet(payload,use_model=True):
    packet=deepcopy(payload['packet'])
    at=datetime.now(timezone.utc).isoformat()
    result=O.assess(packet,at)  # Server time; client cannot resurrect expired evidence.
    result['evaluated_at']=at
    result['binding']['evaluated_at']=at
    result['export_ready']=all(isinstance(packet.get('binding',{}).get(k),str) and packet['binding'][k].strip() for k in O.SCOPE)
    model=None
    if use_model and result['status']=='affected':
        from .precision_role_runtime import get_precision_runtime
        runtime=get_precision_runtime()
        model=runtime.operational_proposal(packet)
        marker=read_report(runtime.folder/'training_complete.json') or {}
        model['adapter_sha256']=marker.get('adapter_sha256')
        if model.get('status')!='affected' or not model.get('llm_used'):
            result.update(status='under_investigation')
            result['missing_evidence'].append('trained model proposal not confirmed')
    result['model_proposal']=model
    return packet,result


@router.post('/api/precision/item4/assessments')
async def assess(request:Request):
    try:
        payload=await body(request)
        from starlette.concurrency import run_in_threadpool
        packet,result=await run_in_threadpool(evaluated_packet,payload)
        sid=uuid.uuid4().hex;result['review_id']=sid
        review_store.put('operational-context-v1',sid,dict(packet=packet,result=result))
        return result
    except (ValueError,KeyError,TypeError) as exc:raise HTTPException(422,str(exc)) from exc
    except (RuntimeError,FileNotFoundError) as exc:raise HTTPException(503,str(exc)) from exc


@router.post('/api/precision/item4/oval-results')
async def oval(request:Request):
    try:
        payload=await body(request)
        return dict(observations=O.import_oval_results(payload['xml'],payload['definition_conditions'],payload['binding'],payload['evidence']))
    except (ValueError,KeyError,TypeError) as exc:raise HTTPException(422,str(exc)) from exc


@router.post('/api/precision/item4/cves/{cve}/source-extractions',status_code=202)
async def source_extract(cve:str,request:Request):
    from .operational_source_extraction import submit
    try:
        payload=await body(request)
        return submit(cve,payload['product_key'])
    except (ValueError,KeyError,TypeError) as exc:raise HTTPException(422,str(exc)) from exc
    except OverflowError as exc:raise HTTPException(429,str(exc)) from exc
    except (OSError,RuntimeError) as exc:raise HTTPException(503,str(exc)) from exc


@router.get('/api/precision/item4/source-extractions/{identity}')
def extraction_status(identity:str):
    result=review_store.get('operational-source-job',identity)
    if not result:raise HTTPException(404,'Extraction job not found')
    return result


@router.post('/api/precision/item4/mulval-input')
async def mulval(request:Request):
    try:
        p=await body(request)
        return dict(input_P=O.mulval_input(p['binding'],p.get('network',[]),p.get('services',[]),
            p.get('vulnerabilities',[]),p['attacker_host']),
            interpretation='Attack-graph input only. No derived path never establishes non-impact.')
    except (ValueError,KeyError,TypeError) as exc:raise HTTPException(422,str(exc)) from exc


@router.post('/api/precision/item4/mulval-runs')
async def mulval_run(request:Request):
    from .operational_tool_runner import run_mulval
    try:
        payload=await body(request)
        # Docker and XSB are external work, so keep the event loop available.
        from starlette.concurrency import run_in_threadpool
        return await run_in_threadpool(run_mulval,payload)
    except (ValueError,KeyError,TypeError) as exc:raise HTTPException(422,str(exc)) from exc
    except (OSError,RuntimeError) as exc:raise HTTPException(503,str(exc)) from exc


@router.get('/api/precision/item4/assessments/{sid}/export/{kind}')
def export(sid:str,kind:str):
    saved=review_store.get('operational-context-v1',sid)
    if not saved:raise HTTPException(404,'Assessment not found')
    at=datetime.now(timezone.utc).isoformat()
    packet=saved['packet'];current=O.assess(packet,at)
    current['evaluated_at']=at
    current['binding']['evaluated_at']=at
    proposal=saved['result'].get('model_proposal')
    if proposal:
        marker=read_report(ROOT/'models/precision_roles_qwen25_14b_v1/training_complete.json') or {}
        if proposal.get('adapter_sha256')!=marker.get('adapter_sha256'):
            raise HTTPException(409,'Model checkpoint changed; reassess before exporting')
    if current['status']=='affected' and (not proposal or proposal.get('status')!='affected' or not proposal.get('llm_used')):
        current['status']='under_investigation'
    if current['status']!=saved['result']['status']:
        raise HTTPException(409,'Evidence validity changed; reassess before exporting')
    if kind=='review':return JSONResponse(dict(packet=packet,decision=current,model_proposal=proposal))
    if kind=='vulntology':raise HTTPException(409,'Native export requires separate source-reviewed native fields and pinned-schema validation; operational extension alone is incomplete')
    if kind!='openvex':raise HTTPException(404,'Unknown export format')
    b=packet.get('binding',{});status=current['status']
    if any(not isinstance(b.get(k),str) or not b[k].strip() for k in O.SCOPE) or not re.fullmatch(r'CVE-\d{4}-\d{4,}',b.get('cve','')):
        raise HTTPException(409,'Complete asset/CVE/product/build/config/mode/attack-origin scope required for export')
    scope={k:b[k] for k in O.SCOPE if k!='cve'}
    scope_id=hashlib.sha256(json.dumps(scope,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
    notes=dict(scope=scope,evaluated_at=at,synthetic=packet.get('synthetic') is True,
        assessment_policy=current['policy'],adapter_sha256=proposal.get('adapter_sha256') if proposal else None)
    statement=dict(vulnerability=dict(name=b['cve']),products=[{'@id':'urn:ics-vex:asset-scope:sha256:'+scope_id}],
        status=status,timestamp=at,status_notes=json.dumps(notes,ensure_ascii=False,sort_keys=True))
    if status=='affected':statement['action_statement']=packet['action_statement']
    elif status=='not_affected':statement['impact_statement']='Reviewed exhaustive structural nonexecution evidence for the recorded asset scope.'
    document={'@context':'https://openvex.dev/ns/v0.2.0','@id':'urn:uuid:'+str(uuid.uuid4()),
        'author':str(packet.get('reviewer') or ('ICS-VEX fictional simulation service' if packet.get('synthetic') else 'ICS-VEX automated assessment service')),
        'role':'automated evidence assessment','timestamp':at,'version':1,'statements':[statement]}
    from jsonschema import Draft202012Validator,FormatChecker
    errors=list(Draft202012Validator(read_report(ROOT/'data/standards/openvex-schema.json'),format_checker=FormatChecker()).iter_errors(document))
    if errors:raise HTTPException(409,'OpenVEX validation failed: '+errors[0].message)
    return JSONResponse(document)


@router.get('/precision.html',response_class=HTMLResponse)
def workbench():return (ROOT/'src/precision_workbench.html').read_text(encoding='utf-8')
