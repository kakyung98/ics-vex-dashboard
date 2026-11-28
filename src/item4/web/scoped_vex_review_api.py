"""Public read-only catalogue; private scoped assessments and current exports."""
from copy import deepcopy
import json
import uuid
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from src.item4.decision import scoped_vex_review as A
from src.common.data import analysis_job_store as review_store

router=APIRouter(prefix='/api/asset-vulntology',tags=['asset-vulntology'])


@router.get('/catalogue')
def catalogue():return A.catalogue()


@router.get('/advisory-groups')
def advisory_groups():return A.advisory_groups()


@router.get('/asset-navigation')
def asset_navigation():return A.asset_navigation()


@router.get('/cves')
def search(asset:str='',q:str='',offset:int=0,limit:int=40):
    try:return A.search(asset,q,offset,limit)
    except ValueError as exc:raise HTTPException(422,str(exc)) from exc


@router.get('/cves/{cve}')
def detail(cve:str):
    try:return A.detail(cve)
    except KeyError as exc:raise HTTPException(404,str(exc)) from exc
    except ValueError as exc:raise HTTPException(422,str(exc)) from exc


@router.post('/source-drafts')
async def extract_source(request:Request):
    raw=await request.body()
    if len(raw)>200000:raise HTTPException(413,'Source passage is too large')
    try:
        import hashlib,re
        payload=json.loads(raw);record=A.detail(payload['cve'])
        if payload.get('prior_draft'):
            prior=review_store.get('asset-vulntology-source',payload['prior_draft'])
            if not prior or prior['cve']!=record['cve']:raise ValueError('Prior source draft missing or belongs to another CVE')
            record=prior
        key=payload['product_key']
        if key not in {p['key'] for p in record['products']}:raise ValueError('Unknown source product')
        text=payload['text'];origin=payload['source']
        if not isinstance(text,str) or not text.strip() or len(text)>100000 or not isinstance(origin,str) or not origin.strip() or len(origin)>2000:
            raise ValueError('Provide a bounded source passage and its URL/document identifier')
        if set(re.findall(r'CVE-\d{4}-\d{4,}',text))-{record['cve']}:
            raise ValueError('Select a CVE-specific passage; other CVE subjects require separate source review')
        selected=next(p for p in record['products'] if p['key']==key)
        if selected.get('binding')=='unresolved':
            name=payload.get('product_name','')
            if not isinstance(name,str) or not 2<=len(name.strip())<=500 or name.strip().casefold() not in text.casefold():
                raise ValueError('For an unresolved product, supply its exact name as stated in the added source passage')
            name=name.strip();key='vendor-product:'+A.digest([record['cve'],origin,name])[:24]
            if key not in {p['key'] for p in record['products']}:
                record['products'].append(dict(key=key,name=name,asset_ids=[],binding='user_source_product_pending_review',
                    advisory_id=None,source_product_id=None))
        sid='vendor:'+A.digest([origin,text,key])[:24]
        if any(s['id']==sid for s in record['sources']):raise ValueError('This source passage is already present')
        record['sources'].append(dict(id=sid,text=text,text_sha256=hashlib.sha256(text.encode()).hexdigest(),
            url=origin,product_keys=[key],scope_binding='user_supplied_CVE_product_source_pending_review',subject_ambiguous=False))
        record['scenarios']=A.extract({**record,'sources':[s for s in record['sources'] if not s.get('subject_ambiguous')]})
        record['extraction_status']='drafts_pending_review' if record['scenarios'] else 'no_supported_path'
        record['record_digest']=A.digest({k:v for k,v in record.items() if k!='record_digest'})
        draft_id=uuid.uuid4().hex;review_store.put('asset-vulntology-source',draft_id,record)
        return dict(source_draft_id=draft_id,record=record,selected_product_key=key)
    except (ValueError,TypeError,KeyError) as exc:raise HTTPException(422,str(exc)) from exc


def documents(result,reviewer):
    from src.item4.decision.grouped_question_evaluation import export_openvex
    from src.item4.decision.csaf_vex_export import export_csaf
    evaluation={'decisions':[result['decision']]}
    return dict(openvex=export_openvex(evaluation,reviewer,result['evaluated_at']),
                csaf=export_csaf(evaluation,reviewer,result['evaluated_at']))


@router.post('/assessments')
async def assess(request:Request):
    raw=await request.body()
    if len(raw)>2*1024*1024:raise HTTPException(413,'Assessment exceeds 2 MiB')
    try:
        payload=json.loads(raw);record=A.detail(payload['cve']);base_digest=A.digest(record);stamp=A.now()
        if payload.get('source_draft_id'):
            drafted=review_store.get('asset-vulntology-source',payload['source_draft_id'])
            if not drafted or drafted['cve']!=record['cve']:raise ValueError('Source draft expired or belongs to another CVE')
            record=drafted
        result=A.evaluate(record,payload,stamp)
        identification=None
        if payload.get('identification_job'):
            from src.item3.web.identification_jobs_api import get_job
            job=get_job(payload['identification_job'])
            if not job or job['status']!='completed':raise ValueError('Identification job missing or not completed')
            relevant=[r for r in job['result']['components'] if any(v['cve_id']==record['cve'] and v.get('match_status')!='no_match' for v in r.get('cves',[]))]
            if job['result'].get('asset_analysis'):
                r=job['result']['asset_analysis']
                if any(v['cve_id']==record['cve'] and v.get('match_status')!='no_match' for v in r.get('cves',[])):relevant.append(r)
            if not relevant:raise ValueError('CVE is outside the identification job')
            if payload['scope']['asset_ref'] not in {r['component']['id'] for r in relevant}:
                raise ValueError('Select an exact component reference from the identification job')
            identification=dict(job_id=payload['identification_job'],sbom=job.get('input_sbom'),
                                component_mappings=[deepcopy(r['component']) for r in relevant])
        result['exports']=documents(result,payload['reviewer'])
        sid=uuid.uuid4().hex;result['review_id']=sid
        result['identification']=identification
        review_store.put('asset-vulntology',sid,dict(payload=payload,reviewed_at=stamp,
            base_digest=base_digest,record_snapshot=record,identification=identification))
        return result
    except (ValueError,TypeError,KeyError) as exc:raise HTTPException(422,str(exc)) from exc


def current(sid):
    saved=review_store.get('asset-vulntology',sid)
    if not saved:raise HTTPException(404,'Review not found or expired')
    record=A.detail(saved['payload']['cve'])
    if A.digest(record)!=saved['base_digest']:raise HTTPException(409,'Source snapshot changed; review the current scenarios')
    try:result=A.evaluate(saved['record_snapshot'],saved['payload'],saved['reviewed_at'])
    except ValueError as exc:raise HTTPException(409,'Reassessment required: '+str(exc)) from exc
    result.update(review_id=sid,identification=saved['identification'])
    result['exports']=documents(result,saved['payload']['reviewer'])
    return result


@router.get('/assessments/{sid}')
def reopen(sid:str):return current(sid)


@router.get('/assessments/{sid}/export/{kind}')
def export(sid:str,kind:str):
    result=current(sid)
    if kind=='review':return JSONResponse(result)
    if kind in {'openvex','csaf'}:return JSONResponse(result['exports'][kind])
    if kind=='vulntology':
        if not result['native_export_ready']:
            raise HTTPException(409,'Native Vulntology has missing mandatory source-supported fields; export the draft review envelope instead')
        return JSONResponse([s['document'] for s in result['native_scenarios']])
    raise HTTPException(404,'Unknown export format')
