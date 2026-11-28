"""Source analysis, CVSS common / CVE-specific inputs and scoped VEX exports."""
import sqlite3
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from src.item4.workflow import source_analysis_jobs as Q

router=APIRouter(prefix='/api/item4/analyses')
legacy_router=APIRouter(prefix='/api/item4/questionnaires')


@router.get('/automation-policy')
def automation_policy():
    from src.item4.analysis import condition_automation as AUTO
    from src.item4.analysis import condition_question_contract as CONTRACT
    from src.item4.analysis import asset_operating_question_generation as V3
    from src.item4.analysis import prerequisite_taxonomy as TAXONOMY
    from src.item4.assets.source_question_policy import POLICY
    return dict(version=AUTO.VERSION,extraction_version=Q.vep.VERSION,question_version=V3.VERSION,
        taxonomy_version=TAXONOMY.VERSION,operator_policy=Q.vep.OP.POLICY,
        scope='Each identified CVE in any supported CycloneDX or SPDX 2.x BOM',
        max_attempts_per_stage=AUTO.MAX_ATTEMPTS,max_network_attempts_per_reference=3,
        repair_scopes=['evidence_only','logic_only','condition','question_presentation'],
        question_contracts=CONTRACT.definitions(),confidence_policy=POLICY,
        condition_types=TAXONOMY.condition_types(),
        extraction_dimensions=TAXONOMY.DIMENSIONS,
        ics_extension=dict(version=TAXONOMY.IC.VERSION,kinds=TAXONOMY.IC.KINDS,
                           annotation_field='ics_context',shared_atoms=True),
        low_confidence_retry=False,failed_or_missing='unknown',
        source_review='Every source record, including empty extractions without keyword cues',
        question_retry_unit='condition_id; successful questions are retained')


def handle(fn):
    try:
        return fn()
    except Q.QueueFullError as exc:
        raise HTTPException(429, str(exc), headers={'Retry-After': '2'}) from exc
    except Q.StaleInputError as exc:
        raise HTTPException(409,str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(404,str(exc)) from exc
    except (ValueError,TypeError,IndexError) as exc:
        raise HTTPException(422,str(exc)) from exc
    except (OSError,sqlite3.OperationalError) as exc:
        import logging
        logging.getLogger(__name__).exception('Operational VEX dependency or storage unavailable')
        raise HTTPException(503,'An analysis dependency or its durable storage is unavailable. Retry after restoring the service.',
                            headers={'Retry-After':'5'}) from exc


async def body(request):
    limit=4*1024*1024
    raw=bytearray()
    async for chunk in request.stream():
        if len(raw)+len(chunk)>limit:
            raise HTTPException(413,'The request must not exceed 4 MiB.')
        raw.extend(chunk)
    import json
    def pairs(items):
        value={}
        for key,item in items:
            if key in value:raise ValueError('Duplicate JSON key: '+key)
            value[key]=item
        return value
    def constant(value):
        raise ValueError('Non-finite JSON number: '+value)
    try:
        value=json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)
    except (ValueError,RecursionError) as exc:
        raise HTTPException(422,'Valid JSON is required.') from exc
    if not isinstance(value,dict):
        raise HTTPException(422,'A JSON object is required.')
    return value


@router.post('/start')
async def start(request:Request):
    value=await body(request)
    if set(value)-{'bom','representative_ref','request_id'} or 'bom' not in value:
        raise HTTPException(422,'Only bom, representative_ref and request_id are accepted.')
    return await run_in_threadpool(handle,lambda:Q.start(value['bom'],value.get('representative_ref'),value.get('request_id')))


@router.get('/jobs/{jid}')
def job(jid:str):
    return handle(lambda:Q.get(jid))


@router.get('/jobs/{jid}/cluster-diagnostics')
def cluster_diagnostics(jid:str):
    from src.item4.assets.cluster_diagnostics import for_job
    return handle(lambda:for_job(Q.get(jid)))


@router.post('/jobs/{jid}/retry')
async def retry(jid:str,request:Request):
    value=await body(request)
    return await run_in_threadpool(handle,lambda:Q.retry(jid,value))


@router.get('/jobs/{jid}/export/{kind}')
def export(jid:str,kind:str):
    if kind not in {'analysis','review','openvex','cyclonedx'}:
        raise HTTPException(422,'Supported formats: analysis, review, openvex, cyclonedx.')
    value=handle(lambda:Q.export(jid,kind))
    return JSONResponse(value,
                        headers={'Content-Disposition':'attachment; filename="item4-'+kind+'.json"'})


@router.get('/jobs/{jid}/assessment')
def assessment_state(jid:str):
    value=handle(lambda:Q.get(jid))
    return dict(agent=4,state=value['assessment_state'],assessment=value.get('assessment'),
                error=value.get('assessment_error'),
                engine_retained=True,operating_questionnaire_enabled=True)


@router.get('/asset-keys')
def asset_keys():
    from src.item4.assets.asset_observations import catalogue
    return handle(catalogue)


@router.get('/condition-taxonomy')
def condition_taxonomy():
    from src.item4.analysis.prerequisite_taxonomy import VERSION,CATEGORIES,PRIMARY,DIMENSIONS,IC,LEGACY_CATEGORIES,REFERENCE
    return dict(version=VERSION,categories=CATEGORIES,
                applicability_gate='C0',operating_conditions=list(DIMENSIONS),
                extraction_dimensions=DIMENSIONS,cvss_concepts=PRIMARY,
                ics_extension=dict(version=IC.VERSION,kinds=IC.KINDS,annotation_field='ics_context',
                                   shared_atoms=True,cvss_metric=False),
                retained_categories=['OTHER','AC'],legacy_categories=LEGACY_CATEGORIES,
                reference=REFERENCE,missing_source='unknown',cvss_scoring=False,
                classification_is_evidence=False)


@router.get('/common-question-schema')
def common_question_schema():
    raise HTTPException(410,'CVSS common questions have been removed. Use /question-policy for source-only question admission.')


@router.get('/question-policy')
def question_policy():
    from src.item4.assets.source_question_policy import POLICY
    return POLICY


@router.post('/jobs/{jid}/answers')
async def answers(jid:str,request:Request):
    value=await body(request)
    return await run_in_threadpool(handle,lambda:Q.save_answers(jid,value))


@router.post('/jobs/{jid}/assess')
async def assess(jid:str,request:Request):
    value=await body(request)
    return await run_in_threadpool(handle,lambda:Q.assess(jid,value))


@legacy_router.api_route('/{path:path}',methods=['GET','POST','PUT','PATCH','DELETE'])
def retired_questionnaire(path:str):
    raise HTTPException(410,'The operating questionnaire and answer-based workflow have been removed. Use /api/item4/analyses for source analysis.')
