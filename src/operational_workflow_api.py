"""English operational workflow; reuse the existing scoped evidence/export engine."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import uuid
from fastapi import APIRouter, HTTPException
from . import review_store
from .operational_workflow import DOMAINS, PREDICATES, NIST_URL, build_workflow, question
from .source_logic_inference import infer_record
from .context_vex_pipeline import leaves
from .prerequisite_models import model_status, extract_conditions

router=APIRouter(prefix='/api/operational-workflow',tags=['operational-workflow'])


@router.post('/restore-source')
def restore_source(payload:dict):
    try:
        record=payload['record']
        if not isinstance(record.get('cve'),str) or not record['cve'].strip() or not record.get('sources'):
            raise ValueError('Source record requires a CVE and source passages')
        if len(record['sources'])>100 or sum(len(s['text']) for s in record['sources'])>1000000:
            raise ValueError('Source bundle is too large')
        ids=[s['id'] for s in record['sources']]
        if len(set(ids))!=len(ids):raise ValueError('Duplicate source IDs')
        infer_record(record)  # Verify the original source hashes before restoring.
        sid=uuid.uuid4().hex
        review_store.put('operational-source',sid,record)
        return dict(source_id=sid)
    except (ValueError,KeyError,TypeError) as exc:
        raise HTTPException(422,str(exc)) from exc


@router.get('/schema')
def schema():
    return dict(domains=DOMAINS,predicates=[dict(id=k,domain=v[0],template=v[1]) for k,v in PREDICATES.items()],
                nist_url=NIST_URL,nist_version='SP 800-82 Rev. 3',
                extraction='Existing source-clause inference proposes candidates; explicit analyst review is required.',
                models=model_status(),
                clustering='Attack-path spherical k-means with structured or locally cached semantic embeddings.')


@router.post('/source')
def source(payload:dict):
    try:
        cve=str(payload['cve']).strip().upper()
        if not cve or len(cve)>80:raise ValueError('CVE identifier required')
        text=str(payload.get('text','')).strip()
        if text:
            if len(text)>100000:raise ValueError('Source text exceeds 100,000 characters')
            origin=str(payload.get('source','')).strip()
            if not origin:raise ValueError('Provide the advisory URL or document identifier')
            record=dict(cve=cve,sources=[dict(id='advisory',text=text,url=origin,text_sha256=hashlib.sha256(text.encode()).hexdigest())])
        else:
            from .question_mining_api import data
            record=deepcopy(data()['records'].get(cve))
            if not record:raise ValueError('CVE not available locally. Paste its advisory text and source URL.')
        inferred=infer_record(record)
        mode=payload.get('extraction_mode','source_clauses')
        if mode not in {'source_clauses','llm'}:raise ValueError('Unknown extraction mode')
        draft=extract_conditions(record) if mode=='llm' else None
        sid=uuid.uuid4().hex
        review_store.put('operational-source',sid,record)
        return dict(source_id=sid,record=record,inference=inferred,structured_draft=draft,
                    extraction_mode=mode)
    except (ValueError,KeyError,TypeError,FileNotFoundError) as exc:
        raise HTTPException(422,str(exc)) from exc


@router.post('/compile')
def compile_workflow(payload:dict):
    try:
        reviewer=str(payload.get('reviewer','')).strip()
        if not reviewer or payload.get('review_confirmed') is not True:
            raise ValueError('Identify the reviewer and confirm source, conditions and formula review')
        rows=payload['reviews']
        if not isinstance(rows,list) or not 1<=len(rows)<=500:raise ValueError('Provide 1 to 500 reviews')
        stamp=datetime.now(timezone.utc).isoformat()
        approval=dict(validation_status='approved',reviewer=reviewer,reviewed_at=stamp)
        records=[];reviews=[]
        for row in rows:
            record=review_store.get('operational-source',row['source_id'])
            if not record:raise ValueError('Source snapshot expired; load the source again')
            conditions=[];questions=[]
            if not row.get('conditions'):raise ValueError('Add source-linked conditions before compiling')
            for item in row['conditions']:
                if item.get('role','necessary_condition')!='necessary_condition':
                    raise ValueError('Nonrequirements and unknown mentions must remain outside the executable prerequisite formula')
                predicate=item['predicate'];target=str(item['target']).strip()
                if predicate not in PREDICATES or not target or target.casefold() in {'unknown','unresolved'}:
                    raise ValueError('Choose a known predicate and a specific target')
                c=dict(id=item['id'],predicate=predicate,target=target,value=str(item.get('value','')).strip(),
                    role='necessary_condition',
                    explicitness=item.get('explicitness','explicit'),
                    operator_observable=item.get('operator_observable',True) is True and not predicate.startswith('attacker_'),necessity='required_for_path',
                    source_refs=deepcopy(item['source_refs']),**approval)
                if predicate in {'configuration_required','privilege_required','attacker_has_required_privilege','user_performs_action','custom'} and not c['value']:
                    raise ValueError('This predicate requires an explicit value or action')
                q=question(c);text=str(item.get('question') or q['text']).strip()
                if item.get('yes_means','true') not in {'true','false'}:raise ValueError('Invalid answer polarity')
                reverse=item.get('yes_means')=='false'
                # Include the value in the executable predicate so admin/user cannot share facts.
                c['predicate']=predicate+':'+c['value'] if c['value'] else predicate
                conditions.append(c)
                questions.append(dict(id=record['cve']+':'+c['id']+':question',text=text,target=target,cost=1,domain=q['domain'],**approval,
                    mappings=[dict(condition_id=c['id'],coverage='FULL',source_refs=c['source_refs'],**approval,
                        answers=dict(yes='false' if reverse else 'true',no='true' if reverse else 'false',unknown='unknown'))]))
            expression=row['formula']
            if leaves(expression)!={c['id'] for c in conditions}:
                raise ValueError('The formula must reference exactly the selected conditions')
            reviews.append(dict(cve=record['cve'],conditions=conditions,questions=questions,
                source_information=deepcopy(row.get('source_information',{})),
                formula=dict(expression=expression,coverage_complete=row.get('coverage_complete') is True,
                    source_refs=[ref for c in conditions for ref in c['source_refs']],**approval)))
            records.append(record)
        workflow=build_workflow(reviews,records,k=payload.get('k',0),threshold=payload.get('threshold',.8),min_support=payload.get('min_support',2),
            embedding_mode=payload.get('embedding_mode','structured'),similarity_threshold=payload.get('similarity_threshold',0.0))
        sid=uuid.uuid4().hex
        saved=dict(id=sid,records=records,reviewer=reviewer,created_at=stamp,**workflow,
            reviewer_identity_authenticated=False,adjudication_is_independent_gold=False)
        if payload.get('identification_job_id'):
            from .prerequisite_bom import identification_snapshot
            saved['identification']=identification_snapshot(payload['identification_job_id'],[r['cve'] for r in reviews])
        review_store.put('pattern-workbench',sid,saved)
        return saved
    except (ValueError,KeyError,TypeError,IndexError) as exc:
        raise HTTPException(422,str(exc)) from exc
