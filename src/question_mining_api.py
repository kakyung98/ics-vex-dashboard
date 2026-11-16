"""Source-linked pattern browser and durable analyst-reviewed asset workflow."""
from copy import deepcopy
from datetime import datetime,timezone
from functools import lru_cache
import hashlib,json,sqlite3,re
from pathlib import Path
import uuid
from fastapi import APIRouter,HTTPException
from fastapi.responses import HTMLResponse,FileResponse
from . import review_store
from .cluster_question_pipeline import compile_plan,evaluate_plan,export_openvex
from .csaf_cluster_export import export_csaf
from .operational_evidence_judge import instant
from .source_logic_inference import infer_record,VERSION as LOGIC_VERSION
from .cluster_question_pipeline import digest
from .context_vex_pipeline import leaves

ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/'results/item4_pattern_method_v6'
router=APIRouter()


def read(path):return [json.loads(line) for line in path.open(encoding='utf-8') if line.strip()]


def candidate_memberships(cve,contract=None):
    # Support >=3 prioritizes the mining catalogue. Two explicitly reviewed
    # matching facts can still share an answer even when that atom is rarer.
    groups=['source-atom:'+aid for aid in data()['cves'][cve]['atom_ids']]
    if contract:
        groups+=['reviewed-source-fact:'+c['predicate'] for c in contract['conditions'] if c['id'].startswith('inferred:')]
    return dict(cve=cve,cluster_ids=sorted(set(groups)))


def publisher_labels(cve,limit=12):
    path=ROOT/'results/item4_reference_verification_v1/publisher_index.sqlite3'
    if not path.exists():return dict(count=0,examples=[],status='reference_not_built')
    with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as connection:
        count=connection.execute('SELECT count(*) FROM labels WHERE cve=?',(cve,)).fetchone()[0]
        rows=connection.execute('SELECT payload FROM labels WHERE cve=? ORDER BY status,id LIMIT ?',(cve,limit)).fetchall()
    return dict(count=count,examples=[json.loads(r[0]) for r in rows],scope='published_product_status; not actual asset impact')


@router.get('/api/question-mining/cves/{cve}/logic')
def inferred_logic(cve:str):
    record=data()['records'].get(cve.upper())
    if not record:raise HTTPException(404,'CVE outside fixed population')
    value=infer_record(record)
    value['passages'].sort(key=lambda p:(-int(any(h['derivation']=='explicit_necessity' for h in p['hypotheses'])),
        -max((len(leaves(h['expression'])) for h in p['hypotheses']),default=0)))
    return dict(**value,publisher_reference=publisher_labels(cve.upper()))


@router.get('/api/question-mining/reference/{kind}')
def reference_download(kind:str):
    paths={'publisher':ROOT/'data/item4_publisher_reference_v1/gold.jsonl',
           'logic':ROOT/'data/item4_source_logic_reference_v1/gold.jsonl'}
    if kind not in paths:raise HTTPException(404,'Unknown reference kind')
    return FileResponse(paths[kind],media_type='application/x-ndjson',filename='ics-vex-'+kind+'-reference.jsonl')


@lru_cache(maxsize=1)
def data():
    manifest=json.loads((DATA/'manifest.json').read_text(encoding='utf-8'))
    for name,expected in manifest['artifacts'].items():
        if hashlib.sha256((DATA/name).read_bytes()).hexdigest()!=expected:raise ValueError('Mining artifact hash mismatch')
    source_file=ROOT/'results/ics_sentence_conditions_v1/full_inputs.jsonl'
    if hashlib.sha256(source_file.read_bytes()).hexdigest()!=manifest['source_inputs_sha256']:
        raise ValueError('Original source snapshot hash differs from mining provenance')
    records=read(source_file)
    condition_file=ROOT/'results/ics_operational_recluster_15_40_v1/bge_index.jsonl'
    if hashlib.sha256(condition_file.read_bytes()).hexdigest()!=manifest['source_sha256']:
        raise ValueError('Original condition candidate snapshot hash differs from mining provenance')
    original_conditions={r['condition_id']:r for r in read(condition_file)}
    flagged={}
    for row in read(DATA/'triage.jsonl'):
        if row['flags']:
            flagged.setdefault(row['cve'],[]).append(dict(row,original=original_conditions.get(row['condition_id'])))
    return dict(summary=json.loads((DATA/'summary.json').read_text()),
        cves={r['cve']:r for r in read(DATA/'cves.jsonl')},
        atoms={r['id']:r for r in read(DATA/'atoms.jsonl')},patterns=read(DATA/'patterns.jsonl'),
        records={r['cve']:r for r in records},flagged=flagged)


@router.get('/question-mining.html',response_class=HTMLResponse)
def page():
    from .operational_workflow_page import render
    return render()


@router.get('/api/question-mining/methodology')
def methodology():
    return FileResponse(ROOT/'docs/ITEM4_PATTERN_MINING_METHOD.md',media_type='text/markdown; charset=utf-8',
                        filename='ICS-VEX-question-methodology.md')


@router.get('/api/question-mining/summary')
def summary():return data()['summary']


@router.get('/api/question-mining/patterns')
def patterns(limit:int=30,offset:int=0):
    d=data();ordered=sorted(d['patterns'],key=lambda p:(-p['support_count'],-len(p['atom_ids']),p['id']))
    rows=ordered[max(0,offset):max(0,offset)+min(max(limit,1),100)]
    return [dict(p,items=[d['atoms'][aid]['proposition'] for aid in p['atom_ids']],
        item_details=[{k:d['atoms'][aid][k] for k in ('proposition','kind','necessity')} for aid in p['atom_ids']]) for p in rows]


@router.get('/api/question-mining/cves')
def search(search:str='',limit:int=30):
    return [r for c,r in data()['cves'].items() if search.upper() in c][:min(max(limit,1),100)]


@router.get('/api/question-mining/cves/{cve}')
def cve_detail(cve:str):
    d=data();row=d['cves'].get(cve.upper())
    if not row:raise HTTPException(404,'CVE outside fixed population')
    atoms=[]
    for aid in row['atom_ids']:
        atom=deepcopy(d['atoms'][aid]);atom['sources']=[s for s in atom['sources'] if s['cve']==row['cve']]
        atom['common']=atom['distinct_cves']>=d['summary']['min_distinct_cves'];atoms.append(atom)
    return dict(**row,atoms=atoms,sources=d['records'][row['cve']]['sources'],flagged_candidates=d.get('flagged',{}).get(row['cve'],[]))


@router.get('/api/question-mining/evaluation')
def evaluation():
    file=ROOT/'results/item4_pattern_evaluation_v3/report.json'
    report=json.loads(file.read_text(encoding='utf-8')) if file.exists() else {'status':'not_run'}
    for key,path in [('publisher_reference','data/item4_publisher_reference_v1/manifest.json'),
        ('reference_verification','results/item4_reference_verification_v1/report.json'),
        ('source_logic_inference','results/item4_source_logic_inference_v3/summary.json'),
        ('source_logic_evaluation','results/item4_source_logic_eval_v3/report.json'),
        ('full_population_holdout','results/item4_full_population_70_30_v1/report.json')]:
        source=ROOT/path
        if source.exists():report[key]=json.loads(source.read_text(encoding='utf-8'))
    report['final_llm']=item4_final_llm()
    return report


@router.get('/api/question-mining/item4/final-llm')
def item4_final_llm():
    dataset=ROOT/'data/item4_cluster_source_70_30_v4'
    output=ROOT/'results/item4_cluster_source_final_llm_v1'
    result={}
    for key,path in [('dataset',dataset/'manifest.json'),('clusters',dataset/'clusters.json'),
        ('questions',dataset/'common_question_catalog.jsonl'),('queue',output/'queue_status.json'),
        ('worker',output/'status.json'),('audit',output/'dataset_audit.json'),('report',output/'report.json')]:
        if path.exists():result[key]=read(path) if path.suffix=='.jsonl' else json.loads(path.read_text(encoding='utf-8-sig'))
    result['precision_percent']=result.get('report',{}).get('metrics',{}).get('precision_percent')
    return result


@router.get('/api/question-mining/item4/dataset/{kind}')
def item4_dataset_download(kind:str):
    base=ROOT/'data/item4_cluster_source_70_30_v4'
    paths={'manifest':'manifest.json','clusters':'clusters.json','common':'common_question_catalog.jsonl',
        'provenance':'source_validation_ledger.jsonl','train-inputs':'train/inputs.jsonl',
        'eval-inputs':'eval/inputs.jsonl','train-gold':'train/gold.jsonl','eval-gold':'eval/gold.jsonl'}
    if kind not in paths:raise HTTPException(404,'Unknown dataset artifact')
    file=base/paths[kind]
    if not file.exists():raise HTTPException(404,'Dataset not built')
    return FileResponse(file,filename='item4-'+kind+file.suffix,
        media_type='application/x-ndjson' if file.suffix=='.jsonl' else 'application/json')


@router.post('/api/question-mining/reviews')
def review(payload:dict):
    try:
        cve=payload['cve'].upper();d=data();record=d['records'][cve]
        reviewer=payload.get('reviewer','').strip()
        if not reviewer or payload.get('source_review_confirmed') is not True:raise ValueError('Identify reviewer and explicitly confirm source/answer implication review')
        stamp=datetime.now(timezone.utc).isoformat()
        approved=dict(validation_status='approved',reviewer=reviewer,reviewed_at=stamp)
        detail=cve_detail(cve)
        logic_result=inferred_logic(cve) if any(str(i.get('condition_id','')).startswith('inferred:') for i in payload['conditions']) else None
        inferred_conditions={c['id']:c for p in logic_result['passages'] for c in p['conditions']} if logic_result else {}
        available={s['condition_id']:s for atom in detail['atoms'] for s in atom['sources']}
        atom_for={s['condition_id']:atom['id'] for atom in detail['atoms'] for s in atom['sources']}
        conditions=[];questions=[]
        for item in payload['conditions']:
            cid=item['condition_id']
            if cid in available:
                source=available[cid]
                ref=dict(source_id=source['source_id'],span=source['source_span'],quote=source['source_quote'])
                predicate=item.get('predicate') or atom_for[cid]
                source_refs=[ref]
            elif cid in inferred_conditions:
                inferred=inferred_conditions[cid];ref=deepcopy(inferred['source_ref'])
                source_refs=[ref]+deepcopy(inferred.get('context_refs',[]))
                semantic=dict(proposition=' '.join(inferred['proposition'].casefold().split()))
                qualified=[r['quote'] for r in inferred.get('context_refs',[]) if re.search(r'\bor\b|\b(?:after|before|until|while)\b',r['quote'],re.I)]
                if qualified:semantic['shared_qualification_contexts']=[' '.join(s.casefold().split()) for s in qualified]
                predicate='source-inferred-fact:'+digest(semantic)
            elif cid.startswith('manual:') and item.get('source_ref'):
                ref=deepcopy(item['source_ref'])
                # validate_review below checks the exact source ID, quote and span.
                # Manual facts are CVE-specific; mining membership cannot approve reuse.
                predicate='manual:'+cve+':'+str(item.get('predicate','')).strip()
                if predicate.endswith(':'):raise ValueError('Manual source facts need a reviewed predicate')
                source_refs=[ref]
            else:raise ValueError('Unknown mined condition or invalid manual source condition')
            target=item.get('target','').strip();text=item.get('question','').strip()
            if not target or target.casefold() in {'unknown','unresolved'} or not text:raise ValueError('Every selected condition needs a specific target and reviewed question')
            conditions.append(dict(id=cid,predicate=predicate,target=target,operator_observable=True,
                necessity='required_for_path',source_refs=source_refs,**approved))
            if item.get('yes_means') not in {'true','false'}:raise ValueError('Explicit yes-answer polarity required')
            reverse=item['yes_means']=='false'
            questions.append(dict(id=cid+':question',text=text,target=target,cost=1,**approved,
                mappings=[dict(condition_id=cid,coverage='FULL',source_refs=source_refs,**approved,
                    answers=dict(yes='false' if reverse else 'true',no='true' if reverse else 'false',unknown='unknown'))]))
        if not conditions:raise ValueError('Select at least one source condition')
        ids={c['id'] for c in conditions};expression=payload.get('formula')
        if not expression:raise ValueError('Provide source-reviewed AND/OR/NOT relation; co-occurrence is not a formula')
        refs=[ref for c in conditions for ref in c['source_refs']]
        derivation=None;selection=payload.get('inference_selection')
        if selection:
            if not logic_result:raise ValueError('Inference selection requires inferred source conditions')
            passage=logic_result['passages'][int(selection['passage'])]
            hypothesis=passage['hypotheses'][int(selection['hypothesis'])]
            expected=hypothesis['expression'];choice=selection.get('alternative')
            if hypothesis['scope_ambiguous']:
                if choice is None:raise ValueError('Ambiguous attachment needs an explicit inferred alternative choice')
                expected=hypothesis['alternatives'][int(choice)]['expression']
            if expression!=expected or ids!=leaves(expected):raise ValueError('Submitted formula differs from the selected source inference')
            refs+=[hypothesis['cue'],hypothesis['source_ref']]
            derivation=dict(method=LOGIC_VERSION,source_ref=hypothesis['source_ref'],cue=hypothesis['cue'],
                scope_ambiguous=hypothesis['scope_ambiguous'],selected_alternative=choice,
                inferred_before_user_review=True,semantic_exhaustiveness_inferred=False)
        contract=dict(cve=cve,conditions=conditions,questions=questions,
            formula=dict(expression=expression,coverage_complete=payload.get('coverage_complete') is True,source_refs=refs,**approved))
        if derivation:contract['formula']['inference']=derivation
        plan=compile_plan([contract],[record],[candidate_memberships(cve,contract)])
        sid=uuid.uuid4().hex
        value=dict(id=sid,plan=plan,records=[record],reviewer=reviewer,created_at=stamp,
                   reviewer_identity_authenticated=False,adjudication_is_independent_gold=False)
        review_store.put('pattern-workbench',sid,value)
        return value
    except (KeyError,ValueError,TypeError,IndexError) as exc:raise HTTPException(422,str(exc)) from exc


@router.post('/api/question-mining/reviews/merge')
def merge_reviews(payload:dict):
    try:
        sessions=[review_store.get('pattern-workbench',sid) for sid in payload['session_ids']]
        if not sessions or any(s is None for s in sessions):raise ValueError('Select existing unexpired source reviews')
        contracts=[r for s in sessions for r in s['plan']['reviews']]
        records=[r for s in sessions for r in s['records']]
        cves=[r['cve'] for r in contracts]
        if len(cves)!=len(set(cves)):raise ValueError('Keep one reviewed contract per CVE')
        members=[candidate_memberships(c,next(r for r in contracts if r['cve']==c)) for c in cves]
        plan=compile_plan(contracts,records,members)
        sid=uuid.uuid4().hex;value=dict(id=sid,plan=plan,records=records,
            reviewer=payload['reviewer'],created_at=datetime.now(timezone.utc).isoformat(),
            source_session_ids=payload['session_ids'],reviewer_identity_authenticated=False)
        if not str(value['reviewer']).strip():raise ValueError('Reviewer identity required')
        review_store.put('pattern-workbench',sid,value);return value
    except (KeyError,ValueError,TypeError) as exc:raise HTTPException(422,str(exc)) from exc


@router.get('/api/question-mining/reviews/{sid}')
def reopen(sid:str):
    value=review_store.get('pattern-workbench',sid)
    if not value:raise HTTPException(404,'Review missing or expired')
    return value


@router.post('/api/question-mining/reviews/{sid}/answers')
def answers(sid:str,payload:dict):
    saved=review_store.get('pattern-workbench',sid)
    if not saved:raise HTTPException(404,'Review missing or expired')
    try:
        now=datetime.now(timezone.utc);cases=[];shared=[]
        scope={**payload['scope'],'evaluated_at':payload['scope'].get('evaluated_at') or now.isoformat()}
        common={q['id']:q for q in saved['plan']['common_questions']}
        known_ids=set(common)|{q['id'] for r in saved['plan']['reviews'] for q in r['questions']}
        if any(a.get('question_id') not in known_ids for a in payload.get('answers',[])):
            raise ValueError('Unknown question ID for the stored plan')
        for cvplan in saved['plan']['cves']:
            cve=cvplan['cve'];binding={**scope,'cve':cve};evidence=[];responses=[]
            local_ids={q['id'] for r in saved['plan']['reviews'] if r['cve']==cve for q in r['questions']}
            def ev(eid,kind,source,quote,**extra):
                observed=instant(payload.get('observed_at'));expiry=instant(payload.get('valid_until'))
                if observed is None or expiry is None or observed>now:
                    raise ValueError('Evidence needs an explicit timezone-aware observation time and validity end; future observations are invalid')
                return dict(id=eid,kind=kind,binding=binding,source=source,quote=quote,reviewer=saved['reviewer'],
                    observed_at=payload['observed_at'],reviewed_at=now.isoformat(),valid_until=payload['valid_until'],**extra)
            for index,answer in enumerate(payload.get('answers',[])):
                qid=answer['question_id']
                applicable=qid in local_ids or qid in common and any(m['cve']==cve for m in common[qid]['members'])
                if not applicable:continue
                if answer.get('value') not in {'yes','no','unknown'}:raise ValueError('Answer must be yes/no/unknown')
                eid='operator-'+str(index);refs=[]
                if answer['value']!='unknown':
                    if not answer.get('source') or not answer.get('quote'):raise ValueError('Non-unknown answers need source and evidence text')
                    kind=answer.get('kind','operational_observation')
                    if kind not in {'operational_observation','firewall_policy','reviewed_nonexecution_analysis'}:
                        raise ValueError('Unsupported answer evidence kind')
                    evidence.append(ev(eid,kind,answer['source'],answer['quote']));refs=[eid]
                if qid in local_ids:responses.append(dict(question_id=qid,value=answer['value'],evidence_ids=refs))
            findings=[];claim=payload.get('product_assertion')
            if claim and (len(saved['plan']['cves'])==1 or cve in claim.get('cves',[])):
                if not claim.get('source') or not claim.get('quote'):raise ValueError('Supplier/product assertion needs source and exact claim')
                kind='supplier_fix_mapping' if claim['status']=='fixed' else claim.get('kind','supplier_product_status')
                evidence.append(ev('product-assertion',kind,claim['source'],claim['quote'],asserted_status=claim['status']))
                refs=['product-assertion']
                if claim['status']=='fixed' and claim.get('installation'):
                    install=claim['installation']
                    if not install.get('source') or not install.get('quote'):raise ValueError('Installation confirmation needs its own record')
                    evidence.append(ev('installation','installation_record',install['source'],install['quote'],execution_verified=install.get('execution_verified') is True))
                    refs.append('installation')
                findings.append(dict(status=claim['status'],evidence_ids=refs,action_statement=claim.get('action_statement'),
                    justification=claim.get('justification'),impact_statement=claim.get('impact_statement')))
            formula_ids=[];route=payload.get('route_analyses',{}).get(cve)
            if route:
                if route.get('review_confirmed') is not True or not route.get('source') or not route.get('quote'):
                    raise ValueError('Complete-route analysis needs explicit review, source and quoted record')
                evidence.append(ev('complete-routes','reviewed_complete_route_analysis',route['source'],route['quote']))
                formula_ids=['complete-routes']
            cases.append(dict(binding=binding,evidence=evidence,answers=responses,product_findings=findings,formula_evidence_ids=formula_ids))
        for index,answer in enumerate(payload.get('answers',[])):
            if answer['question_id'] not in common or answer['value']=='unknown':continue
            shared.append(dict(plan_id=saved['plan']['plan_id'],question_id=answer['question_id'],
                target=common[answer['question_id']]['target'],value=answer['value'],scope=scope,
                evidence_by_cve={c['binding']['cve']:['operator-'+str(index)] for c in cases
                    if any(e['id']=='operator-'+str(index) for e in c['evidence'])}))
        result=evaluate_plan(saved['plan'],saved['records'],cases,shared)
        result['review_session_id']=sid
        stamp=now.isoformat();result['csaf_vex']=export_csaf(result,saved['reviewer'],stamp)
        result['openvex']=export_openvex(result,saved['reviewer'],stamp)
        saved['last_cases']=cases
        if saved.get('identification'):
            from .prerequisite_bom import context_bom
            result['context_bom']=context_bom(saved,result)
        saved.setdefault('history',[]).append(dict(evaluated_at=stamp,cases=cases,evaluation=result))
        saved.update(last_cases=cases,last_evaluation=result);review_store.put('pattern-workbench',sid,saved)
        return result
    except (KeyError,ValueError,TypeError) as exc:raise HTTPException(422,str(exc)) from exc


@router.get('/api/question-mining/demo')
def demo():
    from tools.demo_cluster_question_pipeline import fixtures
    reviews,records,members,cases=fixtures()
    return dict(synthetic=True,plan=compile_plan(reviews,records,members),records=records,cases=cases)
