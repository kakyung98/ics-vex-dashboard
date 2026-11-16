"""Shared grounded extraction -> branch evidence -> locked-decision VEX authoring.

Model outputs are observations/drafts, never an answer key. All branches preserve
the same case ID and exact input hashes. Invalid outputs remain visible and do
not silently become valid model generations.
"""
from collections import OrderedDict,Counter
from copy import deepcopy
import hashlib
import json
import threading
import os
from src.grounded_role_tasks import check_conditions,check_writer,writer_diagnostics

_cache=OrderedDict()
_lock=threading.Lock()


def fingerprint(value):return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False).encode()).hexdigest()


def infer(role,packet):
    from src.inference_policy import require_writer
    require_writer(role)
    from src.identification_agents import get_runtime
    return get_runtime().grounded_role(role,packet)


def infer_base(role,packet):
    raise ValueError('Base-model analysis is disabled; LLM is reserved for final VEX writing.')


def extraction(cve,description):
    from src.rule_analysis import extraction as extract_rules
    return extract_rules(cve,description)


def prepare(cases,*,product='unspecified-product',run_id='review',simulation=False):
    prepared=[]
    for original in cases:
        c=dict(original);cve=c['cve']
        c['case_id']=c.get('case_id') or 'case-'+fingerprint([run_id,product,cve,c.get('mappings',[]),c.get('functions',[]),
                                        c.get('component_present'),c.get('version_in_range'),
                                        fingerprint(c.get('description','')),c.get('vector'),bool(simulation)])[:20]
        c['product']=str(product or 'unspecified-product');c['simulation']=bool(simulation)
        c['extraction']=extraction(cve,c.get('description',''))
        pred=c['extraction'].get('prediction') if c['extraction']['usable'] else None
        c['condition_function_candidates']=[f['name'] for f in pred['function_candidates']] if pred else []
        c['condition_candidates']=pred['conditions'] if pred else []
        prepared.append(c)
    return prepared


def requirements(base,case):
    req=dict(base)
    req['condition_extraction']={k:v for k,v in case['extraction'].items() if k!='raw'}
    # Quotation support is not semantic verification. These candidates require
    # evidence and cannot refute a CVE or be silently treated as satisfied.
    req['condition_candidates']=[{'id':case['case_id']+':condition:'+str(i),**c,'can_refute':False}
                                     for i,c in enumerate(case['condition_candidates'])]
    req['llm_condition_candidates']=req['condition_candidates']  # Legacy field name; values originate from rules.
    return req


def decision_packet(case,statement,result):
    case_id=case['case_id'];evidence=statement.get('evidence') or {}
    scope=(evidence.get('cfg') or {}).get('claim_boundary') or statement.get('scope') or result.get('arm','review')
    facts=[{'id':case_id+':decision','text':statement.get('reason') or 'Evidence is incomplete.'}]
    if statement.get('branch_evidence'):
        facts.append({'id':case_id+':combined-evidence','text':json.dumps({
            'workflow':statement.get('analysis_route',{}).get('workflow_branch'),
            'branches':{k:{'status':s['status'],'scope':s.get('scope'),'reason':s.get('reason')}
                        for k,s in statement['branch_evidence'].items()},
            'progress':statement.get('evidence_progress')},ensure_ascii=False)})
    missing=list(evidence.get('missing_evidence',[]))
    for i,item in enumerate(statement.get('missing',[])):
        missing.append(str(item.get('requirement') or item))
    if not case['extraction']['usable']:missing.append('validated Description extraction')
    if case.get('version_decided') is False:missing.append('confirmed installed product/version applicability')
    if any(m.get('identification_evidence',{}).get('architecture') in {'evidence-v3','unified-identification-v1'} for m in case.get('mappings',[])):
        facts.append({'id':case_id+':identification','text':'Initial identification snapshot. A later component version-evaluation supersedes this version status: '+json.dumps([{
            'component_id':m.get('component_id'),'identity_status':m.get('identification_evidence',{}).get('identity',{}).get('identity_status'),
            'model_confirmation':m.get('identification_evidence',{}).get('identity',{}).get('model_confirmation'),
            'version_status':m.get('identification_evidence',{}).get('version_status'),
            'acceptance_rule':m.get('identification_evidence',{}).get('identity',{}).get('acceptance_rule'),
            'match_status':m.get('match_status'),'deployment_verified':False} for m in case['mappings']],ensure_ascii=False)})
    review=statement.get('operational_review')
    if review:
        if review.get('operational_context'):
            facts.append({'id':case_id+':operating-context',
                          'text':'Scoped operator report, not independently verified: '+json.dumps(review['operational_context'],ensure_ascii=False)})
        for i,qa in enumerate(review['questions_and_answers']):
            if qa.get('deprecated_version_field'):continue
            facts.append({'id':qa['id'],'text':'Operator report (not independently verified): '+qa['question']+' '+__import__('json').dumps(qa['answer'],ensure_ascii=False)})
        assessment=review['assessment']
        effective=review.get('effective_assessment')
        if effective:
            facts.append({'id':case_id+':operational-assessment','text':'Effective advisory assessment, not a verified VEX verdict: '+effective['assessment']+'. '+effective['explanation']})
        elif assessment['status']=='validated_draft' and assessment.get('prediction',{}).get('assessment')==statement['operational_assessment']:
            facts.append({'id':case_id+':operational-assessment','text':'Advisory LLM likelihood, not a verified VEX verdict: '+statement['operational_assessment']+'. '+assessment['prediction']['explanation']})
        if review.get('version_evaluation'):
            ve=review['version_evaluation']
            facts.append({'id':case_id+':version-evaluation','text':json.dumps({'version_decided':ve['version_decided'],
                'components':[{k:r[k] for k in ['component_ref','product_name','installed_version','state','operator_attested','operator_evidence']} |
                    {'source_refs':[e['source'] for e in r['source_evidence']]} for r in ve['components']],
                'independent_deployment_verification':False},ensure_ascii=False)})
    if case['extraction']['usable']:
        for i,c in enumerate(case['condition_candidates'][:4]):
            facts.append({'id':case_id+':quote:'+str(i),'text':'Quoted source condition candidate, not independently verified: '+c['evidence']})
    facts.append({'id':case_id+':context','text':json.dumps({'refutations':statement.get('refutations',[]),
                 'mitigations':statement.get('mitigations',[]),'version_gate':statement.get('identification_gate'),
                 'CWE_classification_only':True},ensure_ascii=False)})
    return {'vulnerability':case['cve'],'product':case['product'],'scope':str(scope),
            'simulation':case['simulation'],'decision':{'status':statement['status'],'justification':statement.get('justification')},
            'evidence':facts,'missing_evidence':sorted(set(missing))}


def finish(result,cases):
    known={c['cve']:c for c in cases}
    for statement in result['statements']:
        c=known[statement['cve']]
        if statement['status']=='affected' and not c['extraction']['usable']:
            statement.update(status='under_investigation',justification=None,branch_status_before_extraction_gate='affected',
                             reason='Description extraction did not pass grounding/schema checks; the available prerequisites are incomplete.')
        packet=decision_packet(c,statement,result)
        statement['case_id']=c['case_id'];statement['extraction']=c['extraction']
        statement['evidence_packet']=packet
        attempts=[]
        try:
            output=infer('vex-writer',packet);checks=check_writer(packet,output.get('prediction'))
            accepted=all(checks.values()) and not output.get('error')
            attempts=[{**output,'input_sha256':fingerprint(packet),'checks':checks,'diagnostics':writer_diagnostics(output.get('prediction'))}]
            if not accepted and output.get('error') in {None,'invalid_json_output','output_token_limit'}:
                retry_packet={**packet,'generation_feedback':{
                    'failed_checks':[k for k,v in checks.items() if not v],
                    'errors':attempts[0]['diagnostics']['errors'],
                    'generation_error':output.get('error'),
                    'instruction':'Write a new concise complete JSON object. Do not repeat sentences. Preserve all assigned IDs/status/justification. Include every required field; do not copy previous malformed output.'}}
                output=infer('vex-writer',retry_packet);checks=check_writer(packet,output.get('prediction'))
                accepted=all(checks.values()) and not output.get('error')
                attempts.append({**output,'input_sha256':fingerprint(retry_packet),'generation_feedback':retry_packet['generation_feedback'],
                                 'checks':checks,'diagnostics':writer_diagnostics(output.get('prediction'))})
            writer={**output,'status':'validated_draft' if accepted else 'rejected','checks':checks,
                    'attempts':attempts,
                    'diagnostics':writer_diagnostics(output.get('prediction')),'output_contract':'vex-draft/2',
                    'input_sha256':fingerprint(packet),'semantic_correctness':'requires_human_review'}
        except Exception as e:writer={'status':'unavailable','reason':str(e)[:300],'prediction':None,'attempts':attempts,'input_sha256':fingerprint(packet)}
        statement['authoring']=writer
        statement['document_draft']={k:v for k,v in writer['prediction'].items() if k!='missing_evidence'} if writer['status']=='validated_draft' else None
        if isinstance(writer.get('prediction'),dict) and 'missing_evidence' in writer['prediction']:writer['metadata']={'missing_evidence':writer['prediction']['missing_evidence']}
        statement['pipeline_complete']=bool(c['extraction']['usable'] and statement['document_draft'])
        statement['review_required']=True
    result['pipeline']={'name':'ICS-VEXForge grounded VEX pipeline','stages':['condition_and_function_extraction','branch_evidence_and_rule_decision','vex_authoring','output_validation'],
                        'case_count':len(result['statements']),'complete_cases':sum(s['pipeline_complete'] for s in result['statements']),
                        'extraction_status':dict(Counter(s['extraction']['status'] for s in result['statements'])),
                        'authoring_status':dict(Counter(s['authoring']['status'] for s in result['statements'])),
                        'answer_key_used':False,'review_required':True}
    result['vex_drafts']=[s['document_draft'] for s in result['statements'] if s['document_draft']]
    if result.get('questionnaire_id'):
        result['pipeline']['stages']=['rule_condition_and_function_extraction','rule_operational_questions',
            'operator_answers','rule_operational_assessment','conservative_vex_decision','vex_authoring','output_validation']
        result['pipeline']['complete_cases']=sum(s['pipeline_complete'] and
            s['operational_review']['generation']['status']=='validated' and
            s['operational_review']['assessment']['status'] in {'validated_draft','validated_rules'} for s in result['statements'])
        for s in result['statements']:
            s['pipeline_complete']=bool(s['pipeline_complete'] and s['operational_review']['generation']['status']=='validated' and s['operational_review']['assessment']['status'] in {'validated_draft','validated_rules'})
    counts=Counter(s['status'] for s in result['statements']);n=len(result['statements']);deferred=counts.get('under_investigation',0)
    result.update(by_status=dict(counts),total=n,deferred=deferred,decision_rate=round((n-deferred)/n,4) if n else None,
                  deferral_rate=round(deferred/n,4) if n else None)
    return result
