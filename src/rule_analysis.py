"""Deterministic source-span extraction, operational templates and answer summaries."""
from src.cve_source_evidence import catalog
from src.grounded_role_tasks import weak_conditions


def extraction(cve,description):
    sources=catalog(cve,description);conditions=[];functions=[];seen=set();fseen=set()
    for source in sources:
        if source['source_kind'] not in {'description','summary'}:continue
        weak=weak_conditions(source['text'])
        for c in weak['conditions'] if source['condition_eligible'] else []:
            key=(c['kind'],c['evidence'])
            if key in seen or c['evidence'] not in source['text']:continue
            seen.add(key);conditions.append({**c,'evidence_ids':[source['id']],'source_id':source['id'],
                 'source_span':[source['text'].index(c['evidence']),source['text'].index(c['evidence'])+len(c['evidence'])],
                 'necessity':'uncertain','can_refute':False})
        for f in weak['function_candidates']:
            if f['name'] in fseen or f['name'] not in source['text']:continue
            fseen.add(f['name']);functions.append({**f,'evidence_ids':[source['id']]})
    pred={'conditions':conditions,'function_candidates':functions,'function_status':'mentioned' if functions else 'unresolved',
          'assessment':'partial','can_refute':False}
    return {'status':'validated' if sources else 'unavailable','usable':bool(sources),'prediction':pred if sources else None,
            'strategy':'deterministic_source_spans','method':'regex_source_catalog','llm_used':False,
            'source_catalog':sources,'condition_evidence_ids':sorted({c['source_id'] for c in conditions}),
            'checks':{'literal_source_spans':True},'extraction_completeness':'not_established','can_refute':False}


TEMPLATES={
 'transport-encryption':('Is encryption enforced on the communication paths described in the cited advisory?','data_flow'),
 'protocol-cryptography':('Which protocol versions and cipher settings are enabled on the affected service?','configuration'),
 'interface-authentication':('Is authentication required on the service described in the cited advisory?','authentication'),
 'password-configuration':('Are default accounts disabled and vendor-supported password requirements enforced?','configuration'),
 'cookie-configuration':('Which management protocol and cookie security settings are currently in use?','configuration'),
 'resource-permissions':('What ownership and access permissions are configured for the resource described in the cited advisory?','configuration')}
TEMPLATES.update({
 'crypto-configuration':TEMPLATES['protocol-cryptography'],
 'key-configuration':('Which vendor-documented key or certificate replacement records apply to this asset? Do not enter key material.','configuration'),
 'deployment-configuration':('Which vendor-documented deployment settings control access to the service or resource described in the advisory?','configuration'),
 'authorization-enforcement':('Which actual user roles and permissions are assigned to the operation described in the cited advisory?','privileges'),
 'crypto-implementation':('Which interfaces use the affected credential, certificate or cryptographic service described in the advisory?','configuration'),
 'security-enforcement':('Which users and systems can access the operation protected by the control described in the advisory?','network_path')})


def questions(case,sources):
    usable=[s for s in sources if s['source_kind'] in {'description','summary'}]
    if not usable:return {'prediction':{'questions':[]},'method':'rule_templates','llm_used':False},[]
    decisions=(case.get('analysis_route') or {}).get('decisions',[])
    profiles=(case.get('analysis_route') or {}).get('question_profiles',[])
    matched=[d for d in decisions if d.get('rule_id') in TEMPLATES]
    selected=next((q for q in profiles if q in TEMPLATES),None)
    chosen={'rule_id':selected} if selected else matched[0] if matched else None
    quotes=[e['quote'] for d in matched for e in d.get('evidence',[])]
    refs=[s['id'] for s in usable if any(q in s['text'] for q in quotes)][:2] or [usable[0]['id']]
    question,kind=TEMPLATES[chosen['rule_id']] if chosen else ('Which interfaces and services are used by the component named in the cited advisory?','discovery')
    pairs=[('common','Which parties can access the interfaces described in the cited advisory?','network_path'),('specific',question,kind)]
    byid={s['id']:s for s in usable};rows=[]
    for scope,text,topic in pairs:
        rows.append({'scope':scope,'question':'On this asset, '+text[0].lower()+text[1:],
            'purpose':'Record observable operating facts for '+case['cve']+'.',
            'evidence_ids':refs,'evidence':'\n'.join(byid[i]['text'] for i in refs),
            'source_provenance':[byid[i]['source'] for i in refs],
            'kind':topic,'answer_type':'text' if text.startswith(('Which','What')) else 'yes_no_unknown',
            'origin':'rule','rule_id':chosen['rule_id'] if chosen else 'discovery',
            'semantic_review_required':False,'necessity':'not_established','can_refute':False})
    return {'prediction':{'questions':rows},'method':'rule_templates','llm_used':False,'fine_tuned_for_role':False},rows


def assessment(questions,version_evaluation):
    operating=[q for q in questions if q.get('origin')=='rule' and not q.get('deprecated_version_field')]
    recorded=[q for q in operating if q['answer']['value'] not in {'unknown',''} and q['answer']['evidence'].strip()]
    explanation=f'{len(recorded)} operating answers have supporting records. These reports do not establish complete exploitability conditions.'
    pred={'assessment':'likely_cannot_determine','explanation':explanation,'answer_refs':[q['id'] for q in recorded][:4],
          'missing_evidence':['Complete validated exploitation-condition coverage']}
    return {'prediction':pred,'method':'deterministic_answer_summary','llm_used':False,'fine_tuned_for_role':False}
