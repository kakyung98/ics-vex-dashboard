"""Deterministic, scoped proof interpreter for selectable NIST observations.

Proof records are coded findings reviewed by people, not facts extracted from
their prose by a model. Hashes establish snapshot consistency, not semantic
accuracy or reviewer identity. No networking or model client is used here.
"""
from copy import deepcopy
from datetime import datetime,timezone
import hashlib,json
from jsonschema import Draft202012Validator
from src.item4.decision.condition_logic_evaluation import logic

VERSION='nist-three-axis-vex/1'
SCOPE=('asset_ref','product','build','config_baseline','mode','origin')
KINDS=('product_identity','condition','product_status','installation','route_coverage')
CONCLUSIONS=('matches','true','false','affected','fixed','not_affected','running_fixed_build','complete')
MECHANISMS=('inventory_match','direct_observation','structural_nonexecution','supplier_statement','qualified_product_analysis','runtime_installation','exhaustive_route_analysis')
ELIGIBLE={
 'network_access':{'C13-05.05','C13-08.01','C13-08.02','C12-07.02','C12-08.03','C16-02.03','C16-10.04','C16-11.02'},
 'local_access':{'C13-12.01','C13-12.02','C13-13.01','C13-13.02','C13-13.03','C13-13.04','C13-14.03'},
 'physical_access':{'C14-01.01','C14-01.02','C14-01.03','C14-05.01','C14-05.02'},
 'file_processing':{'C13-08.02','C13-14.03','C13-20.01','C15-01.01','C15-01.02','C15-02.01','C15-02.02','C16-04.01'},
 # Attacker possession of credentials is never inferred from account settings.
 'attacker_authentication':set(),
 'source_condition':{'C13-02.02','C13-08.01','C13-08.02','C13-14.03','C13-20.01','C15-01.01','C15-01.02','C15-02.01','C15-02.02','C16-05.01','C16-05.02','C16-05.03','C16-06.01','C16-06.02','C16-06.03','C16-09.02','C16-10.01'},
}
def string(n=2000):return dict(type='string',minLength=1,maxLength=n)
def array(items,maximum=167):return dict(type='array',items=items,uniqueItems=True,maxItems=maximum)
PROOF_SCHEMA=dict(type='object',additionalProperties=False,required=['kind','conclusion','mechanism','cve','product_key','asset_type_id','source_digest','scope','evidence_ids','field_ids','question_id','source_quote_sha256','coverage','reviewed'],properties={
 'kind':{'enum':list(KINDS)},'conclusion':{'enum':list(CONCLUSIONS)},'mechanism':{'enum':list(MECHANISMS)},
 'cve':string(100),'product_key':string(),'asset_type_id':{'pattern':'^A00(?:0[1-9]|1[0-8])$','type':'string'},
 'source_digest':{'type':'string','pattern':'^[a-f0-9]{64}$'},
 'scope':dict(type='object',additionalProperties=False,required=list(SCOPE),properties={k:string() for k in SCOPE}),
 'evidence_ids':{**array(string(200),100),'minItems':1},'field_ids':array(string(100)),
 'question_id':dict(type='string',maxLength=300),'source_quote_sha256':dict(type='string',pattern='^(|[a-f0-9]{64})$'),
 'coverage':{'enum':['complete','partial']},'reviewed':dict(type='boolean')})
REVIEW_SCHEMA=dict(type='object',additionalProperties=False,required=['version','records','selected_ids'],properties={
 'version':{'const':VERSION},'records':dict(type='object',maxProperties=2000,additionalProperties=PROOF_SCHEMA),
 'selected_ids':array(string(200),2000)})

def sha(text):return hashlib.sha256(text.encode('utf-8')).hexdigest()
def digest(value):return sha(json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')))
def blank():return dict(version=VERSION,records={},selected_ids=[])
def validate_bundle(bundle):
    errors=list(Draft202012Validator(REVIEW_SCHEMA).iter_errors(bundle))
    if errors:raise ValueError('Invalid typed review '+str(list(errors[0].absolute_path))+': '+errors[0].message)
    if any(i not in bundle['records'] for i in bundle['selected_ids']):raise ValueError('Unknown selected proof record')

def decorate_plan(plan):
    plan=deepcopy(plan)
    for q in plan['questions']:
        q['typed_field_ids']=sorted(ELIGIBLE.get(q['kind'],set()) & {f['id'] for f in plan['fields']})
        q['source_quote_sha256']=sha(q['source_refs'][0]['quote'])
    plan['typed_review_policy']=dict(version=VERSION,llm_used=False,source_digest=plan['source_digest'],
      rule='Coded source-specific proof + exact asset/build/origin + selected observations; no truth inferred from prose.',
      unsupported_conditions_remain_unknown=True,review_schema_url='/nist-typed-review.schema.json')
    plan.pop('plan_sha256',None);plan['plan_sha256']=digest(plan)
    return plan

def assess(plan,profile,bundle,approved_scenarios,base,now=None):
    validate_bundle(bundle)
    result=deepcopy(base);now=now or datetime.now(timezone.utc)
    selected=set(bundle['selected_ids']);qs={q['id']:q for q in plan['questions']}
    fields={f['id']:f for f in plan['fields']};scenarios={s['id']:s for s in plan['scenarios']}
    approved=set(approved_scenarios);trace=[];usable={}
    def evidence_ok(ids,allowed=None):
        for eid in ids:
            e=profile['evidence'].get(eid)
            if not e or e.get('reviewed') is not True:return False
            if allowed and e['kind'] not in allowed:return False
            if any(e[k]!=profile['scope'][k] for k in ('asset_ref','build','config_baseline')):return False
            try:
                start=datetime.fromisoformat(e['observed_at'].replace('Z','+00:00'));end=datetime.fromisoformat(e['valid_until'].replace('Z','+00:00'))
                if not start<=now<=end:return False
            except (ValueError,TypeError):return False
        return bool(ids)
    def observed(ids):
        if not ids:return False
        for fid in ids:
            if fid not in fields:return False
            o=profile['inventory']['values'][fid]
            if o['state']!='recorded' or profile['gates'][fid.split('.')[0]]['state']!='present':return False
            if o['coverage_scope']!='assessed_asset':return False
            if not evidence_ok(o['evidence_ids']):return False
        return True
    for pid in sorted(selected):
        p=bundle['records'][pid];reasons=[]
        if not p['reviewed']:reasons.append('Original coded finding has not been reviewed.')
        if any(p[k]!=plan[k] for k in ('cve','product_key','asset_type_id') if k in plan):reasons.append('CVE/product/type mismatch.')
        if p['product_key']!=plan['product']['key']:reasons.append('Source product key mismatch.')
        if p['source_digest']!=plan['source_digest']:reasons.append('CVE source changed; review again.')
        if any(p['scope'][k]!=profile['scope'][k] for k in SCOPE):reasons.append('Asset/product/build/baseline/mode/origin mismatch.')
        if not evidence_ok(p['evidence_ids']):reasons.append('Evidence is missing, unreviewed, expired, or bound to another asset/build.')
        if p['kind']=='product_identity':
            if p['conclusion']!='matches' or p['mechanism']!='inventory_match':reasons.append('Invalid identity proof type.')
            if not evidence_ok(p['evidence_ids'],{'inventory_record','configuration_record'}):reasons.append('Product identity requires installation/configuration inventory evidence.')
            if not {'C13-01.01','C13-01.03'}<=set(p['field_ids']) or not observed(p['field_ids']):reasons.append('Select current manufacturer/model and running-version observations.')
            else:
                model=profile['inventory']['values']['C13-01.01']['data']
                names=[profile['reference_values'][i]['label'] for i in model['value_refs']]
                if model['choice']!='listed' or profile['scope']['product'] not in names:reasons.append('Product identity must exactly match a current registered manufacturer/model value.')
                version=profile['inventory']['values']['C13-01.03']['data']
                labels=[profile['reference_values'][i]['label'] for i in version['value_refs']]
                if version['choice']!='listed' or profile['scope']['build'] not in labels:reasons.append('Running version must exactly match a current registered version.')
            if p['coverage']!='complete':reasons.append('Incomplete product/build identity match.')
        elif p['kind']=='condition':
            q=qs.get(p['question_id'])
            if not q:reasons.append('Unknown or out-of-product source condition.')
            else:
                s=scenarios[q['scenario_id']]
                if q['scenario_id'] not in approved or not s['approvable']:reasons.append('Source prerequisite and AND/OR meaning not approved.')
                if p['source_quote_sha256']!=q['source_quote_sha256']:reasons.append('Source predicate changed or refers to a different predicate.')
                eligible=set(q['typed_field_ids'])
                if not p['field_ids'] or not set(p['field_ids'])<=eligible:reasons.append('Selected NIST fields do not support this predicate domain.')
                if not q['operator_observable'] and p['mechanism']!='structural_nonexecution':reasons.append('This source predicate requires qualified product-specific analysis.')
                if q['kind']=='network_access' and 'C13-05.05' in p['field_ids']:
                    finding=profile['inventory']['values']['C13-05.05']
                    required='reachable' if p['conclusion']=='true' else 'blocked'
                    if not finding.get('data') or finding['data']['choice']!=required:reasons.append('The reachability conclusion contradicts the selected operational finding.')
            if p['conclusion'] not in ('true','false') or p['mechanism'] not in ('direct_observation','structural_nonexecution'):reasons.append('Invalid condition observation type.')
            if not observed(p['field_ids']):reasons.append('Related selectable observations must be recorded, relevant, and scoped to this asset.')
            if p['conclusion']=='false' and p['coverage']!='complete':reasons.append('A negative condition requires complete assessed scope.')
            if p['mechanism']=='structural_nonexecution':
                if p['conclusion']!='false' or not evidence_ok(p['evidence_ids'],{'vendor_document','assessment_record'}):reasons.append('Non-execution requires CVE-specific vendor/qualified analysis; ordinary firewall or test observations cannot substitute.')
        elif p['kind']=='product_status':
            if p['conclusion'] not in ('affected','fixed','not_affected') or p['mechanism'] not in ('supplier_statement','qualified_product_analysis'):reasons.append('Invalid product status proof.')
            allowed={'vendor_document'} if p['mechanism']=='supplier_statement' else {'assessment_record'}
            if not evidence_ok(p['evidence_ids'],allowed):reasons.append('Product status requires the corresponding supplier or qualified analysis record.')
            if p['coverage']!='complete':reasons.append('Product status must bind the complete assessed product/build scope.')
        elif p['kind']=='installation':
            if p['conclusion']!='running_fixed_build' or p['mechanism']!='runtime_installation' or p['coverage']!='complete':reasons.append('Invalid running-fix proof.')
            if not evidence_ok(p['evidence_ids'],{'inventory_record','configuration_record','test_record'}):reasons.append('Running fixed build requires an installation/runtime record.')
        elif p['kind']=='route_coverage':
            if p['conclusion']!='complete' or p['mechanism']!='exhaustive_route_analysis' or p['coverage']!='complete':reasons.append('Invalid exhaustive-route proof.')
            if not evidence_ok(p['evidence_ids'],{'vendor_document','assessment_record'}):reasons.append('All-path closure requires qualified/source-specific analysis.')
            if not scenarios or set(scenarios)!=approved or any(not s['approvable'] for s in scenarios.values()):reasons.append('Missing, ambiguous, or unreviewed source paths prevent exhaustive closure.')
        if p['kind']!='condition' and (p['question_id'] or p['source_quote_sha256']):reasons.append('Non-condition proof cannot carry a predicate binding.')
        trace.append(dict(proof_id=pid,kind=p['kind'],accepted=not reasons,reasons=reasons,evidence_ids=p['evidence_ids'],field_ids=p['field_ids']))
        if not reasons:usable[pid]=p
    ids=lambda kind:[i for i,p in usable.items() if p['kind']==kind]
    identities=ids('product_identity');conflicts=[];facts={qid:'unknown' for qid in qs};structural=dict(facts);mappings=[]
    for qid,q in qs.items():
        proofs=[(i,p) for i,p in usable.items() if p['kind']=='condition' and p['question_id']==qid]
        states={p['conclusion'] for _,p in proofs}
        if len(states)>1:conflicts.append(qid)
        elif states:
            facts[qid]=next(iter(states))
            if any(p['mechanism']=='structural_nonexecution' for _,p in proofs):structural[qid]=facts[qid]
        mappings.append(dict(question_id=qid,requested_value='computed',accepted_value=facts[qid],field_ids=sorted({f for _,p in proofs for f in p['field_ids']}),profile_evidence_ids=sorted({e for _,p in proofs for e in p['evidence_ids']}),proof_ids=[i for i,_ in proofs],reasons=['Conflicting coded observations.'] if qid in conflicts else [],source_refs=q['source_refs']))
    paths=[]
    for sid,s in scenarios.items():
        pf={q['condition_id']:facts[qid] for qid,q in qs.items() if q['scenario_id']==sid}
        sf={q['condition_id']:structural[qid] for qid,q in qs.items() if q['scenario_id']==sid}
        reviewed=sid in approved and s['approvable']
        paths.append(dict(scenario_id=sid,reviewed=reviewed,value=logic(s['expression'],pf) if reviewed else 'unknown',structural_value=logic(s['expression'],sf) if reviewed else 'unknown',expression=s['expression'],source_ref=s['source_ref']))
    statuses={usable[i]['conclusion'] for i in ids('product_status')}
    closure=bool(ids('route_coverage') and paths and all(p['structural_value']=='false' for p in paths))
    if closure:statuses.add('not_affected')
    scope_ok=not base['profile_validation']['missing_scope'] and not base['profile_validation']['evidence_expired'] and not base['profile_validation']['observation_in_future']
    status='under_investigation';reason='Select reviewed product identity and CVE-specific proof records. Missing facts remain unknown.'
    if identities and scope_ok and not conflicts and plan.get('product',{}).get('binding')!='unresolved' and plan.get('original_nvd_status')!='Rejected' and not plan.get('source_identity_ambiguous'):
        if len(statuses)>1:reason='CVE-specific status proofs conflict; resolve them before a verdict.'
        elif len(statuses)==1:
            candidate=next(iter(statuses))
            if candidate=='fixed' and not ids('installation'):reason='Supplier fix is documented, but execution of the fixed build is not confirmed.'
            else:status=candidate;reason={'affected':'Reviewed CVE-specific supplier/product evidence identifies this exact running product/build as affected.','fixed':'A CVE-specific fix and the running fixed build are both supported by reviewed records.','not_affected':'Reviewed CVE-specific product analysis or exhaustive structural route evidence establishes no impact for this recorded scope.'}[status]
    if conflicts:reason='Conflicting operational condition proofs require resolution.'
    exposure='prerequisites_observed' if any(p['value']=='true' for p in paths) else 'registered_paths_refuted' if paths and all(p['value']=='false' for p in paths) else 'unknown'
    if not identities or not scope_ok:exposure='unknown'
    decision=result['decision'];decision.update(status=status,reason=reason,justification=None,accepted_evidence_ids=sorted({e for p in usable.values() for e in p['evidence_ids']}) if status!='under_investigation' else [],proofs=[dict(id=i,status=p['conclusion'],supported=True,evidence_ids=p['evidence_ids']) for i,p in usable.items()],decision_trace=[dict(check='three_axis',asset_type_id=profile['asset_type_id'],cve=plan['cve'],profile_sha256=digest(profile),source_digest=plan['source_digest'],identity_proofs=identities,condition_values=facts,status_candidates=sorted(statuses),conflicts=conflicts,complete_structural_closure=closure,final_status=status)])
    for key in ('action_statement','impact_statement'):decision.pop(key,None)
    if status=='affected':decision['action_statement']='Apply the supplier remediation and retain the asset/build/configuration and CVE-specific evidence recorded in this assessment.'
    if status=='not_affected':decision['impact_statement']=reason+' Limited to the recorded asset, build, baseline, operating mode, origin, and evidence validity period.'
    issues=[r for t in trace for r in t['reasons']]
    if status=='under_investigation':issues.insert(0,reason)
    if not qs:issues.append('No source-supported prerequisite paths exist for this product. No conditions are invented.')
    result.update(version=VERSION,llm_used=False,condition_rule_status='Coded, source-bound proof interpreter; unsupported or unreviewed predicates remain unknown',mappings=mappings,paths=paths,operational_exposure=exposure,remaining_issues=list(dict.fromkeys(issues)),typed_proof_trace=trace,typed_review_sha256=digest(bundle),typed_rule_version=VERSION,export_ready=bool(scope_ok and identities),evidence_semantics_independently_verified=False,reviewer_identity_authenticated=False)
    result['evidence_graph']['mapping_trace']=mappings;result['evidence_graph']['verdict_proofs']=decision['proofs']
    for node in result['evidence_graph']['nodes']:
        if node['id']=='vex':node['status']=status
    result['assessment_sha256']=digest({k:v for k,v in result.items() if k!='assessment_sha256'})
    return result
