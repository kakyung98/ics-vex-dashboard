"""Source-bound VEX: attack graph -> asset operational information -> mitigation verification.

No operator-supplied verdict, condition truth or proof conclusion is used.
Natural-language observations use a generative LLM; graph logic is explicit.
The registry is deliberately bounded; unregistered CVEs are never guessed safe.
"""
from copy import deepcopy
from datetime import datetime,timezone
from functools import lru_cache
from pathlib import Path
import hashlib,json,re
from jsonschema import Draft202012Validator,FormatChecker
from src.item4.assets import operating_profile_catalog as M
from src.item4.decision.condition_logic_evaluation import leaves
from src.item4.decision import scoped_vex_review as A
from src.item4.decision import population_condition_rules as P
from src.item4.decision import attack_graph_builder as G
from src.item4.models import operating_record_review_model as N
from src.item4.analysis import exploitation_prerequisites as VEP
from src.item4.decision import exploitability_evaluation as X
from src.item4.workflow import component_review_workflow as W
ROOT=Path(__file__).resolve().parents[3]
VERSION='source-bound-mulval-llm-vep/10'
SCOPE=('asset_ref','product','build','config_baseline','mode','origin')
_SOURCE_SIGNATURES={}
def digest(x):return hashlib.sha256(json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def now():return datetime.now(timezone.utc)
def instant(s):
    try:
        d=datetime.fromisoformat(s.replace('Z','+00:00'));return d if d.utcoffset() is not None else None
    except (ValueError,TypeError,AttributeError):return None
def normalize(s):return ' '.join(re.sub('[^a-z0-9]+',' ',s.casefold()).split())
def scope_hash(profile):return digest({k:profile['scope'][k] for k in SCOPE})

@lru_cache(maxsize=512)
def _checked_blank_profile(serialized):return M.validate(json.loads(serialized))
def check_profile(profile,templates=None):
    # Cached schema checks only for the untouched optional catalogue. Every
    # auto-answer evidence record and its validity window is still checked on
    # every assessment below; current scope-time flags are never cached.
    inventory=profile.get('inventory',{}).get('values',{}) if isinstance(profile,dict) else {}
    gates=profile.get('gates',{}) if isinstance(profile,dict) else {}
    blank=bool(inventory and gates) and all(isinstance(v,dict) and v.get('state')=='unknown' for v in inventory.values()) and all(isinstance(g,dict) and g.get('state')=='unknown' for g in gates.values())
    if templates is not None or not blank:return M.validate(profile,templates)
    result=deepcopy(_checked_blank_profile(json.dumps(profile,sort_keys=True,separators=(',',':'),ensure_ascii=False)))
    at=now();end=instant(profile['scope']['valid_until']);start=instant(profile['scope']['observed_at'])
    result['evidence_expired']=bool(end and end<=at);result['observation_in_future']=bool(start and start>at);result['state']='expired' if result['evidence_expired'] else 'draft'
    return result

def registry():
    directory=ROOT/'data/nist_auto_vex'
    signature=tuple((p.name,p.stat().st_size,p.stat().st_mtime_ns,p.stat().st_ctime_ns) for p in sorted(directory.glob('*.json')))
    return _registry(signature)

@lru_cache(maxsize=2)
def _registry(signature):
    directory=ROOT/'data/nist_auto_vex';data=json.loads((directory/'rules.json').read_text(encoding='utf-8'))
    if digest({k:v for k,v in data.items() if k!='sha256'})!=data['sha256']:raise ValueError('Rule registry integrity changed')
    sources={}
    for sid,item in data['sources'].items():
        s=json.loads((directory/item['file']).read_text(encoding='utf-8'))
        if hashlib.sha256(s['text'].encode()).hexdigest()!=item['sha256']:raise ValueError('Vendor source snapshot changed: '+sid)
        sources[sid]=s
    for r in data['rules'].values():
        refs=[r['source']]+r['fix_sources']+r.get('nonrequirements',[])+[q['source'] for q in r['questions']]
        refs += [u['source_ref'] for u in r.get('unresolved_operands',[])]
        for ref in refs:
            s=sources[ref['source_id']];a,b=ref['span']
            if s['text'][a:b]!=ref['quote'] or ref['source_sha256']!=s['text_sha256']:raise ValueError('Invalid source predicate/fix span')
        if leaves(r['expression'])!={q['id'] for q in r['questions']}:raise ValueError('Predicate/formula mismatch')
        if any(set(q['options']) & {'affected','not_affected','fixed','true','false'} for q in r['questions']):raise ValueError('A questionnaire must ask asset operational information, not conclusions')
    return data

def version_state(rule,version):
    """Manufacturer-specific comparison. Unknown/backported builds stay unknown."""
    if rule['version_scheme']=='csaf_source_set':return P.status(rule,version)
    if rule['version_scheme']=='openssl_letter':
        m=re.fullmatch(r'(0\.9\.8|1\.0\.[012])([a-z]*)',version.strip())
        if not m or (m[2] and not re.fullmatch(r'[a-z]|z[a-z]|zz[a-z]',m[2])):return 'unknown'
        branch,suffix=m.groups();floor=rule['fixed_releases'].get(branch)
        if floor is None:return 'unaffected' if branch in rule.get('unaffected_branches',[]) else 'unknown'
        return 'fixed' if suffix>=floor else 'vulnerable'
    m=re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(?:-h([1-9]\d*))?',version.strip())
    if not m:return 'unknown'
    major,minor,patch,hotfix=int(m[1]),int(m[2]),int(m[3]),int(m[4] or 0)
    if patch>=100:return 'unknown' # Marketplace image labels are not CLI version strings.
    branch=f'{major}.{minor}'
    if branch in rule.get('unaffected_branches',[]):return 'unaffected'
    thresholds=rule['fixed_releases'].get(branch)
    if thresholds:
        maxpatch=max(map(int,thresholds))
        if patch>maxpatch:return 'fixed'
        threshold=thresholds.get(str(patch))
        return 'fixed' if threshold is not None and hotfix>=threshold else 'vulnerable' if threshold is not None else 'unknown'
    if major>11 or (major==11 and minor>1):return 'fixed' # Vendor explicitly: all later PAN-OS versions.
    return 'unknown'

def supported_product(rule,name):return normalize(name) in {normalize(v) for v in rule['product_aliases']}

def rule_for(cve,product):
    specific=registry()['rules'].get(cve)
    if specific and supported_product(specific,product):
        return VEP.vendor_rule(specific,registry())
    compiled=P.make_rule(cve,product)
    return compiled

def plan(cve,profile,product_key=None,record=None,templates=None):
    if not isinstance(cve,str) or not re.fullmatch(r'CVE-\d{4}-\d{4,}',cve):raise ValueError('Invalid CVE ID')
    check_profile(profile,templates);reg=registry();rule=rule_for(cve,profile['scope']['product'])
    # Check current population identity status too; vendor rules do not revive Rejected CVEs.
    try:
        if record is None:
            source_path=A.DATA/('records_'+cve.split('-')[1]+'.json')
            signature=(source_path.stat().st_mtime_ns,source_path.stat().st_size,source_path.stat().st_ctime_ns) if source_path.exists() else None
            if _SOURCE_SIGNATURES.get(str(source_path))!=signature:A.shard.cache_clear();_SOURCE_SIGNATURES[str(source_path)]=signature
            record=A.detail(cve)
    except KeyError:record=None
    if record is not None and record['cve']!=cve:raise ValueError('Source CVE identity mismatch')
    identity_bad=bool(record and (record.get('original_nvd_status')=='Rejected' or record.get('identity_ambiguous')))
    key='compiled-cve:'+cve if rule and rule.get('decision_mode')=='full_population' else 'vendor-rule:'+cve if rule else 'unresolved:'+cve
    if product_key is not None and product_key!=key:raise ValueError('Source product scope or automatic-rule version changed; relink this CVE')
    questions=[];sources=[];expression=None;source_digest=digest(dict(cve=cve,unsupported=True))
    if rule:
        source_digest=digest(dict(rule=rule,registry=reg['sha256'],population_record_digest=record.get('record_digest') if record else None))
        sources=[rule['source']]+rule['fix_sources']+rule.get('nonrequirements',[])
        questions=[dict(id='deployment',label='Is this exact BOM component instance deployed in the assessed operating asset?',nist_fields=['C13-01.01'],options={'running':'Installed and currently deployed','not_deployed':'Absent from the complete deployed-component inventory','mixed':'Multiple instances / deployment scope unresolved','unknown':'Unknown / not verified','conflicting':'Conflicting records'},true_values=['running'],false_values=['not_deployed'],absence_coverage='complete',source=rule['source'],evidence_kinds=['inventory_record','configuration_record','assessment_record'])]
        if not supported_product(rule,profile['scope']['product']):
            # A firmware version must never be substituted for an embedded library version.
            questions.append(dict(id='product_family',label='Which product family does this assessed component instance implement? Use its inventory/vendor record.',nist_fields=['C13-01.01'],options={'expected':rule['product'],'different':'A different product family','mixed':'Several product families / component binding unresolved','unknown':'Unknown','conflicting':'Conflicting records'},true_values=['expected'],false_values=[],source=rule['source'],evidence_kinds=['inventory_record','vendor_document','assessment_record']))
        options={'unknown':'Unknown / running component version not verified','conflicting':'Conflicting version records'};version_values={}
        if supported_product(rule,profile['scope']['product']) and profile['scope']['build'].strip():
            options['bom']='The running component uses BOM version '+profile['scope']['build'];version_values['bom']=profile['scope']['build']
        for rid,r in sorted(profile['reference_values'].items()):
            if r['kind']=='version' and r['asset_ref']==profile['scope']['asset_ref']:
                code='inventory:'+rid;options[code]=r['label'];version_values[code]=r['label']
        questions.append(dict(id='runtime_version',label='Which exact version is executing for this component instance? Select the running software/library version, not an appliance firmware or marketplace image label.',nist_fields=['C13-01.03'],options=options,version_values=version_values,source=rule['fix_sources'][0],evidence_kinds=['inventory_record','configuration_record','test_record','assessment_record']))
        questions+=deepcopy(rule['questions']);expression=deepcopy(rule['expression'])
    component_binding=bool(rule and supported_product(rule,profile['scope']['product']))
    if rule and not component_binding:questions=[];expression=None
    for question in questions:N.annotate(question,profile['scope'],question.get('source') or (rule['source'] if rule else None))
    result=dict(version=VERSION,cve=cve,asset_type_id=profile['asset_type_id'],profile_sha256=digest(profile),scope_sha256=scope_hash(profile),source_digest=source_digest,rule_registry_sha256=reg['sha256'],product=dict(key=key,name=rule['product'] if rule else 'Unresolved source product'),products=[dict(key=key,name=rule['product'] if rule else 'Unresolved source product')],supported=bool(rule) and not identity_bad and component_binding,source_identity_ambiguous=identity_bad,questions=questions,expression=expression,sources=sources,coverage_complete=bool(rule and rule['coverage_complete']),rule_version=reg['version'],policy='Only the server evaluates operational choices. Unsupported CVEs, unclear product/version bindings and missing evidence remain under investigation.',llm_used=bool(rule and (rule.get('prerequisite') or {}).get('llm_used')))
    result['population_member']=P.get(cve) is not None
    result['population_catalogue_sha256']=P.manifest()['sha256'] if result['population_member'] else None
    result['compiler_mode']=rule.get('decision_mode','vendor_specific') if rule else 'missing_cve_source'
    result['untranslated_conditions']=rule.get('compiled_gaps',[]) if rule else []
    result['source_product_binding']='matched' if rule and (not rule.get('decision_mode') or rule.get('source_product_rows')) else 'unresolved'
    result['attack_graph']=G.build(cve,expression,questions,profile['scope'],profile['asset_type_id'],
        result['coverage_complete'],source_digest,result['untranslated_conditions'],sources)
    result['attack_graph_backend']='MulVAL/XSB'
    result['condition_extraction']=dict(default=rule.get('extraction_provider','source_specific_supplier_rules') if rule else 'unresolved_source',
        format=VEP.VERSION, nli_enabled=False, error=rule.get('extraction_error') if rule else None,
        extraction_is_not_independent_semantic_validation=True,
        prerequisite_sha256=(rule.get('prerequisite') or {}).get('sha256') if rule else None)
    result['mitigation_questions']=G.mitigation_questions(questions)
    result['operational_record_policy']=N.policy()
    result['nli_enabled']=False
    result['prerequisite']=deepcopy(rule.get('prerequisite')) if rule else None
    result['prerequisite_format']=VEP.VERSION
    result['workflow']=['build_attack_graph','observe_operating_information','find_attack_paths','verify_mitigations_for_found_paths']
    result['operating_information_catalogue']=dict(source_rows=54,collection_elements=167,
        relevant_field_ids=result['attack_graph']['operational_field_ids'])
    result['policy']='Source-supported product applicability, prerequisite satisfaction, deployment exploitability and product VEX status are reported separately. Blocked modeled paths or verified external controls alone do not establish product not_affected; fixed requires a documented fixed running version. Missing evidence or unresolved paths remain under investigation.'
    result['workflow_contract']=W.contract(result,profile)
    result['plan_sha256']=digest(result);return result

def validate_request(payload):
    allowed={'cve','product_key','profile','plan_sha256','auto_observations'}
    if not isinstance(payload,dict) or set(payload)-allowed:raise ValueError('Only operational observations are accepted. Verdicts, condition-truth bindings and proof/status records are forbidden.')
    if not {'cve','profile','plan_sha256'}<=set(payload):raise ValueError('Missing assessment target, profile or plan hash')
    observations=payload.get('auto_observations',{})
    schema=dict(type='object',maxProperties=200,additionalProperties=dict(type='object',additionalProperties=False,required=['value','evidence_ids','coverage','scope_sha256'],properties=dict(value=dict(type='string',maxLength=2200),evidence_ids=dict(type='array',uniqueItems=True,maxItems=100,items=dict(type='string',maxLength=200)),coverage=dict(enum=['complete','partial']),scope_sha256=dict(type='string',pattern='^[a-f0-9]{64}$'))))
    errors=list(Draft202012Validator(schema).iter_errors(observations))
    if errors:raise ValueError('Invalid operational answer '+str(list(errors[0].absolute_path))+': '+errors[0].message)
    return observations

def evaluate(payload,record=None,templates=None,reviewed_at=None,force_source_refresh=False):
    observations=validate_request(payload);profile=payload['profile'];validation=check_profile(profile,templates)
    current=plan(payload['cve'],profile,payload.get('product_key'),record,templates)
    if payload['plan_sha256']!=current['plan_sha256']:raise ValueError('Source, rule registry, BOM component, operating scope or evidence changed. Rebuild the questionnaire.')
    questions={q['id']:q for q in current['questions']+current['mitigation_questions']}
    if set(observations)-set(questions):raise ValueError('Answer is outside the questions required for this CVE')
    at=now();trace=[];facts={};raw_values={};evidence_used=set();expiry=[instant(profile['scope'].get('valid_until'))]
    reasons=[];scope=profile['scope'];scope_ok=not validation['missing_scope'] and not validation['evidence_expired'] and not validation['observation_in_future']
    def check_evidence(ids,q):
        errors=[]
        if not ids:return ['No original evidence selected.']
        for eid in ids:
            e=profile['evidence'].get(eid)
            if not e:errors.append('Missing evidence '+eid);continue
            if e.get('reviewed') is not True:errors.append('Original evidence is not reviewed: '+eid)
            if e['kind'] not in q['evidence_kinds']:errors.append('Evidence kind does not support this operational fact: '+eid)
            if any(e[k]!=scope[k] for k in ('asset_ref','build','config_baseline')):errors.append('Evidence belongs to another asset/build/baseline: '+eid)
            start,end,observed=instant(e['observed_at']),instant(e['valid_until']),instant(scope['observed_at'])
            if not start or not end or not observed or not start<=observed<=at<=end:errors.append('Evidence is expired, future-dated, or outside the assessment observation time: '+eid)
        return errors
    record_budget=64
    for qid,q in questions.items():
        answer=observations.get(qid);value=answer['value'] if answer else 'unknown';errors=[];truth='unknown';actual=None;comparison=None
        if value not in q['options']:raise ValueError('Invalid operational choice for '+qid)
        if answer and answer['scope_sha256']!=current['scope_sha256']:errors.append('Operational answer belongs to a different asset/component/mode/origin.')
        if value not in ('unknown','conflicting','mixed'):
            errors+=check_evidence(answer['evidence_ids'],q)
            if qid in ('deployment','runtime_version','product_family') and answer['coverage']!='complete':errors.append('Identity and running-version observations need complete coverage of this component instance.')
            if value in q.get('false_values',[]) and answer['coverage']!='complete':errors.append('An absence/negative operational finding requires complete scoped evidence.')
            if q.get('requires_effectiveness_record'):
                if answer['coverage']!='complete':errors.append('Post-mitigation verification requires complete scoped coverage.')
                if not any(profile['evidence'].get(eid,{}).get('kind') in ('test_record','assessment_record') for eid in answer['evidence_ids']):
                    errors.append('A test or assessment record verifying control effectiveness on this path is required.')
            if qid=='runtime_version':
                actual=q['version_values'][value]
                if value.startswith('inventory:'):
                    refs=profile['reference_values'][value[len('inventory:'):]]['evidence_ids']
                    if not set(refs)<=set(answer['evidence_ids']):errors.append('Selected version record evidence is not linked to this answer.')
            elif value in q.get('true_values',[]):truth='true'
            elif value in q.get('false_values',[]):truth='false'
            if value=='from_evidence':
                comparison=dict(requested=True,executed=False,value='unknown',reasons=list(errors))
                allowed={'configuration_record','operating_record','assessment_record','test_record'}
                if any(profile['evidence'].get(eid,{}).get('kind') not in allowed for eid in answer['evidence_ids']):
                    errors.append('Natural-language operating observations need actual configuration, operating, test or assessment records, not vendor documentation alone.')
                if len(answer['evidence_ids'])>record_budget:errors.append('Operating record budget exceeded for this assessment')
                if not errors:
                    records=[dict(profile['evidence'][eid],id=eid) for eid in answer['evidence_ids']]
                    record_budget-=len(records)
                    comparison=N.compare(q,records,answer['coverage'])
                    truth=comparison['value'];errors.extend(comparison['reasons'])
                else:comparison['reasons']=list(errors)
        elif value in ('conflicting','mixed'):errors.append('Conflicting or mixed operational records remain unknown.')
        if errors:truth='unknown';actual=None
        elif value not in ('unknown','conflicting','mixed'):
            evidence_used.update(answer['evidence_ids'])
            expiry.extend(instant(profile['evidence'][eid]['valid_until']) for eid in answer['evidence_ids'])
        facts[qid]=truth;raw_values[qid]=actual
        trace.append(dict(question_id=qid,nist_fields=q['nist_fields'],operational_choice=value,computed_value=truth,actual_version=actual,evidence_ids=answer['evidence_ids'] if answer else [],reasons=errors,source=q['source'],evaluation_method='operating_record_generative_llm' if comparison else 'structured_operational_observation',record_review=comparison,nli=None))
        trace[-1]['operating_records']=[dict(id=eid,sha256=digest(profile['evidence'][eid]),
            record=deepcopy(profile['evidence'][eid])) for eid in trace[-1]['evidence_ids'] if eid in profile['evidence']]
    rule=rule_for(payload['cve'],scope['product'])
    facts.update(rule.get('implicit_values',{}) if rule else {})
    runtime=raw_values.get('runtime_version');version=version_state(rule,runtime) if rule and runtime else 'unknown'
    path_values,path_trace=P.path_bindings(rule,runtime) if rule else ({},[])
    facts.update(path_values)
    analysis=X.analyse(current,facts,version,trace,scope_ok=scope_ok,
        product_ok=bool(rule and supported_product(rule,scope['product'])),
        runtime_matches_bom=not runtime or runtime==scope['build'],rule_present=bool(rule),source_bindings=path_trace)
    status=analysis['status'];reason=analysis['reason'];initial_status=analysis['initial_status']
    resolution_basis=analysis['resolution_basis'];graph_result=analysis['graph_result']
    post_graph=analysis['post_graph'];formula_value=analysis['formula_value'];verified_controls=analysis['verified_controls']
    remaining=[e for t in trace for e in t['reasons']]
    if status=='under_investigation':remaining.insert(0,reason)
    identity=dict(cve=current['cve'],asset_ref=scope['asset_ref'],product=scope['product'],build=scope['build'],config_baseline=scope['config_baseline'],mode=scope['mode']+' | origin: '+scope['origin'],evaluated_at=at.isoformat())
    decision=dict(cve=current['cve'],status=status,reason=reason,binding=identity,justification=None,
        accepted_evidence_ids=sorted(evidence_used),proofs=[],decision_trace=[])
    decision['resolution_basis']=resolution_basis
    decision['initial_status']=initial_status
    decision['decision_trace']=[dict(check='attack_graph_reachability',graph_sha256=current['attack_graph']['sha256'],
        initial_status=initial_status,graph=graph_result,post_mitigation_graph=post_graph,
        verified_control_questions=verified_controls,resolution_basis=resolution_basis,final_status=status)]
    if path_trace:decision['decision_trace'].append(dict(check='source_path_product_version_binding',bindings=deepcopy(path_trace)))
    if status=='affected':decision['action_statement']='Apply the supplier remediation for this CVE and verify the actual running component version.'
    if status=='not_affected':decision['impact_statement']=reason+' This applies only to the recorded component instance, configuration, operating mode, origin and evidence validity period; it does not assert absence of compromise.'
    if resolution_basis=='verified_path_mitigation':decision['impact_statement']=reason+' Scope: recorded component, configuration, origin and evidence validity period only.'
    if rule and rule.get('decision_mode')=='full_population':
        decision['decision_trace'].append(dict(check='primary_csaf_product_version_status',version_parser=P.PARSER_VERSION,memberships=[dict(product_key=p['key'],source_status=p['status'],version_text=p['version_text'],membership=P.row_membership(p,runtime) if runtime else 'unknown',source_file=p['source_file'],status_pointer=p['status_pointer'],product_pointer=p['product_pointer'],document_sha256=p['document_sha256']) for p in rule['source_product_rows']],unresolved_source_operands=current['untranslated_conditions']))
    result=dict(version=VERSION,cve=current['cve'],asset_type_id=profile['asset_type_id'],product_key=current['product']['key'],evaluated_at=at.isoformat(),reviewed_at=reviewed_at or at.isoformat(),valid_until=min((d for d in expiry if d),default=at).isoformat(),profile_sha256=digest(profile),plan_sha256=current['plan_sha256'],source_digest=current['source_digest'],rule_registry_sha256=current['rule_registry_sha256'],decision=decision,operational_exposure='prerequisites_observed' if formula_value=='true' else 'registered_paths_refuted' if formula_value=='false' else 'unknown',formula_value=formula_value,condition_values=facts,question_trace=trace,mappings=[dict(question_id=t['question_id'],requested_value='computed_from_operational_choice',accepted_value=t['computed_value'],field_ids=t['nist_fields'],profile_evidence_ids=t['evidence_ids'],reasons=t['reasons'],source_refs=[t['source']]) for t in trace],paths=[],scope=deepcopy(scope),profile_validation=validation,remaining_issues=list(dict.fromkeys(remaining)),export_ready=scope_ok,automatic_type_truth=False,llm_used=current['llm_used'],operator_selects_verdict=False,evidence_semantics_independently_verified=False,reviewer_identity_authenticated=False,evidence_graph=dict(nodes=[dict(id='cve',kind='vendor_rule',source_digest=current['source_digest']),dict(id='profile',kind='operating_snapshot',sha256=digest(profile)),dict(id='vex',kind='decision',status=status)],edges=[dict(source='cve',target='profile',relation='typed_predicates'),dict(source='profile',target='vex',relation='attack_graph_reachability')],mapping_trace=trace))
    result['workflow_contract']=current['workflow_contract']
    result.update(analysis['assessment_dimensions'])
    result['exploitability_analysis_version']=X.VERSION
    result['source_path_binding_trace']=path_trace
    result['attack_graph']=current['attack_graph'];result['attack_graph_evaluation']=graph_result
    result['operational_record_review']=dict(policy=N.policy(),requested=sum(bool(t['record_review']) for t in trace),
        executed=sum(bool(t['record_review'] and t['record_review']['executed']) for t in trace),
        comparisons=[dict(question_id=t['question_id'],**t['record_review']) for t in trace if t['record_review']])
    result['nli_used']=False
    result['prerequisite']=current['prerequisite']
    result['paths']=[dict(kind='reachable_prerequisite_witness',node_ids=graph_result['witness_nodes'],graph_sha256=graph_result['graph_sha256'])] if graph_result['path_found'] else []
    result['mitigation_review']=dict(required=initial_status=='affected',questions=current['mitigation_questions'] if initial_status=='affected' else [],
        verified_question_ids=verified_controls,post_graph=post_graph,resolution_basis=resolution_basis,
        all_paths_blocked=bool(verified_controls and post_graph['no_path_proven']),
        pending=status=='affected' and not bool(verified_controls and post_graph['no_path_proven']),status_semantics='fixed requires a documented software fix; verified external controls block modeled paths without changing vulnerable-product status to not_affected')
    result['assessment_sha256']=digest(result);return result

def export(payload,kind='openvex',record=None,templates=None,reviewed_at=None):
    result=evaluate(payload,record,templates,reviewed_at,True)
    if kind=='review':return result
    if kind!='openvex':raise ValueError('Supported exports: review, openvex')
    if not result['export_ready']:raise ValueError('Complete current asset scope and evidence validity before export')
    d=result['decision'];statement=dict(vulnerability=dict(name=result['cve']),products=[{'@id':'urn:ics-vex:component-snapshot:'+digest({k:result['scope'][k] for k in SCOPE})}],status=d['status'],status_notes=json.dumps(dict(reason=d['reason'],scope=result['scope'],source_digest=result['source_digest'],rule_registry_sha256=result['rule_registry_sha256'],assessment_sha256=result['assessment_sha256'],valid_until=result['valid_until'],formula_value=result['formula_value'],graph_sha256=result['attack_graph']['sha256'],resolution_basis=d['resolution_basis'],initial_status=d['initial_status'],operational_record_review_sha256=digest(result['operational_record_review']),prerequisite_sha256=(result.get('prerequisite') or {}).get('sha256'),nli_used=result['nli_used'],product_applicability=result['product_applicability'],prerequisite_status=result['prerequisite_status'],deployment_exploitability=result['deployment_exploitability'],product_vex_status=result['product_vex_status']),ensure_ascii=False))
    for key in ('action_statement','impact_statement'):
        if d.get(key):statement[key]=d[key]
    document={'@context':'https://openvex.dev/ns/v0.2.0','@id':'urn:sha256:'+result['assessment_sha256'],'author':payload['profile']['scope']['reviewer'],'timestamp':result['evaluated_at'],'version':1,'statements':[statement]}
    schema=json.loads((ROOT/'data/standards/openvex-schema.json').read_text(encoding='utf-8'));Draft202012Validator(schema,format_checker=FormatChecker()).validate(document)
    return document
