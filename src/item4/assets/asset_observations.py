"""Source-bound operating atoms and confidence-filtered LLM questions."""
from copy import deepcopy
from functools import lru_cache
from pathlib import Path
from src.item4.assets import question_record_context as RECORD_CONTEXT
from src.item4.analysis import operating_information_requirements as INFORMATION
import csv
import gzip
import hashlib
import io
import json
import re

VERSION='item4-source-operating-input/5-information-requirements'
ROOT=Path(__file__).resolve().parents[3]
# The catalogue is a naming/reference dictionary, never a list of mandatory inputs.
CATALOGUE=ROOT/'benchmark/item4_evaluation/catalog/operator_asset_keys_clustered.csv'
VALUES={'o','x','unknown','not_applicable','mixed'}
OPTIONS=[dict(code=k,label=v) for k,v in [('unknown','Unknown'),('o','o · Yes'),
    ('x','x · No'),('not_applicable','Not applicable'),('mixed','Conflicting records')]]

# Exact positive enabled-feature atoms only. Do not reduce names to keywords,
# strip port qualifiers, infer credentials, or treat configured ACLs as reachability.
ENABLED_TARGETS={
 'http_listener_enabled':('HTTP','HTTP service','HTTP server'),
 'https_listener_enabled':('HTTPS','HTTPS service','HTTPS server'),
 'ssh_listener_enabled':('SSH','SSH service','SSH server'),
 'telnet_listener_enabled':('Telnet','Telnet service'),
 'snmp_listener_enabled':('SNMP','SNMP agent'),
 'ftp_server_enabled':('FTP','FTP server','FTP service'),
 'modbus_server_enabled':('Modbus server',),'opcua_server_enabled':('OPC UA server',),
 'rdp_listener_enabled':('RDP','RDP service','RDP server'),
 'smb_listener_enabled':('SMB server','SMB service'),
 'ssl_vpn_enabled':('SSL VPN',),'ipsec_vpn_enabled':('IPsec VPN',),
 'winrm_listener_enabled':('WinRM','WinRM service'),
 'netconf_enabled':('NETCONF','NETCONF service'),
 'restconf_enabled':('RESTCONF','RESTCONF service'),
 'saml_auth_enabled':('SAML authentication',),'mqtt_broker_enabled':('MQTT broker',),
}

def normalize(value):return ' '.join(str(value).casefold().split())

def condition_identity(value):
    """Use the same IDs in generation and display regardless of caller digest."""
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()

@lru_cache(maxsize=2)
def _catalogue(raw):
    text = gzip.decompress(raw) if raw.startswith(b'\x1f\x8b') else raw
    rows=list(csv.DictReader(io.StringIO(text.decode('utf-8-sig'))))
    types={};seen=set()
    for r in rows:
        aid,key=r['asset_type_id'],r['key']
        if not re.fullmatch(r'A00(?:0[1-9]|1[0-8])',aid) or not re.fullmatch(r'[a-z][a-z0-9_]*',key) or (aid,key) in seen:
            raise ValueError('Invalid or duplicate asset-key catalogue entry.')
        seen.add((aid,key))
        types.setdefault(aid,[]).append(dict(key=key,label=key.replace('_',' '),
            label_ko=r['확인항목'],scope_kind=r['확인대상단위'],
            yes_criterion=r['o_판정기준'],no_criterion=r['x_판정기준'],
            evidence_guidance=r['확인자료'],purpose=r['VEX_대조항목'],
            selection_basis=r['선정근거'],asset_type_id=aid,
            asset_name=r['asset_type_en'],source=r['MITRE_자산유형출처']))
    if set(types)!={f'A{i:04}' for i in range(1,19)}:
        raise ValueError('All 18 asset types are required in the catalogue.')
    return dict(version=VERSION,sha256=hashlib.sha256(raw).hexdigest(),asset_types=types,question_count=len(rows))

def catalogue():return deepcopy(_catalogue(CATALOGUE.read_bytes()))

def classifications(job):
    result=job.get('asset_classification') or {}
    entries=result.get('component_classifications')
    if entries is None:entries=[dict(result,component_ref=
        result.get('component_ref') or job.get('representative',{}).get('ref'))]
    return {e['component_ref']:e['asset_type_id'] for e in entries if e.get('status')=='classified'
            and e.get('component_ref') and e.get('asset_type_id')}

def build(job,digest,cat=None,raw=False):
    from src.item4.decision import asset_vex_assessment as E
    from src.item4.decision.condition_logic_evaluation import leaves
    from src.item4.assets.source_question_policy import POLICY, admitted, extraction_admitted
    from src.item4.analysis.prerequisite_taxonomy import category
    cat=cat or catalogue();types=classifications(job)
    context,cases=E.controls(job)
    questions=[];unmapped=[];results={r['cve']:r for r in job.get('conditions',[])}
    for case in cases:
        result=results.get(case['cve'],{})
        draft=(result.get('prerequisite') or {}).get('draft',{}) if result.get('source_kind')=='CVE description' else {}
        available=cat['asset_types'].get(types.get(case['declared_ref']),[])
        scenario_ids={a['id']:[s.get('id') for s in draft.get('scenarios',[])
            if a['id'] in leaves(s['expression'])] for a in draft.get('prerequisites',[])}
        for atom in draft.get('prerequisites',[]):
            if atom.get('necessity','required') not in {'required','alternative'}:continue
            if not scenario_ids[atom['id']]:
                unmapped.append(dict(case_id=case['id'],cve=case['cve'],condition_id=atom['id'],
                    reason='condition_not_bound_to_source_scenario',value='unknown'))
            if (atom.get('operator_observable') is not True or not atom.get('source_refs')
                or not atom.get('operational_quote') or not atom.get('observation')
                or atom.get('operator')!='eq' or atom.get('expected') is not True):continue
            candidates=[]
            if (atom.get('predicate')=='feature_enabled' and normalize(atom.get('value','')) in {'','enabled','true'}
                and atom['observation'].get('quantifier','single')=='single'):
                candidates=[r for r in available if normalize(atom['target']) in
                    {normalize(a) for a in ENABLED_TARGETS.get(r['key'],())}]
            match=candidates[0] if len(candidates)==1 else None
            key=match['key'] if match else 'cve_fact_'+atom['id']
            q=dict(id='source-'+condition_identity([case['id'],atom['id'],key])[:24],key=key,
                label=atom['statement'],cve=case['cve'],component_ref=case['declared_ref'],condition_id=atom['id'],
                case_id=case['id'],asset_type_id=types.get(case['declared_ref']),question_group='cve_special',
                scope_id='condition:'+condition_identity([case['declared_ref'],case['cve'],atom])[:24],scope_kind=atom['target'],
                source_refs=deepcopy(atom['source_refs']),operational_quote=atom['operational_quote'],
                condition_ids=[atom['id']],category=category(atom),predicate=atom['predicate'],
                ics_context=deepcopy(atom.get('ics_context',[])),
                extraction_confidence=atom.get('extraction_confidence'),review_status=atom.get('review_status','pending'),
                extraction_admitted=extraction_admitted(atom.get('extraction_confidence')) and atom.get('review_status')!='rejected',
                observation=deepcopy(atom['observation']),
                binding='exact_positive_feature_target' if match else 'direct_source_condition',
                yes_criterion='Confirmed true for this component, target and assessment scope: '+atom['statement'],
                no_criterion='Confirmed false throughout this component, target and assessment scope: '+atom['statement'],
                options=deepcopy(OPTIONS),answer_type='single_choice',default='unknown',
                provenance='operator_attestation_not_independently_verified')
            if match:q['catalogue_definition']=deepcopy(match)
            q['condition_mapping']=dict(condition_id=atom['id'],scenario_ids=scenario_ids[atom['id']],
                component_ref=case['declared_ref'],cve=case['cve'],target=atom['target'],
                scope_id=q['scope_id'],asset_type_id=q['asset_type_id'],
                catalogue_keys=[match['key']] if match else [],
                selection='v2_extracted_condition',scenario_relation='stated' if scenario_ids[atom['id']] else 'unresolved',
                source_refs=deepcopy(atom['source_refs']))
            q['information_requirement']=INFORMATION.for_question(atom,q,cat)
            q['asset_record_context']=RECORD_CONTEXT.bind(q,cat['sha256'])
            questions.append(q)
    visible=[];gaps=[];rejections=[]
    extraction_rejections=[dict(case_id=q['case_id'],cve=q['cve'],condition_id=q['condition_id'],
        confidence=q['extraction_confidence'],reason='V2 extraction confidence must exceed 0.8 and the condition must not be rejected; condition remains Unknown.')
        for q in questions if not q['extraction_admitted']]
    if raw:visible=deepcopy([q for q in questions if q['extraction_admitted']])
    else:
        from src.item4.analysis import asset_operating_question_generation as V3
        for case in cases:
            scoped=[q for q in questions if q['case_id']==case['id'] and q['extraction_admitted']]
            if not scoped:continue
            payload=V3.packet(job,case,scoped)
            artifact=job.get('question_generations',{}).get(case['id'])
            if not V3.accepted(artifact,payload):
                gaps.append(dict(case_id=case['id'],cve=case['cve'],reason=(artifact or {}).get('error','Source-bound questions have not been generated for the current source and asset context.')))
                continue
            for q in scoped:
                row=artifact['prediction']['questions'].get(q['condition_id'])
                if row is None:
                    failure=artifact.get('condition_failures',{}).get(q['condition_id'],{})
                    gaps.append(dict(case_id=case['id'],cve=case['cve'],condition_id=q['condition_id'],
                        reason=failure.get('failure',{}).get('message','Question generation attempts exhausted; condition remains Unknown.')))
                    continue
                if not admitted(row.get('confidence')):
                    rejections.append(dict(case_id=case['id'],cve=case['cve'],condition_id=q['condition_id'],confidence=row.get('confidence'),reason='LLM-reported confidence must exceed 80/100. The unasked condition remains Unknown.'))
                    continue
                q=deepcopy(q);q.update(label=row['question'].rstrip().rstrip('.?!')+'?',positive_fact=row['positive_fact'],
                    operating_check=row['check'].replace(row['record_type'],row['record_type'].replace('_',' ')),
                    llm_confidence=row['confidence'],confidence_kind=POLICY['confidence_kind'],
                    question_confidence=row['confidence']/100,
                    question_generation_sha256=artifact['sha256'],question_generator=artifact.get('model'),question_llm_used=artifact.get('llm_used'))
                visible.append(q)
    from src.item4.assets.condition_coverage import coverage
    coverage_rows=coverage(job,cases,visible,extraction_rejections,rejections)
    absence=[]
    for case in cases:
        if any(q['case_id']==case['id'] for q in visible):continue
        result=results.get(case['cve'],{});artifact=result.get('prerequisite') or {}
        atoms=artifact.get('draft',{}).get('prerequisites',[])
        if (artifact.get('coverage_review') or {}).get('status')=='failed':
            reason='source_review_failed';detail=artifact['coverage_review'].get('error')
        elif not artifact:
            reason='extraction_unavailable';detail=result.get('reason','Source extraction is unavailable.')
        elif not atoms:
            reason='no_operating_conditions';detail='No source-supported operating condition was extracted; this is not a confidence rejection.'
        elif any(r['case_id']==case['id'] for r in extraction_rejections):
            reason='extraction_confidence_rejected';detail='No eligible V2 condition passed the extraction confidence/review gate.'
        elif any(r['case_id']==case['id'] for r in rejections):
            reason='question_confidence_rejected';detail='No generated V3 question exceeded 80/100.'
        else:
            reason='question_unavailable';detail='Questions are ungenerated, invalid, failed, or not bound to an executable condition.'
        absence.append(dict(case_id=case['id'],cve=case['cve'],reason=reason,detail=detail))
    return dict(asset_questions=visible,questions=questions,special_questions=visible,
        unmapped_source_conditions=unmapped,
        question_selection=dict(mode='v2_extracted_conditions_only',asset_catalogue_is_question_source=False,
            mapped_conditions=len(questions),visible_questions=len(visible),unplaced_conditions=len(unmapped)),
        question_absence_reasons=absence,
        extraction_confidence_rejections=extraction_rejections,condition_coverage=coverage_rows,
        question_generation_gaps=gaps,question_confidence_rejections=rejections,question_policy=deepcopy(POLICY),
        context_questions=context,assessment_cases=cases,catalogue_sha256=cat['sha256'],
        asset_key_counts={aid:len(items) for aid,items in cat['asset_types'].items()})


def prepare(job,digest):
    from src.item4.decision.asset_vex_assessment import CONTROLS_VERSION; from src.item4.decision.asset_vex_assessment import VERSION as assessment_version; from src.item4.decision.asset_vex_assessment import controls

    from src.item4.analysis import asset_operating_question_generation as V3
    from src.item4.assets.source_question_policy import POLICY
    cat=catalogue()
    signature=digest(dict(contract=VERSION,information_requirements=INFORMATION.signature(),record_context=RECORD_CONTEXT.signature(),v3_contract=V3.VERSION,v3_prompt=V3.digest(V3.SYSTEM),question_policy=POLICY,binding_vocabulary=ENABLED_TARGETS,catalogue=cat['sha256'],bom=job['bom_sha256'],
        asset=job.get('asset_classification'),conditions=job.get('conditions',[]),status=job['status'],
        components=job.get('components',[]),declared_cves=job.get('declared_cves',[]),
        representative=job.get('representative'),question_generations=job.get('question_generations',{})))
    previous=deepcopy(job)
    if job.get('asset_input_contract')!=VERSION or job.get('plan_sha256')!=signature:
        legacy=job.get('asset_input_contract')!=VERSION
        if legacy and job.get('asset_input_contract'):
            job.setdefault('operating_input_history',[]).append({k:deepcopy(job.get(k)) for k in (
                'asset_input_contract','plan_sha256','revision','answers','context_answers','answer_provenance','assessment','question_generations')})
        job.update(build(job,digest,cat) if job['status']=='completed' else dict(
            asset_questions=[],questions=[],special_questions=[],question_confidence_rejections=[],question_policy=POLICY,context_questions=[],assessment_cases=[],catalogue_sha256=cat['sha256']))
        job.update(asset_input_contract=VERSION,plan_sha256=signature,answers={},context_answers={},
            answer_provenance={},asked_question_ids=[],assessment=None,assessment_state='awaiting_inputs',
            product_vex_status='under_investigation')
        job['revision']=job.get('revision',0)+1
        from src.item4.assets.condition_coverage import coverage
        job['condition_coverage']=coverage(job,job['assessment_cases'],job['asset_questions'],job.get('extraction_confidence_rejections',[]),job.get('question_confidence_rejections',[]))
        if legacy:job['migration_note']='Source-only operating questions installed. Only questions with LLM-reported confidence above 80/100 are shown. Previous inputs are retained for audit; reconfirm current observations.'
    elif job['status'] == 'completed' and job.get('context_controls_version') != CONTROLS_VERSION:
        job['context_questions'], job['assessment_cases'] = controls(job)
        for case in job['assessment_cases']:
            job['context_answers'].pop(case['prefix'] + 'inventory_coverage', None)
        job.update(assessment=None, assessment_state='inputs_saved', product_vex_status='under_investigation',
                   revision=job['revision'] + 1)
    elif job.get('assessment') and job['assessment'].get('version') != assessment_version:
        job.update(assessment=None, assessment_state='inputs_saved', product_vex_status='under_investigation',
                   revision=job['revision'] + 1)
    job.update(version=VERSION,context_controls_version=CONTROLS_VERSION,operating_questionnaire_enabled=True,methodology_required=False)
    job['special_source_refresh_required']=any(r.get('source_kind')!='CVE description' or
        r.get('source_policy')!='cve-description-special/1' or
        any('extraction_confidence' not in a or 'category' not in a for a in (r.get('prerequisite') or {}).get('draft',{}).get('prerequisites',[]))
        for r in job.get('conditions',[]))
    job['source_review_retry_required']=any(((r.get('prerequisite') or {}).get('coverage_review') or {}).get('status')=='failed'
        for r in job.get('conditions',[]))
    job['question_generation_required']=bool(job.get('question_generation_gaps'))
    from src.item4.analysis.operating_question_tree import build as build_trees
    job['operating_question_trees']=build_trees(job,job.get('assessment_cases',[]),job.get('asset_questions',[]))
    job['agents']=[dict(id='asset_classification',number=1,code='V1',name='Asset classification'),
        dict(id='prerequisite_extraction',number=2,code='V2',name='Exploitation prerequisite extraction'),
        dict(id='asset_key_input',number=3,code='V3',name='Asset-aware LLM operating questions',state=job.get('question_state','not_generated')),
        dict(id='exploitability_vex_generation',number=4,code='V4',name='Exploitability and VEX',state=job['assessment_state'])]
    job['policy']='CVE-source prerequisites only; V2 extraction confidence >0.8 and V3 question confidence >80/100 are required. Self-reported confidence is not calibrated accuracy. Unknown and unasked conditions remain Unknown.'
    for key in ('common_questions','cvss_plans','common_question_schema','context_specific_questions','context_specific_question_gaps'):
        job.pop(key,None)
    job['unresolved']=[dict(cve=r['cve'],reason=reason) for r in job.get('conditions',[])
        for reason in ((r.get('prerequisite') or {}).get('draft',{}).get('unknowns',[]) or
            ([r.get('reason','Prerequisite extraction remains unresolved.')] if r.get('status')!='extracted' else []))]
    return job!=previous
