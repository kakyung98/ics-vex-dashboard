
from src.dataset_paths import public_sbom_file
import json
from copy import deepcopy
from pathlib import Path
import pytest
from src import vex_roles as VR,operational_questions as OQ,review_store
from src.cve_source_evidence import catalog,resolve_selection,documents
from src.grounded_role_tasks import check_writer,writer_diagnostics
from src.operational_versions import assets_for,compare_case,formal_version_status
from tests.test_shared_vex_pipeline import provider,DESCRIPTION

def test_rule_extraction_preserves_literal_quotes_without_model_retry(monkeypatch):
    calls=[]
    monkeypatch.setattr(VR,'infer',lambda *a:calls.append(a))
    x=VR.extraction('CVE-2099-88888',DESCRIPTION)
    assert x['usable'] and x['strategy']=='deterministic_source_spans' and not calls
    assert all(c['evidence'] in DESCRIPTION for c in x['prediction']['conditions'])

def test_unknown_ids_or_version_scope_cannot_be_operational_conditions():
    sources=[{'id':'v','text':'This issue affects Foo before 1.2.3.','condition_eligible':False,'source_kind':'description'}]
    pred={'conditions':[{'kind':'configuration','evidence_ids':['v'],'necessity':'explicit'}],
          'function_candidates':[],'function_status':'unresolved','assessment':'partial','can_refute':False}
    assert resolve_selection(sources,pred)[0] is None
    pred['conditions'][0]['evidence_ids']=['invented'];assert resolve_selection(sources,pred)[0] is None

def test_optional_writer_metadata_does_not_falsely_report_identity_or_decision_errors():
    packet={'vulnerability':'CVE-2026-64893','product':'target','simulation':False,'decision':{'status':'under_investigation','justification':None},'evidence':[{'id':'e','text':'unknown'}]}
    pred={'vulnerability':packet['vulnerability'],'product':'target','status':'under_investigation','justification':None,
          'impact_statement':'Evidence incomplete.','evidence_refs':['e'],'action_statement':None,'missing_evidence':['version']}
    assert all(check_writer(packet,pred).values())
    assert writer_diagnostics(pred)['warnings']==['optional_metadata_separated:missing_evidence']
    pred['unexpected']=True;checks=check_writer(packet,pred)
    assert not checks['schema_valid'] and checks['decision_preserved'] and checks['identifiers_preserved']

@pytest.mark.parametrize('family,release,expected',[('EC','V3.3b64','listed_fixed'),('CW','V3.3b26','listed_fixed'),('EC','V3.3b63','listed_affected'),('EC','V3.3b65','unknown')])
def test_actual_pinned_csaf_version_scope_without_lexical_guessing(family,release,expected):
    c={'cve':'CVE-2026-64893','product':'fixture','mappings':[{'component_id':'ec','component':'fixture'}]}
    facts={'ec':{'present':'yes','product_name':'Johnson Controls EasyIO Neo Series '+family+' Controllers','installed_version':release,'evidence':'Simulated record','attested':True}}
    r=compare_case(c,assets_for([c]),facts)
    assert r['components'][0]['state']==expected
    assert formal_version_status(r)[0]==('fixed' if expected=='listed_fixed' else 'under_investigation')
    facts['ec']['attested']=False
    assert not compare_case(c,assets_for([c]),facts)['version_decided']

def test_product_family_cannot_be_guessed_from_version():
    c={'cve':'CVE-2026-64892','product':'fixture','mappings':[{'component_id':'ec','component':'fixture'}]}
    facts={'ec':{'present':'yes','product_name':'Wrong Vendor EC','installed_version':'V3.3b64','evidence':'Simulated record','attested':True}}
    assert compare_case(c,assets_for([c]),facts)['components'][0]['state']=='unknown'

def fake_provider(monkeypatch):
    fallback=provider([])
    def run(role,packet):
        if role=='cve-conditions':
            return {'prediction':{'conditions':[],'function_candidates':[],'function_status':'unresolved','assessment':'partial','can_refute':False}}
        if role=='operation-questions':
            s=next(s for s in packet['sources'] if s['condition_eligible'])
            return {'prediction':{'questions':[{'question':'On this asset, is the documented management interface used?',
                'purpose':'Identify the operating path.','kind':'discovery','answer_type':'yes_no_unknown','evidence_ids':[s['id']]}]}}
        if role=='operation-assessment':
            return {'prediction':{'assessment':'likely_affected','explanation':'The asset is likely affected. RAW SUGGESTION MUST NOT BECOME FACT.',
                'answer_refs':[packet['questions_and_answers'][0]['id']],'missing_evidence':['Installed version']}}
        return fallback(role,packet)
    monkeypatch.setattr(VR,'infer',run)

def plan(monkeypatch):
    fake_provider(monkeypatch)
    sbom={'bomFormat':'CycloneDX','specVersion':'1.7','version':1,'metadata':{'component':{'type':'application','name':'Test asset'}},
        'components':[{'bom-ref':'ec','name':'EC fixture','type':'firmware','version':'NOASSERTION'},
                      {'bom-ref':'cw','name':'CW fixture','type':'firmware','version':'NOASSERTION'}],
        'dependencies':[{'ref':'ec','dependsOn':[]}],'properties':[{'name':'preserved','value':'original'}],
        'vulnerabilities':[{'id':'CVE-2026-64893','description':'Original vulnerability metadata','affects':[{'ref':'ec'}]}]}
    desc='Cleartext Transmission of Sensitive Information vulnerability in Johnson Controls EasyIO NEO allows Man In the Middle Attack.'
    c={'cve':'CVE-2026-64893','description':desc,'mappings':[{'component_id':'ec','component':'EC fixture'},{'component_id':'cw','component':'CW fixture'}]}
    return sbom,OQ.create([c],'Test asset','repair-regression',simulation=True,sbom=sbom)

def test_unknown_versions_and_empty_evidence_cannot_leak_raw_likely_affected_prose(monkeypatch):
    sbom,p=plan(monkeypatch);r=OQ.assess(p['id'],{});s=r['statements'][0]
    assert s['operational_assessment']=='likely_cannot_determine' and s['status']=='under_investigation'
    assert s['operational_review']['assessment']['llm_used'] is False
    assert 'RAW SUGGESTION' not in json.dumps(s['evidence_packet'])
    assert all(v['analysis']['state']=='in_triage' for v in r['sbom_vex']['vulnerabilities'])

def test_attested_fixed_version_is_bound_once_and_merged_per_component(monkeypatch):
    original,p=plan(monkeypatch);before=deepcopy(original)
    facts={'ec':{'present':'yes','product_name':'Johnson Controls EasyIO Neo Series EC Controllers',
                 'installed_version':'V3.3b64','evidence':'SIMULATED device firmware record, not an observed asset','attested':True},
           'cw':{'present':'no'}}
    OQ._plans.clear() # Simulate process-memory loss; the plan must survive.
    r=OQ.assess(p['id'],{},facts);s=r['statements'][0]
    assert s['status']=='fixed' and s['operational_review']['version_evaluation']['version_decided']
    assert s['authoring']['status']=='validated_draft'
    out=r['sbom_vex'];by_ref={v['affects'][0]['ref']:v for v in out['vulnerabilities']}
    assert by_ref['ec']['analysis']['state']=='resolved' and by_ref['cw']['analysis']['state']=='in_triage'
    assert out['components'][0]['version']=='V3.3b64' and out['components'][1]==original['components'][1]
    assert out['dependencies']==original['dependencies']
    assert out['vulnerabilities'][0]['description']=='Original vulnerability metadata'
    assert out['version']==2 and original==before
    assert review_store.get('review',p['id'])['sbom_vex']==out
    assert r['sbom_vex_validation']['status']=='valid'

def test_known_input_schema_repairs_are_logged_without_mutating_original():
    from src.sbom_vex import merge
    from src.sbom_schema import validate
    root=Path(__file__).resolve().parents[1]
    original=json.loads((public_sbom_file('icsa-26-274-04_SBOM-CVE.json')).read_text(encoding='utf-8'))
    before=deepcopy(original)
    out=merge(original,{'statements':[]},[])
    assert original==before
    assert validate(out)['status']=='valid'
    assert any(p['name']=='ics-vex:input-normalizations' for p in out['properties'])

def test_bad_feature_reification_is_rejected_even_with_a_literal_quote(monkeypatch):
    fake_provider(monkeypatch)
    p=OQ.create([{'cve':'CVE-2099-12345','description':DESCRIPTION}],'fixture','rule-questions')
    g=p['cases'][0]['generation'];questions=[q for q in p['cases'][0]['questions'] if q['origin']=='rule']
    assert g['llm_used'] is False and g['status']=='validated'
    assert len({q['question'] for q in questions})==len(questions)
    assert all('feature for collecting' not in q['question'] for q in questions)

def test_completed_identification_job_survives_memory_loss(monkeypatch):
    from src import candidate_web
    review_store.put('job','persisted-regression',{'id':'persisted-regression','status':'completed','input_sbom':{'preserved':True}})
    assert candidate_web.get_job('persisted-regression')['input_sbom']=={'preserved':True}


def test_generated_bom_refs_preserve_component_specific_version_scope():
    from src.sbom_vex import merge
    bom={'bomFormat':'CycloneDX','specVersion':'1.7','version':1,'components':[
        {'name':'First','type':'firmware'},{'name':'Second','type':'firmware'}]}
    case={'cve':'CVE-2099-12345','mappings':[{'component_id':'0'},{'component_id':'1'}]}
    rows=[{'component_ref':str(i),'state':state,'operator_attested':True,
           'operator_evidence':'Simulated record','product_name':'Fixture','installed_version':'1.0'}
          for i,state in enumerate(['listed_fixed','not_selected'])]
    st={'cve':case['cve'],'case_id':'scope','status':'fixed','reason':'Scoped fixture.',
        'operational_review':{'version_evaluation':{'components':rows}}}
    out=merge(bom,{'statements':[st]},[case])
    assert {
        v['affects'][0]['ref']:v['analysis']['state'] for v in out['vulnerabilities']}=={
            out['components'][0]['bom-ref']:'resolved',out['components'][1]['bom-ref']:'in_triage'}






def test_truncated_writer_retries_once_without_changing_locked_decision(monkeypatch):
    base=provider([]);calls=[]
    def run(role,packet):
        if role=='vex-writer':
            calls.append(deepcopy(packet))
            if len(calls)==1:return {'prediction':None,'raw':'{"impact_statement":"unfinished','error':'output_token_limit'}
        return base(role,packet)
    monkeypatch.setattr(VR,'infer',run)
    cases=VR.prepare([{'cve':'CVE-2099-12345','description':DESCRIPTION}])
    result=VR.finish({'arm':'operational-context','statements':[{'cve':cases[0]['cve'],
        'status':'under_investigation','justification':None,'reason':'Installed version unknown.'}]},cases)
    w=result['statements'][0]['authoring']
    assert w['status']=='validated_draft' and len(w['attempts'])==2
    assert w['attempts'][0]['raw'].endswith('unfinished')
    assert calls[0]['decision']==calls[1]['decision']
    assert calls[1]['generation_feedback']['generation_error']=='output_token_limit'
    assert w['attempts'][0]['input_sha256']!=w['attempts'][1]['input_sha256']


def test_writer_repeated_sentences_are_not_accepted():
    packet={'vulnerability':'CVE-2099-12345','product':'fixture','decision':{
        'status':'under_investigation','justification':None},'evidence':[{'id':'e'}]}
    pred={**{k:packet[k] for k in ('vulnerability','product')},**packet['decision'],
          'impact_statement':'The installed product version has not been confirmed. '*3,
          'action_statement':None,'evidence_refs':['e']}
    assert not check_writer(packet,pred)['nonrepetitive']
    assert 'repeated_statement' in writer_diagnostics(pred)['errors']
