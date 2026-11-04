import json
from src.grounded_role_tasks import weak_conditions,check_conditions,check_writer,evaluate


def packet():
    return {'description':'The parse_frame() function is used when diagnostic mode is enabled. Remote attackers send crafted frames.'}


def test_functions_are_grounded_candidates_not_absence_or_verdict():
    p=packet();g=weak_conditions(p['description'])
    assert g['function_candidates'][0]['name']=='parse_frame'
    assert all(check_conditions(p,g).values())
    assert g['can_refute'] is False and g['assessment']=='partial'
    unknown=weak_conditions('An implementation flaw has an unspecified impact.')
    assert unknown['function_status']=='unresolved' and unknown['function_candidates']==[]


def test_unsupported_quote_and_clearance_authority_are_rejected():
    p=packet();g=weak_conditions(p['description'])
    g['conditions'][0]['evidence']='requires physical access'
    g['can_refute']=True
    checks=check_conditions(p,g)
    assert not checks['quotes_supported'] and not checks['policy_preserved']


def writer():
    p={'vulnerability':'CVE-2099-99999','product':'simulation-1','simulation':True,'decision':{'status':'under_investigation','justification':None},'evidence':[{'id':'e1','text':'unknown applicability'}]}
    d={'vulnerability':p['vulnerability'],'product':p['product'],'status':'under_investigation','justification':None,'impact_statement':'In this simulated scenario, applicability remains unknown.','evidence_refs':['e1'],'action_statement':None}
    return p,d


def test_writer_cannot_change_status_or_invent_evidence():
    p,d=writer();assert all(check_writer(p,d).values())
    d['status']='not_affected';d['evidence_refs']=['invented']
    checks=check_writer(p,d)
    assert not checks['decision_preserved'] and not checks['evidence_refs_valid']


def test_bad_generated_types_do_not_crash_evaluation():
    p=packet();g=weak_conditions(p['description']);g['conditions'][0]['kind']={}
    assert not check_conditions(p,g)['schema_valid']
    p,d=writer();d['impact_statement']={}
    assert not check_writer(p,d)['schema_valid']
    assert not check_writer(p,d)['simulation_disclosed']


def test_reference_agreement_is_not_expert_semantic_accuracy():
    p=packet();g=weak_conditions(p['description'])
    r={'id':'case','packet':p,'annotation_basis':'weak','messages':[{'content':json.dumps(g)}]}
    metrics,_=evaluate('cve-conditions',[r],[json.dumps(g)])
    assert metrics['reference_exact_agreement']==1
    assert metrics['semantic_correctness_expert_evaluated'] is False
