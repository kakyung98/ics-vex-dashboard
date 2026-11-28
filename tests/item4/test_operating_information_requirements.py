"""Source-to-information-to-question contracts; no independent semantic gold."""
from copy import deepcopy
from unittest.mock import patch
import pytest
from src.item4.analysis import operating_information_requirements as R
from src.item4.analysis import condition_question_contract as C
from src.item4.analysis import asset_operating_question_generation as V3
from src.item4.assets import asset_observations as A
from src.item4.workflow import source_analysis_jobs as Q
from src.item4.decision import assessment_evidence_chain as CHAIN
from tests.item4.test_item4_asset_key_workflow import fixture_job,generate_fixture_questions

CASES=[
 ('feature_enabled','OTHER','configuration','configuration_export','configuration'),
 ('configuration_required','AT','configuration','configuration_export','configuration'),
 ('interface_available','OTHER','service_inventory','service_inventory','input_availability'),
 ('interface_reachable','AV','network_access','firewall_acl','access_path'),
 ('network_reachable','AV','network_access','firewall_acl','access_path'),
 ('maintenance_access','AV','network_access','access_control_record','access_path'),
 ('remote_maintenance','AV','network_access','maintenance_log','access_path'),
 ('authentication_required','PR','access_policy','access_control_record','authentication'),
 ('privilege_required','PR','access_policy','access_control_record','principal_permission'),
 ('configuration_required','AT','operating_mode','configuration_export','operating_state'),
 ('file_import','UI','operating_workflow','operating_event_log','recorded_action'),
 ('input_processed','AT','operating_workflow','operating_event_log','recorded_action'),
 ('external_file_source','OTHER','operating_workflow','operating_procedure','recorded_action'),
 ('user_performs_action','UI','operating_workflow','operating_event_log','recorded_action'),
 ('physical_access','AV','physical_access','access_control_record','physical_access'),
 ('local_console_access','AV','physical_access','maintenance_log','physical_access'),
]


def condition(predicate,category,kind,record_type):
    return dict(id='required',predicate=predicate,category=category,target='source-specified target',value='source-specified value',
        statement='The same source-qualified actor has the specified state or action for the source-specified target.',
        operator='eq',expected=True,operator_observable=True,extraction_confidence=.95,
        operational_quote='Exploitation requires the same source-qualified actor and source-specified target.',
        source_refs=[dict(source_id='fixture',quote='Exploitation requires the same source-qualified actor and source-specified target.')],
        observation=dict(kind=kind,record_type=record_type,check='Inspect the exact source-described record.',quantifier='all'))


@pytest.mark.parametrize('predicate,category,kind,record_type,group',CASES)
@pytest.mark.parametrize('aid,family', [('A0001','host'),('A0003','device'),('A0016','infrastructure'),(None,'unknown')])
def test_every_supported_condition_has_scoped_information_and_accessible_records(predicate,category,kind,record_type,group,aid,family):
    item=condition(predicate,category,kind,record_type);before=deepcopy(item)
    scope=dict(cve='CVE-2099-12345',component_ref='asset',scope_id='scope-1',asset_type_id=aid,asset_name='Fixture asset')
    r=R.compile_condition(item,scope)
    assert r['question_type']==group and r['asset_family']==family
    assert r['source_condition']['statement']==item['statement'] and r['source_condition']['value']==item['value']
    assert r['quantifier']=='all' and r['scope']==scope
    assert r['verification']['source_record_type']==record_type
    assert r['verification']['source_check']==item['observation']['check']
    assert r['verification']['record_sources'] and r['verification']['required_dimensions'] and r['verification']['limitations']
    assert all(s['target']==item['target'] and s['supports_condition_id']=='required' for s in r['verification']['record_sources'])
    assert r['answer_semantics']==dict(yes='true',no='false',unknown='unknown')
    assert r['boolean_expression_modified'] is False and r['asset_mapping']['feature_support_inferred'] is False
    assert r['verification']['operating_values_supplied'] is False
    assert item==before


@pytest.mark.parametrize('aid',[f'A{i:04}' for i in range(1,19)])
def test_all_asset_types_receive_record_plans_without_inferred_operating_values(aid):
    r=R.compile_condition(condition('privilege_required','PR','access_policy','access_control_record'),dict(asset_type_id=aid))
    assert r['asset_mapping']['status']=='type_specific_record_plan'
    assert r['asset_mapping']['profile_record_locations']==['authentication']
    assert r['source_qualifiers']['actor_and_origin'].startswith('not_separately_structured')


def test_at_does_not_imply_operating_mode_and_workflow_does_not_imply_file_ingress():
    ordinary=condition('configuration_required','AT','configuration','configuration_export')
    assert C.source_group(ordinary)=='configuration'
    ordinary['observation']['kind']='operating_mode'
    assert C.source_group(ordinary)=='operating_state'
    user_action=condition('user_performs_action','UI','operating_workflow','operating_event_log')
    r=R.compile_condition(user_action,dict(asset_type_id='A0001'))
    assert r['information_key']=='qualified_user_action' and r['asset_mapping']['profile_record_locations']==[]


@pytest.mark.parametrize('case', [CASES[3],CASES[8],CASES[9],CASES[10],CASES[13]])
def test_real_question_pipeline_receives_and_preserves_requirement(case):
    predicate,category,kind,record_type,group=case
    job,_=fixture_job();job['asset_classification']['asset_type_id']='A0003'
    item=condition(predicate,category,kind,record_type);item['id']='http'
    job['conditions'][0]['prerequisite']['draft']['prerequisites']=[item]
    before=deepcopy(job['conditions'][0]['prerequisite']['draft'])
    generate_fixture_questions(job);A.prepare(job,Q.digest)
    assert len(job['asset_questions'])==1
    q=job['asset_questions'][0];r=q['information_requirement']
    assert r['question_type']==group and q['asset_record_context']['mode']=='typed_condition_records'
    base=A.build(job,V3.digest,raw=True);p=V3.packet(job,base['assessment_cases'][0],base['special_questions'])
    supplied=p['atoms']['http']
    assert supplied['information_requirement']==r
    assert supplied['question_contract']['information_requirement']==r
    assert supplied['asset_record_context']['verification_plan']==r['verification']
    assert job['conditions'][0]['prerequisite']['draft']==before
    bad=deepcopy(base['special_questions']);bad[0]['information_requirement']['source_condition']['target']='another target'
    with pytest.raises(ValueError,match='differs from the source condition'):
        V3.packet(job,base['assessment_cases'][0],bad)


def test_permissions_and_workflow_verification_preserve_qualified_actor_and_limits():
    item=condition('user_performs_action','UI','operating_workflow','operating_event_log')
    item['statement']='A user with higher privileges than the attacker opens the supplied project.'
    r=R.compile_condition(item,dict(asset_type_id='A0001'))
    assert item['statement'] in r['verification']['instruction']
    assert r['source_qualifiers']['preserved_fact']==item['statement']
    assert any('procedure alone' in s for s in r['verification']['limitations'])
    assert not any('administrator' in s['label'].lower() for s in r['verification']['record_sources'])


def test_requirement_changes_invalidate_question_plan_and_export_input_identity():
    job,_=fixture_job();old=job['plan_sha256'];evidence=CHAIN.input_digest(job)
    with patch.dict(R.RULES['configuration'],limits=['Changed record-verification contract']):
        A.prepare(job,Q.digest)
    assert job['plan_sha256']!=old
    job,_=fixture_job();evidence=CHAIN.input_digest(job)
    job['asset_questions'][0]['information_requirement']['label']='Tampered information description'
    assert CHAIN.input_digest(job)!=evidence
