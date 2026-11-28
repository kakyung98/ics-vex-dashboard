"""Condition-driven selection; synthetic responses are not semantic accuracy gold."""
from copy import deepcopy
from unittest.mock import patch
import pytest
from src.item4.assets import asset_observations as A
from src.item4.analysis import asset_operating_question_generation as V3
from src.item4.decision import asset_vex_assessment as E
from src.item4.workflow import source_analysis_jobs as Q
from tests.item4.test_item4_asset_key_workflow import fixture_job,generate_fixture_questions


@pytest.mark.parametrize('aid',[None]+[f'A{i:04}' for i in range(1,19)])
def test_asset_type_never_expands_the_extracted_question_set(aid):
    job,_=fixture_job()
    job['asset_classification'].update(status='classified' if aid else 'unresolved',asset_type_id=aid)
    generate_fixture_questions(job);A.prepare(job,Q.digest)
    assert len(job['asset_questions'])==1
    question=job['asset_questions'][0]
    mapping=question['condition_mapping']
    assert mapping['condition_id']=='http' and mapping['scenario_ids']==['path']
    assert mapping['component_ref']=='asset' and mapping['target']=='HTTP'
    assert mapping['scope_id']==question['scope_id']
    assert question['asset_record_context']['mode'] in {'catalogue_target','source_only'}
    assert job['question_selection']['mode']=='v2_extracted_conditions_only'
    assert job['question_selection']['asset_catalogue_is_question_source'] is False


def test_full_catalogue_never_generates_questions_without_v2_conditions():
    job,_=fixture_job();draft=job['conditions'][0]['prerequisite']['draft']
    draft.update(prerequisites=[],scenarios=[])
    with patch.object(V3.L,'generate') as model:
        job['question_generations']=V3.run_job(job)
    model.assert_not_called()
    result=A.build(job,Q.digest)
    assert result['asset_questions']==[] and result['questions']==[]
    assert A.catalogue()['question_count']==505


def test_unmatched_condition_does_not_import_other_profile_fields():
    job,_=fixture_job();atom=job['conditions'][0]['prerequisite']['draft']['prerequisites'][0]
    atom.update(target='Source feature',statement='Source feature is enabled')
    generate_fixture_questions(job)
    q=A.build(job,Q.digest)['asset_questions'][0]
    assert q['positive_fact']=='Source feature is enabled'
    assert q['condition_mapping']['catalogue_keys']==[]
    assert q['asset_record_context']['fields']==[]
    assert q['asset_record_context']['source_observation']==atom['observation']


def test_missing_relationship_keeps_question_but_cannot_complete_source_logic():
    job,_=fixture_job();draft=job['conditions'][0]['prerequisite']['draft']
    draft['scenarios']=[];generate_fixture_questions(job)
    result=A.build(job,Q.digest)
    assert len(result['asset_questions'])==1
    assert result['asset_questions'][0]['condition_mapping']['scenario_relation']=='unresolved'
    assert result['unmapped_source_conditions'][0]['condition_id']=='http'
    assert any(g['kind']=='required_condition' for g in E.source_gaps(draft))


@pytest.mark.parametrize('mutation',['extra','label','predicate','target','quote','observation'])
def test_v3_packet_rejects_questions_not_bound_to_exact_v2_condition(mutation):
    job,_=fixture_job();base=A.build(job,V3.digest,raw=True)
    qs=deepcopy(base['special_questions']);q=qs[0]
    if mutation=='extra':q['condition_id']='catalogue_only'
    elif mutation=='label':q['label']='A profile feature is enabled'
    elif mutation=='predicate':q['predicate']='configuration_required'
    elif mutation=='target':q['scope_kind']='SSH'
    elif mutation=='quote':q['operational_quote']='A catalogue recommendation'
    else:q['observation']['check']='Inspect another unrelated feature'
    with pytest.raises(ValueError,match='current V2 extracted condition'):
        V3.packet(job,base['assessment_cases'][0],qs)


def test_mapping_and_cache_identity_are_independent_of_caller_digest():
    job,_=fixture_job()
    left=A.build(job,Q.digest,raw=True);right=A.build(job,V3.digest,raw=True)
    assert left['special_questions'][0]['condition_mapping']==right['special_questions'][0]['condition_mapping']
    assert left['special_questions'][0]['id']==right['special_questions'][0]['id']
    assert V3.packet(job,left['assessment_cases'][0],left['special_questions'])==V3.packet(job,right['assessment_cases'][0],right['special_questions'])


@pytest.mark.parametrize('op',['and','or'])
def test_mapping_preserves_boolean_relations_and_separate_source_conditions(op):
    job,_=fixture_job();draft=job['conditions'][0]['prerequisite']['draft']
    atom=deepcopy(draft['prerequisites'][0]);atom['id']='second'
    draft['prerequisites'].append(atom)
    draft['scenarios'][0]['expression']=dict(op=op,args=[dict(condition='http'),dict(op='not',args=[dict(condition='second')])])
    before=deepcopy(draft);generate_fixture_questions(job)
    base=A.build(job,V3.digest,raw=True)
    payload=V3.packet(job,base['assessment_cases'][0],base['special_questions'])
    assert set(payload['atoms'])=={'http','second'}
    assert payload['locked_scenarios']==before['scenarios'] and draft==before
