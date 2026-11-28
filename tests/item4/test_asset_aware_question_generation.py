"""Contract tests use stub model responses, never measured semantic gold."""
from copy import deepcopy
from unittest.mock import patch
import pytest
from src.item4.analysis import asset_operating_question_generation as V3
from src.item4.assets import asset_observations as A
from tests.item4.test_item4_asset_key_workflow import fixture_job


def payload():
    job,_=fixture_job();base=A.build(job,V3.digest,raw=True)
    case=base['assessment_cases'][0]
    return job,V3.packet(job,case,base['special_questions'])


def response(packet):
    return dict(questions={key:dict(positive_fact=a['positive_fact'],
        question='Is the following true for this asset: '+a['positive_fact']+'?',
        check='Inspect the configuration export for the applied HTTP service setting.',
        record_type=a['observation']['record_type'],confidence=95) for key,a in packet['atoms'].items()})


def test_asset_source_common_and_logic_present_without_extra_facts():
    job,p=payload()
    assert p['asset_classification']['asset_type_id']=='A0002'
    assert p['sources'] and p['locked_scenarios'] and 'cvss_common_questions' not in p
    assert set(p['atoms'])=={'http'}
    assert V3.validate(response(p),p)


def test_catalogue_record_materials_reach_model_and_visible_question():
    job,p=payload();context=p['atoms']['http']['asset_record_context']
    definition=job['questions'][0]['catalogue_definition']
    assert context['mode']=='catalogue_target'
    assert context['fields'][0]['key']=='http_listener_enabled'
    assert context['fields'][0]['evidence_guidance']==definition['evidence_guidance']
    assert context['asset_type_id']=='A0002'
    assert A.build(job,V3.digest)['special_questions'][0]['asset_record_context']==context
    seen=[]
    def runner(system,wire,role):
        seen.append(wire)
        out=response(wire)
        for key,row in out['questions'].items():
            row['question']=wire['atoms'][key]['question_contract']['question']
        return dict(prediction=out,llm_used=True,model=dict(model='fixture'))
    V3.generate(p,runner)
    assert seen[0]['atoms']['http']['asset_record_context']==context


@pytest.mark.parametrize('aid', ['A0003','A0001'])
def test_unmatched_fact_keeps_only_source_observation_without_profile_fields(aid):
    job,_=payload()
    job['asset_classification'].update(asset_type_id=aid)
    atom=job['conditions'][0]['prerequisite']['draft']['prerequisites'][0]
    atom.update(target='Vendor feature',statement='Vendor feature is enabled')
    base=A.build(job,V3.digest,raw=True)
    case=base['assessment_cases'][0];p=V3.packet(job,case,base['special_questions'])
    context=p['atoms']['http']['asset_record_context']
    assert context['mode']=='source_only'
    assert context['fields']==[]
    assert context['source_observation']==atom['observation']
    assert p['atoms']['http']['positive_fact']=='Vendor feature is enabled'


@pytest.mark.parametrize('classification', [None, {},
    dict(status='unresolved',asset_type_id='A0002'),
    dict(status='classified',asset_type_id='A9999'),
    dict(status='classified',asset_type_id='A0002',component_classifications=[]),
    dict(component_classifications=[dict(component_ref='other',status='classified',asset_type_id='A0002')])])
def test_unknown_asset_keeps_v2_questions_and_original_observation(classification):
    from tests.item4.test_item4_asset_key_workflow import generate_fixture_questions
    job,_=payload();job['asset_classification']=classification
    base=A.build(job,V3.digest,raw=True)
    p=V3.packet(job,base['assessment_cases'][0],base['special_questions'])
    assert set(p['atoms'])=={'http'}
    atom=p['atoms']['http'];context=atom['asset_record_context']
    assert context['mode']=='source_only' and context['fields']==[]
    assert context['source_observation']==atom['observation']
    generate_fixture_questions(job)
    visible=A.build(job,V3.digest)['special_questions']
    assert len(visible)==1 and visible[0]['condition_id']=='http'
    assert visible[0]['positive_fact']=='HTTP is enabled'
    assert visible[0]['default']=='unknown'


def test_record_context_change_invalidates_cached_generation():
    job,p=payload();artifact=next(iter(job['question_generations'].values()))
    changed=deepcopy(p)
    changed['atoms']['http']['asset_record_context']['fields'][0]['evidence_guidance']='Changed records'
    assert not V3.accepted(artifact,changed)


def test_component_classification_does_not_leak_other_asset_profile():
    job,_=payload()
    job['asset_classification']['component_classifications']=[
        dict(component_ref='asset',status='classified',asset_type_id='A0003'),
        dict(component_ref='other',status='classified',asset_type_id='A0001')]
    base=A.build(job,V3.digest,raw=True)
    p=V3.packet(job,base['assessment_cases'][0],base['special_questions'])
    assert p['atoms']['http']['asset_record_context']['asset_type_id']=='A0003'


def test_terminal_full_stop_can_become_question_mark_without_changing_fact():
    _,p=payload();p['atoms']['http']['positive_fact']='HTTP is enabled.'
    p['schema']['properties']['questions']['properties']['http']['properties']['positive_fact']['const']='HTTP is enabled.'
    r=response(p);r['questions']['http']['question']='Is the following true: HTTP is enabled?'
    assert V3.validate(r,p)


@pytest.mark.parametrize('mutation',['missing','extra','negated','polarity','internal','qualifier','record'])
def test_reject_drift(mutation):
    _,p=payload();r=response(p)
    if mutation=='missing':r['questions'].clear()
    elif mutation=='extra':r['questions']['invented']=deepcopy(r['questions']['http'])
    elif mutation=='negated':r['questions']['http']['question']='Is it not true: HTTP is enabled?'
    elif mutation=='polarity':r['questions']['http']['positive_fact']='HTTP is disabled'
    elif mutation=='internal':r['questions']['http']['check']='Run an exploit to verify HTTP behavior.'
    elif mutation=='qualifier':r['questions']['http']['question']='Is HTTP available?'
    else:r['questions']['http']['record_type']='source_code'
    with pytest.raises(Exception):V3.validate(r,p)


def test_cached_context_and_prompt_bound_and_generation_failure_hidden():
    job,p=payload();original=deepcopy(job['question_generations'])
    artifact=next(iter(original.values()))
    assert V3.accepted(artifact,p)
    changed=deepcopy(p);changed['asset_classification']['asset_type_id']='A0015'
    assert not V3.accepted(artifact,changed)
    with patch.object(V3,'SYSTEM',V3.SYSTEM+' changed'):
        assert not V3.accepted(artifact,p)
    job['question_generations']={}
    built=A.build(job,V3.digest)
    assert built['questions'] and 'common_questions' not in built
    assert not built['special_questions'] and built['question_generation_gaps']


def test_generation_rejects_static_fallback_and_keeps_failure_visible():
    job,p=payload()
    with pytest.raises(ValueError,match='actual generative'):
        V3.generate(p,lambda *a,**k:dict(prediction=response(p),llm_used=False))
    job['question_generations']={}
    artifacts=V3.run_job(job,runner=lambda *a,**k:(_ for _ in ()).throw(RuntimeError('unavailable')))
    assert all(a['status']=='failed' for a in artifacts.values())


def test_no_source_atoms_no_llm_invocation():
    job,_=payload()
    draft=job['conditions'][0]['prerequisite']['draft'];draft['prerequisites']=[];draft['scenarios']=[]
    with patch.object(V3.L,'generate') as model:
        artifacts=V3.run_job(job)
    model.assert_not_called()
    assert all(a['status']=='no_special_conditions' for a in artifacts.values())


def test_generation_locks_short_confirmation_wrapper_without_filling_confidence():
    _,p=payload();seen=[]
    def runner(system,wire,role):
        seen.append(wire)
        out=response(wire)
        for key,row in out['questions'].items():
            row['question']=wire['schema']['properties']['questions']['properties'][key]['properties']['question']['const']
        return dict(prediction=out,llm_used=True,model=dict(model='fixture'))
    artifact=V3.generate(p,runner)
    assert seen[0]['schema']['properties']['questions']['properties']['http']['properties']['question']==dict(const='For this asset, is the following true: HTTP is enabled?')
    assert 'const' not in p['schema']['properties']['questions']['properties']['http']['properties']['question']
    assert artifact['question_wrapper']=='locked_positive_fact_confirmation'
    assert artifact['prediction']['questions']['http']['confidence']==95
