"""Source omission regressions; synthetic inference responses are not accuracy gold."""
from copy import deepcopy
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch
import hashlib

import pytest
from src.item4.analysis import exploitation_prerequisites as V
from src.item4.analysis import source_surface_review as R
from src.item4.analysis import operator_verifiable_conditions as OP
from src.item4.assets import asset_observations as A
from src.item4.models import review_adapter_config as ADAPTER
from src.item4.workflow import source_analysis_jobs as Q
from tests.item4.test_item4_asset_key_workflow import fixture_job,generate_fixture_questions


def source(text='A remote unauthenticated attacker can craft special HTTP requests to bypass web-service authentication.'):
    return dict(cve='CVE-2099-12345',products=[],sources=[dict(id='s',text=text,
        text_sha256=hashlib.sha256(text.encode()).hexdigest(),product_keys=[],scope_binding='unresolved')])


def empty(record):
    return dict(format=V.VERSION,cve=record['cve'],prerequisites=[],scenarios=[],nonrequirements=[],
        excluded_facts=[],unknowns=['The source operating requirements remain unresolved.'])


def recovered(record,score=0.95):
    draft=empty(record);refs=[dict(evidence_id='e1')]
    draft['prerequisites']=[dict(id='http_input',condition_id='http_input',category='OTHER',
        predicate='interface_available',target='HTTP',value='available',statement='The HTTP request input is available on the assessed device.',
        operator_observable=True,operator='eq',expected=True,extraction_confidence=score,
        necessity='required',review_status='pending',evidence_directness='direct_evidence',
        operational_quote='craft special HTTP requests',source_refs=refs,
        observation=dict(kind='service_inventory',record_type='configuration_export',
            check='Inspect the current device configuration for availability of the HTTP request input.'))]
    draft['scenarios']=[dict(id='http_route',product_keys=[],product_binding='unresolved',
        expression=dict(condition='http_input'),source_refs=refs)]
    draft['unknowns']=['The product applicability of the source route remains unresolved.']
    draft['uncertainty_details']=[dict(reason=draft['unknowns'][0],kind='product_binding',
        scenario_ids=['http_route'],source_refs=refs)]
    return draft


def runner_for(record,review):
    calls=[]
    def runner(system,packet,role):
        calls.append(role)
        return dict(prediction=deepcopy(empty(record) if role=='exploitation-prerequisites' else review),
            model=dict(role=role,adapter='primary' if role=='exploitation-prerequisites' else None),llm_used=True)
    return runner,calls


def test_empty_named_route_gets_independent_source_review_with_full_lineage():
    record=source();runner,calls=runner_for(record,recovered(record))
    artifact=V.extract(record,runner=runner)
    assert calls==['exploitation-prerequisites',R.ROLE]
    assert artifact['coverage_review']['status']=='recovered'
    assert artifact['draft']['prerequisites'][0]['predicate']=='interface_available'
    assert artifact['draft']['prerequisites'][0]['vep_category']=='V3'
    assert artifact['draft']['scenarios'][0]['product_binding']=='unresolved'
    assert artifact['coverage_complete'] is False
    assert [a['role'] for a in artifact['execution_history']]==calls
    assert artifact['prompt_sha256']==artifact['execution_history'][-1]['prompt_sha256']
    assert artifact['review_system_sha256']==V.digest(R.SYSTEM)


def test_defect_only_gets_review_without_forcing_a_question():
    record=source('The product has a buffer overflow and command injection vulnerability.')
    runner,calls=runner_for(record,empty(record));artifact=V.extract(record,runner=runner)
    assert calls==['exploitation-prerequisites',R.ROLE]
    assert not artifact['draft']['prerequisites'] and artifact['coverage_review']['status']=='no_supported_conditions'


def test_review_can_honestly_return_no_conditions():
    record=source();runner,_=runner_for(record,empty(record));artifact=V.extract(record,runner=runner)
    assert artifact['coverage_review']['status']=='no_supported_conditions'
    assert not artifact['draft']['scenarios']


def test_missing_source_only_relation_gets_model_repair_without_code_inventing_and():
    record=source();broken=recovered(record);broken['scenarios']=[];broken['unknowns']=[];broken.pop('uncertainty_details')
    good=recovered(record)
    outputs=iter([empty(record),broken,{k:good[k] for k in ('scenarios','unknowns')}])
    def runner(system,packet,role):
        return dict(prediction=next(outputs),model=dict(role=role),llm_used=True)
    artifact=V.extract(record,runner=runner)
    assert artifact['coverage_review']['status']=='recovered'
    assert len(artifact['execution_history'])==3
    assert artifact['draft']['scenarios'][0]['expression']==dict(condition='http_input')


def test_failed_review_is_retryable_and_not_frozen_in_success_cache(tmp_path,monkeypatch):
    record=source();monkeypatch.setenv('ICSVEX_VEP_CACHE',str(tmp_path))
    monkeypatch.setattr(V.L,'identity',lambda *args:dict(model='test'))
    outputs=iter([empty(record),RuntimeError('temporary failure'),RuntimeError('temporary failure'),RuntimeError('temporary failure'),empty(record),recovered(record)])
    def runner(*args,**kwargs):
        value=next(outputs)
        if isinstance(value,Exception):raise value
        return dict(prediction=value,model=dict(model='test'),llm_used=True)
    monkeypatch.setattr(V.L,'generate',runner)
    assert V.resolve(record)['coverage_review']['status']=='failed'
    assert not list(tmp_path.glob('*.json'))
    assert V.resolve(record)['coverage_review']['status']=='recovered'
    assert len(list(tmp_path.glob('*.json')))==1


def test_invalid_review_is_preserved_as_failure_without_overwriting_primary_uncertainty():
    record=source();review=recovered(record);review['prerequisites'][0]['target']='SSH'
    runner,_=runner_for(record,review);artifact=V.extract(record,runner=runner)
    assert artifact['coverage_review']['status']=='failed'
    assert 'named exactly' in artifact['coverage_review']['error']
    assert not artifact['draft']['prerequisites']
    assert set(empty(record)['unknowns'])<=set(artifact['draft']['unknowns'])
    assert artifact['automation']['attempts']==4


@pytest.mark.parametrize('score,question_count',[(0.8,0),(0.81,1)])
def test_recovered_unbound_condition_reaches_v3_without_bypassing_confidence(score,question_count):
    record=source();runner,_=runner_for(record,recovered(record,score));artifact=V.extract(record,runner=runner)
    job,_=fixture_job();job['conditions'][0].update(prerequisite=artifact,sources=record['sources'])
    generate_fixture_questions(job);A.prepare(job,Q.digest)
    assert len(job['asset_questions'])==question_count
    assert job['condition_coverage'][0]['total_conditions']==1
    if question_count:
        q=job['asset_questions'][0]
        assert q['binding']=='direct_source_condition' and q['condition_id']=='http_input'
    else:
        assert job['question_absence_reasons'][0]['reason']=='extraction_confidence_rejected'


def test_source_review_uses_base_context_without_mutating_primary_adapter_selection():
    events=[]
    @contextmanager
    def disabled():
        events.append('base');yield;events.append('restore')
    runtime=SimpleNamespace(model=SimpleNamespace(disable_adapter=disabled))
    with patch.object(ADAPTER,'active_roles',side_effect=AssertionError('Do not replace primary configuration')):
        with ADAPTER.inference_context(runtime,R.ROLE) as spec:assert spec is None
    assert events==['base','restore']


def test_bare_http_server_defect_is_not_a_named_attack_input_route():
    record=source('The HTTP server fails to validate input, allowing code execution.')
    assert not R.passages(record)


@pytest.mark.parametrize('target,accepted',[('HTTP',True),('HTTP interface',True),('HTTPS',False),('HTTP management interface',False),('HTTP port 80',False)])
def test_surface_names_allow_generic_noun_but_preserve_protocol_and_qualifiers(target,accepted):
    record=source();packet=V.extraction_packet(record)
    atom=V.resolve_references(recovered(record),packet)['prerequisites'][0];atom['target']=target
    sources={s['id']:s for s in record['sources']}
    if accepted:OP.validate_condition(atom,sources)
    else:
        with pytest.raises(OP.OperationalPrerequisiteError,match='named exactly'):OP.validate_condition(atom,sources)


def test_interface_question_cannot_ask_whether_attacks_succeed():
    record=source();packet=V.extraction_packet(record)
    atom=V.resolve_references(recovered(record),packet)['prerequisites'][0]
    atom['statement']='HTTP input is available for brute-force attacks'
    with pytest.raises(OP.OperationalPrerequisiteError,match='observable input state'):
        OP.validate_condition(atom,{s['id']:s for s in record['sources']})
