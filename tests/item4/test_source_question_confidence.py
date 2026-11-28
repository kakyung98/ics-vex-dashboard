from copy import deepcopy
import pytest
from src.item4.assets.source_question_policy import admitted
from src.item4.assets import asset_observations as A
from src.item4.analysis import asset_operating_question_generation as V3
from src.item4.workflow import source_analysis_jobs as Q
from tests.item4.test_item4_asset_key_workflow import fixture_job


@pytest.mark.parametrize('score,expected',[(None,False),(0,False),(80,False),(81,True),(95,True),(100,True),(101,False),(True,False),(0.95,False)])
def test_strict_80_point_boundary(score,expected):assert admitted(score) is expected


def change_score(job,score):
    for a in job['question_generations'].values():
        for row in a['prediction']['questions'].values():row['confidence']=score
        a['sha256']=V3.digest({k:v for k,v in a.items() if k!='sha256'})
    A.prepare(job,Q.digest)


def test_rejected_question_does_not_delete_the_source_condition_or_turn_it_false():
    job,_=fixture_job();raw_id=job['questions'][0]['id']
    change_score(job,80)
    assert job['asset_questions']==[] and job['questions'][0]['id']==raw_id
    assert job['question_confidence_rejections'][0]['confidence']==80
    assert job['answers'].get(raw_id,'unknown')=='unknown'
    assert job['assessment'] is None
    change_score(job,81)
    assert len(job['asset_questions'])==1 and job['asset_questions'][0]['llm_confidence']==81
    assert 'common_questions' not in job and 'cvss_plans' not in job


def test_missing_score_is_not_filled_in_and_source_only_packet_ignores_cvss():
    job,_=fixture_job();case=job['assessment_cases'][0]
    packet=V3.packet(job,case,job['questions'])
    assert 'cvss_common_questions' not in packet
    artifact=next(iter(job['question_generations'].values()))
    prediction=deepcopy(artifact['prediction'])
    for row in prediction['questions'].values():row.pop('confidence')
    with pytest.raises(Exception):V3.validate(prediction,packet)


def test_active_evaluation_and_retired_common_schema():
    from fastapi.testclient import TestClient
    from tools.item4.serve_nist_operational_vex import app
    client=TestClient(app)
    assert client.get('/api/item4/analyses/common-question-schema').status_code==410
    policy=client.get('/api/item4/analyses/question-policy').json()
    assert policy['comparison']=='>' and policy['threshold']==80 and policy['confidence_is_accuracy_probability'] is False
    r=client.post('/api/item4/analyses/evaluation/run').json()
    assert r['version']=='item4-source-question-contract/1' and r['cases']==r['correct']
    assert r['llm_called'] is False
