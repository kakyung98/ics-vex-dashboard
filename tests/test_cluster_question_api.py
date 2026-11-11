"""HTTP integration for common/specific questions and bound VEX export."""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from src.cluster_question_api import router
from tests.test_cluster_question_pipeline import fixture, shared_answer


def test_compile_answer_evaluate_and_export_api():
    app=FastAPI();app.include_router(router);client=TestClient(app)
    reviews,records,members,cases=fixture()
    response=client.post('/api/cluster-questions/compile',json=dict(reviews=reviews,records=records,memberships=members))
    assert response.status_code==200,response.text
    plan=response.json()
    response=client.post('/api/cluster-questions/evaluate',json=dict(plan=plan,records=records,cases=cases,
        common_answers=[shared_answer(plan,cases)],export_openvex=True,author='synthetic integration'))
    assert response.status_code==200,response.text
    result=response.json()
    assert [d['status'] for d in result['decisions']]==['not_affected','under_investigation']
    assert [s['status'] for s in result['openvex']['statements']]==['not_affected','under_investigation']
    assert result['decisions'][1]['next_specific_questions'][0]['id']=='SIM-B:file'
    plan['plan_id']='stale'
    response=client.post('/api/cluster-questions/evaluate',json=dict(plan=plan,records=records,cases=cases))
    assert response.status_code==422


def test_invalid_compile_request_returns_validation_error():
    app=FastAPI();app.include_router(router);client=TestClient(app)
    assert client.post('/api/cluster-questions/compile',json={}).status_code==422
