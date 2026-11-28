"""Active API failures, retries and assessment concurrency, with isolated stores."""
from concurrent.futures import ThreadPoolExecutor
import threading

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.item4.workflow import source_analysis_jobs as Q
from src.item4.decision import asset_vex_assessment as E
from src.item4.web.asset_vex_questionnaire_api import router
from tests.item4.test_item4_asset_key_workflow import fixture_job
from tests.item4.test_item4_questionnaire import bom, extracted


@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setattr(Q.store,'DB',tmp_path/'jobs.sqlite3')
    monkeypatch.setattr(Q,'JOBS',{})
    monkeypatch.setattr(Q,'ASSESSING',set())
    monkeypatch.setattr(Q,'extraction_identity',lambda:'fixture')
    app=FastAPI();app.include_router(router)
    with TestClient(app) as client:yield client


def token(job):return dict(revision=job['revision'],plan_sha256=job['plan_sha256'])


@pytest.mark.parametrize('modify',[
    lambda b:b.update(components=[{'name':'x','bom-ref':{}}]),
    lambda b:b.update(components=[{'name':' '}]),
    lambda b:b.update(components=[{'name':'x','version':3}]),
    lambda b:b['vulnerabilities'][0].update(affects={}),
    lambda b:b.update(metadata={'component':[]}),
    lambda b:b.update(bomFormat=None,spdxVersion='SPDX-2.3',packages=[{}]),
    lambda b:b.update(bomFormat=None,spdxVersion='SPDX-2.3',packages={}),
    lambda b:b.update(bomFormat=None,spdxVersion='SPDX-2.3',documentDescribes={},packages=[]),
])
def test_malformed_bom_is_validation_error_not_server_error(client,modify):
    document=bom();modify(document)
    response=client.post('/api/item4/analyses/start',json={'bom':document})
    assert response.status_code==422,response.text
    assert not Q.JOBS


@pytest.mark.parametrize('raw',[b'{"bom":{},"bom":{}}',b'{"bom":NaN}',b'\xff',b'['*1100])
def test_invalid_json_rejected(client,raw):
    assert client.post('/api/item4/analyses/start',content=raw).status_code==422


def test_oversized_stream_rejected(client):
    response=client.post('/api/item4/analyses/start',content=b' '* (4*1024*1024+1))
    assert response.status_code==413


def test_retry_retains_successful_cves_and_rebuilds_inputs(client,monkeypatch):
    from src.item4.analysis import asset_operating_question_generation as V3
    monkeypatch.setattr(V3,'requires_generation',lambda _:False)
    monkeypatch.setattr(V3,'run_job',lambda *a,**kw:{})
    submissions=[]
    monkeypatch.setattr(Q.QUEUE,'submit',lambda *args:submissions.append(args))
    job=Q.start(bom());jid=job['id']
    successful=extracted(job['declared_cves'][0]['cve'])
    successful.update(bom_declaration=job['declared_cves'][0],extraction_policy=Q.vep.VERSION)
    job.update(status='completed',extraction_identity='fixture',conditions=[successful,
        dict(cve=job['declared_cves'][1]['cve'],status='unresolved',reason='temporary failure')],
        asset_state='completed',asset_classification=dict(status='classified',asset_type_id='A0003',classification_version=Q.asset_model.VERSION,retrieval_version=Q.RETRIEVAL_VERSION))
    from src.item4.assets.question_record_context import extraction_context
    components,_=Q.inventory(job['input_bom'])
    successful['asset_type_context_sha256']=Q.digest(extraction_context(job,
        [c for c in components if c['ref'] in job['declared_cves'][0]['component_refs']]))
    successful['extraction_identity']='fixture'
    Q._prepare_analysis(job);Q._commit(job)
    old=token(job)
    response=client.post(f'/api/item4/analyses/jobs/{jid}/retry',json=old)
    assert response.status_code==200,response.text
    queued=response.json()
    assert queued['id']==jid and queued['retry_count']==1
    assert queued['conditions']==[successful]
    assert queued['assessment'] is None and queued['answers']=={}
    assert queued['plan_sha256']!=old['plan_sha256']
    assert client.post(f'/api/item4/analyses/jobs/{jid}/retry',json=old).status_code==409
    seen=[]
    monkeypatch.setattr(Q,'extract_declared',lambda c,components,**kw:seen.append(c) or extracted(c))
    Q._run(*submissions[-1][1:])
    assert seen==[job['declared_cves'][1]['cve']]
    assert Q.get(jid)['status']=='completed'


def test_missing_optional_registry_is_empty_but_corruption_is_not_hidden(tmp_path,monkeypatch):
    monkeypatch.setattr(E.E,'ROOT',tmp_path)
    empty=E.supplier_registry()
    assert empty['rules']=={} and empty['sha256']
    directory=tmp_path/'data/nist_auto_vex';directory.mkdir(parents=True)
    (directory/'rules.json').write_text('corrupt',encoding='utf8')
    with pytest.raises(ValueError):E.supplier_registry()


def test_failed_assessment_is_persisted_and_can_be_retried(client,monkeypatch):
    job,_=fixture_job();Q._commit(job)
    monkeypatch.setattr(E,'evaluate',lambda job:(_ for _ in ()).throw(OSError('offline')))
    url=f"/api/item4/analyses/jobs/{job['id']}"
    response=client.post(url+'/assess',json=token(job))
    assert response.status_code==503
    saved=Q.get(job['id'])
    assert saved['assessment_state']=='failed' and saved['assessment'] is None
    assert not Q.ASSESSING
    monkeypatch.setattr(E,'evaluate',lambda job:dict(decisions=[]))
    assert client.post(url+'/assess',json=token(saved)).status_code==200


def test_duplicate_assessment_is_bounded_and_concurrent_edit_wins(client,monkeypatch):
    job,_=fixture_job();Q._commit(job)
    entered=threading.Event();release=threading.Event()
    def evaluate(snapshot):
        entered.set()
        assert release.wait(5)
        return dict(decisions=[])
    monkeypatch.setattr(E,'evaluate',evaluate)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future=pool.submit(Q.assess,job['id'],token(job))
        try:
            assert entered.wait(5)
            assert Q.get(job['id'])['assessment_state']=='running'
            with pytest.raises(Q.QueueFullError):Q.assess(job['id'],token(job))
            changed=Q.save_answers(job['id'],dict(token(job),context_answers={'mode':'normal'}))
        finally:release.set()
        with pytest.raises(Q.StaleInputError):future.result(timeout=5)
    latest=Q.get(job['id'])
    assert latest['revision']==changed['revision']
    assert latest['assessment_state']=='inputs_saved' and latest['assessment'] is None
    assert not Q.ASSESSING


def test_interrupted_assessment_preserves_inputs(client):
    job,_=fixture_job()
    job.update(assessment_state='running',answers={job['questions'][0]['id']:'o'})
    Q._save(job)
    result=Q.get(job['id'])
    assert result['assessment_state']=='failed'
    assert result['answers']==job['answers']
    assert result['revision']==job['revision']
