"""Synthetic end-to-end recovery contracts, not measured model accuracy."""
from copy import deepcopy
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from src.item4.analysis import condition_question_contract as CONTRACT
from src.item4.analysis import operational_evidence_catalogue as CATALOGUE
from src.item4.analysis import exploitation_prerequisites as V
from src.item4.analysis import asset_operating_question_generation as V3
from src.item4.assets import asset_observations as A
from src.item4.workflow import source_analysis_jobs as Q
from src.item4.analysis import cve_reference_sources as SOURCES
from tests.item4.test_empty_extraction_review import source,empty
from tests.item4.test_asset_aware_question_generation import payload


def extraction(wire):
    evidence=wire['evidence'][0]
    # Generic invented service name is deliberately outside prior CVE cases.
    quote=evidence['quote'];target=quote.split('requires ',1)[1].split(' enabled',1)[0]
    choice=next(r['id'] for r in wire['operational_evidence'] if r['quote']==quote)
    return dict(format=V.VERSION,cve=wire['cve'],prerequisites=[dict(id='service',
        condition_type='OTHER:feature_enabled',target=target,value='enabled',
        statement=target+' is enabled',operator_observable=True,operator='eq',expected=True,
        extraction_confidence=.93,operational_evidence_id=choice,
        source_refs=[dict(evidence_id=evidence['evidence_id'])],
        observation=dict(kind='configuration',record_type='configuration_export',check='Read the current applied '+target+' service configuration.'))],
        scenarios=[dict(id='route',product_keys=[],product_binding='unresolved',expression=dict(condition='service'),
            source_refs=[dict(evidence_id=evidence['evidence_id'])])],
        nonrequirements=[],excluded_facts=[],unknowns=[])


def questions(wire,score=91):
    return dict(questions={key:dict(positive_fact=a['positive_fact'],
        question=wire['schema']['properties']['questions']['properties'][key]['properties']['question']['const'],
        check=a['observation']['check'],record_type=a['observation']['record_type'],confidence=score)
        for key,a in wire['atoms'].items()})


def response(prediction):return dict(prediction=prediction,llm_used=True,model=dict(model='synthetic-contract'))


def test_every_registered_predicate_has_a_question_contract():
    assert set(CONTRACT.definitions())==set(V.OP.PREDICATES)
    assert CONTRACT.group_for('configuration_required','C5')=='principal_permission'
    assert CONTRACT.group_for('configuration_required','C7')=='operating_state'
    assert CONTRACT.group_for('feature_enabled','C2')=='input_availability'


def test_typed_wire_schema_cannot_generate_an_invalid_predicate_category_pair():
    wire=V.TAXONOMY.bind_type_schema(CATALOGUE.bind(V.extraction_packet(source())))
    item=wire['schema']['properties']['prerequisites']['items']
    assert 'predicate' not in item['properties'] and 'category' not in item['properties']
    choices=item['properties']['condition_type']['enum']
    assert 'OTHER:feature_enabled' in choices and 'AV:feature_enabled' not in choices
    atom=dict(condition_type='AT:configuration_required')
    V.TAXONOMY.resolve_type(atom)
    assert atom==dict(category='AT',predicate='configuration_required')
    with pytest.raises(ValueError,match='Unknown condition type'):
        V.TAXONOMY.resolve_type(dict(condition_type='AV:feature_enabled'))


def test_automation_policy_is_available_without_inference():
    from tools.item4 import serve_nist_operational_vex as service
    with patch.object(V.L,'generate',side_effect=AssertionError('No model needed for policy')):
        policy=TestClient(service.app).get('/api/item4/analyses/automation-policy').json()
    assert policy['max_attempts_per_stage']==3
    assert policy['low_confidence_retry'] is False
    assert policy['confidence_policy']['extraction_threshold']==.8
    assert set(policy['question_contracts'])==set(V.OP.PREDICATES)


def test_network_retries_transient_failures_but_not_not_found(tmp_path):
    import requests
    cve='CVE-2099-987654';calls=[]
    def transient(url):
        calls.append(url)
        if len(calls)<3:raise OSError('temporary connection problem')
        return json.dumps(dict(cveMetadata=dict(cveId=cve,state='PUBLISHED'),containers=dict(cna=dict(
            descriptions=[dict(lang='en',value='Exploitation requires telemetry enabled.')])))).encode(),'application/json',url
    rows,receipt=SOURCES.collect(cve,cache=tmp_path/'ok',network=True,fetcher=transient)
    assert rows and len(calls)==3 and len(receipt['network_attempts'])==3
    calls.clear()
    def permanent(url):
        calls.append(url);r=requests.Response();r.status_code=404
        raise requests.HTTPError('not found',response=r)
    rows,receipt=SOURCES.collect(cve,cache=tmp_path/'missing',network=True,fetcher=permanent)
    assert not rows and len(calls)==1 and receipt['network_attempts'][0]['retryable'] is False


def test_parallel_boms_can_pin_the_same_reference_without_cache_races(tmp_path):
    raw=json.dumps(dict(cveMetadata=dict(cveId='CVE-2099-987654',state='PUBLISHED'))).encode()
    def pin(index):return SOURCES.ingest('https://vendor.example/a',raw,'application/json',cache=tmp_path)
    with ThreadPoolExecutor(max_workers=8) as pool:rows=list(pool.map(pin,range(24)))
    assert len({r['document_sha256'] for r in rows})==1
    assert len(list(tmp_path.glob('*.json')))==1


def test_quote_catalogue_is_only_literal_scoped_spans():
    record=source('A GET first.cgi or GET second.cgi request can cause a buffer overflow.')
    wire=CATALOGUE.bind(V.extraction_packet(record))
    parents={e['evidence_id']:e['quote'] for e in wire['evidence']}
    for item in wire['operational_evidence']:
        assert parents[item['evidence_id']][slice(*item['span'])]==item['quote']
    assert any('GET first.cgi or GET second.cgi request'==r['quote'] for r in wire['operational_evidence'])


def test_relation_repair_cannot_remove_an_existing_unresolved_requirement():
    from src.item4.analysis.prerequisite_automation import merge
    base=dict(prerequisites=[dict(id='a',extraction_confidence=.83)],scenarios=[],unknowns=['Required origin is unresolved.'])
    request=dict(mode='logic_only',base=deepcopy(base))
    fixed=merge(dict(prediction=dict(scenarios=[],unknowns=[])),request)
    assert fixed['unknowns']==base['unknowns'] and fixed['prerequisites']==base['prerequisites']


def test_selected_literal_span_must_cite_its_parent_paragraph():
    wire=CATALOGUE.bind(V.extraction_packet(source()))
    atom=dict(operational_evidence_id=wire['operational_evidence'][0]['id'],source_refs=[dict(evidence_id='not-the-parent')])
    with pytest.raises(ValueError,match='parent paragraph'):CATALOGUE.resolve(atom,wire)


def test_new_source_phrasing_can_select_any_exact_clause_without_a_new_rule():
    record=source('The user submits data via a Ravel input causing a buffer overflow.')
    wire=CATALOGUE.bind(V.extraction_packet(record));clause='via a Ravel input'
    assert not any(r['quote']==clause for r in wire['operational_evidence'])
    atom=dict(operational_evidence_id=wire['operational_evidence'][0]['id'],
        operational_quote=clause,source_refs=[dict(evidence_id='e1')])
    CATALOGUE.resolve(atom,wire);assert atom['operational_quote']==clause
    bad=dict(operational_evidence_id=wire['operational_evidence'][0]['id'],
        operational_quote='via a guessed HTTP input',source_refs=[dict(evidence_id='e1')])
    with pytest.raises(ValueError,match='exact unique substring'):CATALOGUE.resolve(bad,wire)


def test_automatic_evidence_then_logic_repair_preserves_the_atom_and_score():
    record=source('Exploitation requires telemetry enabled.');modes=[];original=None
    def runner(system,wire,role):
        nonlocal original
        if role=='exploitation-prerequisites':return response(empty(record))
        assert wire['assessment_contract']['phase']=='source_requirement_extraction'
        if wire['repair_scope']=='full':assert 'candidate_extraction' not in wire
        modes.append(wire['repair_scope'])
        if wire['repair_scope']=='full':
            original=extraction(wire);broken=deepcopy(original)
            broken['prerequisites'][0]['operational_evidence_id']='nonexistent'
            broken['scenarios']=[]
            return response(broken)
        if wire['repair_scope']=='evidence_only':
            atom=original['prerequisites'][0]
            return response(dict(bindings={'service':{k:deepcopy(atom[k]) for k in ('operational_evidence_id','source_refs')}}))
        return response({k:deepcopy(original[k]) for k in ('scenarios','unknowns')})
    artifact=V.extract(record,runner=runner)
    assert modes==['full','evidence_only','logic_only']
    assert artifact['draft']['prerequisites'][0]['extraction_confidence']==.93
    assert artifact['draft']['prerequisites'][0]['statement']=='telemetry is enabled'
    assert artifact['draft']['scenarios'][0]['expression']==dict(condition='service')
    assert artifact['coverage_review']['status']=='recovered'
    assert [e['status'] for e in artifact['execution_history']]==['accepted','rejected','rejected','accepted']
    assert all(e.get('finished_at') for e in artifact['execution_history'])


def test_transport_failure_retries_the_same_restricted_evidence_repair():
    record=source('Exploitation requires telemetry enabled.');modes=[];original=None
    def model(system,wire,role):
        nonlocal original
        if role=='exploitation-prerequisites':return response(empty(record))
        modes.append(wire['repair_scope'])
        if len(modes)==1:
            original=extraction(wire);broken=deepcopy(original)
            broken['prerequisites'][0]['operational_evidence_id']='nonexistent'
            return response(broken)
        if len(modes)==2:raise RuntimeError('Temporary model connection failure')
        atom=original['prerequisites'][0]
        return response(dict(bindings={'service':{k:deepcopy(atom[k]) for k in ('operational_evidence_id','source_refs')}}))
    artifact=V.extract(record,runner=model)
    assert modes==['full','evidence_only','evidence_only']
    assert artifact['draft']['prerequisites'][0]['extraction_confidence']==.93


def test_partial_questions_retry_only_failed_atom_and_never_low_confidence():
    _,p=payload();p['atoms']['other']=deepcopy(p['atoms']['http'])
    props=p['schema']['properties']['questions'];props['properties']['other']=deepcopy(props['properties']['http']);props['required'].append('other')
    calls=[]
    def bad(system,wire,role):
        key=next(iter(wire['atoms']));calls.append(key);out=questions(wire,79)
        if key=='other':out['questions'][key]['check']='Run an exploit to verify the device.'
        return response(out)
    artifact=V3.generate(p,bad)
    assert artifact['status']=='partial' and V3.accepted(artifact,p)
    assert calls==['http','other','other','other']
    assert artifact['prediction']['questions']['http']['confidence']==79
    repaired=[]
    def good(system,wire,role):repaired.extend(wire['atoms']);return response(questions(wire))
    final=V3.generate(p,good,previous=artifact)
    assert repaired==['other'] and final['status']=='generated'
    assert final['prediction']['questions']['http']['confidence']==79
    assert final['condition_failures']=={}


def test_template_lock_does_not_bypass_logical_question_length_validation():
    from src.item4.analysis.condition_automation import StageExhausted
    _,p=payload();p['atoms']['http']['positive_fact']='X'*1000
    p['atoms']['http']['question_contract']=CONTRACT.blueprint(p['atoms']['http'])
    p['schema']['properties']['questions']['properties']['http']['properties']['positive_fact']={'const':'X'*1000}
    with pytest.raises(StageExhausted) as failed:
        V3.generate(p,lambda system,wire,role:response(questions(wire)))
    assert len(failed.value.execution_history)==3
    assert failed.value.failure['stage']=='schema'


def test_partial_question_success_remains_visible_and_missing_atom_stays_in_logic():
    from tests.item4.test_item4_asset_key_workflow import fixture_job
    from tests.item4.test_condition_pipeline_contract import install
    job,_=fixture_job();install(job,.95,op='and');before=deepcopy(job['conditions'][0]['prerequisite']['draft'])
    job['question_generations']={}
    def model(system,wire,role):
        out=questions(wire)
        if 'http_high' in wire['atoms']:out['questions']['http_high']['check']='Run an exploit.'
        return response(out)
    job['question_generations']=V3.run_job(job,runner=model)
    A.prepare(job,Q.digest)
    assert len(job['asset_questions'])==1 and job['asset_questions'][0]['condition_id']=='http'
    assert job['question_generation_gaps'][0]['condition_id']=='http_high'
    assert job['condition_coverage'][0]['total_conditions']==2
    assert job['condition_coverage'][0]['question_coverage']==.5
    assert job['conditions'][0]['prerequisite']['draft']==before
    assert job['answers']=={}


def test_resume_uses_each_cve_policy_tag_not_an_overwritten_job_tag(tmp_path,monkeypatch):
    from tests.item4.test_item4_asset_key_workflow import fixture_job
    job,_=fixture_job();components,declared=Q.inventory(job['input_bom'])
    row=job['conditions'][0];row.update(extraction_policy=V.VERSION,
        extraction_identity='old-policy',bom_declaration=declared[0])
    job['extraction_identity']='current-policy'  # A previous run stamped the job before its first CVE finished.
    monkeypatch.setattr(Q.store,'DB',tmp_path/'resume.sqlite3');monkeypatch.setattr(Q,'JOBS',{job['id']:job})
    monkeypatch.setattr(Q,'extraction_identity',lambda:'current-policy')
    monkeypatch.setattr(Q,'classify',lambda *a:job['asset_classification'])
    monkeypatch.setattr(V3,'run_job',lambda *a,**kw:{})
    with patch.object(Q,'extract_declared',return_value=deepcopy(row)) as extract:
        Q._run(job['id'],job['input_bom'],components[0],declared)
    extract.assert_called_once()
    current=Q.store.get('item4_questionnaire',job['id'])
    assert current['status']=='completed' and current['conditions'][0]['extraction_identity']=='current-policy'
    Q.JOBS[job['id']]=current
    with patch.object(Q,'extract_declared',side_effect=AssertionError('Validated CVE should be reused')) as extract:
        Q._run(job['id'],job['input_bom'],components[0],declared)
    extract.assert_not_called()


@pytest.mark.parametrize('bom_format,cve,relations_known',[
    ('CycloneDX','CVE-2097-987654',True),('SPDX','CVE-2098-765432',True),
    ('CycloneDX','CVE-2099-876543',False)])
def test_bom_runs_real_collect_extract_review_question_and_retry_handoffs(bom_format,cve,relations_known,tmp_path,monkeypatch):
    from tools.item4 import serve_nist_operational_vex as service
    monkeypatch.setattr(Q.store,'DB',tmp_path/'jobs.sqlite3');monkeypatch.setattr(Q,'JOBS',{})
    monkeypatch.setattr(SOURCES,'CACHE',tmp_path/'references')
    monkeypatch.setenv('ICSVEX_VEP_CACHE',str(tmp_path/'vep-cache'))
    monkeypatch.setattr(V.L,'identity',lambda *a:dict(model='synthetic-contract'))
    monkeypatch.setattr(Q.descriptions,'detail',lambda c:(_ for _ in ()).throw(KeyError(c)))
    monkeypatch.setattr(Q.population,'get',lambda c:None)
    monkeypatch.setattr(Q,'classify',lambda *a:dict(status='unresolved',asset_type_id=None))
    document=dict(document=dict(csaf_version='2.0'),vulnerabilities=[dict(cve=cve,notes=[dict(category='summary',text='Exploitation requires telemetry enabled.')])])
    SOURCES.ingest('https://vendor.example/security/new-advisory',json.dumps(document).encode(),'application/json')
    roles=[];question_calls=0
    def model(system,wire,role):
        nonlocal question_calls
        roles.append(role)
        if role!='item4-questions':
            draft=extraction(wire)
            if not relations_known:
                draft.update(scenarios=[],unknowns=['The source route relationship remains unresolved.'])
            return response(draft)
        question_calls+=1
        if question_calls==1:raise RuntimeError('Temporary model transport failure')
        return response(questions(wire))
    monkeypatch.setattr(V.L,'generate',model)
    if bom_format=='CycloneDX':
        bom=dict(bomFormat='CycloneDX',specVersion='1.6',version=1,
            components=[{'bom-ref':'asset','type':'device','name':'Previously unseen gateway','version':'1.0'}],
            vulnerabilities=[dict(id=cve,affects=[dict(ref='asset')])])
    else:
        bom=dict(spdxVersion='SPDX-2.3',documentDescribes=['asset'],packages=[dict(SPDXID='asset',name='Previously unseen gateway',versionInfo='1.0',cves=[cve])])
    client=TestClient(service.app);started=client.post('/api/item4/analyses/start',json=dict(bom=bom))
    assert started.status_code==200,started.text
    url='/api/item4/analyses/jobs/'+started.json()['id'];deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        job=client.get(url).json()
        if job['status'] in ('completed','failed'):break
        time.sleep(.01)
    assert job['status']=='completed',job.get('error')
    assert roles==['exploitation-prerequisites','exploitation-coverage-review','item4-questions','item4-questions']
    assert len(job['asset_questions'])==1 and job['asset_questions'][0]['cve']==cve
    assert job['asset_questions'][0]['asset_type_id'] is None
    if not relations_known:
        from src.item4.decision.asset_vex_assessment import source_gaps
        assert not job['conditions'][0]['prerequisite']['draft']['scenarios']
        assert any(g['kind']=='required_condition' for g in source_gaps(job['conditions'][0]['prerequisite']['draft']))
        assert job['condition_coverage'][0]['total_conditions']==1
    artifact=next(iter(job['question_generations'].values()))
    assert artifact['execution_history'][0]['failure']['stage']=='inference'
    assert artifact['automation']['attempts']==2
    from src.item4.decision.asset_vex_assessment import verify_source
    verify_source(job['conditions'][0])
