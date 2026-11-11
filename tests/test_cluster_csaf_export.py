"""Official CSAF validation and workbook-specific output policy counterexamples."""
from copy import deepcopy
import json
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.cluster_question_pipeline import compile_plan,evaluate_plan,export_openvex
from src.csaf_cluster_export import export_csaf,validate_csaf
from src.cluster_question_api import router
from tests.test_cluster_question_pipeline import fixture,shared_answer

STAMP='2026-02-01T00:00:00Z'


def evaluated():
    reviews,records,members,cases=fixture()
    plan=compile_plan(reviews,records,members)
    return evaluate_plan(plan,records,cases,[shared_answer(plan,cases)]),plan,records,cases


def metadata(available=True):
    return dict(publisher=dict(name='Synthetic fixture organization',namespace='https://example.invalid/fixture',
                              contact_details='Synthetic contact only'),
        products={'asset':dict(name='Fixture controller',purl='pkg:generic/fixture-controller@1',
                              sbom_urls=['https://example.invalid/controller.sbom.json'])},
        components={'SIM-A':dict(name='Fixture library',version='1',purl='pkg:generic/fixture-library@1')},
        vulnerabilities={cve:dict(source_code_available=available,title='Synthetic vulnerability',epss='0',hbom_evidence=[],
            semantic_estimation=dict(status='likely_cannot_determine',rationale='Controlled fixture only',evidence=[]),
            cvss=dict(version='3.1',vectorString='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',baseScore=9.8,baseSeverity='CRITICAL'),
            references=[dict(category='external',summary='Synthetic reference',url='https://example.invalid/advisory')])
            for cve in ('SIM-A','SIM-B')})


def test_workbook_fields_relationships_and_official_schema():
    evaluation,*_=evaluated()
    document=export_csaf(evaluation,'Fixture',STAMP,metadata=metadata())
    assert validate_csaf(document)['valid']
    assert document['document']['publisher']['namespace']=='https://example.invalid/fixture'
    assert document['document']['lang']=='ko-KR'
    relation=document['product_tree']['relationships'][0]
    vulnerability=document['vulnerabilities'][0]
    assert relation['category']=='default_component_of'
    assert vulnerability['product_status']['known_not_affected']==[relation['full_product_name']['product_id']]
    assert 'flags' not in vulnerability  # Structural fixture has impact explanation, no invented justification.
    assert vulnerability['threats'][0]['category']=='impact'
    assert vulnerability['analysis']['schema_version']=='2.0'
    assert vulnerability['analysis']['product_analyses'][0]['epss']=='0'
    assert vulnerability['analysis']['product_analyses'][0]['hbom_evidence']==[]
    assert vulnerability['scores'][0]['cvss_v3']['version']=='3.1'
    assert 'cvss' not in vulnerability['scores'][0]
    assert vulnerability['references'][0]['category']=='external'


def test_missing_source_never_overrides_evidence_and_does_not_mutate_decisions():
    evaluation,*_=evaluated();original=deepcopy(evaluation)
    document=export_csaf(evaluation,'Fixture',STAMP,metadata=metadata(False))
    assert evaluation==original
    assert set(document['vulnerabilities'][0]['product_status'])=={'known_not_affected'}
    trace=json.loads(document['vulnerabilities'][0]['notes'][1]['text'])
    assert trace['engine_status']==trace['exported_status']=='not_affected'
    assert trace['source_availability_is_informational']
    assert not document['vulnerabilities'][0].get('flags')


def test_explicit_evidence_policy_retains_existing_engine_status_without_source():
    evaluation,*_=evaluated()
    document=export_csaf(evaluation,'Fixture',STAMP,metadata=metadata(False),source_policy='evidence')
    assert 'known_not_affected' in document['vulnerabilities'][0]['product_status']
    assert document['vulnerabilities'][0]['analysis']['source_code_available'] is False


def test_standard_only_export_preserves_workbook_analysis_in_notes():
    evaluation,*_=evaluated()
    document=export_csaf(evaluation,'Fixture',STAMP,metadata=metadata(),include_extensions=False)
    assert all('analysis' not in v for v in document['vulnerabilities'])
    assert 'cvss' not in document['vulnerabilities'][0]['scores'][0]
    assert any(n['title']=='Operational analysis v2 fields' for n in document['vulnerabilities'][0]['notes'])


@pytest.mark.parametrize('change',['bad_cvss','bad_epss','bad_source_type','bad_uri','bad_label'])
def test_invalid_metadata_is_rejected(change):
    evaluation,*_=evaluated();data=metadata()
    target=data['vulnerabilities']['SIM-A']
    if change=='bad_cvss':target['cvss']['baseScore']=20
    if change=='bad_epss':target['epss']='1.1'
    if change=='bad_source_type':target['source_code_available']='true'
    if change=='bad_uri':data['publisher']['namespace']='not a URI'
    if change=='bad_label':target['semantic_estimation']['status']='affected'
    with pytest.raises(ValueError):export_csaf(evaluation,'Fixture',STAMP,metadata=data)


def test_product_reference_and_conflicting_statuses_are_checked():
    evaluation,*_=evaluated();document=export_csaf(evaluation,'Fixture',STAMP,metadata=metadata())
    v=document['vulnerabilities'][0]
    v['product_status']['known_affected']=v['product_status']['known_not_affected'][:]
    with pytest.raises(ValueError,match='Conflicting'):validate_csaf(document)


def test_known_nonimpact_requires_product_scoped_explanation():
    evaluation,*_=evaluated();document=export_csaf(evaluation,'Fixture',STAMP,metadata=metadata())
    document['vulnerabilities'][0].pop('threats')
    with pytest.raises(ValueError,match='explanation'):validate_csaf(document)


def test_revised_document_keeps_original_history_and_dates():
    evaluation,*_=evaluated();data=metadata()
    data.update(version='2',initial_release_date='2026-01-01T00:00:00Z',
                revision_history=[dict(number='1',date='2026-01-01T00:00:00Z',summary='Original fixture')])
    tracking=export_csaf(evaluation,'Fixture',STAMP,metadata=data)['document']['tracking']
    assert [r['number'] for r in tracking['revision_history']]==['1','2']
    assert tracking['initial_release_date']=='2026-01-01T00:00:00Z'
    data.pop('revision_history')
    with pytest.raises(ValueError):export_csaf(evaluation,'Fixture',STAMP,metadata=data)


def test_api_supports_csaf_and_openvex_together():
    evaluation,plan,records,cases=evaluated()
    app=FastAPI();app.include_router(router)
    response=TestClient(app).post('/api/cluster-questions/evaluate',json=dict(plan=plan,records=records,cases=cases,
        common_answers=[shared_answer(plan,cases)],author='Fixture',timestamp=STAMP,
        export_csaf=True,export_openvex=True,csaf_metadata=metadata()))
    assert response.status_code==200,response.text
    result=response.json()
    assert result['openvex']['statements'][0]['status']=='not_affected'
    assert 'known_not_affected' in result['csaf_vex']['vulnerabilities'][0]['product_status']


def test_no_bound_cases_never_creates_a_fabricated_vex():
    with pytest.raises(ValueError):export_csaf(dict(plan_id='empty',decisions=[]),'Fixture',STAMP)


def test_legacy_source_gate_is_retired_and_unknown_availability_is_null():
    evaluation,*_=evaluated()
    with pytest.raises(ValueError,match='retired'):
        export_csaf(evaluation,'Fixture',STAMP,source_policy='workbook')
    document=export_csaf(evaluation,'Fixture',STAMP)
    assert document['vulnerabilities'][0]['analysis']['source_code_available'] is None
    assert 'known_not_affected' in document['vulnerabilities'][0]['product_status']


def test_analysis_status_and_question_trace_match_the_formal_decision():
    evaluation,*_=evaluated()
    document=export_csaf(evaluation,'Fixture',STAMP,metadata=metadata(False))
    analysis=document['vulnerabilities'][0]['analysis']['product_analyses'][0]
    assert analysis['formal_status']=='not_affected'
    assert analysis['question_plan']['common_answers'][0]['value']=='no'
    assert analysis['question_plan']['plan_id']==evaluation['plan_id']
    assert analysis['evidence']['accepted_ids']
    analysis['formal_status']='affected'
    with pytest.raises(ValueError,match='differs'):validate_csaf(document)


def test_affected_without_source_matches_openvex_and_preserves_question_text():
    reviews,records,members,cases=fixture();plan=compile_plan(reviews,records,members)
    supplier=deepcopy(cases[1]['evidence'][0])
    supplier.update(id='supplier-impact',kind='supplier_product_status',asserted_status='affected')
    cases[1]['evidence'].append(supplier)
    cases[1]['product_findings']=[dict(status='affected',evidence_ids=['supplier-impact'],action_statement='Apply reviewed fixture fix.')]
    evaluation=evaluate_plan(plan,records,cases,[shared_answer(plan,cases,'yes')])
    csaf=export_csaf(evaluation,'Fixture',STAMP,metadata=metadata(False))
    vex=export_openvex(evaluation,'Fixture',STAMP)
    assert vex['statements'][1]['status']=='affected'
    assert 'known_affected' in csaf['vulnerabilities'][1]['product_status']
    analysis=csaf['vulnerabilities'][1]['analysis']['product_analyses'][0]
    assert analysis['source_code_available'] is False
    assert analysis['question_plan']['common_answers'][0]['question_text']=='Is the controller service reachable?'
    assert analysis['condition_definitions'] and analysis['formula']['expression']['op']=='or'


def test_source_availability_alone_never_establishes_impact():
    reviews,records,members,cases=fixture();plan=compile_plan(reviews,records,members)
    evaluation=evaluate_plan(plan,records,cases)
    document=export_csaf(evaluation,'Fixture',STAMP,metadata=metadata(True))
    assert all(set(v['product_status'])=={'under_investigation'} for v in document['vulnerabilities'])
