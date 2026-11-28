"""Synthetic integration tests; no claims about calibrated model accuracy."""
from copy import deepcopy
from itertools import product
import json
from unittest.mock import patch

import pytest
from src.item4.assets import asset_observations as A
from src.item4.assets.source_question_policy import extraction_admitted
from src.item4.analysis import exploitation_prerequisites as V
from src.item4.decision import asset_vex_assessment as E
from src.item4.decision.condition_logic_evaluation import logic
from src.item4.workflow import source_analysis_jobs as Q
from tests.item4.test_item4_asset_key_workflow import fixture_job, generate_fixture_questions, graph_fixture


@pytest.mark.parametrize('score,accepted',[(None,False),(True,False),(0,False),(0.8,False),
    (0.80001,True),(0.95,True),(1,True),(1.1,False),(float('nan'),False),(float('inf'),False),('0.95',False)])
def test_v2_strict_threshold(score,accepted):
    assert extraction_admitted(score) is accepted


def test_missing_relation_does_not_mask_a_bad_operational_quote():
    job,packet=fixture_job()
    draft=deepcopy(job['conditions'][0]['prerequisite']['draft'])
    draft['scenarios']=[]
    draft['prerequisites'][0]['operational_quote']='Invented quotation.'
    with pytest.raises(V.OP.OperationalPrerequisiteError,match='exact, unique source clause'):
        V.validate(draft,packet)


def test_colisted_inputs_do_not_prove_a_joint_requirement():
    quote='CGI applications alpha.cgi and beta.cgi receive web-request headers.'
    atoms=[dict(id=name,predicate='interface_available',target=name+'.cgi',operational_quote=quote) for name in ['alpha','beta']]
    draft=dict(prerequisites=atoms,scenarios=[dict(expression=dict(op='and',args=[dict(condition='alpha'),dict(condition='beta')]))],unknowns=[])
    with pytest.raises(V.OP.OperationalPrerequisiteError,match='co-listed input routes'):
        V.OP.validate_relations(draft)
    draft['scenarios'][0]['expression']['op']='or'
    V.OP.validate_relations(draft)


def test_interface_only_graph_cannot_silently_omit_a_cited_permission():
    atom=dict(id='a',predicate='interface_available',target='WebUI',operational_quote='WebUI input receives requests.',source_refs=[dict(quote='An actor with permission to upload files uses WebUI input.')])
    draft=dict(prerequisites=[atom],scenarios=[dict(expression=dict(condition='a'))],unknowns=[])
    with pytest.raises(V.OP.OperationalPrerequisiteError,match='permission requirement'):
        V.OP.validate_relations(draft)
    draft['unknowns']=['The assessed actor permission requirement is unresolved.']
    V.OP.validate_relations(draft)


def install(job, score, op=None):
    artifact=job['conditions'][0]['prerequisite'];draft=artifact['draft']
    atom=draft['prerequisites'][0]
    if score is None:atom.pop('extraction_confidence',None)
    else:atom['extraction_confidence']=score
    if op:
        high=deepcopy(atom);high.update(id='http_high',extraction_confidence=0.99)
        draft['prerequisites'].append(high)
        draft['scenarios'][0]['expression']=dict(op=op,args=[dict(condition='http'),dict(condition='http_high')])
    artifact['sha256']=V.digest({k:v for k,v in artifact.items() if k!='sha256'})
    generate_fixture_questions(job);A.prepare(job,Q.digest)


def assess(job, packet):
    context=dict(scope='current_single',mode='normal')
    for case in job['assessment_cases']:
        context[case['prefix']+'deployment']='running';context[case['prefix']+'runtime']='bom'
    job['context_answers']=context
    with patch.object(Q,'description_packet',return_value=packet),patch.object(E.G,'build',side_effect=graph_fixture),patch.object(E,'version_binding',return_value=dict(state='vulnerable',product_bound=True,condition_product_bound=True,sources=[])):
        return E.evaluate(job)


@pytest.mark.parametrize('score',[None,0.8,0.1])
def test_excluded_v2_condition_keeps_logic_unknown_even_with_stale_yes(score):
    job,packet=fixture_job();old_id=job['asset_questions'][0]['id'];install(job,score)
    assert job['asset_questions']==[]
    job['answers'][old_id]='o'
    report=assess(job,packet);row=report['decisions'][0]
    assert row['status']=='under_investigation'
    assert row['prerequisite_status']=='unknown'
    c=row['condition_coverage'];assert c['total_conditions']==1 and c['question_covered']==0
    assert c['conditions'][0]['gap_reason']=='extraction_confidence_rejected'
    assert row['evidence_chain']['conditions'][0]['value']=='unknown'
    assert row['evidence_chain']['scenarios'][0]['expression']==dict(condition='http')


@pytest.mark.parametrize('op,answer,expected',[('and','x','unsatisfied'),('and','o','unknown'),('or','o','satisfied'),('or','x','unknown')])
def test_high_confidence_alternative_or_blocker_can_decide_with_unasked_condition(op,answer,expected):
    job,packet=fixture_job();install(job,0.8,op)
    assert len(job['asset_questions'])==1
    job['answers']={job['asset_questions'][0]['id']:answer}
    row=assess(job,packet)['decisions'][0]
    assert row['prerequisite_status']==expected
    assert row['condition_coverage']['question_coverage']==0.5
    assert row['condition_coverage']['answer_coverage']==0.5
    assert row['evidence_chain']['scenarios'][0]['value']=={'satisfied':'true','unsatisfied':'false','unknown':'unknown'}[expected]
    assert row['status']==('affected' if expected=='satisfied' else 'under_investigation')


@pytest.mark.parametrize('op',['and','or'])
def test_complete_three_valued_truth_tables(op):
    for a,b in product(['true','false','unknown'],repeat=2):
        expected=('false' if 'false' in (a,b) else 'true' if a==b=='true' else 'unknown') if op=='and' else ('true' if 'true' in (a,b) else 'false' if a==b=='false' else 'unknown')
        assert logic(dict(op=op,args=[dict(condition='a'),dict(condition='b')]),dict(a=a,b=b))==expected


@pytest.mark.parametrize('value,expected',[('true','false'),('false','true'),('unknown','unknown')])
def test_not_preserves_unknown(value,expected):
    assert logic(dict(op='not',args=[dict(condition='a')]),dict(a=value))==expected


def test_evidence_chain_survives_both_exports_and_blocks_record_mutation():
    job,packet=fixture_job();qid=job['asset_questions'][0]['id'];job['answers'][qid]='o'
    job['answer_provenance']={qid:dict(value='o',operating_records=dict(references=['config-export:sha256:example'],observed_at='2026-11-26T09:00:00+09:00'),independent_evidence_verified=False)}
    job['assessment']=assess(job,packet)
    row=job['assessment']['decisions'][0];chain=row['evidence_chain']
    assert [s['agent'] for s in chain['stages']]==['V1','V2','V3','V4']
    assert chain['conditions'][0]['source_refs'][0]['span']==[0,len(packet['sources'][0]['text'])]
    assert chain['conditions'][0]['answer_provenance']['operating_records']['references']
    assert chain['sha256']==E.digest({k:v for k,v in chain.items() if k!='sha256'})
    with patch.object(Q,'description_packet',return_value=packet):
        ov=E.export(job,'openvex');assert json.loads(ov['statements'][0]['status_notes'])['evidence_chain']==chain
        cdx=E.export(job,'cyclonedx');props=cdx['vulnerabilities'][0]['properties']
        assert any(json.loads(p['value']).get('evidence_chain')==chain for p in props if p['name']=='ics-vex:component-decision')
        job['answer_provenance'][qid]['operating_records']['references']=['changed']
        with pytest.raises(ValueError,match='evidence changed'):E.export(job,'openvex')


def test_reference_document_hash_and_locator_survive_the_vex_chain():
    job,packet=fixture_job()
    provenance=dict(raw_path='fixture-only.pdf',document_sha256='f'*64,locator=dict(page=3,span=[10,90]))
    packet['sources'][0]['provenance']=provenance
    packet['sources'][0]['cve_binding']=packet['cve']
    artifact=job['conditions'][0]['prerequisite']
    artifact['source_record_sha256']=V.digest(packet)
    artifact['sha256']=V.digest({k:v for k,v in artifact.items() if k!='sha256'})
    receipt=dict(source_count=1,attempts=[dict(status='scoped')])
    job['conditions'][0]['source_collection']=receipt
    generate_fixture_questions(job);A.prepare(job,Q.digest)
    job['assessment']=assess(job,packet)
    chain=job['assessment']['decisions'][0]['evidence_chain']
    assert chain['conditions'][0]['source_refs'][0]['source_provenance']==provenance
    assert chain['source_collection']==receipt
    with patch.object(Q,'description_packet',return_value=packet):
        ov=E.export(job,'openvex')
        assert json.loads(ov['statements'][0]['status_notes'])['evidence_chain']['source_collection']==receipt


def test_generation_schema_requires_taxonomy_and_confidence_legacy_is_not_filled():
    job,packet=fixture_job();schema=V.extraction_packet(packet)['schema']
    required=schema['properties']['prerequisites']['items']['required']
    assert {'category','extraction_confidence'}<=set(required)
    atom=job['conditions'][0]['prerequisite']['draft']['prerequisites'][0]
    atom.pop('extraction_confidence');assert 'extraction_confidence' not in atom
    install(job,None);assert job['special_source_refresh_required']


def test_condition_taxonomy_api_is_separate_from_agent_codes():
    from src.item4.web.asset_vex_questionnaire_api import condition_taxonomy
    taxonomy=condition_taxonomy()
    assert set(taxonomy['categories'])=={'C0','AV','PR','UI','AT','OTHER'}
    assert taxonomy['operating_conditions']==['AV','PR','UI','AT','IC']
    assert taxonomy['missing_source']=='unknown' and taxonomy['cvss_scoring'] is False
    assert taxonomy['applicability_gate']=='C0'
    assert taxonomy['classification_is_evidence'] is False


def test_record_metadata_is_saved_and_metadata_only_edit_invalidates_vex(tmp_path,monkeypatch):
    job,_=fixture_job();monkeypatch.setattr(Q.store,'DB',tmp_path/'jobs.sqlite3')
    monkeypatch.setattr(Q,'JOBS',{job['id']:job});monkeypatch.setattr(Q,'extraction_identity',lambda:'fixture')
    qid=job['asset_questions'][0]['id']
    def submit(record):
        current=Q.get(job['id'])
        return Q.save_answers(job['id'],dict(revision=current['revision'],plan_sha256=current['plan_sha256'],answers={qid:'o'},answer_records={qid:record}))
    record=dict(references=['config-export-1'],observed_at='2026-11-26T09:00:00+09:00',recorded_by='operator')
    saved=submit(record);assert saved['answer_provenance'][qid]['operating_records']==record
    assert saved['condition_coverage'][0]['answer_covered']==1
    revision=saved['revision'];record['references']=['config-export-2']
    saved=submit(record);assert saved['revision']>revision and saved['assessment'] is None
    with pytest.raises(ValueError,match='timezone'):submit(dict(observed_at='2026-11-26T09:00:00'))
    with pytest.raises(ValueError,match='only'):submit(dict(status='not_affected'))
