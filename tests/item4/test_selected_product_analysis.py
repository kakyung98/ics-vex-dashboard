"""Selected product scope follows BOM references, never name/version guesses."""
from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import patch
import pytest
from src.item4.workflow import source_analysis_jobs as Q
from src.item4.analysis import asset_operating_question_generation as V3
from tests.item4.test_item4_asset_key_workflow import fixture_job,generate_fixture_questions


def collection():
    return dict(bomFormat='CycloneDX',specVersion='1.6',
        metadata=dict(component={'bom-ref':'collection:fixture','name':'Advisory collection','type':'data'}),
        components=[{'bom-ref':'product-a','name':'Same product','version':'>=1.0|<=1.2','type':'application'},
                    {'bom-ref':'product-b','name':'Same product','version':'<2.0','type':'application'}],
        vulnerabilities=[dict(id='CVE-2099-10001',affects=[dict(ref='product-a')]),
                         dict(id='CVE-2099-10002',affects=[dict(ref='product-b')]),
                         dict(id='CVE-2099-10003',affects=[dict(ref='product-a'),dict(ref='product-b')]),
                         dict(id='CVE-2099-10004'),
                         dict(id='CVE-2099-10003',affects=[dict(ref='product-b')])])


@pytest.mark.parametrize('ref,expected',[('product-a',['CVE-2099-10001','CVE-2099-10003']),
    ('product-b',['CVE-2099-10002','CVE-2099-10003'])])
def test_selection_scopes_references_and_citation_pointers(ref,expected):
    bom=collection();before=deepcopy(bom)
    components,declared,scope=Q.selected_inventory(bom,ref)
    assert [c['ref'] for c in components]==[ref]
    assert [d['cve'] for d in declared]==expected
    assert all(d['component_refs']==[ref] for d in declared)
    shared=next(d for d in declared if d['cve']=='CVE-2099-10003')
    assert shared['pointers']==(['/vulnerabilities/2'] if ref=='product-a' else ['/vulnerabilities/2','/vulnerabilities/4'])
    assert scope['unassigned_cve_ids']==['CVE-2099-10004']
    assert bom==before


def test_start_queues_only_selected_product_and_preserves_original_bom(tmp_path,monkeypatch):
    monkeypatch.setattr(Q.store,'DB',tmp_path/'jobs.sqlite3');monkeypatch.setattr(Q,'JOBS',{})
    bom=collection()
    with patch.object(Q.QUEUE,'submit') as submit:
        job=Q.start(bom,'product-b')
    assert job['input_bom']==bom and job['bom_sha256']==Q.digest(bom)
    assert [c['ref'] for c in job['components']]==['product-b']
    assert job['representative']['version']=='<2.0' and job['cves_total']==2
    assert [d['cve'] for d in submit.call_args.args[-1]]==['CVE-2099-10002','CVE-2099-10003']


def test_no_implicit_assignment_of_unlinked_cves(tmp_path,monkeypatch):
    bom=collection();bom['vulnerabilities']=[dict(id='CVE-2099-10004')]
    monkeypatch.setattr(Q.store,'DB',tmp_path/'jobs.sqlite3');monkeypatch.setattr(Q,'JOBS',{})
    with patch.object(Q.QUEUE,'submit') as submit,pytest.raises(ValueError,match='explicitly linked'):
        Q.start(bom,'product-a')
    submit.assert_not_called()


def test_classification_never_classifies_sibling_products():
    bom=collection();components,_=Q.inventory(bom)
    chosen=next(c for c in components if c['ref']=='product-a')
    with patch.object(Q,'_classify_component',return_value=dict(status='unresolved')) as model:
        result=Q.classify(bom,chosen)
    model.assert_called_once_with(bom,chosen)
    assert [c['component_ref'] for c in result['component_classifications']]==['product-a']


def test_spdx_selection_uses_exact_package_references():
    bom=dict(spdxVersion='SPDX-2.3',documentDescribes=['SPDXRef-A','SPDXRef-B'],
        packages=[dict(SPDXID='SPDXRef-A',name='Same product',versionInfo='1.0',cves=['CVE-2099-10001']),
                  dict(SPDXID='SPDXRef-B',name='Same product',versionInfo='2.0',cves=['CVE-2099-10002'])])
    cs,ds,scope=Q.selected_inventory(bom,'SPDXRef-B')
    assert [c['ref'] for c in cs]==['SPDXRef-B']
    assert [d['cve'] for d in ds]==['CVE-2099-10002']
    assert scope['version_range']=='2.0'


def test_actual_uploaded_advisory_candidates_are_each_scoped_independently():
    path=Path(__file__).resolve().parents[2]/'benchmark/icsa-cpe-synthetic sbom/sbom/icsa-26-300-02.json'
    bom=json.loads(path.read_text(encoding='utf-8-sig'))
    components,declared=Q.inventory(bom);choices=Q.representative_candidates(bom,components)
    assert len(choices)==43 and len(declared)==4
    for chosen in choices:
        cs,ds,scope=Q.selected_inventory(bom,chosen['ref'])
        assert len(cs)==1 and cs[0]['ref']==chosen['ref']
        assert ds and all(d['component_refs']==[chosen['ref']] for d in ds)


def test_selected_job_runs_only_its_v1_v2_and_cve_question_trees(tmp_path,monkeypatch):
    original,source=fixture_job();bom=deepcopy(original['input_bom'])
    bom['metadata']['component'].update(type='data',**{'bom-ref':'collection:test'})
    bom['components']=[dict(original['components'][0],**{'bom-ref':'asset'}),
        {'bom-ref':'other','name':'Other product','type':'application','version':'9.0'}]
    bom['vulnerabilities'].append(dict(id='CVE-2099-99999',affects=[dict(ref='other')]))
    monkeypatch.setattr(Q.store,'DB',tmp_path/'jobs.sqlite3');monkeypatch.setattr(Q,'JOBS',{})
    monkeypatch.setattr(Q,'extraction_identity',lambda:'fixture')
    with patch.object(Q.QUEUE,'submit') as submit:
        queued=Q.start(bom,'asset')
    calls=[]
    def extract(cve,components,**kwargs):
        calls.append((cve,[c['ref'] for c in components]))
        return deepcopy(original['conditions'][0])
    # Capture the original runner to avoid recursive test patching.
    real_run=V3.run_job
    def run_questions(job,progress=None):
        with patch.object(V3,'run_job',real_run):generate_fixture_questions(job)
        return job['question_generations']
    with (patch.object(Q,'classify',return_value=original['asset_classification']) as classify,
         patch.object(Q,'extract_declared',side_effect=extract),patch.object(V3,'run_job',side_effect=run_questions)):
        Q._run(*submit.call_args.args[1:])
    result=Q.store.get('item4_questionnaire',queued['id'])
    assert result['status']=='completed'
    assert calls==[(source['cve'],['asset'])]
    classify.assert_called_once()
    assert len(result['operating_question_trees'])==1 and result['operating_question_trees'][0]['cve']==source['cve']
    assert result['operating_question_trees'][0]['component_ref']=='asset'
