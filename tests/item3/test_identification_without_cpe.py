"""A missing input CPE is supported; missing server references are a service error."""
import pytest

from src.item3.evidence.product_candidate_search import ProductIndex
from src.item3.matching.identification_pipeline import run_unified


def test_product_and_version_identify_without_any_input_cpe():
    cpe='cpe:2.3:a:fixture_vendor:fixture_product:1.2.3:*:*:*:*:*:*:*'
    index=ProductIndex([{'cpe':cpe,'title':'Fixture product'}])

    class FixtureLookup:
        def get_all(self,*args,**kwargs):
            return {'vulnerabilities':[{'cve':{
                'id':'CVE-2099-0001',
                'configurations':[{'operator':'OR','cpeMatch':[{'criteria':cpe,'vulnerable':True}]}],
            }}]}

    sbom={'bomFormat':'CycloneDX','specVersion':'1.7','components':[{
        'type':'application','name':'fixture_product','version':'1.2.3',
        'manufacturer':{'name':'fixture_vendor'},
    }]}
    result=run_unified(sbom,FixtureLookup(),index=index,mode='rules',mapping_scope='identification')
    row=result['components'][0]
    assert row['component']['cpes']==[]
    assert row['validation']['status']=='validated'
    assert [(c['cve_id'],c['match_status']) for c in row['cves']]==[('CVE-2099-0001','match')]


def test_web_accepts_an_sbom_without_cpe(tmp_path,monkeypatch):
    from src.item3.web import identification_jobs_api as web
    from src.common import gpu_lease
    monkeypatch.setattr(gpu_lease,'assert_inference_available',lambda:None)
    monkeypatch.setattr(web,'ROOT',tmp_path)
    (tmp_path/'data/item3_identification_sources_v11').mkdir(parents=True)
    for name in ['data/cpe_dictionary.jsonl','data/item3_identification_sources_v11/manifest.json',
                 'data/item3_identification_sources_v11/cves.jsonl','data/cisa_advisories.json','data/cisa_reference_manifest.json']:
        (tmp_path/name).write_text('{}\n')
    monkeypatch.setattr(web,'_jobs',{})
    monkeypatch.setattr(web,'model_status',lambda:{'version':'test'})
    monkeypatch.setattr(web.STORE,'put',lambda *args:None)
    calls=[]

    def match(sbom,**options):
        calls.append(sbom)
        return {'architecture':'fixture','components':[]}

    class ImmediateExecutor:
        def submit(self,fn):fn()

    monkeypatch.setattr(web,'match_candidates',match)
    monkeypatch.setattr(web,'_executor',ImmediateExecutor())
    sbom={'bomFormat':'CycloneDX','components':[{'type':'application','name':'fixture','version':'1'}]}
    result=web.submit(sbom)
    job=web.get_job(result['id'])
    assert job['status']=='completed'
    assert calls==[job['input_sbom']]
    component,=calls[0]['components']
    assert {key:value for key,value in component.items() if key!='bom-ref'}==sbom['components'][0]
    if 'bom-ref' in component:
        assert component['bom-ref'] and job['original_input_sbom']==sbom
    assert 'bom-ref' not in sbom['components'][0]


def test_missing_server_dictionary_is_not_reported_as_missing_input_cpe(tmp_path,monkeypatch):
    from src.item3.web import identification_jobs_api as web
    monkeypatch.setattr(web,'ROOT',tmp_path)
    with pytest.raises(RuntimeError,match='server configuration problem') as error:
        web.require_reference_data('local')
    assert 'SBOMs without CPE identifiers are supported' in str(error.value)


def test_local_source_snapshot_is_required_only_for_local_lookup(tmp_path,monkeypatch):
    from src.item3.web import identification_jobs_api as web
    monkeypatch.setattr(web,'ROOT',tmp_path)
    (tmp_path/'data').mkdir()
    (tmp_path/'data/cpe_dictionary.jsonl').write_text('{}\n')
    web.require_reference_data('live')
    web.require_reference_data('none')
    with pytest.raises(RuntimeError):web.require_reference_data('local')
