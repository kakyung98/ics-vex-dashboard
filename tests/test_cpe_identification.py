from copy import deepcopy
from src.identity_retrieval import ProductIndex
from src.identity_evidence import run_evidence
from src.unified_identification import run_unified
from tests.test_unified_identification import provider
from ics_agent_matcher_full.ics_agent_matcher.matcher import NVD


def fixture():
    return ProductIndex([{'cpe':'cpe:2.3:a:acme:control:1.0:*:*:*:*:*:*:*'},
                         {'cpe':'cpe:2.3:o:linux:linux_kernel:6.0:*:*:*:*:*:*:*'}])


def document(cpe,name='control',kind='application'):
    return {'bomFormat':'CycloneDX','components':[{'name':name,'type':kind,'version':'NOASSERTION','cpe':cpe}]}


def test_wildcard_cpe_matches_product_without_inventing_release():
    sbom=document('cpe:2.3:a:acme:control:*:*:*:*:*:*:*:*');original=deepcopy(sbom)
    for mode in ['evidence','unified']:
        row=(run_evidence(sbom,NVD(offline=True),index=fixture()) if mode=='evidence' else
             run_unified(sbom,NVD(offline=True),index=fixture(),agents=provider([],proposal='wrong_model_proposal')))['components'][0]
        assert row['validation']['status']=='validated'
        assert row['l3']['normalized'] is None
        assert row['l2']['retrieval']['input_cpe_checks'][0]['status']=='dictionary_product_identity'
    assert sbom==original


def test_wrong_part_suggested_but_not_silently_corrected():
    row=run_evidence(document('cpe:2.3:a:linux:linux_kernel:*:*:*:*:*:*:*:*','Linux Kernel','library'),NVD(offline=True),index=fixture())['components'][0]
    check=row['l2']['retrieval']['input_cpe_checks'][0]
    assert check['status']=='not_in_dictionary' and check['suggested_dictionary_entries']
    assert check['automatically_corrected'] is False
    assert row['validation']['status']=='unresolved'


def test_unverified_cpe_release_does_not_become_installed_version():
    row=run_evidence(document('cpe:2.3:a:acme:control:999:*:*:*:*:*:*:*'),NVD(offline=True),index=fixture())['components'][0]
    assert row['l2']['retrieval']['input_cpe_checks'][0]['status']=='product_found_release_or_attributes_unverified'
    assert row['l3']['normalized'] is None and row['l3']['unverified_cpe_inputs']


def test_invalid_cpe_retained_and_never_accepted_as_dictionary_evidence():
    for cpe in ['not-a-cpe','cpe:2.3:a:acme:control','cpe:2.3:a:acme:control\\:x:*:*:*:*:*:*:*:*']:
        row=run_evidence(document(cpe),NVD(offline=True),index=fixture())['components'][0]
        check=row['l2']['retrieval']['input_cpe_checks'][0]
        assert not check['usable_identity'] and not check['automatically_corrected']
        assert row['component']['cpes']==[cpe]


def test_asset_analyzed_separately_without_cpe_inheritance(monkeypatch):
    import src.identity_evidence as evidence
    from src.candidate_match import match_candidates
    monkeypatch.setattr(evidence,'get_index',fixture)
    sbom=document('',name='Unidentified library')
    sbom['metadata']={'component':{'name':'control','type':'application','cpe':'cpe:2.3:a:acme:control:*:*:*:*:*:*:*:*'}}
    r=match_candidates(sbom,agent_mode='evidence',lookup_mode='none')
    assert r['summary']['components']==1 and r['summary']['validated']==0
    assert r['asset_analysis']['validation']['status']=='validated'
    assert r['asset_summary']['analyzed'] and r['analysis_scope']['asset_identity_analyzed']
    assert not r['components'][0]['component']['cpes']


def test_vendor_separator_equivalence_and_description_cleanup():
    idx=ProductIndex([{'cpe':'cpe:2.3:a:hitachienergy:tro600:1.0:*:*:*:*:*:*:*'}])
    sbom=document('',name='TRO600 Vendor Firmware/Application')
    sbom['components'][0]['manufacturer']={'name':'Hitachi Energy'}
    row=run_evidence(sbom,NVD(offline=True),index=idx)['components'][0]
    assert row['validation']['vendor']=='hitachienergy'


def test_asset_candidate_handoff_keeps_its_own_reference(monkeypatch):
    from fastapi.testclient import TestClient
    from src.api_server import app
    import src.candidate_web as jobs
    original={'bomFormat':'CycloneDX','metadata':{'component':{'name':'Asset'}},'components':[]}
    saved={'status':'completed','input_sbom':original,'result':{'components':[],
        'asset_analysis':{'architecture':'evidence-v3','component':{'id':'metadata:component','name':'Asset','version':'NOASSERTION'},
                          'validation':{'status':'unresolved'},'cves':[{'cve_id':'CVE-2026-13162','match_status':'unknown'}]}}}
    monkeypatch.setattr(jobs,'get_job',lambda _:saved)
    data=TestClient(app).get('/api/cve-match/jobs/example/vex').json()
    assert data['mapping_count']==1
    assert data['cves'][0]['mappings'][0]['component_id']=='metadata:component'
    assert data['cves'][0]['mappings'][0]['identification_evidence']['architecture']=='evidence-v3'
    assert data['sbom']['metadata']['component']['bom-ref']=='metadata:component'
    assert 'bom-ref' not in original['metadata']['component']
