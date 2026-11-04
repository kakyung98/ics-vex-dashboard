from copy import deepcopy
from src.identification_diagnostics import explain_identification


def test_diagnostics_distinguish_input_identifiers_scope_and_identity_acceptance():
    sbom={'metadata':{'component':{'name':'Asset','cpe':'cpe:2.3:o:vendor:asset:*:*:*:*:*:*:*:*'}}}
    row={'component':{'name':'Kernel','component_type':'library','manufacturer':'Kernel Organization',
                      'cpes':['cpe:2.3:a:linux:linux_kernel:*:*:*:*:*:*:*:*']},
         'l2':{'normalized':'linux_kernel','candidates':[{'vendor':'linux','product':'linux_kernel','part':'o',
                'conflicts':['explicit_manufacturer_differs'],'features':{'dictionary_verified_input_cpe':False}}]},
         'l3':{'normalized':None,'status':'unknown'},'validation':{'status':'unresolved','reasons':['conflicting_identity_evidence']},'cves':[]}
    original=deepcopy(row);result=explain_identification({'components':[row]},sbom)
    scope=result['analysis_scope'];d=row['diagnostics']
    assert scope['asset_cpe']==sbom['metadata']['component']['cpe']
    assert scope['asset_identity_analyzed'] is False and scope['analyzed_components']==1
    assert d['input_cpes']==original['component']['cpes']
    assert 'not confirmed' in d['cpe_check']
    assert 'component_type_differs_from_dictionary_part' in d['candidate_comparisons'][0]['conflicts']
    assert [s['observed'] for s in d['stages']]==['linux_kernel','Installed version unconfirmed','Identity deferred']
    assert {k:v for k,v in row.items() if k!='diagnostics'}==original


def test_missing_cpe_and_verified_cpe_are_distinct_even_when_identity_is_deferred():
    rows=[{'component':{},'validation':{}},
          {'component':{'cpes':['example']},'l2':{'candidates':[{'features':{'dictionary_verified_input_cpe':True}}]},'validation':{}}]
    explain_identification({'components':rows},{})
    assert rows[0]['diagnostics']['cpe_check']=='no component CPE supplied'
    assert rows[1]['diagnostics']['cpe_check']=='supplied CPE found in the recorded dictionary evidence'
    assert rows[1]['diagnostics']['stages'][2]['observed']=='Identity deferred'


def test_saved_job_receives_diagnostics_without_rewriting_historical_result(monkeypatch):
    from fastapi.testclient import TestClient
    from src.api_server import app
    import src.candidate_web as jobs
    saved={'id':'saved','status':'completed','input_sbom':{'metadata':{'component':{'name':'Saved asset'}}},
           'result':{'components':[{'component':{'name':'Item'},'validation':{'status':'unresolved'}}]}}
    original=deepcopy(saved)
    monkeypatch.setattr(jobs,'get_job',lambda job_id:saved)
    response=TestClient(app).get('/api/cve-match/jobs/saved')
    assert response.status_code==200
    assert response.json()['result']['analysis_scope']['asset_name']=='Saved asset'
    assert response.json()['result']['components'][0]['diagnostics']['stages'][2]['observed']=='Identity deferred'
    assert saved==original
