"""Taxonomy preservation and rejection of unsupported evidence assignments."""
from copy import deepcopy
import hashlib,json
import pytest
from fastapi.testclient import TestClient
from src import cwe_evidence_policy as P,item4_review as I4,review_store as STORE
from src.cwe_taxonomy import load,ancestry
from src.vex_routing import classify


def cwe_case(cwe,description='A product vulnerability exists.'):
    return {'cve':'CVE-2099-45678','cwe':cwe,'description':description}


def test_all_944_profiles_preserve_official_records_without_method_assignment():
    t=load();data=P.catalog()
    expected={cid for cid,r in t['records'].items() if r['abstraction']!='Pillar' and r['status']!='Deprecated' and ancestry(cid,t)['pillars']}
    assert set(data['profiles'])==expected and len(expected)==944
    assert data['summary']['pillar_count']==10
    assert sum(p['memberships'] for p in data['summary']['per_pillar'].values())==1201
    assert data['summary']['by_source_requirement']=={'undetermined':944}
    assert not data['summary']['automatic_routing_enabled']
    for cid,row in data['profiles'].items():
        assert row['definition']==t['records'][cid]['description']
        assert row['pillars']==ancestry(cid,t)['pillars']
        assert row['source_requirement']==row['operational_requirement']=='undetermined'
        assert row['resolution']=='unresolved'
        assert not row['matched_rules'] and not row['required_facts'] and not row['question_profiles']
        assert 'cve_mapping_gate' not in row
        assert 'mapping_usage' not in row['official_metadata']
        assert 'mapping_rationale' not in row['official_metadata']
        for present in (False,True):
            r=classify(cwe_case(cid),source_available=present)
            assert r['workflow_branch']=='routing_unknown'
            assert r['initial_vex_status']=='under_investigation'
            assert not r['source_required'] and not r['operational_required']
    assert json.loads((P.ROOT/'data/cwe_routing/v2/profiles.json').read_text(encoding='utf-8'))==data


@pytest.mark.parametrize('key',['rules','facts','operator_observable_baseline_allowlist','source_refinements','operational_refinements','operational_rules'])
def test_retired_manual_assignments_cannot_be_reenabled(key):
    p=deepcopy(P.policy());p[key]=['unjustified assignment']
    with pytest.raises(ValueError,match='Retired heuristic'):P.validate(p,load())


@pytest.mark.parametrize('cid',['CWE-119','CWE-263','CWE-319','CWE-787','CWE-862','CWE-1042','CWE-1252','CWE-999999','CWE-284'])
def test_keywords_and_untrusted_client_requirements_do_not_assign_routes(cid):
    c={**cwe_case(cid,'Remote buffer overflow; cleartext TLS configuration; hardcoded keys; missing authentication.'),
       'requirement':'operational_review','source_required':False,
       'analysis_route':{'requirement':'source_required'},'_fixture_requirement':'source_required'}
    r=classify(c,source_available=True)
    assert r['cwes']==[cid] and r['workflow_branch']=='routing_unknown'
    assert not r['operational_requirement_evidence']
    assert all(not d['evidence'] and not d['refinement_rules'] for d in r['decisions'])


def test_unassigned_review_cannot_enter_questions_source_or_writer(monkeypatch):
    from src import vex_roles
    calls=[];monkeypatch.setattr(vex_roles,'infer',lambda *a,**k:calls.append(a))
    result=I4.start([cwe_case('CWE-319')]);rid=result['review_id']
    before=deepcopy(I4.get(rid))
    with pytest.raises(ValueError):I4.questions(rid)
    with pytest.raises(ValueError):I4.record_source(rid,{'statements':[{'cve':'CVE-2099-45678','status':'not_affected'}]})
    assert I4.get(rid)==before and not calls
    assert result['statements'][0]['status']=='under_investigation'


def test_catalog_api_and_old_policy_sessions_require_new_review():
    from src.api_server import app
    client=TestClient(app)
    data=client.get('/api/item4/cwe-policy').json()
    assert data['summary']['unassigned_profiles']==944
    assert client.get('/api/item4/cwe-policy/CWE-862').json()['resolution']=='unresolved'
    assert client.get('/api/item4/cwe-policy/not-a-cwe').status_code==400
    result=I4.start([cwe_case('CWE-319')]);rid=result['review_id'];master=I4.get(rid)
    master['cases'][0]['analysis_route']['policy_version']='cwe-evidence-v2.1'
    STORE.put('item4_review',rid,master)
    with pytest.raises(KeyError,match='policy changed'):I4.get(rid)
    assert STORE.get('item4_review',rid)==master


def test_metadata_hash_and_xml_pin_are_recorded_and_do_not_imply_mandatory_detection():
    data=P.metadata();t=load()
    assert data['taxonomy_xml_sha256']==t['xml_sha256']
    assert data['detection_methods_are_not_mandatory_analysis_requirements']
    assert len(data['records'])==984
    assert any(d['method']=='Automated Static Analysis' for d in P.profile('CWE-862')['official_metadata']['detection_methods'])


def test_policy_semantic_hash_is_stable_across_json_line_endings_and_key_order():
    a=json.loads('{\n"a": 1,\n"b": "example"\n}')
    b=json.loads('{\r\n"b": "example",\r\n"a": 1\r\n}')
    assert P.json_fingerprint(a)==P.json_fingerprint(b)
    assert P.json_fingerprint(a)!=P.json_fingerprint({**a,'a':2})


def test_pinned_catalog_accepts_only_eol_normalization_not_changed_content():
    from src.cwe_taxonomy import snapshot_hash_matches
    lf=b'{\n"name":"original"\n}';crlf=lf.replace(b'\n',b'\r\n')
    for original in [lf,crlf]:
        sha=hashlib.sha256(original).hexdigest()
        assert snapshot_hash_matches(lf,sha) and snapshot_hash_matches(crlf,sha)
        assert not snapshot_hash_matches(lf.replace(b'original',b'changed!'),sha)
