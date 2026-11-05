from copy import deepcopy
import hashlib,json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from src import cwe_evidence_policy as P, item4_review as I4, review_store as STORE
from src.cwe_taxonomy import load,ancestry
from src.vex_routing import classify


def cwe_case(cwe,description='A product vulnerability exists.'):
    return {'cve':'CVE-2099-45678','cwe':cwe,'description':description}


def test_every_mapped_active_detailed_cwe_has_exactly_one_reproducible_profile():
    t=load();data=P.catalog()
    expected={cid for cid,r in t['records'].items() if r['abstraction']!='Pillar' and r['status']!='Deprecated' and ancestry(cid,t)['pillars']}
    assert set(data['profiles'])==expected and len(expected)==944
    assert data['summary']['pillar_count']==10
    assert sum(data['summary']['by_source_requirement'].values())==944
    assert sum(v['memberships'] for v in data['summary']['per_pillar'].values())==1201
    assert not data['summary']['independently_validated']
    for cid,row in data['profiles'].items():
        assert row['cwe']==cid and row['rationale'] and row['definition_url']
        assert row['source_requirement'] in {'required','not_required','undetermined'}
        assert row['policy_sha256']==P.policy()['sha256']
        if row['source_requirement']!='undetermined':
            assert row['matched_rules'] and row['required_facts']
        for match in row['matched_rules']:
            for anchor in match['anchors']:
                assert t['records'][anchor['cwe']]['abstraction']!='Pillar'
                assert anchor['path'][0]==cid and anchor['path'][-1]==anchor['cwe']
                for child,parent in zip(anchor['path'],anchor['path'][1:]):assert parent in t['records'][child]['parents_view_1000']
    saved=json.loads((P.ROOT/'data/cwe_routing/v2/profiles.json').read_text(encoding='utf-8'))
    assert saved==data


@pytest.mark.parametrize('cwe,source,rule',[
    ('CWE-862','required','authorization-enforcement'),
    ('CWE-89','required','input-processing'),
    ('CWE-787','required','memory-safety'),
    ('CWE-319','not_required','transport-encryption'),
    ('CWE-732','not_required','resource-permissions'),
    ('CWE-521','not_required','password-configuration'),
    ('CWE-200','undetermined','unspecified-mechanism'),
    ('CWE-1252','undetermined','hardware-design-evidence')])
def test_specific_weaknesses_have_explained_evidence_locations(cwe,source,rule):
    p=P.profile(cwe)
    assert p['source_requirement']==source
    assert rule in {m['rule_id'] for m in p['matched_rules']}


def test_missing_authorization_is_explicit_enforcement_not_default_source():
    p=P.profile('CWE-862')
    assert p['resolution']=='inherited'
    assert p['matched_rules'][0]['anchors'][0]['path']==['CWE-862','CWE-285']
    assert {f['location'] for f in p['required_facts']}=={'source','operator'}
    r=classify(cwe_case('CWE-862'),source_available=True)
    assert r['workflow_branch']=='source_to_operational'
    assert r['decisions'][0]['rule_id']=='authorization-enforcement'


def test_all_four_routes_and_unknown_are_distinct():
    assert classify(cwe_case('CWE-787'),source_available=True)['workflow_branch']=='source_only'
    assert classify(cwe_case('CWE-787','Remote out-of-bounds write.'),source_available=True)['workflow_branch']=='source_to_operational'
    assert classify(cwe_case('CWE-787'))['workflow_branch']=='source_missing'
    assert classify(cwe_case('CWE-319'))['workflow_branch']=='operational_only'
    assert classify(cwe_case('CWE-200'))['workflow_branch']=='routing_unknown'


def test_more_specific_operating_rule_overrides_generic_implementation_parent():
    p=P.profile('CWE-614')
    assert p['source_requirement']=='not_required'
    assert all(m['distance']==0 for m in p['matched_rules'])
    assert p['shadowed_rules']  # broad ancestry does not silently override the detailed rule


def test_equal_distance_evidence_requirements_are_combined():
    rules=deepcopy(P.policy())
    rules['rules'].append({'id':'test-equally-specific','anchors':['CWE-787'],
        'facts':['resource_permissions'],'rationale':'Controlled test of equal-specificity union.'})
    rules['rules'].append({'id':'test-equally-specific-code','anchors':['CWE-787'],
        'facts':['memory_bounds_lifetime'],'rationale':'Controlled code requirement.'})
    p=P.profile('CWE-787',rules=rules)
    assert {f['location'] for f in p['required_facts']}=={'source','operator'}
    assert p['source_requirement']=='required' and p['operational_requirement']=='required'


def test_context_refinement_does_not_invent_complete_exploit_prerequisites():
    broad=classify(cwe_case('CWE-327','The server supports TLS with weak cipher settings.'))
    assert broad['workflow_branch']=='operational_only'
    assert broad['decisions'][0]['resolution']=='cve_refined'
    assert not any(f['id']=='cve_specific_mechanism' for f in broad['required_facts'])
    defect=classify(cwe_case('CWE-319','The implementation has a buffer overflow.'))
    assert defect['requirement']=='source_required'
    assert any(e['quote']=='buffer overflow' for e in defect['decisions'][0]['evidence'])
    assert defect['routing_confers_negative_verdict'] is False


@pytest.mark.parametrize('cwe',['CWE-284','CWE-999999','CWE-16'])
def test_pillar_and_invalid_mappings_cannot_be_promoted_by_cve_keywords(cwe):
    r=classify(cwe_case(cwe,'Remote buffer overflow with cleartext traffic.'))
    assert r['requirement']=='undetermined' and not r['source_required']


def test_unknown_cwe_cannot_be_hidden_by_another_source_requirement():
    r=classify(cwe_case(['CWE-787','CWE-999999']))
    assert r['requirement']=='undetermined' and r['unresolved_cwes']==['CWE-999999']


def test_invalid_or_pillar_rule_anchor_is_rejected():
    rules=deepcopy(P.policy());rules['rules'][0]['anchors']=['CWE-284']
    with pytest.raises(ValueError,match='overly broad'):P.validate(rules,load())


def test_catalog_api_and_policy_changed_session_handling():
    from src.api_server import app
    client=TestClient(app)
    catalog=client.get('/api/item4/cwe-policy');assert catalog.status_code==200
    assert len(catalog.json()['profiles'])==944
    row=client.get('/api/item4/cwe-policy/CWE-862').json()
    assert row['source_requirement']=='required'
    assert client.get('/api/item4/cwe-policy/not-a-cwe').status_code==400
    initial=I4.start([cwe_case('CWE-319')]);rid=initial['review_id'];master=I4.get(rid)
    master['cases'][0]['analysis_route']['policy_version']='item4-pillar-v1';STORE.put('item4_review',rid,master)
    with pytest.raises(KeyError,match='policy changed'):I4.get(rid)
    assert STORE.get('item4_review',rid)==master


def test_all_944_runtime_routes_respect_mapping_gate_and_availability_is_separate():
    p=P.policy()
    for cid,row in P.catalog()['profiles'].items():
        absent=classify(cwe_case(cid));present=classify(cwe_case(cid),source_available=True)
        assert absent['requirement']==present['requirement']
        assert absent['initial_vex_status']=='under_investigation'
        assert not absent['routing_confers_negative_verdict']
        if row['cve_mapping_gate']['blocked_for_cve_routing']:
            assert absent['requirement']=='undetermined'
        elif row['source_requirement']=='required':
            assert absent['workflow_branch']=='source_missing'
            assert present['workflow_branch'] in {'source_only','source_to_operational'}
        elif row['source_requirement']=='not_required':
            assert cid in p['operator_observable_baseline_allowlist']
            assert absent['workflow_branch']==present['workflow_branch']=='operational_only'
        else:assert absent['workflow_branch']==present['workflow_branch']=='routing_unknown'


@pytest.mark.parametrize('cid',['CWE-493','CWE-500','CWE-582','CWE-583','CWE-608'])
def test_language_access_modifiers_never_inherit_operator_permissions(cid):
    row=P.profile(cid)
    assert row['source_requirement']=='required'
    assert 'language-access-modifiers' in {m['rule_id'] for m in row['matched_rules']}


def test_crypto_implementation_and_hardware_are_not_just_cipher_settings():
    assert P.profile('CWE-1240')['source_requirement']=='undetermined'
    for cid in ['CWE-328','CWE-759','CWE-760','CWE-780']:
        assert P.profile(cid)['source_requirement']=='required'
    g=classify(cwe_case('CWE-327','The product uses TLS.'))
    assert g['workflow_branch']=='routing_unknown'  # TLS alone is not configuration evidence
    g=classify(cwe_case('CWE-327','The server supports TLS with weak cipher settings.'))
    assert g['workflow_branch']=='operational_only'
    h=P.profile('CWE-1221')
    assert h['source_requirement']=='undetermined'
    assert any(p.get('Name')=='Verilog' for p in h['official_metadata']['platforms'])


def test_explicit_configuration_vs_implementation_is_decided_before_workflow():
    config=classify(cwe_case('CWE-862','Authentication is misconfigured by an access policy setting.'))
    assert config['workflow_branch']=='operational_only'
    assert not any(f['location']=='source' for f in config['required_facts'])
    label_only=classify(cwe_case('CWE-306','Missing authentication results from an access policy configuration file.'))
    assert label_only['workflow_branch']=='operational_only'  # weakness label alone is not a separate code-mechanism proof
    code=classify(cwe_case('CWE-862','The handler fails to check for proper permissions when remote users access it.'),source_available=True)
    assert code['workflow_branch']=='source_to_operational'
    assert 'explicit-enforcement-defect' in code['decisions'][0]['refinement_rules']
    both=classify(cwe_case('CWE-862','The handler fails to check permissions even with authentication configuration options.'),source_available=True)
    assert both['source_required']  # explicit code defect always wins over configuration words


def test_embedded_default_key_overrides_operator_key_rotation_profile():
    base=classify(cwe_case('CWE-1394'))
    embedded=classify(cwe_case('CWE-1394','The device uses a hardcoded default cryptographic key.'))
    assert base['workflow_branch']=='operational_only'
    assert embedded['source_required']


def test_prohibited_mapping_never_becomes_source_clearance_from_keywords():
    restricted=next(cid for cid,r in P.catalog()['profiles'].items() if r['official_metadata']['mapping_usage']=='Prohibited')
    result=classify(cwe_case(restricted,'Remote buffer overflow with an insecure configuration.'))
    assert result['requirement']=='undetermined'
    assert result['decisions'][0]['cve_mapping_gate']['blocked_for_cve_routing']


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
