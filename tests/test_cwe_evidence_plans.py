"""Evidence-plan provenance and limits; not classification accuracy tests."""
from src.cwe_evidence_policy import catalog,metadata
from src.cwe_taxonomy import load
from src.cwe_evidence_plans import plan,METHODS,contract_hash
from src.vex_routing import classify


def test_all_944_plans_match_only_their_own_official_definition_and_methods():
    data=catalog();taxonomy=load();official=metadata()
    assert data['summary']['evidence_plans']['total']==944
    assert data['summary']['evidence_plans']['entry_specific_method_available']==596
    assert data['summary']['evidence_plans']['mechanism_first']==348
    for cid,row in data['profiles'].items():
        p=row['evidence_plan'];record=taxonomy['records'][cid];methods=official['records'][cid]['detection_methods']
        assert p['cwe']==cid and p['contract_sha256']==contract_hash()
        assert p['source_snapshot']['metadata_sha256']==official['sha256']
        a,b=p['claim_to_examine']['span']
        assert record['description'][a:b]==p['claim_to_examine']['text']
        assert len(p['alternatives'])==len(methods)
        for entry,method in zip(p['alternatives'],methods):
            assert entry['method'] in METHODS
            assert entry['evidence']['method']==method['method']
            assert entry['evidence']['description']==method.get('description','')
            assert entry['listed_on_this_CWE'] and not entry['inherited']
        assert not p['assigns_CWE'] and not p['authorizes_VEX_status']


def test_method_missing_does_not_inherit_from_parents_with_detection_methods():
    data=catalog()['profiles'];m=metadata()['records']
    candidates=[cid for cid,r in data.items() if not m[cid]['detection_methods'] and
                any(m.get(a,{}).get('detection_methods') for a in r['ancestors'] if a!=cid)]
    assert candidates
    for cid in candidates:
        p=data[cid]['evidence_plan']
        assert p['recommended_routes']==['cve_mechanism_first']
        assert p['next_action'] and not p['alternatives']


def test_static_and_dynamic_methods_are_alternatives_not_joint_requirements():
    record={'description':'A specific property is violated.','url':'https://example.invalid/CWE'}
    info={'detection_methods':[{'method':'Automated Static Analysis - Source Code','description':'Inspect the source.'},
                               {'method':'Automated Dynamic Analysis','description':'Observe execution.'}]}
    p=plan('CWE-89',record,info)
    assert p['recommended_routes']==['runtime_observation','source_review']
    assert p['route_relation']=='alternatives_require_case_selection'
    assert p['source_required']=='not_determined_by_detection_method'
    assert not p['operator_questionnaire_alone_established_sufficient']


def test_generic_static_analysis_is_not_silently_restricted_to_source():
    p=plan('CWE-89',{'description':'A property.','url':''},{'detection_methods':[{'method':'Automated Static Analysis'}]})
    assert p['recommended_routes']==['implementation_review']
    assert 'source_review' not in p['recommended_routes']


def test_plans_do_not_change_runtime_requirements_or_assign_a_new_CWE():
    r=classify({'cve':'CVE-2099-45678','cwe':['CWE-89'],
                'evidence_plan':{'recommended_routes':['source_review']},
                'description':'SQL injection in a remote interface.'},source_available=True)
    assert r['cwes']==['CWE-89'] and r['workflow_branch']=='routing_unknown'
    assert r['decisions'][0]['evidence_plan']['alternatives']
    assert r['initial_vex_status']=='under_investigation'
