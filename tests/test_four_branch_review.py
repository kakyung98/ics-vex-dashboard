"""Evidence ordering, isolation and export must not change the locked decision."""
from copy import deepcopy
import pytest
from src import item4_review as I4, vex_roles as VR
from src.vex_routing import classify
from tests.test_item4_routing import case
from tests.test_shared_vex_pipeline import provider


def source(cve, status='under_investigation'):
    return {'cve':cve, 'status':status, 'justification':'code_not_present' if status=='not_affected' else None,
            'reason':'Scoped source evidence.', 'scope':'complete declared product build', 'arm':'source-code'}


def test_source_only_and_missing_source_are_distinct(monkeypatch):
    calls=[];monkeypatch.setattr(VR,'infer',provider(calls))
    initial=I4.start([case()]);rid=initial['review_id'];cve=initial['statements'][0]['cve']
    assert initial['routes'][cve]['workflow_branch']=='source_missing'
    assert not calls
    final=I4.record_source(rid,{'statements':[source(cve,'not_affected')]})
    assert final['routes'][cve]['workflow_branch']=='source_only'
    assert final['statements'][0]['status']=='not_affected'
    assert {r for r,_ in calls}=={'vex-writer'}


def test_source_then_operating_context_waits_and_retains_source(monkeypatch):
    calls=[];monkeypatch.setattr(VR,'infer',provider(calls))
    initial=I4.start([case(description='A remote attacker triggers an out-of-bounds write.')]);rid=initial['review_id']
    cve=initial['statements'][0]['cve'];case_id=initial['statements'][0]['case_id']
    with pytest.raises(ValueError):I4.questions(rid)
    midway=I4.record_source(rid,{'statements':[source(cve,'not_affected')]})
    row=midway['statements'][0]
    assert row['status']=='under_investigation' and not calls
    assert row['analysis_route']['workflow_branch']=='source_to_operational'
    assert row['evidence_progress']['pending']==['Required operational review is missing.']
    plan=I4.questions(rid)
    with pytest.raises(ValueError):I4.answers(rid,{},plan_id='foreign-plan')
    assert plan['cases'][0]['case_id']==case_id
    assert I4.questions(rid)['id']==plan['id']
    final=I4.answers(rid,{})
    row=final['statements'][0]
    assert row['case_id']==case_id and row['status']=='not_affected'
    assert set(row['branch_evidence'])=={'source','operational'}
    assert row['evidence_progress']['ready_for_authoring']
    before=len(calls)
    I4.record_source(rid,{'statements':[source(cve,'not_affected')]})
    assert len(calls)==before  # identical evidence does not author twice


def test_operational_only_does_not_escalate_to_source(monkeypatch):
    calls=[];monkeypatch.setattr(VR,'infer',provider(calls))
    c=case('CWE-319','Network traffic is unencrypted.')
    initial=I4.start([c]);rid=initial['review_id'];cve=c['cve']
    assert initial['routes'][cve]['workflow_branch']=='operational_only'
    plan=I4.questions(rid)
    assert not any(q['id'].endswith(':custom-implementation') for q in plan['cases'][0]['questions'])
    final=I4.answers(rid,{})
    assert final['routes'][cve]['workflow_branch']=='operational_only'
    assert not final['routes'][cve]['source_required']
    assert set(final['statements'][0]['branch_evidence'])=={'operational'}
    assert final['statements'][0]['case_id']==initial['statements'][0]['case_id']
    assert {r for r,_ in calls}=={'vex-writer'}
    with pytest.raises(ValueError):I4.record_source(rid,{'statements':[source(cve)]})


def test_retired_five_path_reviews_require_restart_without_deleting_history():
    from src import review_store as STORE
    initial=I4.start([case()]);rid=initial['review_id'];master=I4.get(rid)
    master['cases'][0]['analysis_route']['workflow_policy_version']='five-branch-v1'
    STORE.put('item4_review',rid,master)
    with pytest.raises(KeyError,match='retired five-path'):I4.get(rid)
    assert STORE.get('item4_review',rid)==master


def test_conflicting_decisions_are_not_authored_or_overwritten(monkeypatch):
    calls=[];monkeypatch.setattr(VR,'infer',provider(calls))
    initial=I4.start([case(description='Remote out-of-bounds write.')]);rid=initial['review_id'];cve=initial['statements'][0]['cve']
    I4.record_source(rid,{'statements':[source(cve,'not_affected')]})
    master=I4.get(rid)
    result=I4._update(master,[{'cve':cve,'status':'fixed','justification':None,'reason':'Vendor build record.'}],'operational_review')
    row=result['statements'][0]
    assert row['status']=='under_investigation' and not calls
    assert 'conflict' in row['reason']
    assert row['branch_evidence']['source']['status']=='not_affected'
    assert row['branch_evidence']['operational']['status']=='fixed'


def test_export_cannot_clear_required_source_with_fixed_version_row():
    from src.sbom_vex import merge
    c=case('CWE-319','Network traffic is unencrypted.')
    sbom={'bomFormat':'CycloneDX','specVersion':'1.6','version':1,
          'components':[{'type':'firmware','name':'Fixture','bom-ref':'device'}]}
    s={'cve':c['cve'],'case_id':'bound-case','status':'under_investigation','reason':'Required source missing.',
       'evidence_progress':{'ready_for_authoring':False},
       'operational_review':{'version_evaluation':{'components':[{
           'component_ref':'device','state':'listed_fixed','operator_attested':True,
           'operator_evidence':'record-42','product_name':'Fixture','installed_version':'2'}]}}}
    result=merge(sbom,{'statements':[s]},[c])
    assert result['vulnerabilities'][0]['analysis']['state']=='in_triage'
    assert 'vulnerabilities' not in sbom


def test_source_and_operational_requirements_cite_triggering_text():
    r=classify(case(description='Remote attackers trigger an out-of-bounds write.'),source_available=True)
    assert r['workflow_branch']=='source_to_operational'
    assert r['operational_requirement_evidence'][0]['quote']=='Remote'


def test_foreign_or_duplicate_source_results_are_atomic():
    c=case();initial=I4.start([c]);rid=initial['review_id']
    before=deepcopy(I4.get(rid))
    for statements in ([source(c['cve']),source('CVE-2099-99999')], [source(c['cve'])]*2):
        with pytest.raises(ValueError):I4.record_source(rid,{'statements':statements})
        assert I4.get(rid)==before
