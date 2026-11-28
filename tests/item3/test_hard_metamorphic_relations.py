from copy import deepcopy
from src.item3.hard_metamorphic import compare,summarize


def fixture():
    ref=dict(identity=['a','maker','controller'],version='1.2.3')
    row=dict(error=None,agent_failures=[],target=dict(identity=['validated','a','maker','controller'],version='1.2.3',range=None,cves=[['CVE-A','match'],['CVE-B','no_match']],conflicts=[],lookup_error=None))
    return ref,row


def test_constant_unresolved_cannot_pass_invariance():
    r,a=fixture();a['target']['identity']=['unresolved',None,None,None]
    assert not compare('redundant_purl',a,deepcopy(a),r)['passed']


def test_singleton_interval_preserves_release_meaning():
    r,a=fixture();b=deepcopy(a);b['target'].update(version=None,range=dict(lower='1.2.3',upper='1.2.3',lower_inclusive=True,upper_inclusive=True))
    assert compare('singleton_interval',a,b,r)['passed']
    b['target']['range']['upper_inclusive']=False;assert not compare('singleton_interval',a,b,r)['passed']


def test_release_conflict_requires_unresolved_version_and_unknown_match():
    r,a=fixture();b=deepcopy(a);b['target'].update(version=None,conflicts=['explicit_versions_disagree'],cves=[['CVE-A','unknown'],['CVE-B','unknown']])
    assert compare('conflicting_release_evidence',a,b,r)['passed']
    b['target']['cves'][0][1]='match';assert not compare('conflicting_release_evidence',a,b,r)['passed']


def test_removing_information_cannot_create_new_confirmed_cve():
    r,a=fixture();b=deepcopy(a);b['target'].update(version=None,cves=[['CVE-A','unknown'],['CVE-B','match']])
    assert not compare('release_information_removed',a,b,r)['passed']


def test_identity_conflict_is_not_repaired_by_choosing_a_side():
    r,a=fixture();b=deepcopy(a);b['target']['cves']=[]
    assert not compare('conflicting_manufacturer',a,b,r)['passed']
    b['target']['identity']=['unresolved',None,None,None];assert compare('conflicting_manufacturer',a,b,r)['passed']


def test_missing_prediction_remains_a_failure():
    r,a=fixture();inputs=[dict(id='x__original',base_id='x',relation='original'),dict(id='x__redundant_purl',base_id='x',relation='redundant_purl')]
    a['id']='x__original';r['id']='x';result=summarize(inputs,[a],[r]);assert result['counts']['pairs']==1 and result['counts']['passed']==0
