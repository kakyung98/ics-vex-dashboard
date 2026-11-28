from copy import deepcopy

import pytest

from tools.item4 import adjudicate_item4_spectrum as case


@pytest.fixture
def observations():
    supplier = {'source_id':'SSA-324467','cve_id':case.CVE,'url':'https://cert-portal.siemens.com/productcert/pdf/ssa-324467.pdf'}
    row = {'review_id':case.CASE,'source_scenario_id':case.SCENARIO,
           'reviewer_a':{'status':'under_investigation'},'reviewer_b':{'status':'affected'}}
    field = {'review_id':case.CASE,'source_scenario_id':case.SCENARIO,'cve':case.CVE,
             'verified_field_records':0,'running_release_verified':None,'portal_installation_verified':None,
             'bugfix_installation_verified':None}
    return supplier,field,row


def test_unknown_field_state_preserves_prior_pair_and_yields_hold(observations):
    supplier,field,row = observations
    summary = case.assess(supplier,field,row)
    assert summary['status']=='under_investigation' and summary['human_reviewed_scenarios']==0
    assert summary['previous_statuses']=={'reviewer_a':'under_investigation','reviewer_b':'affected'}
    assert all(field[k] is None for k in ('running_release_verified','portal_installation_verified','bugfix_installation_verified'))


@pytest.mark.parametrize('changes', [
    {'verified_field_records':None}, {'verified_field_records':1}, {'running_release_verified':True},
    {'portal_installation_verified':True}, {'bugfix_installation_verified':True},
    {'source_scenario_id':'other'}, {'cve':'CVE-2019-0000'}, {'review_id':'other'},
])
def test_an_updated_or_unmatched_observation_cannot_reuse_the_historical_hold(observations, changes):
    supplier,field,row = observations
    with pytest.raises(ValueError):
        case.assess(supplier,dict(field,**changes),row)


def test_source_identity_and_vendor_pdf_binding(observations, monkeypatch, tmp_path):
    from tools.item4 import item4_spectrum_supplier as vendor
    valid = vendor.supplier_evidence()
    assert valid['remediation']['fix_id']=='bf-47456_PE_WOP_fix'
    assert valid['version_context']['title_version']=='4.7' and valid['version_context']['affected_version_range'] is None
    wrong = deepcopy(valid)
    wrong['cve_id']='CVE-2019-0000'
    with pytest.raises(ValueError):
        case.assess(wrong,*observations[1:])
    monkeypatch.setattr(vendor,'ROOT',tmp_path)
    file = tmp_path/vendor.SNAPSHOT
    file.parent.mkdir(parents=True)
    file.write_bytes(b'changed')
    with pytest.raises(ValueError,match='SHA-256'):
        vendor.supplier_evidence()
