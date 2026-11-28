import pytest
from src.item4.evaluation.identified_impact_precision import score,controlled_truth,score_identified_cves


def test_all_identifications_are_positive_and_false_is_fp():
    result=score([True,False,False,True])
    assert result['identified_positives']==4
    assert (result['TP'],result['FP'],result['precision'])==(2,2,.5)


def test_unknowns_cannot_be_dropped_or_counted_as_negative():
    result=score([True,False,None,None])
    assert result['precision'] is None and result['target_met'] is None
    assert result['precision_bounds']==[.25,.75]
    assert result['judged_only_precision']==.5


def test_threshold_is_strict_and_empty_is_undefined():
    assert score([True]*85+[False]*15)['target_met'] is False
    assert score([True]*86+[False]*14)['target_met'] is True
    assert score([])['precision'] is None
    with pytest.raises(ValueError):score([1])


def test_world_truth_uses_physical_facts_and_not_candidate_status():
    world=dict(component_deployed=True,cve_vulnerable_implementation_present=True,
               complete_exploitation_route_active=True,required_actor_control_available=True,
               effective_inline_protection=False)
    assert controlled_truth(world) is True
    for key in list(world):
        changed=dict(world);changed[key]=not changed[key]
        assert controlled_truth(changed) is False


def test_all_identified_cves_stay_in_denominator_including_unknowns():
    predictions=[dict(id='asset-a',component_predictions=[dict(component_ref='component',
        confirmed_cves=['CVE-1','CVE-2','CVE-3','CVE-1'],candidate_cves=['CVE-unconfirmed'])])]
    labels=[dict(sbom_id='asset-a',component_ref='component',cve='CVE-1',actual_exploitable=True),
            dict(sbom_id='asset-a',component_ref='component',cve='CVE-2',actual_exploitable=False)]
    result=score_identified_cves(predictions,labels)
    assert result['identified_cves']==3
    assert result['confirmed_exploitable_fraction']==1/3
    assert result['exploitability_fraction'] is None
    assert result['exploitability_fraction_bounds']==[1/3,2/3]
    assert result['unknown_exploitability']==1
    assert score_identified_cves(predictions)['unknown_exploitability']==3
    assert score_identified_cves(predictions*2)['identified_cves']==3
    with pytest.raises(ValueError,match='Duplicate'):
        score_identified_cves(predictions,labels*2)
    with pytest.raises(ValueError,match='outside'):
        score_identified_cves([],labels)
