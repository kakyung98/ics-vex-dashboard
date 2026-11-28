import pytest
from tools.item4.analyze_cluster_metadata import categorical_stats, label_panel


def test_perfect_alignment_and_permutation_baseline():
    c=['a']*20+['b']*20
    labels=['network']*20+['local']*20
    r=categorical_stats(c,labels,50)
    assert r['weighted_purity']==1
    assert r['ami']==pytest.approx(1)
    assert r['global_majority_baseline']==.5
    assert r['purity_above_permuted_mean']>0
    assert r['permutation_mi_p']<=.05


def test_reference_masks_do_not_remove_assigned_ids():
    assignments={'I1':'a','I2':'b','I3':'b','C4':'a'}
    labels={'I1':'N','I2':'L','I3':'CONFLICT:L|N'}
    original=assignments.copy()
    r=label_panel(assignments,labels,0)
    assert r['population']==4 and r['reference_missing']==1
    assert r['all_ids_including_missing']['n']==4
    assert r['observed_reference_only']['n']==3
    assert r['single_valued_reference_only']['n']==2
    assert assignments==original


def test_degenerate_metadata_cannot_be_interpreted_as_validation():
    r=categorical_stats(['a','a','b','b'],['N']*4)
    assert r['status']=='degenerate_reference'
    assert r['weighted_purity']==r['global_majority_baseline']==1
    assert r['entropy_reduction_fraction'] is None
    assert 'permutation_mi_p' not in r
