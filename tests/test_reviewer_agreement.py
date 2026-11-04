from copy import deepcopy
import pytest
from src.reviewer_agreement import cohen_kappa, agreement_report


def test_known_chance_corrected_agreement():
    # Observed .8, expected .5: kappa .6, not raw .8.
    score = cohen_kappa(['yes']*5+['no']*5, ['yes']*4+['no']+['yes']+['no']*4)
    assert score['raw_agreement'] == .8
    assert score['expected_agreement'] == .5
    assert score['kappa'] == pytest.approx(.6)
    assert cohen_kappa(['a','b'], ['b','a'])['kappa'] == -1


def test_undefined_is_not_zero_or_perfect():
    assert cohen_kappa([], [])['kappa'] is None
    assert cohen_kappa(['a','a'], ['a','a'])['kappa'] is None
    with pytest.raises(ValueError): cohen_kappa(['a'], [])


def ratings(rater):
    return [{'unit_id': str(i), 'case_id': 'c'+str(i), 'group_id': 'g'+str(i), 'split': 'test',
             'task': 'routing', 'dimension': 'source_requirement', 'rater_id': rater,
             'rater_kind': 'human', 'phase': 'independent', 'label': 'yes' if i%2 else 'no'} for i in range(8)]


def test_alignment_missing_and_cluster_bootstrap():
    a=ratings('a');b=list(reversed(ratings('b')))
    b[0]['label']=None
    result=agreement_report(a,b,bootstrap=50)
    assert result['paired_units']==7 and result['missing_rating_pairs']==1
    assert result['strata'][0]['kappa']==1
    assert result==agreement_report(a,b,bootstrap=50)
    assert result['strata'][0]['bootstrap']['unit']=='group_id'
    assert not result['gold_correctness_established']


@pytest.mark.parametrize('change', ['same_rater','adjudicated','mixed_kind','metadata','duplicate'])
def test_invalid_independent_pairs_rejected(change):
    a=ratings('a');b=deepcopy(ratings('b'))
    if change=='same_rater':
        for r in b:r['rater_id']='a'
    if change=='adjudicated':b[0]['phase']='adjudicated'
    if change=='mixed_kind':
        for r in b:r['rater_kind']='model'
    if change=='metadata':b[0]['group_id']='different'
    if change=='duplicate':b.append(b[0])
    with pytest.raises(ValueError):agreement_report(a,b)


def test_cross_model_is_not_human_agreement():
    a=ratings('claude');b=ratings('gemini')
    for r in a+b:r['rater_kind']='model'
    assert agreement_report(a,b,bootstrap=0)['agreement_kind']=='cross_model'
    assert agreement_report([],[])['status']=='not_evaluated'
