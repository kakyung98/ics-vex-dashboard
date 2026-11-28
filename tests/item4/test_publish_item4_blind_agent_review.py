from copy import deepcopy
import json
import pytest

from tools.item4 import publish_item4_blind_agent_review as review


def example():
    card = dict(review_id='R-1',evidence=[dict(evidence_id='O01',title='운영 관측',kind='synthetic',source={})])
    row = dict(review_id='R-1',status='under_investigation',evidence_ids=['O01'],rationale='범위가 불명확하다.',
               needed_records='해당 자산의 관측시점이 있는 설치 기록',field_record_types=['deployment_inventory'])
    ballot = dict(schema_version=review.BALLOT,packet_id='packet',reviewer_kind='ai_agent',
                  reviewer_slot='reviewer_a',ratings=[row])
    return {card['review_id']:card}, row, ballot


@pytest.mark.parametrize('mutate', [
    lambda b:b.update(reviewer_kind='human'),lambda b:b.update(reviewer_slot='reviewer_b'),
    lambda b:b['ratings'].append(deepcopy(b['ratings'][0])),
    lambda b:b['ratings'][0].update(evidence_ids=['S99']),
    lambda b:b['ratings'][0].update(field_record_types=['supplier_scope']),
])
def test_swapped_duplicate_or_unsubstantiated_submission_fails(mutate):
    cards,row,ballot = example()
    assert review.load_ballot(review.encoded(ballot),'reviewer_a','packet',cards) == {'R-1':row}
    mutate(ballot)
    with pytest.raises(ValueError):
        review.load_ballot(review.encoded(ballot),'reviewer_a','packet',cards)


def test_union_counts_and_human_count_are_per_scenario():
    cards,a,_ = example()
    b = dict(a,status='affected',field_record_types=['deployment_inventory','change_history'])
    key = [dict(review_id='R-1',cve='CVE-fixture',source_scenario_id='src-1',candidate_status='affected',stratum='affected')]
    rows,stats = review.compare(dict(packet_id='packet',source_run_id='source'),cards,key,
                                {'reviewer_a':{'R-1':a},'reviewer_b':{'R-1':b}})
    assert not rows[0]['agreement'] and rows[0]['shared_field_record_types']==['deployment_inventory']
    info = stats['agent_review']
    assert (info['agent_ratings'],info['agreements'],info['disagreements'],info['human_reviewed_scenarios'])==(2,0,1,0)
    assert info['field_record_type_counts']['deployment_inventory']==info['field_record_type_counts']['change_history']==1
    assert stats['agreement_ids']==[] and stats['disagreement_ids']==['R-1']


def test_external_locks_checked_before_unsealing_or_comparison():
    with pytest.raises(ValueError, match='hashes reported'):
        review.make_outputs({}, {}, [], dict.fromkeys(review.SLOTS,b'invalid JSON'),
                            dict.fromkeys(review.SLOTS,'0'*64),{})


def test_duplicate_key_is_rejected():
    with pytest.raises(ValueError, match='Duplicate JSON key'):
        json.loads('{"reviewer_slot":"reviewer_a","reviewer_slot":"reviewer_b"}',object_pairs_hook=review.unique_keys)
