import copy
import json

import pytest

from src.item4.evaluation.blind_inventory_review import inspect_absence
from tools.item4 import publish_item4_policy_rereview as review


def example():
    component = {'ref':'component-1','name':'Product','vendor':'Supplier','cpes':[],'version':'1.0'}
    location = {'file':'cves/1.json','packet_sha256':'1'*64}
    card = {'component':component,'review_id':'R-1','cve':'CVE-test','evidence':[
        {'evidence_id':'B01','kind':'synthetic_bom_component','facts':{'component':component.copy()},
         'source':dict(location,pointer='/job/input_bom/components/0')},
        {'evidence_id':'O01','kind':'synthetic_operator_input','facts':{'context':{
            'deployment':'not_deployed','scope':'current_single','inventory_coverage':'complete'}},
         'source':dict(location,pointer='/cases/4',original_line_sha256='a'*64)}]}
    rating = {'review_id':'R-1','status':'not_affected','decision_basis':'deployment_absence',
              'inventory_evidence_ids':['O01','B01'],'evidence_ids':['O01','B01'],
              'rationale':'해당 단일 자산의 전수 조회에서 미배포를 확인했다.',
              'field_record_types':['inventory_completeness'],'needed_records':'해당 시점의 인벤토리 조회와 예외 목록'}
    return card, rating


def test_complete_inventory_and_matching_component_and_observation_accepted():
    card, rating = example()
    assert inspect_absence(card,rating)['coverage_explicit_complete']
    ballot = dict(schema_version='item4-independent-agent-ballot/2',packet_id='P',reviewer_kind='ai_agent',
                  reviewer_slot='reviewer_a',ratings=[rating])
    assert review.ratings_for(json.dumps(ballot),'reviewer_a','P',{'R-1':card}) == {'R-1':rating}


@pytest.mark.parametrize('change', ['missing','partial','unknown','other_scope','bom_only','wrong_component',
                                    'wrong_packet','wrong_case_pointer','spurious_citation','wrong_basis','relabel'])
def test_missing_or_unscoped_absence_evidence_rejected(change):
    card,rating = example()
    bom,operator = card['evidence']
    ctx = operator['facts']['context']
    if change=='missing':
        del ctx['inventory_coverage']
    elif change in {'partial','unknown'}:
        ctx['inventory_coverage']=change
    elif change=='other_scope':
        ctx['scope']='fleet'
    elif change=='bom_only':
        rating['inventory_evidence_ids']=['B01']
    elif change=='wrong_component':
        bom['facts']['component']['ref']='unrelated'
    elif change=='wrong_packet':
        bom['source']['packet_sha256']='2'*64
    elif change=='wrong_case_pointer':
        operator['source']['pointer']='/job'
    elif change=='spurious_citation':
        rating['inventory_evidence_ids']=['O01','B01','S99']
    elif change=='wrong_basis':
        rating['decision_basis']='other'
    else:
        del ctx['inventory_coverage']
        rating['decision_basis']='supplier_status'
    with pytest.raises(ValueError):
        inspect_absence(card,rating)


def test_blinding_commits_and_legacy_contract():
    card,rating = example()
    card['evidence'][1]['facts']['context'].pop('inventory_coverage')
    rating.update(status='under_investigation',decision_basis='insufficient_evidence')
    assert inspect_absence(card,rating)['inventory_coverage'] is None
    with pytest.raises(ValueError,match='attested'):
        review.check_locks(dict.fromkeys(review.SLOTS,b'not yet opened'),dict.fromkeys(review.SLOTS,'0'*64))
    ballot = dict(schema_version=review.first.BALLOT,packet_id='P',reviewer_kind='ai_agent',reviewer_slot='reviewer_a',ratings=[rating])
    with pytest.raises(ValueError,match='ballot/2'):
        review.ratings_for(json.dumps(ballot),'reviewer_a','P',{'R-1':card})


def test_only_one_transition_per_prior_case_and_new_disagreements_distinguished():
    card, rating = example()
    card['evidence'][1]['facts']['context']['deployment']='running'
    def row(rid, a, b):
        return dict(review_id=rid,reviewer_a=dict(rating,status=a,decision_basis='other'),
                    reviewer_b=dict(rating,status=b,decision_basis='other'),agreement=a==b)
    u,a,n='under_investigation','affected','not_affected'
    prior = [row('R-1',n,n),row('R-2',u,a),row('R-3',a,a)]
    current = [row('R-1',u,u),row('R-2',a,a),row('R-3',u,a)]
    policy,stats = review.transitions(current,{r['review_id']:r for r in prior},
                                    {r['review_id']:copy.deepcopy(card) for r in prior})
    assert (policy['prior_not_affected_count'],policy['prior_disagreement_count'],policy['prior_disagreements_now_agree'])==(1,1,1)
    assert policy['prior_not_affected_pairs']=={u+' / '+u:1}
    assert stats['newly_disagreed']==1 and stats['ordered_pairs_changed']==3
    assert [r['prior_groups'] for r in current]==[['prior_not_affected'],['prior_disagreement'],[]]


@pytest.mark.parametrize('basis', ['insufficient_evidence','other'])
@pytest.mark.parametrize('status', ['affected','fixed'])
def test_no_decisive_deployment_on_an_absent_unverified_asset(basis, status):
    card,rating=example()
    del card['evidence'][1]['facts']['context']['inventory_coverage']
    rating.update(decision_basis=basis,status=status,evidence_ids=['O01'],inventory_evidence_ids=['O01'])
    with pytest.raises(ValueError):
        inspect_absence(card,rating)
