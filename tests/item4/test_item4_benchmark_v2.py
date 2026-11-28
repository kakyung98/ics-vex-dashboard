"""Meaningful failure-boundary checks for the new benchmark, not accuracy claims."""
import json
import pytest

from src.item4.evaluation.synthetic_vex_benchmark import JUSTIFICATIONS; from src.item4.evaluation.synthetic_vex_benchmark import scenario; from src.item4.evaluation.synthetic_vex_benchmark import reference; from src.item4.evaluation.synthetic_vex_benchmark import kappa; from src.item4.evaluation.synthetic_vex_benchmark import agreement; from src.item4.evaluation.synthetic_vex_benchmark import affected_precision; from src.item4.evaluation.synthetic_vex_benchmark import csaf_vex
from tools.item4.build_item4_csaf_benchmark import advisory_split, review_blank
from tools.item4.item4_expert_review import validate, paired, complete


def test_five_distinct_reasons_and_positive_control():
    for justification in JUSTIFICATIONS:
        candidate=scenario(justification,True)
        assert candidate['candidate_actual_affected'] is False
        assert candidate['candidate_justifications']==[justification]
    assert scenario('affected_control',True)['candidate_actual_affected'] is True
    assert scenario('insufficient_evidence',True)['candidate_actual_affected'] is None


def test_missing_source_never_becomes_fabricated_code_or_path_claim():
    for justification in JUSTIFICATIONS[1:]:
        candidate=scenario(justification,False)
        assert candidate['candidate_status']=='under_investigation'
        assert candidate['candidate_justifications']==[]
    assert scenario('affected_control',False)['candidate_actual_affected'] is None


def test_partial_facts_do_not_establish_positive_or_inline_mitigation():
    assert reference({'inline_protection_effective':True}) is None
    assert reference({'component_present':True,'vulnerable_code_present':True}) is None


def test_kappa_known_nontrivial_table_and_degenerate_marginal():
    pairs=[('yes','yes')]*20+[('yes','no')]*5+[('no','yes')]*10+[('no','no')]*15
    result=kappa(pairs)
    assert result['observed_agreement']==pytest.approx(.7)
    assert result['chance_agreement']==pytest.approx(.5)
    assert result['kappa']==pytest.approx(.4)
    assert kappa([('yes','yes')]*10)['kappa'] is None
    assert kappa([])['kappa'] is None


def test_cluster_bootstrap_and_missing_pair_reporting():
    rows=[dict(advisory_id='a',a={'status':'affected'},b={'status':'affected'}),
          dict(advisory_id='b',a={'status':'not_affected'},b={'status':'not_affected'}),
          dict(advisory_id='c',a={'status':None},b={'status':'affected'})]
    result=agreement(rows,'status',100)
    assert result['clusters']==2 and result['missing_pairs']==1
    assert result['kappa']==1
    assert result['ci95']==[1,1]


def test_existing_precision_strict_threshold_and_unknown_positive_block():
    predictions={str(i):{'status':'affected'} for i in range(20)}
    gold={str(i):{'actual_affected':i<17} for i in range(20)}
    report=affected_precision(predictions,gold)
    assert report['precision']==.85 and report['target_met'] is False
    gold['19']['actual_affected']=None
    report=affected_precision(predictions,gold)
    assert report['unjudged_predicted_affected']==1
    assert report['precision'] is None and report['target_met'] is None
    with pytest.raises(ValueError):affected_precision({},gold)
    assert affected_precision({'x':{'status':'under_investigation'}},
        {'x':{'actual_affected':True}})['precision'] is None


def test_csaf_reason_and_product_scope_and_draft():
    doc=csaf_vex('id','CVE-2020-1234','Hypothetical product','not_affected',
                 ['component_not_present'],'Synthetic complete inventory.')
    v=doc['vulnerabilities'][0]
    assert v['flags'][0]['product_ids']==v['product_status']['known_not_affected']
    assert doc['document']['tracking']['status']=='draft'
    with pytest.raises(ValueError):csaf_vex('id','CVE-2020-1234','p','affected',
                                          ['component_not_present'],'x')
    with pytest.raises(ValueError):csaf_vex('id','CVE-2020-1234','p','not_affected',[],'x')


def test_exact_deterministic_advisory_split_and_blank_is_not_review():
    rows={'icsa-'+str(i).zfill(8):{'declared_cves':[] if i%2 else ['CVE-2020-1234']} for i in range(3881)}
    train,evaluation=advisory_split(rows)
    assert len(train)==2717 and len(evaluation)==1164
    assert not set(train)&set(evaluation)
    assert set(train)|set(evaluation)==set(rows)
    assert (train,evaluation)==advisory_split(rows)
    assert not complete(review_blank('id','CVE-2020-1234','icsa-20-001-01'))


def test_expert_definite_status_requires_source_logic_and_evidence():
    row=review_blank('id','CVE-2020-1234','a')
    row.update(status='not_affected',actual_affected=False,justifications=['component_not_present'],
        source_binding_valid='yes',scenario_logic_valid='yes',evidence_sufficient='yes')
    for j in JUSTIFICATIONS:row['reason_'+j]='yes' if j=='component_not_present' else 'no'
    validate(row)
    row['source_binding_valid']='unknown'
    with pytest.raises(ValueError):validate(row)


def test_rating_scope_and_population_cannot_silently_change(tmp_path):
    (tmp_path/'review').mkdir()
    packet=dict(id='x',cve='CVE-2020-1234',advisory_id='a')
    (tmp_path/'review/packets.jsonl').write_text(json.dumps(packet)+'\n')
    for name in ('a','b'):
        (tmp_path/(name+'.jsonl')).write_text(json.dumps(review_blank('x','CVE-2020-1234','a'))+'\n')
    _,rows,pending=paired(tmp_path,tmp_path/'a.jsonl',tmp_path/'b.jsonl')
    assert not rows and pending==['x']
    (tmp_path/'b.jsonl').write_text('')
    with pytest.raises(ValueError):paired(tmp_path,tmp_path/'a.jsonl',tmp_path/'b.jsonl')
