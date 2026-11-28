from copy import deepcopy
import pytest
from src.item4.evaluation.cvss_extraction_scoring import score


def atom(cid,target):
    quote='Exploitation requires '+target+' enabled.'
    return dict(id=cid,predicate='feature_enabled',target=target,value='enabled',operator='eq',expected=True,
                operational_quote=quote,source_refs=[dict(source_id='fixture',quote=quote)])


def fixture():
    draft=dict(prerequisites=[atom('a','HTTP'),atom('b','SSH')],
               scenarios=[dict(expression=dict(op='and',args=[dict(condition='a'),dict(condition='b')]))])
    gold=dict(cve='CVE-2099-12345',source_record_sha256='fixture-source',draft=draft,
              review_method='independent_human',reviewer='Synthetic control author')
    prediction=dict(cve=gold['cve'],source_record_sha256='fixture-source',status='extracted',artifact=dict(draft=deepcopy(draft)))
    return prediction,gold


def test_extraction_and_logic_are_separate_measures():
    prediction,gold=fixture();prediction['artifact']['draft']['scenarios'][0]['expression']['op']='or'
    report=score([prediction],[gold])
    assert report['precision']==1 and report['recall']==1
    assert report['logic_judged']==1 and report['logic_correct']==0


def test_failed_extraction_is_not_dropped_from_the_recall_denominator():
    prediction,gold=fixture();prediction.update(status='unresolved',artifact=None)
    report=score([prediction],[gold])
    assert report['failed']==1 and report['FN']==2 and report['recall']==0


def test_failed_empty_extraction_does_not_count_as_a_correct_negative():
    prediction,gold=fixture();gold['draft']=dict(prerequisites=[],scenarios=[])
    prediction.update(status='unresolved',artifact=None)
    report=score([prediction],[gold])
    assert report['logic_judged']==1 and report['logic_correct']==0


def test_no_gold_does_not_produce_an_accuracy_number():
    prediction,_=fixture();report=score([prediction])
    assert report['precision'] is None and report['recall'] is None
    assert report['unjudged_cves']==1


def test_source_drift_remains_unjudged_in_the_population():
    prediction,gold=fixture();prediction['source_record_sha256']='other-source'
    report=score([prediction],[gold])
    assert report['source_mismatches']==1 and report['unjudged_cves']==1 and report['cves']==1


def test_model_labels_cannot_be_presented_as_independent_gold():
    prediction,gold=fixture();gold['review_method']='model_generated'
    with pytest.raises(ValueError,match='independent human'):score([prediction],[gold])
