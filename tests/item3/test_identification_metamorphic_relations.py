from copy import deepcopy
from tools.item3.evaluate_identification_metamorphic import report


def fixture():
    inputs=[dict(id='a__original',base_id='a',variant='original',sbom={'name':'relay'}),dict(id='a__case',base_id='a',variant='case',sbom={'name':'RELAY'})]
    signature=[dict(identity=['validated','a','vendor','relay'],version='1.0',range=None,cves=[('CVE-X','match')],lookup_error=None)]
    rows=[dict(id=c['id'],signature=deepcopy(signature),error=None,model_used=True) for c in inputs]
    return inputs,rows


def test_changed_cve_is_a_robustness_failure_without_any_gold():
    inputs,rows=fixture();rows[1]['signature'][0]['cves']=[]
    assert not report(inputs,rows)['above_90']


def test_consistent_inference_failures_do_not_pass():
    inputs,rows=fixture()
    for r in rows:r['agent_failures']=[dict(stage='i3',error='model unavailable')]
    assert report(inputs,rows)['metrics']['all_preserved']==0


def test_missing_transformed_prediction_stays_in_denominator():
    inputs,rows=fixture();r=report(inputs,rows[:1])
    assert r['counts']['pairs']==1 and r['metrics']['all_preserved']==0


def test_stability_can_pass_without_claiming_correctness():
    inputs,rows=fixture();r=report(inputs,rows)
    assert r['above_90'] and 'not CVE accuracy' in r['scope']
