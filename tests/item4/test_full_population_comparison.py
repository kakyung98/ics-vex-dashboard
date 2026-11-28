from copy import deepcopy
import pytest
from src.item4.decision import evidence_based_vex as E
from tools.item4.compare_full_population_benchmark import reseal_payload,metric_comparison


def fixture():
    previous=dict(version='engine/2',product=dict(key='p'),questions=[dict(id='deployment',options={'running':'Installed'})])
    payload=dict(cve='CVE-2026-10001',product_key='p',plan_sha256=E.digest(previous),profile=dict(scope=dict(build='1.0')),auto_observations={'deployment':{'value':'running'}})
    current=deepcopy(previous);current['version']='engine/3';current['plan_sha256']=E.digest(current)
    return payload,current


def test_replay_preserves_every_observation_and_changes_only_the_plan_hash():
    payload,plan=fixture();original=deepcopy(payload)
    updated=reseal_payload(payload,plan,'engine/2')
    assert payload==original
    assert updated==dict(original,plan_sha256=plan['plan_sha256'])


def test_changed_question_content_cannot_be_silently_resealed():
    payload,plan=fixture();plan['questions'][0]['options']['running']='Different fact'
    with pytest.raises(ValueError,match='beyond the engine version'):reseal_payload(payload,plan,'engine/2')


def test_comparison_retains_unknown_metrics_and_reports_percentage_point_deltas():
    result=metric_comparison(dict(precision=None,recall=.8,cases=3,predictions={}),dict(precision=None,recall=.7,cases=3,predictions={}))
    assert result['precision']['delta'] is None
    assert result['recall']['delta']==pytest.approx(-.1)
    assert result['cases']['delta']==0
