import importlib.util
import json
from pathlib import Path

spec=importlib.util.spec_from_file_location('source_training',Path(__file__).resolve().parents[1]/'tools/train_source_evidence.py')
training=importlib.util.module_from_spec(spec)
spec.loader.exec_module(training)


def row():
    return {'id':'VA0001','messages':[{'role':'assistant','content':json.dumps({'dependency_linked':True,'api':'xmlReadMemory','api_reachable_from_main':False,'additional_api_guard_present':False})}]}


def test_complete_fact_match_and_partial_accuracy():
    gold=json.loads(row()['messages'][-1]['content'])
    good=json.dumps(gold)
    bad=json.dumps({**gold,'api_reachable_from_main':True})
    metrics,preds=training.score([row(),row()],[good,bad])
    assert metrics['exact_accuracy']==.5 and metrics['schema_valid_rate']==1
    assert metrics['field_accuracy']['api_reachable_from_main']==.5
    assert len(preds)==2


def test_wrong_boolean_type_and_unrequested_vex_status_are_invalid():
    gold=json.loads(row()['messages'][-1]['content'])
    metrics,_=training.score([row(),row()],[json.dumps({**gold,'dependency_linked':1}),json.dumps({**gold,'vex':'not_affected'})])
    assert metrics['schema_valid_rate']==0 and metrics['exact_accuracy']==0


def test_missing_prediction_is_not_silently_dropped():
    import pytest
    with pytest.raises(ValueError):training.score([row()],[])
