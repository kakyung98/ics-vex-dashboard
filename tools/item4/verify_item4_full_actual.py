"""Independently rescore every frozen ID; no production decision code imported."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
DATA=ROOT/'benchmark/item4_evaluation'
OUT=ROOT/'results/item4_full_actual_20261120'


def main():
    manifest=json.loads((DATA/'full_population_manifest.json').read_bytes())
    for name,h in manifest['artifacts'].items():
        assert hashlib.sha256((DATA/name).read_bytes()).hexdigest()==h,name
    references={}
    for line in (DATA/'full_population_gold.jsonl').open(encoding='utf-8'):
        row=json.loads(line);assert row['id'] not in references
        references[row['id']]=row
    predictions={}
    for line in (OUT/'predictions.jsonl').open(encoding='utf-8'):
        row=json.loads(line);assert row['id'] not in predictions
        predictions[row['id']]=row
    assert len(predictions)==len(references)==62090 and predictions.keys()==references.keys()
    assert len({p['cve'] for p in predictions.values()})==12418
    counts=Counter();statuses=Counter();per_cve=Counter()
    for case,pred in predictions.items():
        ref=references[case];assert pred['cve']==ref['cve']
        actual=ref['actual_affected'];status=pred['status']
        assert status in {'affected','fixed','not_affected','under_investigation'}
        counts['TP']+=status=='affected' and actual is True
        counts['FP']+=status=='affected' and actual is False
        counts['unjudged_predicted_affected']+=status=='affected' and actual is None
        counts['FN_including_abstentions']+=status!='affected' and actual is True
        counts['execution_error_cases']+=bool(pred.get('error'))
        statuses[status]+=1;per_cve[pred['cve']]+=1
    assert set(per_cve.values())=={5}
    denom=counts['TP']+counts['FP']
    precision=100*counts['TP']/denom if denom and not counts['unjudged_predicted_affected'] else None
    report=json.loads((OUT/'report.json').read_bytes())
    for k in ['TP','FP','unjudged_predicted_affected','FN_including_abstentions']:
        assert report['all_cases'][k]==counts[k],k
    assert report['all_cases']['precision_percent']==precision
    assert report['all_cases']['target_met']==(precision>85 if precision is not None else None)
    spec=report['model_config']['roles']['exploitation-prerequisites']
    assert spec['sha256']=='7ce8bfea47c7c226092566396cf75972a3cccc1305f0137e5953f3ba6882ebaf'
    assert report['model_config']['weights_retrained'] is False
    audit=dict(passed=True,population_cves=12418,cases=62090,all_five_variants_present_for_every_CVE=True,
        counts=dict(counts),status_counts=dict(statuses),precision_percent=precision,
        target_met=precision>85 if precision is not None else None,
        exact_input_gold_prediction_ID_match=True,model_adapter_hash_verified=True,
        frozen_artifact_hashes_verified=True,gold_labels_modified_for_score=False,
        independent_rescoring_is_not_independent_reference_accuracy_validation=True)
    (OUT/'independent_rescore.json').write_text(json.dumps(audit,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(audit,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
