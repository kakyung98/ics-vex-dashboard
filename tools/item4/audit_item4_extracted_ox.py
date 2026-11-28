"""Verify the completed O/X run independently of its scoring implementation."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from collections import Counter
from pathlib import Path
import argparse
import hashlib
import json


def read(path):
    return json.loads(path.read_bytes())


def rows(path):
    with path.open(encoding='utf-8') as stream:
        return [json.loads(line) for line in stream if line.strip()]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit(root):
    data=root/'benchmark/item4_evaluation/extracted_ox_v3'
    out=root/'results/item4_extracted_ox_v3'
    assert read(out/'status.json')['status']=='complete'
    assert read(data/'manifest.json')['status']=='complete'
    expected=set(read(data/'population_ledger.json')['cves'])
    assert len(expected)==12418
    inputs=rows(data/'inputs.jsonl');predictions=rows(out/'predictions.jsonl')
    references=rows(data/'candidate_labels.jsonl');expert=rows(data/'expert_gold.jsonl')
    indexes=[]
    for records in [inputs,predictions,references,expert]:
        index={row['id']:row for row in records}
        assert len(index)==len(records)
        assert {row['cve'] for row in records}==expected
        indexes.append(index)
    assert all(set(index)==set(indexes[0]) for index in indexes)
    assert all(row['actual_affected'] is None and row['expert_validated'] is False for row in expert)
    assert all(not {'actual_affected','logic_consistency_only','label_method'}&set(row) for row in inputs)
    for identity in indexes[0]:
        assert len({index[identity]['cve'] for index in indexes})==1
    counts=Counter({key:0 for key in ['TP','FP','FN','unjudged_predicted_affected']})
    labels=Counter();statuses=Counter()
    dimensions={key:Counter() for key in ['product_applicability','prerequisite_status',
        'deployment_exploitability','graph_generation_status']}
    ref=indexes[2]
    for prediction in predictions:
        actual=ref[prediction['id']]['actual_affected']
        assert actual is True or actual is False or actual is None
        positive=prediction['status']=='affected'
        if positive:
            counts['TP' if actual is True else 'FP' if actual is False else 'unjudged_predicted_affected']+=1
        elif actual is True:
            counts['FN']+=1
        labels[str(actual)]+=1;statuses[prediction['status']]+=1
        for key,values in dimensions.items():values[str(prediction.get(key,'missing'))]+=1
    denominator=counts['TP']+counts['FP']
    precision=counts['TP']/denominator if denominator and not counts['unjudged_predicted_affected'] else None
    report=read(out/'report.json');metric=report['all_cases']
    for key in ['TP','FP','FN','unjudged_predicted_affected']:assert counts[key]==metric[key],key
    assert metric['formula']=='TP/(TP+FP)' and metric['strict_threshold']==.85
    assert metric['precision']==precision
    assert metric['target_met']==(precision>.85 if precision is not None else None)
    assert report['status_counts']==dict(statuses)
    assert report['population_cves']==12418 and metric['cases']==len(inputs)
    producer=root/'source_extraction_audit'
    source_config=read(producer/'run_config.json')
    protocol=read(out/'protocol.json')
    for name,expected_hash in protocol['code_sha256'].items():
        assert sha(root/name)==expected_hash,name
    assert sha(root/'tools/item4/run_item4_extracted_ox.py')==protocol['runner_sha256']
    assert sha(producer/'run_config.json')==protocol['extraction_run_config_sha256']
    frozen=producer/'frozen_population'
    assert sha(frozen/'full_population_manifest.json')==source_config['frozen_manifest_sha256']
    for name,expected_hash in read(frozen/'full_population_manifest.json')['artifacts'].items():
        assert sha(frozen/name)==expected_hash,name
    assert sha(frozen/'full_population_inputs.jsonl')==protocol['source_input_sha256']
    assert sha(frozen/'full_population_gold.jsonl')==protocol['source_reference_sha256']
    population=rows(frozen/'full_population_inputs.jsonl')
    assert len(population)==len({row['cve'] for row in population})==12418
    assert {row['cve'] for row in population}==expected
    for name,expected_hash in source_config['code_sha256'].items():
        assert sha(producer/'frozen_producer'/name)==expected_hash,name
    for name,expected_hash in source_config.get('evaluation_code_sha256',{}).items():
        assert sha(producer/'frozen_producer/tools'/name)==expected_hash,name
    raw_counts=Counter();raw_cves=set();raw_nonempty=set();roles=Counter()
    for path in (producer/'raw').glob('*.json'):
        response=read(path);raw_counts['responses']+=1;roles[response.get('role','missing')]+=1
        cve=response.get('cve')
        if cve in expected:raw_cves.add(cve)
        if response.get('role')=='exploitation-prerequisites':
            assert response['model']['adapter']['sha256']==protocol['model']['adapter']['sha256']
        try:parsed=json.loads(response['raw'])
        except (ValueError,KeyError,TypeError):raw_counts['non_JSON_responses']+=1;continue
        raw_counts['JSON_decodable_responses']+=1
        if isinstance(parsed,dict) and parsed.get('prerequisites'):
            raw_counts['responses_with_nonempty_candidate_prerequisites']+=1
            if cve in expected:raw_nonempty.add(cve)
    stages=Counter();extraction_status=Counter();classification_status=Counter();binding=Counter();errors=Counter()
    extraction_failures=Counter()
    for cve in sorted(expected):
        datafile=data/'cves'/(cve+'.json');reffile=data/'references'/(cve+'.json')
        case=read(datafile);result=read(out/'cves'/(cve+'.json'));job=case['job']
        assert case['cve']==result['cve']==cve
        assert case['real_extraction_checkpoint_sha256']==sha(producer/'cves'/(cve+'.json'))
        assert result['input_sha256']==sha(datafile)
        assert result['reference_frozen_sha256']==sha(reffile)
        assert {row['id'] for row in case['cases']}=={row['id'] for row in result['predictions']}
        assert all(indexes[0][row['id']]==row for row in case['cases'])
        assert all(indexes[1][row['id']]==row for row in result['predictions'])
        assert all(indexes[2][row['id']]==row for row in read(reffile))
        stages['CVEs']+=1;stages['questions']+=len(job['questions'])
        stages['CVEs_with_questions']+=bool(job['questions'])
        condition=job['conditions'][0];artifact=condition.get('prerequisite') or {}
        draft=artifact.get('draft') or {}
        stages['CVEs_with_admitted_artifact']+=bool(artifact)
        stages['CVEs_with_nonempty_admitted_conditions']+=bool(draft.get('prerequisites'))
        stages['scenarios_with_product_keys']+=sum(bool(s.get('product_keys')) for s in draft.get('scenarios',[]))
        stages['exhaustive_ternary_CVEs']+=case['generation']['coverage']['exhaustive']
        stages['CVEs_with_independent_source_path']+=case['generation']['independent_source_path_available']
        stages['CVEs_with_source_question_binding']+=bool(case['generation']['source_condition_bindings'])
        extraction_status[condition.get('status','missing')]+=1
        if not artifact:extraction_failures[condition.get('reason','missing')]+=1
        classification_status[(job.get('asset_classification') or {}).get('status','missing')]+=1
        for row in read(reffile):binding[row['label_method']]+=1
        for row in result['predictions']:
            if 'error' in row:errors[row['error'].split(':',1)[0]]+=1
    return dict(status='complete',population_cves=len(expected),cases=len(inputs),
        independently_recomputed_counts=dict(counts),precision_denominator=denominator,
        precision=precision,target_met=precision>.85 if precision is not None else None,
        candidate_counts=dict(labels),prediction_status_counts=dict(statuses),
        production_dimensions={key:dict(values) for key,values in dimensions.items()},
        coverage=dict(stages),extraction_status_counts=dict(extraction_status),
        extraction_failure_reason_counts=dict(extraction_failures),
        assessment_component_status_counts=dict(classification_status),
        candidate_method_counts=dict(binding),errors=dict(errors),
        raw_LLM_coverage=dict(counts=dict(raw_counts),roles=dict(roles),
            CVEs_with_raw_response=len(raw_cves),
            CVEs_with_nonempty_raw_candidate_prerequisites=len(raw_nonempty),
            CVEs_without_raw_response=sorted(expected-raw_cves),
            candidate_presence_is_not_semantic_accuracy=True),
        all_CVE_IDs_and_case_IDs_verified=True,per_CVE_frozen_hashes_verified=True,
        actual_producer_checkpoints_and_frozen_source_hashes_verified=True,
        global_exports_match_per_CVE_records=True,expert_review_complete=False,
        independent_real_asset_accuracy_verified=False)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('root',type=Path);p.add_argument('--output',type=Path)
    args=p.parse_args();result=audit(args.root)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
