"""File boundary, conservative scoring, population coverage and paired regressions."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from tools.item3.item3_splits import canonical_split, canonical_split_map, split_folder
from tools.item3.run_item3_test import predict, rescore_recorded, score, summarize_result


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding='utf-8')


def make_dataset(root, specifications):
    labels = []
    for index, (expected, unknown) in enumerate(specifications):
        control_id = f'control-{index}'
        for scenario, identity in [('control', control_id), ('component_noise', f'variant-{index}')]:
            bom = dict(bomFormat='CycloneDX', components=[dict(name='sensor', version='1')])
            path = root/'sboms'/(identity+'.json')
            put(path, bom)
            label = dict(id=identity, fold='evaluation', sbom_file='sboms/'+path.name,
                scenario=scenario, axis='control' if scenario=='control' else 'P2',
                condition_id=str(index), control_sbom_id=control_id,
                expected_cves=expected, unknown_cves=unknown,
                gold=dict(expected_cves=expected, unknown_cves=unknown),
                export_format=dict(sbom_file_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
            put(root/'annotations'/(identity+'.json'), label)
            labels.append(label)
    (root/'gold.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in labels), encoding='utf-8')
    return labels


def prediction_file(path, labels, outputs, errors=None):
    records = []
    for label in labels:
        if label['id'] not in outputs:
            continue
        records.append(dict(id=label['id'], split='test', sbom_file=Path(label['sbom_file']).name,
            sbom_sha256=label['export_format']['sbom_file_sha256'],
            confirmed_cves=outputs[label['id']], candidate_cves=[], model_backed=False,
            error=(errors or {}).get(label['id'])))
    path.write_text(''.join(json.dumps(r)+'\n' for r in records), encoding='utf-8')
    return path


def test_split_alias_does_not_change_preserved_records(tmp_path):
    assert canonical_split('evaluation') == canonical_split('test') == 'test'
    assert canonical_split('train') == 'train'
    assert split_folder(tmp_path, 'test') == tmp_path/'evaluation'
    (tmp_path/'test').mkdir()
    assert split_folder(tmp_path, 'evaluation') == tmp_path/'test'
    with pytest.raises(ValueError):
        canonical_split('validation')
    assert canonical_split_map({'train':['A'], 'evaluation':['B']}) == {'train':['A'], 'test':['B']}
    with pytest.raises(ValueError, match='Conflicting'):
        canonical_split_map({'test':['A'], 'evaluation':['B']})


def test_prediction_uses_only_sbom_file_and_service_options_without_gold(tmp_path):
    folder = tmp_path/'data/sboms'
    bom = dict(bomFormat='CycloneDX', components=[dict(name='sensor', version='1')])
    put(folder/'one.json', bom)
    calls = []

    def matcher(sbom, **options):
        calls.append((deepcopy(sbom), options))
        return dict(components=[dict(cves=[dict(cve_id='A', match_status='match')])])

    output = tmp_path/'run'
    prediction = predict(folder, output, matcher=matcher)
    assert calls == [(bom, dict(agent_mode='unified', lookup_mode='local'))]
    assert not (folder.parent/'gold.jsonl').exists()
    record = json.loads(prediction.read_text())
    assert record['confirmed_cves'] == ['A']
    assert record['split'] == 'test'
    assert record['sbom_sha256'] == hashlib.sha256((folder/'one.json').read_bytes()).hexdigest()
    with pytest.raises(FileExistsError):
        predict(folder, output, matcher=matcher)


def test_error_is_recorded_and_other_inputs_still_run(tmp_path):
    for name in ('a', 'b'):
        put(tmp_path/'sboms'/(name+'.json'), dict(bomFormat='CycloneDX',components=[dict(name=name)]))

    def matcher(sbom, **options):
        if sbom['components'][0]['name']=='a':
            raise RuntimeError('model unavailable')
        return dict(components=[dict(cves=[])])

    path = predict(tmp_path/'sboms', tmp_path/'run', mode='rules', matcher=matcher)
    records = [json.loads(s) for s in path.read_text().splitlines()]
    assert len(records)==2 and 'model unavailable' in records[0]['error']
    assert records[1]['error'] is None


def test_compact_parallel_audit_preserves_all_emitted_component_cve_ids(tmp_path):
    folder=tmp_path/'inputs'
    for name in ('a','b','c','d'):
        put(folder/(name+'.json'),dict(bomFormat='CycloneDX',components=[{
            'bom-ref':name,'name':'sensor','version':'1'}]))
    def matcher(sbom,**options):
        ref=sbom['components'][0]['bom-ref']
        return {'components':[{'component':{'id':ref},'validation':{'status':'validated'},
            'cves':[{'cve_id':'A','match_status':'match','evidence':{'cpe_query':'source-query'}},
                    {'cve_id':'B','match_status':'unknown'},
                    {'cve_id':'C','match_status':'no_match'}]}]}
    full=predict(folder,tmp_path/'full',matcher=matcher)
    compact=predict(folder,tmp_path/'compact',matcher=matcher,workers=4,audit_detail='compact')
    by_id=lambda path:{r['id']:r for r in map(json.loads,path.read_text().splitlines())}
    left,right=by_id(full),by_id(compact)
    assert set(left)==set(right)=={'a','b','c','d'}
    for identity in left:
        for field in ('confirmed_cves','candidate_cves','component_predictions','error','sbom_sha256'):
            assert left[identity][field]==right[identity][field]
        assert right[identity]['component_predictions']==[{
            'component_ref':identity,'confirmed_cves':['A'],'candidate_cves':['B']}]
        assert right[identity]['result']['components'][0]['source_queries']==['source-query']
    assert not (folder/'gold.jsonl').exists()


def test_pairs_and_unknown_denominator_and_group_metrics(tmp_path):
    dataset = tmp_path/'dataset'
    labels = make_dataset(dataset, [(['A'], []) for _ in range(4)] + [(['A'], ['U'])])
    outputs = {
        'control-0':['A'], 'variant-0':['A'],
        'control-1':['A'], 'variant-1':[],
        'control-2':[], 'variant-2':['A'],
        'control-3':[], 'variant-3':[],
        'control-4':['A'], 'variant-4':['A','U','OUT'],
    }
    path = prediction_file(tmp_path/'predictions.jsonl', labels, outputs)
    before = {p:hashlib.sha256(p.read_bytes()).hexdigest() for p in dataset.rglob('*') if p.is_file()}
    report = score(path, dataset, tmp_path/'report', universe={'A','U'})
    assert report['pairs']['outcomes'] == dict(both_correct=1, control_only_correct=1,
        variant_only_correct=1, both_incorrect=1, indeterminate=1)
    assert report['overall']['TP']==6 and report['overall']['FN']==4
    assert report['overall']['FP']==0 and report['overall']['unjudged']==1
    assert report['overall']['out_of_scope']==1
    assert report['overall']['precision_percent'] is None
    assert report['overall']['precision_lower_bound_percent']==75
    assert report['full_population_complete']
    assert not report['acceptance']['passed']
    assert report['by_input_kind']['control']['cases']==5
    assert report['by_role']['I1']['cases']==5
    assert report['by_scenario']['component_noise']['cases']==5
    assert all(hashlib.sha256(p.read_bytes()).hexdigest()==h for p,h in before.items())


def test_missing_predictions_count_as_errors_and_false_negatives(tmp_path):
    dataset = tmp_path/'dataset'
    labels = make_dataset(dataset, [(['A'],[])])
    path = prediction_file(tmp_path/'p.jsonl', labels, {'control-0':['A']})
    report = score(path, dataset, tmp_path/'report', universe={'A'})
    assert report['missing_predictions']==1
    assert report['overall']['FN']==1 and report['overall']['execution_errors']==1
    assert report['pairs']['outcomes']=={'execution_error':1}
    assert not report['full_population_complete'] and not report['acceptance']['passed']


@pytest.mark.parametrize('change', ['duplicate', 'foreign_id', 'wrong_hash', 'wrong_filename'])
def test_invalid_predictions_cannot_be_silently_scored(tmp_path, change):
    dataset = tmp_path/'dataset'
    labels = make_dataset(dataset, [(['A'],[])])
    path = prediction_file(tmp_path/'p.jsonl', labels, {'control-0':['A'], 'variant-0':['A']})
    records = [json.loads(s) for s in path.read_text().splitlines()]
    if change=='duplicate':
        records.append(records[0])
    elif change=='foreign_id':
        records[0]['id']='foreign'
    elif change=='wrong_hash':
        records[0]['sbom_sha256']='0'*64
    else:
        records[0]['sbom_file']='other.json'
    path.write_text(''.join(json.dumps(r)+'\n' for r in records), encoding='utf-8')
    with pytest.raises(ValueError):
        score(path, dataset, tmp_path/'report', universe={'A'})


def test_corrupted_sbom_and_pair_gold_are_rejected(tmp_path):
    dataset = tmp_path/'dataset'
    labels = make_dataset(dataset, [(['A'],[])])
    path = prediction_file(tmp_path/'p.jsonl', labels, {'control-0':['A'], 'variant-0':['A']})
    sbom = dataset/labels[0]['sbom_file']
    sbom.write_text('{}')
    with pytest.raises(ValueError, match='hash'):
        score(path, dataset, tmp_path/'report', universe={'A'})
    labels = make_dataset(dataset, [(['A'],[])])
    labels[1]['gold']['expected_cves']=['B']
    put(dataset/'annotations'/'variant-0.json', labels[1])
    (dataset/'gold.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in labels), encoding='utf-8')
    with pytest.raises(ValueError, match='Pair'):
        score(path, dataset, tmp_path/'report', universe={'A'})


def test_model_failures_and_lookup_failures_are_not_abstentions():
    result = dict(components=[dict(cves=[], i1=dict(agent=dict(status='rejected')),
                                   i3=dict(lookup_error='source offline'))])
    summary = summarize_result(result)
    assert 'i1:rejected' in summary['error'] and 'source offline' in summary['error']


def test_no_matching_cve_is_distinct_from_unresolved_identity():
    assert not summarize_result(dict(components=[dict(cves=[], validation=dict(status='validated'))]))['deferred']
    assert summarize_result(dict(components=[dict(cves=[], validation=dict(status='unresolved'))]))['deferred']
    assert summarize_result(dict(components=[dict(cves=[dict(cve_id='A', match_status='unknown')])]))['deferred']


def test_legacy_cli_test_uses_file_runner_and_accepts_old_fold_spelling(tmp_path, monkeypatch):
    from tools.item3 import item3_precision_pipeline as pipeline
    from tools.item3 import run_item3_test as runner
    calls = []
    monkeypatch.setattr(pipeline, 'test_dataset', lambda root:tmp_path/'dataset')
    monkeypatch.setattr(runner, 'predict', lambda sboms, output, **kwargs:calls.append((sboms, kwargs)) or output/'predictions.jsonl')
    monkeypatch.setattr(runner, 'score', lambda *args:dict(split='test', full_population_complete=True))
    report = pipeline.evaluate(fold='evaluation', output=tmp_path/'run')
    assert report['split']=='test'
    assert calls[0][0]==tmp_path/'dataset/sboms' and calls[0][1]['mode']=='rules'


def test_recorded_outputs_require_original_file_bytes_and_do_not_claim_inference(tmp_path, monkeypatch):
    dataset = tmp_path/'dataset'
    labels = make_dataset(dataset, [(['A'],[])])
    recorded = tmp_path/'recorded'
    recorded.mkdir()
    ledger = recorded/'case_results.jsonl'
    ledger.write_text(''.join(json.dumps(dict(gold_id=r['id'],
        file='benchmark/item3_evaluation/'+r['sbom_file'], modes=dict(agents=dict(
            confirmed_cves=['A'],candidate_cves=[],accepted_identities=1,error=None,agent_errors=[]))))+'\n'
        for r in labels), encoding='utf-8')
    dbpath = recorded/'validation.sqlite3'
    with sqlite3.connect(dbpath) as db:
        db.execute('CREATE TABLE files(path TEXT,sha256 TEXT)')
        db.executemany('INSERT INTO files VALUES (?,?)', [
            ('benchmark/item3_evaluation/'+p.relative_to(dataset).as_posix(),hashlib.sha256(p.read_bytes()).hexdigest())
            for p in dataset.rglob('*') if p.is_file()])
    put(recorded/'artifacts_manifest.json', {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (ledger,dbpath)})
    report = rescore_recorded(recorded, dataset, tmp_path/'rescore')
    assert report['full_population_complete'] and report['overall']['TP']==2
    assert report['provenance']['inference_performed'] is False
    assert report['overall']['model_usage_unrecorded_cases']==2
    assert report['overall']['deferred_cases']==0
    (dataset/labels[0]['sbom_file']).write_text('{}')
    with pytest.raises(ValueError, match='differs'):
        rescore_recorded(recorded, dataset, tmp_path/'corrupt')


def test_empty_confirmed_output_does_not_pass_precision(tmp_path):
    dataset = tmp_path/'dataset'
    labels = make_dataset(dataset, [([],[])])
    path = prediction_file(tmp_path/'p.jsonl', labels, {'control-0':[], 'variant-0':[]})
    report = score(path, dataset, tmp_path/'report', universe={'A'})
    assert report['full_population_complete']
    assert report['overall']['precision_lower_bound_percent'] is None
    assert not report['acceptance']['passed']
    assert report['pairs']['with_known_positives']=={}
