"""Independently recount emitted CVE edges and check split/training artifacts."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3

from tools.item3.item3_splits import canonical_split, canonical_split_map, split_folder, legacy_source_database


def read(path):
    value = json.loads(Path(path).read_text(encoding='utf-8'))
    if Path(path).name == 'CVE_split.json':
        return canonical_split_map(value)
    if Path(path).name == 'condition_folds.json':
        return {k:canonical_split(v) for k,v in value.items()}
    return value


def rows(path):
    with Path(path).open(encoding='utf-8') as stream:
        for line in stream:
            yield json.loads(line)


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()


def verify(run):
    testdir=split_folder(run,'test')
    split=read(run/'CVE_split.json')
    train,test=map(set,(split['train'],split['test']))
    target=train|test
    assert not train & test and len(train|test)==12418
    train_inputs={r['id']:r for r in rows(run/'train/inputs.jsonl')}
    test_inputs={r['id']:r for r in rows(testdir/'inputs.jsonl')}
    assert len(train_inputs)==len(train)==8693 and len(test_inputs)==len(test)==3725
    assert not {digest(r['sbom']) for r in train_inputs.values()} & {digest(r['sbom']) for r in test_inputs.values()}
    assert {r['cve'] for r in train_inputs.values()}==train
    assert {r['cve'] for r in test_inputs.values()}==test
    for row in rows(run/'train.jsonl'):
        assert row['split']=='train' and row['source_case'] in train_inputs
    with sqlite3.connect((run/'training_coverage.sqlite3').as_uri()+'?mode=ro',uri=True) as db:
        assert db.execute('SELECT count(*) FROM coverage').fetchone()[0]==len(train_inputs)*3
        assert {x[0] for x in db.execute('SELECT DISTINCT case_id FROM coverage')}==set(train_inputs)
    gold={r['id']:r for r in rows(testdir/'labels.jsonl')}
    assert set(gold)==set(test_inputs)
    project=run.parents[1]
    for relative,expected_hash in read(run/'source_integrity.json').items():
        h=hashlib.sha256()
        with (project/relative).open('rb') as stream:
            for block in iter(lambda:stream.read(8*1024*1024),b''):
                h.update(block)
        assert h.hexdigest()==expected_hash, 'Source or test data changed: '+relative
    with sqlite3.connect((legacy_source_database(project)).as_uri()+'?mode=ro',uri=True) as source:
        universe={r[0] for r in source.execute('SELECT DISTINCT cve FROM source_coverage')}|target
        folds=read(run/'condition_folds.json')
        for cve,condition in source.execute('SELECT cve,condition_id FROM source_coverage'):
            if cve in target:
                assert folds[condition]==('train' if cve in train else 'test')
        identities={'train':set(),'test':set()}
        for condition,fields in source.execute('SELECT id,canonical_fields FROM conditions'):
            identities[folds[condition]].add(tuple(json.loads(fields)[:3]))
        assert not identities['train'] & identities['test']
    counts=Counter();unique={};seen=set()
    with sqlite3.connect((testdir/'predictions.sqlite3').as_uri()+'?mode=ro',uri=True) as db:
        for cid,cve,payload,stored_score in db.execute('SELECT id,cve,result,score FROM predictions'):
            assert cid in test_inputs and cve==test_inputs[cid]['cve'] and cve in test
            seen.add(cid)
            result=json.loads(payload)['result']
            emitted={v['cve_id'] for comp in result.get('components',[]) for v in comp.get('cves',[]) if v.get('match_status')=='match'}
            expected,unknown=set(gold[cid]['expected_cves']),set(gold[cid]['unknown_cves'])
            score=dict(TP=len((emitted & expected)-unknown),
                FP=len((emitted & universe)-expected-unknown),
                FN=len(expected-emitted),unjudged=len(emitted & unknown & universe),out_of_scope=len(emitted-universe))
            assert score==json.loads(stored_score)['mapping']
            counts.update(score)
            key=digest(test_inputs[cid]['sbom'])
            assert key not in unique or unique[key]==score
            unique[key]=score
    assert seen==set(test_inputs)
    report=read(testdir/'precision_report.json')
    for key,value in counts.items():
        assert report['all_BOMs_latent_asset_mapping_metrics'][key]==value
    dedup=Counter()
    for score in unique.values():
        dedup.update(score)
    for key,value in dedup.items():
        assert report['deduplicated']['all_BOMs_latent_asset_mapping_metrics'][key]==value
    marker=read(run/'adapter/training_complete.json')
    base_integrity=read(run/'base_integrity.json')
    assert marker['base']==base_integrity['base']
    for name,expected_hash in base_integrity['hashes'].items():
        h=hashlib.sha256()
        with (Path(marker['base'])/name).open('rb') as stream:
            for block in iter(lambda:stream.read(8*1024*1024),b''):
                h.update(block)
        assert h.hexdigest()==expected_hash, 'Base snapshot changed: '+name
    assert marker['heldout_loaded'] is False and marker['prior_adapter_reused'] is False
    assert marker['initial_trainable_sha256']!=marker['final_trainable_sha256']
    assert hashlib.sha256((run/'adapter/adapter_model.safetensors').read_bytes()).hexdigest()==marker['adapter_sha256']
    assert hashlib.sha256((run/'train.jsonl').read_bytes()).hexdigest()==read(run/'training_manifest.json')['train_sha256']
    assert report['execution_errors']==0 and report['full_population_complete']
    assert report['actual_model_requests']['actual_llm_requests']>0
    result=dict(passed=True,train_CVEs=len(train),test_CVEs=len(test),unique_test_SBOMs=len(unique),
        all_emissions_recounted=True,counts=dict(counts),deduplicated_counts=dict(dedup),
        train_test_CVE_overlap=0,train_test_input_overlap=0,source_product_identity_overlap=0,
        all_training_records_accounted_for=True,training_example_ids_all_train=True,source_and_test_hashes_verified=True,
        interpretation='Artifact integrity and independent edge recount; does not establish semantic Gold or real-asset accuracy.')
    (testdir/'reverification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('run',type=Path)
    args=parser.parse_args();print(json.dumps(verify(args.run.resolve()),indent=2))
