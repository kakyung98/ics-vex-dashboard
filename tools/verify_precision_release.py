"""Verify sealed predictions and rescore them; does not rerun GPU inference."""
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.item3_v6_metrics import aggregate,case_score
from src.operational_assessment import affected_precision
from src.training_io import atomic_json


def read(path):return json.loads(path.read_text(encoding='utf-8'))
def sha(path):
    digest=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(8*1024*1024),b''):digest.update(block)
    return digest.hexdigest()


def verify():
    release=read(ROOT/'results/precision_evaluation_v1/release.json')
    config=read(ROOT/'results/item3_precision_v11/trained_evaluation/run_config.json')
    api=release['integration_only_change_after_frozen_inference']
    for name,digest in config['code'].items():
        assert sha(ROOT/name)==(api['after_sha256'] if (ROOT/name).resolve()==(ROOT/api['file']).resolve() else digest),name
    assert sha(ROOT/'tools/item3_precision_pipeline.py')==config['driver_sha256']
    assert sha(ROOT/release['frozen_sources'])==release['frozen_sources_sha256']
    model=ROOT/'models/precision_roles_qwen25_14b_v1'
    assert sha(model/'adapter_model.safetensors')==release['adapter_sha256']==config['adapter']
    for name in ('item3_gold_v11','item4_operational_gold_v2'):
        gold=ROOT/'benchmark'/name;manifest=read(gold/'manifest.json')
        for relative,digest in manifest['artifacts'].items():assert sha(gold/relative)==digest,relative
    assert sha(ROOT/'benchmark/item3_gold_v11/manifest.json')==config['gold_manifest']
    db=sqlite3.connect(ROOT/'results/item3_precision_v11/trained_evaluation/predictions.sqlite3')
    ids={json.loads(s)['id'] for s in (ROOT/'benchmark/item3_gold_v11/evaluation/inputs.jsonl').open(encoding='utf-8')}
    assert ids=={r[0] for r in db.execute('SELECT id FROM predictions')}
    labels={r['id']:r for r in map(json.loads,(ROOT/'benchmark/item3_gold_v11/evaluation/labels.jsonl').open(encoding='utf-8'))}
    universe={json.loads(s)['id'] for s in (ROOT/'data/item3_identification_sources_v11/cves.jsonl').open(encoding='utf-8')}
    def rescored():
        for identity,scenario,score,result in db.execute('SELECT id,scenario,score,result FROM predictions'):
            actual=case_score(json.loads(result)['result'],labels[identity],universe)
            assert actual==json.loads(score),identity
            yield scenario,'evaluation',actual
    recomputed=aggregate(rescored(),len(ids))
    stored=read(ROOT/release['item3_report'])
    assert recomputed['all_BOMs_latent_asset_mapping_metrics']==stored['all_BOMs_latent_asset_mapping_metrics']
    assert recomputed['execution_errors']==0 and recomputed['full_population_complete']
    folder=ROOT/'results/item4_operational_v2'
    predictions=[json.loads(s) for s in (folder/'trained_predictions.jsonl').open(encoding='utf-8')]
    gold=[json.loads(s) for s in (ROOT/'benchmark/item4_operational_gold_v2/evaluation/labels.jsonl').open(encoding='utf-8')]
    actual=affected_precision(predictions,gold);stored4=read(folder/'trained_precision_report.json')
    for k,v in actual.items():assert stored4[k]==v,k
    assert stored4['gold_manifest_sha256']==sha(ROOT/'benchmark/item4_operational_gold_v2/manifest.json')
    assert stored['target_met'] and stored4['target_met']
    report=dict(passed=True,mode='Stored prediction integrity and independent metric recomputation; GPU inference not rerun',
        item3_cases=len(ids),item3_precision=stored['precision'],item4_cases=len(predictions),item4_synthetic_precision=actual['precision'],
        real_asset_precision=None,source_and_model_hashes_verified=True,raw_predictions_rescored=True)
    atomic_json(ROOT/'results/precision_evaluation_v1/reverification.json',report)
    db.close();print(json.dumps(report))


if __name__=='__main__':verify()
