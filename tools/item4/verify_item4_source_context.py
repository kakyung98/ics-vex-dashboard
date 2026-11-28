"""Recompute all scores from sealed raw predictions, separate labels and inputs."""
import json,sqlite3,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item4.evaluation.source_context_simulation import DATA; from src.item4.evaluation.source_context_simulation import MODEL; from src.item4.evaluation.source_context_simulation import gate
from tools.item4.evaluate_item4_source_context import OUT,metric
from tools.item3.item3_precision_pipeline import sha
from src.common.runtime.training_progress_io import atomic_json

def read(path):return json.loads(path.read_text(encoding='utf-8'))

def verify():
    config=read(OUT/'run_config.json');manifest=read(DATA/'manifest.json');report=read(OUT/'precision_report.json')
    assert report['status']=='complete' and report['population']==12418
    for path,h in config['code'].items():assert sha(ROOT/path)==h,path
    for path,h in manifest['artifacts'].items():assert sha(DATA/path.replace('\\','/'))==h,path
    assert sha(DATA/'manifest.json')==config['gold_manifest_sha256']==report['gold_manifest_sha256']
    assert sha(MODEL/'adapter_model.safetensors')==config['adapter_sha256']==report['adapter_sha256']
    train_manifest=read(ROOT/'benchmark/item4_source_context_sft_v1/manifest.json')
    assert sha(ROOT/'benchmark/item4_source_context_sft_v1/train.jsonl')==train_manifest['train_sha256']
    training_rows=list(map(json.loads,(ROOT/'benchmark/item4_source_context_sft_v1/train.jsonl').open(encoding='utf-8')))
    trained={r['cve'] for r in training_rows}
    training_clauses=set()
    for row in training_rows:
        for message in row['messages']:
            if message['role']=='user':
                clause=json.loads(message['content']).get('source_clause')
                if clause:training_clauses.add(clause)
    with sqlite3.connect(OUT/'predictions.sqlite3') as db:
        predictions={r[0]:json.loads(r[1]) for r in db.execute('SELECT id,prediction FROM predictions')}
    all_labels={};raw=[];guarded=[];fold_results={};cves=set();ids=set();overlap=set()
    for fold in ('train','evaluation'):
        labels={r['id']:r for r in map(json.loads,(DATA/fold/'labels.jsonl').open(encoding='utf-8'))}
        fold_cves={v['cve'] for v in labels.values()}
        if fold=='train':assert trained<=fold_cves
        else:assert not trained&fold_cves
        a=[];b=[]
        for row in map(json.loads,(DATA/fold/'inputs.jsonl').open(encoding='utf-8')):
            identity=row['id'];cves.add(row['packet']['cve']);assert identity not in ids;ids.add(identity)
            spec=row['packet'].get('spec')
            if fold=='evaluation' and spec and spec['source']['clause']['quote'] in training_clauses:
                overlap.add(row['packet']['cve'])
            pred=predictions[identity];decision=gate(row['packet']);assert decision==pred['gate']
            assert pred['raw']['llm_used'] is True,identity
            status='affected' if pred['raw']['simulation_status']=='affected' and decision['simulation_status']=='affected' else 'under_investigation'
            assert status==pred['simulation_status'] and not pred['is_production_VEX'] and not pred['export_allowed']
            a.append(dict(id=identity,simulation_status=pred['raw']['simulation_status']))
            b.append(dict(id=identity,simulation_status=status))
        fold_results[fold]=dict(raw_model=metric(a,labels),model_and_gate=metric(b,labels))
        assert fold_results[fold]==report['results'][fold]
        raw.extend(a);guarded.extend(b);all_labels.update(labels)
    assert ids==predictions.keys() and len(cves)==12418
    assert metric(raw,all_labels)==report['results']['all']['raw_model']
    assert metric(guarded,all_labels)==report['results']['all']['model_and_gate']
    assert report['model_inferred_CVEs']==12418 and report['actual_model_requests']==len(ids)
    result=dict(passed=True,CVEs=12418,cases=len(ids),raw_outputs_rescored=True,gate_recomputed_for_all_inputs=True,
        training_examples_not_in_evaluation=True,model_data_code_hashes_verified=True,
        heldout_CVEs_with_exact_training_clause_overlap=sorted(overlap),
        heldout_exact_training_clause_overlap_CVEs=len(overlap),
        heldout_raw_precision=fold_results['evaluation']['raw_model']['precision'],
        heldout_gated_precision=fold_results['evaluation']['model_and_gate']['precision'],
        heldout_raw_target_met=fold_results['evaluation']['raw_model']['target_met'],
        heldout_gated_target_met=fold_results['evaluation']['model_and_gate']['target_met'],
        scope='Source-conditioned synthetic worlds only; source semantics and real installations unverified',
        real_asset_precision=None)
    atomic_json(OUT/'reverification.json',result);print(json.dumps(result))

if __name__=='__main__':verify()
