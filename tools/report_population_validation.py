"""Rescore every frozen raw output; also remove duplicate SBOM weighting."""
from collections import Counter
import hashlib,json,sqlite3,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.item3_v6_metrics import case_score,aggregate,metrics
from tools.validate_population_precision import GOLD,OUT,sha,read
from src.training_io import atomic_json

def summarize():
    assert read(OUT/'status.json')==dict(phase='complete',completed=12418,total=12418)
    manifest=read(GOLD/'manifest.json')
    for name,h in manifest['artifacts'].items():assert sha(GOLD/name)==h
    inputs={r['id']:r for r in map(json.loads,(GOLD/'inputs.jsonl').open(encoding='utf-8'))}
    labels={r['id']:r for r in map(json.loads,(GOLD/'labels.jsonl').open(encoding='utf-8'))}
    target={r['cve'] for r in inputs.values()}
    original={r['cve'] for r in map(json.loads,(ROOT/'benchmark/cve_population_12418_v1/labels.jsonl').open(encoding='utf-8'))}
    assert len(inputs)==len(labels)==len(target)==12418 and target==original and inputs.keys()==labels.keys()
    db=sqlite3.connect(OUT/'item3_predictions.sqlite3')
    assert {r[0] for r in db.execute('SELECT id FROM predictions')}==inputs.keys()
    scores=[];unique={};representatives={};target_diagnostic=Counter();ledger=[]
    for identity,cid,result_text,score_text in db.execute('SELECT id,cve,result,score FROM predictions'):
        raw=json.loads(result_text)['result'];gold=labels[identity]
        assert cid==inputs[identity]['cve']==gold['cve']
        score=case_score(raw,gold,target);assert score==json.loads(score_text),identity
        scores.append((gold['origin_fold'],'population_audit',score))
        text=json.dumps(inputs[identity]['sbom'],ensure_ascii=False,sort_keys=True,separators=(',',':'))
        key=hashlib.sha256(text.encode()).hexdigest()
        if key in unique:
            assert score['mapping']==unique[key]['mapping'] and score['candidates']==unique[key]['candidates'],key
        else:unique[key]=score;representatives[key]=identity
        matched={x['cve_id'] for r in raw.get('components',[]) for x in r.get('cves',[]) if x.get('match_status')=='match'}
        own=gold['own_cve_truth'];hit=cid in matched
        target_diagnostic['TP']+=hit and own is True;target_diagnostic['FP']+=hit and own is False
        target_diagnostic['FN']+=not hit and own is True;target_diagnostic['unjudged']+=hit and own is None
        ledger.append(dict(cve=cid,input_id=identity,input_hash=key,source_fold=gold['origin_fold'],
            own_cve_gold=own,target_cve_emitted=hit,full_output_score=score['mapping']))
    full=aggregate(scores,12418)
    dedup=aggregate((('unique_input','population_audit',s) for s in unique.values()),len(unique))
    saved=read(OUT/'item3_precision_report.json')
    assert full['all_BOMs_latent_asset_mapping_metrics']==saved['all_BOMs_latent_asset_mapping_metrics']
    a=full['all_BOMs_latent_asset_mapping_metrics'];b=dedup['all_BOMs_latent_asset_mapping_metrics']
    # Unknown emitted positives are all counted as FP for the lower bound.
    ok=lambda m: m['precision_lower_bound_percent'] is not None and m['precision_lower_bound_percent']>80
    criterion=ok(a) and ok(b) and full['execution_errors']==dedup['execution_errors']==0
    four=read(OUT/'item4_precision_report.json')
    report=dict(population=12418,original_CVE_ids_verified=True,raw_outputs_rescored=True,
        item3=dict(executed_CVEs=12418,unique_SBOM_inputs=len(unique),duplicate_input_rows=12418-len(unique),
            own_CVE_gold_known=manifest['own_truth_known'],own_CVE_gold_unknown=manifest['own_truth_unknown'],
            full_output_micro=a,deduplicated_full_output_micro=b,
            target_CVE_only_diagnostic=metrics(target_diagnostic),
            target_CVE_only_diagnostic_excludes_other_emitted_CVEs=True,
            precision_criterion_met_by_conservative_bounds=criterion,threshold_strictly_greater_than=.8,
            execution_errors=full['execution_errors'],
            interpretation='Primary metrics include ALL emitted CVEs, not only the target; duplicate-input check must also pass. Unknown emitted edges all treated as FP in lower bound.',
            evaluation_scope=manifest['evaluation_type'],independent_real_asset_accuracy_verified=False),
        item4=four,both_targets_verified=False,
        limitation='Item 3 is a source-derived synthetic-inventory audit including training-origin cases. Item 4 operational impact Gold is unavailable; fictional CVE tests are excluded.')
    with (OUT/'cve_validation_ledger.jsonl').open('w',encoding='utf-8') as f:
        for row in sorted(ledger,key=lambda r:r['cve']):f.write(json.dumps(row)+'\n')
    atomic_json(OUT/'validation_report.json',report)
    db.close();print(json.dumps(report))

if __name__=='__main__':summarize()
