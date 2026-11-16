"""Frozen raw-model and independently gated conditional simulation evaluation."""
from collections import Counter
import json,os,sqlite3,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.item4_source_simulation import DATA,MODEL,gate,predict_batch,PROMPT
from src.training_io import atomic_json
from tools.item3_precision_pipeline import sha
OUT=ROOT/'results/item4_source_context_v1'

def read(p):return json.loads(p.read_text(encoding='utf-8'))

def metric(rows,labels):
    if not rows or {r['id'] for r in rows}!=labels.keys():raise ValueError('Exact nonempty population required')
    tp=fp=unknown=fn=abstain=known=0
    for r in rows:
        label=labels[r['id']];value=label['actual_affected'];positive=r['simulation_status']=='affected'
        tp+=positive and value is True;fp+=positive and value is False;unknown+=positive and value is None
        fn+=not positive and value is True;abstain+=not positive;known+=value is not None
    p=tp/(tp+fp) if tp+fp and not unknown else None
    return dict(cases=len(rows),CVEs=len({labels[r['id']]['cve'] for r in rows}),known_latent_impact_cases=known,
        TP=tp,FP=fp,unjudged_positive=unknown,FN_including_abstentions=fn,
        precision=p,precision_lower_bound=tp/(tp+fp+unknown) if tp+fp+unknown else None,
        recall=tp/(tp+fn) if tp+fn else None,abstention_fraction=abstain/len(rows),
        threshold_strictly_greater_than=.85,target_met=p>.85 if p is not None else False)

def report(db):
    labels={};folds={}
    for fold in ('train','evaluation'):
        labels.update({r['id']:r for r in map(json.loads,(DATA/fold/'labels.jsonl').open(encoding='utf-8'))})
        folds[fold]={r['id'] for r in map(json.loads,(DATA/fold/'inputs.jsonl').open(encoding='utf-8'))}
    predictions={r[0]:json.loads(r[1]) for r in db.execute('SELECT id,prediction FROM predictions')}
    if predictions.keys()!=labels.keys():raise ValueError('Incomplete frozen population')
    results={}
    for name,ids in dict(all=set(labels),**folds).items():
        subset={i:labels[i] for i in ids}
        raw=[dict(id=i,simulation_status=predictions[i]['raw']['simulation_status']) for i in ids]
        guarded=[dict(id=i,simulation_status=predictions[i]['simulation_status']) for i in ids]
        results[name]=dict(raw_model=metric(raw,subset),model_and_gate=metric(guarded,subset))
    index=[json.loads(s) for s in (DATA/'cve_index.jsonl').open(encoding='utf-8')]
    counts=read(DATA/'manifest.json')['counts'];marker=read(MODEL/'training_complete.json')
    result=dict(status='complete',population=12418,cases=len(labels),results=results,
        CVEs_with_conditional_worlds=counts['CVEs_with_conditional_worlds'],CVEs_source_unknown=counts['CVEs_source_unknown'],
        actual_model_requests=sum(r['raw']['llm_used'] for r in predictions.values()),
        adapter_sha256=marker['adapter_sha256'],training_examples=marker['examples'],optimizer_updates=marker['optimizer_updates'],
        gold_manifest_sha256=sha(DATA/'manifest.json'),code=read(OUT/'run_config.json')['code'],
        metric_scope='Real-CVE source-conditioned synthetic selected-path worlds under explicit counterfactual closure and product assumptions',
        source_semantics_verified=False,real_asset_precision=None,production_VEX_accuracy_verified=False,
        no_human_semantic_approval_fabricated=True,
        evaluation_fold_target_met=results['evaluation']['model_and_gate']['target_met'],
        all_population_conditional_target_met=results['all']['model_and_gate']['target_met'],
        test_predictions_used_to_select_checkpoint=False,
        limitation='Source semantic correctness, product-scope transfer and path sufficiency are not established by this score. Unknown-source CVEs retained; no fabricated labels. All-world score includes training-origin cases; evaluation fold is separate. No production VEX export.')
    with (OUT/'cve_results.jsonl').open('w',encoding='utf-8') as f:
        for row in index:
            f.write(json.dumps(dict(**row,predictions=[dict(id=i,**predictions[i]) for i in row['cases']]))+'\n')
    atomic_json(OUT/'precision_report.json',result)
    print(json.dumps(result),flush=True)
    return result

def evaluate():
    from src import gpu_lease
    from src.precision_role_runtime import PrecisionRoleRuntime
    OUT.mkdir(parents=True,exist_ok=True)
    audit=read(DATA/'integrity_audit.json');assert audit['passed']
    manifest=read(DATA/'manifest.json')
    for relative,h in manifest['artifacts'].items():assert sha(DATA/relative)==h
    marker=read(MODEL/'training_complete.json')
    assert marker['source_gold_manifest_sha256']==sha(DATA/'manifest.json')
    assert marker['source_role_code_sha256']==sha(ROOT/'src/item4_source_simulation.py')
    assert marker['conditional_simulation_only'] and marker['shared_tasks']==['OPERATIONAL_SOURCE_SIMULATION']
    assert marker['heldout_loaded'] is False
    config=dict(adapter_sha256=sha(MODEL/'adapter_model.safetensors'),gold_manifest_sha256=sha(DATA/'manifest.json'),
        gold_passed_to_inference=False,checkpoint_selection='Final fixed-budget training checkpoint; no test selection',
        code={str(p.relative_to(ROOT)):sha(p) for p in (Path(__file__),ROOT/'src/item4_source_simulation.py',ROOT/'src/context_vex_pipeline.py')})
    path=OUT/'run_config.json'
    if path.exists():assert read(path)==config,'Frozen implementation changed'
    atomic_json(path,config)
    db=sqlite3.connect(OUT/'predictions.sqlite3');db.execute('CREATE TABLE IF NOT EXISTS predictions(id TEXT PRIMARY KEY,cve TEXT,fold TEXT,prediction TEXT)')
    done={r[0] for r in db.execute('SELECT id FROM predictions')}
    inputs=[]
    for fold in ('train','evaluation'):
        inputs.extend(dict(**r,fold=fold) for r in map(json.loads,(DATA/fold/'inputs.jsonl').open(encoding='utf-8')))
    assert len(inputs)==manifest['counts']['cases'] and len({r['packet']['cve'] for r in inputs})==12418
    # Inference receives packets only. Labels are loaded only after every output is sealed.
    todo=[r for r in inputs if r['id'] not in done]
    gpu_lease.assert_inference_available();atomic_json(gpu_lease.FILE,dict(active=True,pid=os.getpid(),stage='item4_source_context_evaluation'))
    runtime=PrecisionRoleRuntime(folder=MODEL);started=time.perf_counter()
    try:
        for start in range(0,len(todo),64):
            chunk=todo[start:start+64]
            raw=predict_batch(runtime,[r['packet'] for r in chunk])
            with db:
                for row,pred in zip(chunk,raw):
                    decision=gate(row['packet'])
                    status='affected' if pred['simulation_status']=='affected' and decision['simulation_status']=='affected' else 'under_investigation'
                    final=dict(simulation_status=status,raw=pred,gate=decision,is_production_VEX=False,export_allowed=False)
                    db.execute('INSERT INTO predictions VALUES (?,?,?,?)',(row['id'],row['packet']['cve'],row['fold'],json.dumps(final)))
                    done.add(row['id'])
            atomic_json(OUT/'status.json',dict(phase='evaluating',completed=len(done),total=len(inputs),elapsed_seconds=time.perf_counter()-started))
            print('Source context evaluation',len(done),'/',len(inputs),flush=True)
        report(db)
        atomic_json(OUT/'status.json',dict(phase='complete',completed=len(done),total=len(inputs),CVEs=12418))
    finally:
        db.close();atomic_json(gpu_lease.FILE,dict(active=False,pid=os.getpid()))

if __name__=='__main__':evaluate()
