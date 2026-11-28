"""Consume real extraction checkpoints, synthesize operator inputs, run V4."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from collections import Counter
from copy import deepcopy
from pathlib import Path
import argparse
import hashlib
import json
import os
import time
import traceback

from src.item4.evaluation.operator_observation_benchmark import VERSION; from src.item4.evaluation.operator_observation_benchmark import digest; from src.item4.evaluation.operator_observation_benchmark import build_cases; from src.item4.evaluation.operator_observation_benchmark import metrics

ROOT=Path(__file__).resolve().parents[2]


def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix(path.suffix+'.tmp')
    tmp.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');tmp.replace(path)


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def job_for(item,checkpoint):
    from src.item4.workflow import source_analysis_jobs as Q; from src.item4.assets import asset_observations as I; from src.item4.analysis import product_advisory_evidence as C
    bom=item['bom'];components,declared=Q.inventory(bom)
    selected=next(c for c in components if c['ref']==item['cases'][0]['component_ref'])
    job=dict(id='ox3-'+item['cve'],status='completed',revision=1,bom_sha256=Q.digest(bom),input_bom=bom,
        components=[dict(C.component_identity(c),type=c['value'].get('type')) for c in components],
        representative=dict(ref=selected['ref'],name=selected['name'],pointer=selected['pointer']),
        declared_cves=declared,conditions=[checkpoint['extraction']],asset_classification=checkpoint['classification'],
        answers={},context_answers={})
    I.prepare(job,Q.digest)
    return job


def predict(job,cases):
    """Reference-free invocation of the real service decision implementation."""
    from src.item4.decision import asset_vex_assessment as E
    rows=[]
    for case in cases:
        work=deepcopy(job);work['answers']=case['answers']
        work['context_answers']={k:v for k,v in case['context'].items() if k in {'scope','mode','origin'}}
        for assessment in work['assessment_cases']:
            for key in ['deployment','runtime']:
                work['context_answers'][assessment['prefix']+key]=case['context'][key]
        try:
            result=E.evaluate(work);row=result['decisions'][0]
            rows.append(dict(id=case['id'],cve=case['cve'],status=row['status'],reason=row['reason'],
                product_applicability=row['product_applicability'],prerequisite_status=row['prerequisite_status'],
                deployment_exploitability=row['deployment_exploitability'],condition_values=row['condition_values'],
                graph_generation_status=row['attack_graph'].get('generation_status'),
                graph_sha256=row['attack_graph'].get('sha256'),formula_value=row['graph_evaluation'].get('value'),
                operating_formula_value=row['graph_evaluation'].get('node_states',{}).get(row['attack_graph']['operating_root']),
                graph_receipt_sha256=(row['attack_graph'].get('mulval') or {}).get('receipt_sha256'),
                extraction_sha256=(work['conditions'][0].get('prerequisite') or {}).get('sha256')))
        except Exception as exc:
            rows.append(dict(id=case['id'],cve=case['cve'],status='under_investigation',
                error=type(exc).__name__+': '+str(exc),traceback=traceback.format_exc()))
    return rows


def install_graph_cache():
    """Memoize only identical graph-generation requests; never observations."""
    from src.item4.decision import attack_graph_builder as G
    original=G.build;cache={}
    def build(*args,**kwargs):
        key=digest([args,kwargs])
        if key not in cache:cache[key]=original(*args,**kwargs)
        return deepcopy(cache[key])
    G.build=build
    return cache


def finalize(args,items,protocol):
    predictions=[];references=[];counts=Counter();population=[]
    exports={name:(args.output/name).open('w',encoding='utf-8') for name in ['predictions.jsonl','inputs.jsonl','candidate_labels.jsonl','expert_gold.jsonl']}
    try:
        for item in items:
            cve=item['cve'];data=json.loads((args.dataset/'cves'/(cve+'.json')).read_bytes())
            result=json.loads((args.output/'cves'/(cve+'.json')).read_bytes())
            predictions.extend(result['predictions'])
            for row in result['predictions']:exports['predictions.jsonl'].write(json.dumps(row,ensure_ascii=False)+'\n')
            for row in data['cases']:exports['inputs.jsonl'].write(json.dumps(row,ensure_ascii=False)+'\n')
            counts['CVEs']+=1;counts['cases']+=len(data['cases']);counts['questions']+=len(data['job']['questions'])
            counts['CVEs_without_questions']+=not data['job']['questions']
            counts['CVEs_with_extraction_artifact']+=bool(data['job']['conditions'][0].get('prerequisite'))
            population.append(dict(cve=cve,cases=len(data['cases']),questions=len(data['job']['questions']),
                extraction_status=data['job']['conditions'][0].get('status'),coverage=data['generation']['coverage']))
        # Prediction file is durably closed BEFORE references are opened for scoring.
        exports['predictions.jsonl'].close()
        for item in items:
            refs=json.loads((args.dataset/'references'/(item['cve']+'.json')).read_bytes())
            references.extend(refs)
            for row in refs:
                exports['candidate_labels.jsonl'].write(json.dumps(row,ensure_ascii=False)+'\n')
                exports['expert_gold.jsonl'].write(json.dumps(dict(id=row['id'],cve=row['cve'],actual_affected=None,expert_validated=False))+'\n')
                counts['candidate:'+str(row['actual_affected'])]+=1
    finally:
        for f in exports.values():f.close()
    assert len(population)==len({r['cve'] for r in population})==12418
    assert {r['cve'] for r in population}=={r['cve'] for r in items}
    main=metrics(predictions,references)
    status_counts=dict(Counter(r['status'] for r in predictions))
    report=dict(status='complete',population_cves=12418,all_cases=main,counts=dict(counts),status_counts=status_counts,
        errors=sum('error' in r for r in predictions),protocol=protocol,expert_review_complete=False,
        reference='frozen_source_conditional_candidate_NOT_expert_gold',production_decision_code_used=True,
        extracted_expression_logic_reference_is_diagnostic_only=True,
        independent_real_asset_accuracy_verified=False,failed_and_source_poor_CVEs_retained=True,
        no_retraining_or_score_based_model_selection=True)
    write(args.output/'report.json',report);write(args.dataset/'population_index.json',population)
    for name in ['inputs.jsonl','candidate_labels.jsonl','expert_gold.jsonl']:
        (args.output/name).replace(args.dataset/name)
    manifest=dict(version=VERSION,status='complete',population_cves=12418,counts=dict(counts),protocol=protocol,
        artifacts={p.name:sha(p) for p in args.dataset.glob('*.jsonl')})
    write(args.dataset/'manifest.json',manifest)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--extraction-root',type=Path,required=True)
    p.add_argument('--dataset',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--poll-seconds',type=int,default=30);p.add_argument('--once',action='store_true')
    args=p.parse_args();args.output.mkdir(parents=True,exist_ok=True);args.dataset.mkdir(parents=True,exist_ok=True)
    source=ROOT/'benchmark/item4_evaluation'
    items=[json.loads(s) for s in (source/'full_population_inputs.jsonl').open(encoding='utf-8')]
    assert len(items)==len({r['cve'] for r in items})==12418
    config=json.loads((args.extraction_root/'run_config.json').read_bytes())
    protocol=dict(version=VERSION,population_cves=12418,
        extraction_checkpoint_root=str(args.extraction_root),extraction_run_config_sha256=sha(args.extraction_root/'run_config.json'),
        model=config['model'],source_reference_sha256=sha(source/'full_population_gold.jsonl'),
        source_input_sha256=sha(source/'full_population_inputs.jsonl'),
        code_sha256={p.relative_to(ROOT).as_posix():sha(p) for p in (ROOT/'src').rglob('*.py')},
        runner_sha256=sha(Path(__file__)),
        vector_policy='Exhaustive o/x/unknown up to 5 source-bound questions; deterministic three bases, single changes, and up to 32 DNF witnesses above 5; context controls for every CVE.',
        reference_policy='Independent frozen source expression, exact same-source positive-clause mapping only; unmatched/ambiguous leaves unknown; closed-world source path assumption disclosed.',
        metric='affected TP/(TP+FP), strict >0.85, unknown positives block overall score/pass',
        frozen_before_new_predictions=True)
    if (args.output/'protocol.json').exists():assert json.loads((args.output/'protocol.json').read_bytes())==protocol
    else:write(args.output/'protocol.json',protocol)
    write(args.dataset/'protocol.json',protocol)
    refs={}
    for line in (source/'full_population_gold.jsonl').open(encoding='utf-8'):
        row=json.loads(line)
        if row['variant']=='present_true':refs[row['cve']]=row
    assert set(refs)=={r['cve'] for r in items}
    # Same production graph backend, adapted only to avoid nested remote exec.
    import tools.item4.run_item4_full_actual as backend
    backend.OUT=args.output;backend.install_remote_mulval()
    cache=install_graph_cache();started=time.time()
    write(args.dataset/'population_ledger.json',dict(population_cves=12418,cves=sorted(refs),status='building'))
    while True:
        done=0;new=0;cases=0
        for item in items:
            cve=item['cve'];target=args.output/'cves'/(cve+'.json')
            if target.exists():
                previous=json.loads(target.read_bytes());cases+=len(previous['predictions']);done+=1;continue
            path=args.extraction_root/'cves'/(cve+'.json')
            if not path.exists():continue
            raw=path.read_bytes();checkpoint=json.loads(raw)
            artifact=checkpoint['extraction'].get('prerequisite')
            if artifact:
                assert artifact['model']['adapter']['sha256']=='7ce8bfea47c7c226092566396cf75972a3cccc1305f0137e5953f3ba6882ebaf'
            job=job_for(item,checkpoint)
            inputs,references,generation=build_cases(cve,job,refs[cve])
            dataset=dict(cve=cve,job=job,cases=inputs,generation=generation,
                real_extraction_checkpoint_sha256=hashlib.sha256(raw).hexdigest())
            datafile=args.dataset/'cves'/(cve+'.json');reffile=args.dataset/'references'/(cve+'.json')
            if datafile.exists():assert json.loads(datafile.read_bytes())==dataset
            else:write(datafile,dataset)
            if reffile.exists():assert json.loads(reffile.read_bytes())==references
            else:write(reffile,references)
            output=predict(job,inputs)
            write(target,dict(cve=cve,predictions=output,input_sha256=sha(datafile),reference_frozen_sha256=sha(reffile)))
            cache.clear();done+=1;new+=1;cases+=len(output)
            if done%25==0:
                state=dict(status='running',stage='actual_operator_input_and_V4',completed_cves=done,total_cves=12418,
                    completed_cases=cases,updated_at=time.time(),elapsed_seconds=time.time()-started)
                write(args.output/'status.json',state);print(json.dumps(state),flush=True)
        if done==12418:
            report=finalize(args,items,protocol)
            write(args.output/'status.json',dict(status='complete',completed_cves=done,completed_cases=cases,finished_at=time.time()))
            print(json.dumps(report['all_cases']),flush=True);return
        state=dict(status='running',stage='waiting_for_real_LLM_extraction',completed_cves=done,total_cves=12418,
            completed_cases=cases,newly_processed=new,updated_at=time.time())
        write(args.output/'status.json',state)
        if args.once:return
        time.sleep(args.poll_seconds)


if __name__=='__main__':main()
