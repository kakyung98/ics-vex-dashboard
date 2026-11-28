"""Independently check paired replay outputs and freeze their artifact hashes."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from collections import Counter,defaultdict
from datetime import datetime,timezone
from itertools import zip_longest
from pathlib import Path
import argparse,gzip,json,shutil

from tools.item4.compare_full_population_benchmark import BASE,OUT,ROOT,file_hash,render
from tools.item4.run_full_population_benchmark import metrics


def verify(base,out):
    comparison=json.loads((out/'comparison.json').read_text(encoding='utf-8'))
    report=json.loads((out/'report.json').read_text(encoding='utf-8'))
    source_protocol=json.loads((base/'protocol.json').read_text(encoding='utf-8'))
    run=comparison['protocol']
    for name,sha in run['baseline_sha256'].items():
        if file_hash(base/name)!=sha:raise ValueError('Baseline artifact changed: '+name)
    for name,sha in run['source_fingerprints'].items():
        if file_hash(ROOT/name)!=sha:raise ValueError('Engine source changed: '+name)
    expected_population=set(json.loads((base/'population.json').read_text(encoding='utf-8')))
    expected_scenarios=set(source_protocol['case_types']);counts=Counter();seen=set();adaptations=0
    with gzip.open(base/'inputs.jsonl.gz','rt',encoding='utf-8') as old,gzip.open(out/'inputs.jsonl.gz','rt',encoding='utf-8') as new:
        for left,right in zip_longest(old,new):
            if left is None or right is None:raise ValueError('Input count differs')
            a,b=json.loads(left),json.loads(right)
            if a['case_id']!=b['case_id'] or a['case_id'] in seen:raise ValueError('Input identity/uniqueness failed')
            seen.add(a['case_id']);cve,scenario=a['case_id'].split(':')
            if cve not in expected_population or scenario not in expected_scenarios:raise ValueError('Unexpected target/scenario')
            counts[cve]+=1
            old_hash=a['payload'].pop('plan_sha256');new_hash=b['payload'].pop('plan_sha256')
            if a!=b:raise ValueError('A frozen fact, identity or observation was changed: '+a['case_id'])
            adaptations+=old_hash!=new_hash
    expected={c+':'+s for c in expected_population for s in expected_scenarios}
    if len(seen)!=37254 or seen!=expected or set(counts.values())!={3}:raise ValueError('Population coverage failed')
    rows=[];by_id={};by_scenario=defaultdict(list)
    with (out/'predictions.jsonl').open(encoding='utf-8') as f:
        for line in f:
            row=json.loads(line)
            if row['case_id'] in by_id:raise ValueError('Duplicate output case')
            rows.append(row);by_id[row['case_id']]=row;by_scenario[row['scenario']].append(row)
    if set(by_id)!=seen:raise ValueError('Output membership differs from input')
    if metrics(rows)!=report['overall']:raise ValueError('Overall metrics do not reproduce')
    if {k:metrics(v) for k,v in by_scenario.items()}!=report['per_scenario']:raise ValueError('Scenario metrics do not reproduce')
    with (base/'references.jsonl').open(encoding='utf-8') as f:
        for line in f:
            ref=json.loads(line);row=by_id[ref['case_id']]
            if any(row[k]!=ref[k] for k in ('cve','scenario','actual_status','reference_quality')):
                raise ValueError('Reference label/binding changed: '+ref['case_id'])
    with gzip.open(out/'decisions.jsonl.gz','rt',encoding='utf-8') as f:
        decision_ids=set()
        for line in f:
            item=json.loads(line);cid=item['case_id'];row=by_id[cid]
            if cid in decision_ids:raise ValueError('Duplicate decision')
            decision_ids.add(cid)
            if row['error']:
                if item.get('error')!=row['error']:raise ValueError('Error was dropped')
            else:
                result=item['result']
                if result['decision']['status']!=row['prediction'] or result['assessment_sha256']!=row['assessment_sha256']:
                    raise ValueError('Saved decision/prediction mismatch: '+cid)
        if decision_ids!=seen:raise ValueError('Missing full decisions')
    # Keep a standard replay protocol alongside the original execution protocol.
    # Reference files are exact byte copies; the original directory is untouched.
    for name in ('references.jsonl','population.json'):
        target=out/name
        if target.exists() and file_hash(target)!=file_hash(base/name):raise ValueError('Conflicting copied reference artifact')
        if not target.exists():shutil.copyfile(base/name,target)
    replay=dict(source_protocol,version=2,engine_version=report['engine_version'],
        baseline_sha256=run['baseline_sha256'],source_fingerprints=report['source_fingerprints'],
        adaptation=run['adaptation'],sha256={name:file_hash(out/name) for name in ('inputs.jsonl.gz','references.jsonl','population.json')})
    (out/'replay_protocol.json').write_text(json.dumps(replay,indent=2),encoding='utf-8')
    report['baseline_protocol']=source_protocol
    report['protocol']=replay
    (out/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    comparison['replay_protocol']='replay_protocol.json'
    (out/'comparison.json').write_text(json.dumps(comparison,ensure_ascii=False,indent=2),encoding='utf-8')
    render(comparison,json.loads((out/'changed_cases.json').read_text(encoding='utf-8')),out/'comparison.html')
    checks=dict(verified_at=datetime.now(timezone.utc).isoformat(),population_count=len(counts),cases=len(seen),cases_per_cve=3,
        plan_hashes_resealed=adaptations,only_plan_hash_changed=True,original_artifacts_preserved=True,
        exact_reference_labels_preserved=True,all_saved_decisions_match_predictions=True,all_metrics_reproduced=True,
        errors=report['overall']['errors'],runner_snapshot_sha256=file_hash(out/'comparison_runner.py') if (out/'comparison_runner.py').exists() else None,
        artifact_sha256={name:file_hash(out/name) for name in ('protocol.json','replay_protocol.json','inputs.jsonl.gz','references.jsonl','population.json','predictions.jsonl','decisions.jsonl.gz','report.json','comparison.json','changed_cases.json','changed_cases.csv','cases.csv')})
    (out/'validation.json').write_text(json.dumps(checks,indent=2),encoding='utf-8')
    return checks


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',type=Path,default=BASE);parser.add_argument('--output',type=Path,default=OUT)
    args=parser.parse_args();result=verify(args.baseline,args.output)
    print(json.dumps({k:v for k,v in result.items() if k!='artifact_sha256'},indent=2))


if __name__=='__main__':main()
