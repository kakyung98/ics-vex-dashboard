
if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from datetime import datetime
from collections import Counter,defaultdict
from unittest.mock import patch
import gzip,hashlib,json,time
from tools.item4 import serve_nist_operational_vex as S
from src.item4.decision import evidence_based_vex as E
OUT=Path('D:/ICS-VEX/results/nist_auto_vex_20261118/experiment')
def metrics(rows):
    positives=[r for r in rows if r['prediction']=='affected']
    tp=sum(r['actual_status']=='affected' for r in positives);fp=len(positives)-tp
    fn=sum(r['actual_status']=='affected' and r['prediction']!='affected' for r in rows)
    known=[r for r in rows if r['actual_status'] is not None]
    return dict(total=len(rows),tp=tp,fp=fp,fn=fn,precision=tp/(tp+fp) if tp+fp else None,recall=tp/(tp+fn) if tp+fn else None,abstention_rate=sum(r['prediction']=='under_investigation' for r in rows)/len(rows),four_state_exact_accuracy_resolved_reference=sum(r['actual_status']==r['prediction'] for r in known)/len(known) if known else None,reference_unresolved=len(rows)-len(known),unverified_positive=sum(r['actual_status'] is None for r in positives),unexpected_errors=sum(bool(r.get('error')) for r in rows),prediction_counts=dict(Counter(r['prediction'] for r in rows)))
def main():
    engine_sha_at_start=hashlib.sha256(Path(E.__file__).read_bytes()).hexdigest()
    protocol=json.loads((OUT/'protocol.json').read_text())
    for name,h in protocol['sha256'].items():
        if hashlib.sha256((OUT/name).read_bytes()).hexdigest()!=h:raise ValueError('Frozen benchmark changed: '+name)
    if E.registry()['sha256']!=protocol['rule_registry_sha256']:raise ValueError('Rule registry changed; do not silently reseal the benchmark.')
    reference={r['case_id']:r for r in map(json.loads,(OUT/'ground_truth.jsonl').read_text(encoding='utf-8').splitlines())}
    frozen=datetime.fromisoformat(protocol['frozen_at'])
    class Clock(datetime):
        @classmethod
        def now(cls,tz=None):return frozen.astimezone(tz) if tz else frozen.replace(tzinfo=None)
    rows=[];start=time.monotonic()
    with patch.object(E,'now',return_value=frozen),patch.object(S.model,'datetime',Clock),patch('socket.socket.connect',side_effect=AssertionError('No network/LLM allowed')),gzip.open(OUT/'inputs.jsonl.gz','rt',encoding='utf-8') as f:
        for i,line in enumerate(f):
            item=json.loads(line);truth=reference[item['case_id']];row=dict(case_id=item['case_id'],cve=truth['cve'],variant=truth['variant'],actual_status=truth['actual_status'],prediction='under_investigation',error=None)
            try:
                result=S.V.evaluate(item['payload'])
                row.update(prediction=result['decision']['status'],formula_value=result['formula_value'],condition_values=result['condition_values'],assessment_sha256=result['assessment_sha256'],question_trace=result['question_trace'])
                if result['operator_selects_verdict'] or result['llm_used']:raise AssertionError('Automatic-only contract violated')
            except (ValueError,TypeError,KeyError) as error:row['error']=str(error)
            rows.append(row)
            if (i+1)%100==0:print('Automatic cases assessed:',i+1,flush=True)
    if len(rows)!=protocol['total'] or len({r['case_id'] for r in rows})!=len(reference):raise ValueError('Missing/duplicate cases')
    by_cve=defaultdict(list);by_variant=defaultdict(list)
    for row in rows:by_cve[row['cve']].append(row);by_variant[row['variant']].append(row)
    if hashlib.sha256(Path(E.__file__).read_bytes()).hexdigest()!=engine_sha_at_start:raise ValueError('Engine source changed during evaluation; no current-version report will be published.')
    report=dict(protocol=protocol,all_cases=metrics(rows),truthful_observations=metrics([r for r in rows if r['variant']!='semantically_wrong_operating_fact']),per_cve={k:metrics(v) for k,v in sorted(by_cve.items())},per_variant={k:metrics(v) for k,v in sorted(by_variant.items())},excluded_cases=0,elapsed_seconds=time.monotonic()-start,llm_used=False,network_forbidden=True,operator_verdict_in_inputs=False,operator_condition_truth_in_inputs=False,clock_replayed_from_frozen_protocol=True,engine_sha256=engine_sha_at_start,independent_expert_validation=False,real_world_accuracy_validated=False)
    report['precision_target_met']=report['all_cases']['precision'] is not None and report['all_cases']['precision']>=protocol['precision_target']
    (OUT/'predictions.jsonl').write_text('\n'.join(json.dumps(r,ensure_ascii=False) for r in rows)+'\n',encoding='utf-8');(OUT/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:report[k] for k in ['all_cases','truthful_observations','precision_target_met','elapsed_seconds']},indent=2))
if __name__=='__main__':main()
