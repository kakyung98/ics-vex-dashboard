"""Evaluate every frozen case; never modify labels or discard hard cases."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from collections import Counter,defaultdict
from unittest.mock import patch
from datetime import datetime,timezone
import gzip,hashlib,json,math,time
from tools.item4 import serve_nist_operational_vex as S
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'results/nist_three_axis_experiment_20261118'
def metrics(rows):
    tp=sum(r['actual_affected'] and r['predicted']=='affected' for r in rows)
    fp=sum(not r['actual_affected'] and r['predicted']=='affected' for r in rows)
    fn=sum(r['actual_affected'] and r['predicted']!='affected' for r in rows)
    tn=len(rows)-tp-fp-fn
    n=tp+fp;p=tp/n if n else None
    interval=None
    if n:
        z=1.96;center=(p+z*z/(2*n))/(1+z*z/n);half=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/(1+z*z/n);interval=[center-half,center+half]
    return dict(total=len(rows),tp=tp,fp=fp,fn=fn,tn=tn,precision=p,recall=tp/(tp+fn) if tp+fn else None,affected_prediction_rate=n/len(rows),abstention_rate=sum(r['predicted']=='under_investigation' for r in rows)/len(rows),four_status_exact_accuracy=sum(r['actual_status']==r['predicted'] for r in rows)/len(rows),precision_wilson_95=interval,interval_assumes_independent_cases_but_template_replications_are_correlated=True,errors=sum(bool(r.get('error')) for r in rows),predicted_status_counts=dict(Counter(r['predicted'] for r in rows)))
def main():
    protocol=json.loads((OUT/'protocol.json').read_text())
    frozen=datetime.fromisoformat(protocol['frozen_at'])
    class FrozenDatetime(datetime):
        @classmethod
        def now(cls,tz=None):return frozen.astimezone(tz) if tz else frozen.replace(tzinfo=None)
    for name,expected in protocol['sha256'].items():
        if hashlib.sha256((OUT/name).read_bytes()).hexdigest()!=expected:raise ValueError('Frozen data changed: '+name)
    truth={r['case_id']:r for r in map(json.loads,(OUT/'holdout_ground_truth.jsonl').read_text(encoding='utf-8').splitlines())}
    predictions=[];start=time.monotonic()
    with gzip.open(OUT/'holdout_inputs.jsonl.gz','rt',encoding='utf-8') as f,patch('socket.socket.connect',side_effect=AssertionError('No network/LLM during experiment')),patch.object(S.model,'datetime',FrozenDatetime),patch.object(S.typed,'datetime',FrozenDatetime),patch.object(S.V.A,'now',return_value=protocol['frozen_at']):
        for i,line in enumerate(f):
            row=json.loads(line);p=row['profile'];r=row['record'];expected=truth[row['case_id']]
            result=dict(case_id=row['case_id'],family=row['family'],asset_type_id=p['asset_type_id'],actual_status=expected['actual_status'],actual_affected=expected['actual_affected'],predicted='under_investigation',error=None)
            try:
                pl=S.V.plan(r['cve'],p,'fictional-product',r)
                request=dict(cve=r['cve'],product_key='fictional-product',profile=p,plan_sha256=pl['plan_sha256'],approved_scenarios=row['approved_scenarios'],bindings=[],typed_review=row['typed_review'])
                out=S.V.evaluate(request,r)
                result.update(predicted=out['decision']['status'],decision_sha256=out['assessment_sha256'],condition_values={m['question_id']:m['accepted_value'] for m in out['mappings']},proof_trace=out['typed_proof_trace'],llm_used=out['llm_used'])
            except (ValueError,KeyError,TypeError) as e:result['error']=str(e)
            predictions.append(result)
            if (i+1)%200==0:print('Assessed',i+1,flush=True)
    if len(predictions)!=protocol['total'] or len({r['case_id'] for r in predictions})!=len(truth):raise ValueError('Missing/duplicate cases')
    groups=defaultdict(list)
    families=defaultdict(list)
    for r in predictions:groups[r['asset_type_id']].append(r);families[r['family']].append(r)
    report=dict(protocol=protocol,overall=metrics(predictions),per_asset={k:metrics(v) for k,v in sorted(groups.items())},per_family={k:metrics(v) for k,v in sorted(families.items())},elapsed_seconds=time.monotonic()-start,all_cases_retained=True,network_calls_forbidden=True,llm_used=False,production_engine_sha256=hashlib.sha256((ROOT/'src/item4/decision/scoped_proof_evaluation.py').read_bytes()).hexdigest(),not_independent_real_world_accuracy=True)
    report['target_met']=report['overall']['precision'] is not None and report['overall']['precision']>=protocol['target_precision']
    report['assessment_clock']=dict(value=protocol['frozen_at'],policy='Replay the predeclared snapshot time for reproducible historical validity checks; live service always uses the real clock.')
    (OUT/'predictions.jsonl').write_text('\n'.join(json.dumps(r,ensure_ascii=False) for r in predictions)+'\n',encoding='utf-8')
    (OUT/'experiment_report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(dict(overall=report['overall'],target_met=report['target_met'],elapsed=report['elapsed_seconds']),indent=2))
if __name__=='__main__':main()
