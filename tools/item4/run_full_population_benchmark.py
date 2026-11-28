
if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from collections import Counter,defaultdict
from datetime import datetime
from unittest.mock import patch
import csv,gzip,hashlib,json,time
from src.item4.decision import evidence_based_vex as E
from src.item4.decision import population_condition_rules as P
from src.item4.assets import operating_profile_catalog as M
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'results/nist_population_vex_20261118/benchmark'
from src.common.paths import source_path

def metrics(rows):
    positives=[r for r in rows if r['prediction']=='affected'];tp=sum(r['actual_status']=='affected' for r in positives);fp=len(positives)-tp;fn=sum(r['actual_status']=='affected' and r['prediction']!='affected' for r in rows)
    known=[r for r in rows if r['actual_status'] is not None]
    return dict(cases=len(rows),unique_cves=len({r['cve'] for r in rows}),tp=tp,fp=fp,fn=fn,precision=tp/(tp+fp) if tp+fp else None,recall=tp/(tp+fn) if tp+fn else None,abstention_rate=sum(r['prediction']=='under_investigation' for r in rows)/len(rows),resolved_reference_cases=len(known),unresolved_reference_cases=len(rows)-len(known),unverified_positive=sum(r['actual_status'] is None for r in positives),four_state_reference_agreement=sum(r['actual_status']==r['prediction'] for r in known)/len(known) if known else None,predictions=dict(Counter(r['prediction'] for r in rows)),errors=sum(bool(r.get('error')) for r in rows))
def main():
    protocol=json.loads((OUT/'protocol.json').read_text());population=json.loads((OUT/'population.json').read_text());fingerprints={n:hashlib.sha256((source_path(n, root=ROOT)).read_bytes()).hexdigest() for n in ['nist_auto_vex.py','nist_population_rules.py','nist_table_profiles.py']}
    for name,expected in protocol['sha256'].items():
        if hashlib.sha256((OUT/name).read_bytes()).hexdigest()!=expected:raise ValueError('Frozen full-population input/reference changed: '+name)
    if P.manifest()['sha256']!=protocol['catalogue_sha256']:raise ValueError('Compiled source catalogue changed after freezing')
    refs={r['case_id']:r for r in map(json.loads,(OUT/'references.jsonl').read_text(encoding='utf-8').splitlines())};frozen=datetime.fromisoformat(protocol['frozen_at'])
    class Clock(datetime):
        @classmethod
        def now(cls,tz=None):return frozen.astimezone(tz) if tz else frozen.replace(tzinfo=None)
    rows=[];start=time.monotonic()
    with patch.object(E,'now',return_value=frozen),patch.object(M,'datetime',Clock),patch('socket.socket.connect',side_effect=AssertionError('No network or LLM during full-population assessment')),gzip.open(OUT/'inputs.jsonl.gz','rt',encoding='utf-8') as src,gzip.open(OUT/'decisions.jsonl.gz','wt',encoding='utf-8',compresslevel=1) as decisions:
        for i,line in enumerate(src):
            item=json.loads(line);ref=refs[item['case_id']];row=dict(case_id=item['case_id'],cve=ref['cve'],scenario=ref['scenario'],actual_status=ref['actual_status'],reference_quality=ref['reference_quality'],prediction='under_investigation',error=None)
            try:
                result=E.evaluate(item['payload']);row.update(prediction=result['decision']['status'],formula_value=result['formula_value'],assessment_sha256=result['assessment_sha256'],unresolved_operands=sum(v=='unknown' for v in result['condition_values'].values()))
                if result['operator_selects_verdict'] or result['llm_used']:raise AssertionError('Automatic-only contract violated')
                decisions.write(json.dumps(dict(case_id=row['case_id'],result=result),ensure_ascii=False,separators=(',',':'))+'\n')
            except (ValueError,TypeError,KeyError) as error:row['error']=str(error);decisions.write(json.dumps(dict(case_id=row['case_id'],error=str(error)))+'\n')
            rows.append(row)
            if (i+1)%1000==0:print('Evaluated cases:',i+1,'CVEs:',len({r['cve'] for r in rows}),flush=True)
    actual_ids={r['cve'] for r in rows};case_counts=Counter(r['cve'] for r in rows)
    if actual_ids!=set(population) or len(rows)!=protocol['cases'] or set(case_counts.values())!={3}:raise ValueError('Full target membership/case-count failed')
    for name,sha in fingerprints.items():
        if hashlib.sha256((source_path(name, root=ROOT)).read_bytes()).hexdigest()!=sha:raise ValueError('Engine/compiler/validation code changed during evaluation')
    by_cve=defaultdict(list);by_scenario=defaultdict(list)
    for r in rows:by_cve[r['cve']].append(r);by_scenario[r['scenario']].append(r)
    report=dict(protocol=protocol,overall=metrics(rows),per_scenario={k:metrics(v) for k,v in by_scenario.items()},target_membership=dict(expected=12418,evaluated=len(actual_ids),excluded=0,missing=[],unexpected=[],cases_per_cve=3),source_fingerprints=fingerprints,llm_used=False,network_forbidden=True,reference_is_independent_expert_ground_truth=False,measures='Synthetic source-status consistency under declared prerequisite assumptions; not independent real-world classification accuracy.',elapsed_seconds=time.monotonic()-start)
    (OUT/'predictions.jsonl').write_text('\n'.join(json.dumps(r) for r in rows)+'\n',encoding='utf-8');(OUT/'per_cve.json').write_text(json.dumps({k:metrics(v) for k,v in by_cve.items()},indent=2),encoding='utf-8')
    with (OUT/'cases.csv').open('w',newline='',encoding='utf-8-sig') as f:
        keys=['case_id','cve','scenario','actual_status','prediction','reference_quality','formula_value','unresolved_operands','error'];w=csv.DictWriter(f,fieldnames=keys);w.writeheader();w.writerows({k:r.get(k) for k in keys} for r in rows)
    (OUT/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps({k:report[k] for k in ['overall','per_scenario','target_membership','elapsed_seconds']},indent=2))
if __name__=='__main__':main()
