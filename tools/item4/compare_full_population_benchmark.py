"""Replay the frozen population against the corrected engine without changing facts.

Only the plan hash is resealed after proving that its complete content differs
solely in engine version. Sources, observations, references and clock are fixed.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from collections import Counter,defaultdict
from copy import deepcopy
from datetime import datetime,timezone
from html import escape
from itertools import zip_longest
from pathlib import Path
from unittest.mock import patch
import argparse,csv,gzip,hashlib,json,time,shutil

from src.item4.decision import evidence_based_vex as E; from src.item4.decision import population_condition_rules as P; from src.item4.assets import operating_profile_catalog as M
from tools.item4.run_full_population_benchmark import metrics

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'results/nist_population_vex_20261118/benchmark'
OUT=ROOT/'results/nist_population_vex_comparison_20261118_v3'
ENGINE_FILES=('src/item4/decision/evidence_based_vex.py','src/item4/decision/population_condition_rules.py','src/item4/assets/operating_profile_catalog.py','src/common/data/source_version_parser.py')


def file_hash(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()


def reseal_payload(payload,plan,previous_version):
    previous=deepcopy(plan);previous.pop('plan_sha256');previous['version']=previous_version
    if E.digest(previous)!=payload['plan_sha256']:
        raise ValueError('Frozen question plan changed beyond the engine version: '+payload['cve'])
    if payload.get('product_key')!=plan['product']['key']:
        raise ValueError('Frozen product binding changed: '+payload['cve'])
    result=deepcopy(payload);result['plan_sha256']=plan['plan_sha256']
    return result


def metric_comparison(before,after):
    return {key:dict(before=before[key],after=after[key],delta=(after[key]-before[key])
                    if isinstance(before[key],(int,float)) and isinstance(after[key],(int,float)) else None)
            for key in before if key!='predictions'}


def write_csv(path,rows,fields):
    with path.open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader()
        for row in rows:writer.writerow({k:row.get(k) for k in fields})


def render(report,changes,path):
    def fmt(key,value):
        if value is None:return '—'
        if key in ('precision','recall','abstention_rate','four_state_reference_agreement'):
            return f'{value*100:.4f}%'
        return str(value)
    def table(rows):
        return '<table>'+''.join('<tr>'+''.join('<td>'+escape(str(v))+'</td>' for v in row)+'</tr>' for row in rows)+'</table>'
    rows=[['지표','수정 전','수정 후','차이']]
    for key in ('cases','unique_cves','tp','fp','fn','precision','recall','abstention_rate','four_state_reference_agreement','errors'):
        m=report['overall_comparison'][key]
        delta=fmt(key,m['delta'])
        if m['delta'] is not None and key in ('precision','recall','abstention_rate','four_state_reference_agreement'):
            delta=f"{m['delta']*100:+.4f} pp"
        rows.append([key,fmt(key,m['before']),fmt(key,m['after']),delta])
    sections=['<h2>전체 결과</h2>'+table(rows)]
    for name,item in report['per_scenario_comparison'].items():
        rows=[['지표','수정 전','수정 후']]
        for key in ('cases','precision','recall','abstention_rate','four_state_reference_agreement','errors'):
            m=item[key];rows.append([key,fmt(key,m['before']),fmt(key,m['after'])])
        sections.append('<h2>'+escape(name)+'</h2>'+table(rows))
    sections.append('<h2>판정 전이</h2>'+table([['수정 전','수정 후','건수']]+[[r['before'],r['after'],r['cases']] for r in report['transitions']]))
    sections.append('<h2>변경 사례 (최대 50건)</h2>'+table([['사례','원천 정답','수정 전','수정 후','버전 상태 변화']]+[
        [r['case_id'],r['actual_status'],r['before'],r['after'],r['before_version_state']+' → '+r['after_version_state']] for r in changes[:50]]))
    html='''<!doctype html><html lang="ko"><meta charset="utf-8"><title>37,254건 수정 전후 비교</title>
<style>body{font:16px/1.6 system-ui;max-width:1100px;margin:36px auto;padding:0 20px;color:#182535}table{border-collapse:collapse;width:100%;margin:16px 0}td{border:1px solid #cbd5e1;padding:7px 10px}tr:first-child{background:#edf2f7;font-weight:bold}aside{padding:16px;background:#fff5dd}</style>
<h1>37,254건 전수 실험: 수정 전후 비교</h1>
<p>12,418개 CVE × 동일한 3개 시나리오. 입력 관측·정답·원천·평가 시각을 고정하고 질문 계획의 엔진 버전 해시만 갱신했습니다.</p>
<aside>합성 원천 상태 일관성 실험입니다. 독립적인 전문가·실제 설비 정확도 검증이 아닙니다. 이번 실험은 자동 판정 엔진을 호출하며 BOM 제품 연결, 별도 #4 API 시간 처리, Git 배포 문제의 검증은 회귀·통합 테스트에 해당합니다.</aside>'''
    html+=''.join(sections)+'<p>전체 변경 사례: <a href="changed_cases.csv">changed_cases.csv</a> · <a href="comparison.json">comparison.json</a> · <a href="report.json">report.json</a></p></html>'
    path.write_text(html,encoding='utf-8')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',type=Path,default=BASE)
    parser.add_argument('--output',type=Path,default=OUT)
    args=parser.parse_args();base=args.baseline.resolve();out=args.output.resolve()
    if out.exists():raise ValueError('Use a new comparison directory; refusing to overwrite '+str(out))
    protocol=json.loads((base/'protocol.json').read_text(encoding='utf-8'))
    previous_report=json.loads((base/'report.json').read_text(encoding='utf-8'))
    population=json.loads((base/'population.json').read_text(encoding='utf-8'))
    if len(population)!=12418 or len(set(population))!=12418 or protocol['cases']!=37254:
        raise ValueError('Expected the complete original 12,418-CVE / 37,254-case population')
    protected={n:file_hash(base/n) for n in ('protocol.json','report.json','inputs.jsonl.gz','references.jsonl','population.json','predictions.jsonl','decisions.jsonl.gz')}
    for name,expected in protocol['sha256'].items():
        if file_hash(base/name)!=expected:raise ValueError('Frozen artifact changed: '+name)
    if P.manifest()['sha256']!=protocol['catalogue_sha256']:raise ValueError('Source catalogue changed')
    refs={};before={}
    for name,target in [('references.jsonl',refs),('predictions.jsonl',before)]:
        with (base/name).open(encoding='utf-8') as f:
            for line in f:
                row=json.loads(line)
                if row['case_id'] in target:raise ValueError('Duplicate baseline case ID')
                target[row['case_id']]=row
    expected_cases={c+':'+s for c in population for s in protocol['case_types']}
    if set(refs)!=expected_cases or set(before)!=expected_cases:raise ValueError('Baseline case membership changed')
    if metrics(list(before.values()))!=previous_report['overall']:raise ValueError('Baseline metrics do not reproduce from its saved predictions')
    frozen=datetime.fromisoformat(protocol['frozen_at']);fingerprints={n:file_hash(ROOT/n) for n in ENGINE_FILES}
    class Clock(datetime):
        @classmethod
        def now(cls,tz=None):return frozen.astimezone(tz) if tz else frozen.replace(tzinfo=None)
    out.mkdir(parents=True)
    shutil.copyfile(__file__,out/'comparison_runner.py')
    run=dict(engine_version=E.VERSION,baseline=str(base.relative_to(ROOT)) if base.is_relative_to(ROOT) else str(base),
        baseline_sha256=protected,baseline_source_fingerprints=previous_report['source_fingerprints'],
        source_fingerprints=fingerprints,evaluation_time=frozen.isoformat(),started_at=datetime.now(timezone.utc).isoformat(),
        adaptation='plan_sha256 only; complete old/new plan equality after substituting engine version is checked per case',
        observations_changed=False,references_changed=False,source_catalogue_changed=False,
        population_count=12418,cases=37254,excluded_cves=0,llm_used=False,network_forbidden=True)
    (out/'protocol.json').write_text(json.dumps(run,indent=2),encoding='utf-8')
    rows=[];changes=[];transitions=Counter();seen=set();start=time.monotonic();last_plan_key=None;plan=None;previous_version=None
    try:
        with patch.object(E,'now',return_value=frozen),patch.object(M,'datetime',Clock),patch('socket.socket.connect',side_effect=AssertionError('No network/LLM in full-population replay')),gzip.open(base/'inputs.jsonl.gz','rt',encoding='utf-8') as inputs,gzip.open(base/'decisions.jsonl.gz','rt',encoding='utf-8') as old_decisions,gzip.open(out/'inputs.jsonl.gz','wt',encoding='utf-8',compresslevel=1) as adapted,gzip.open(out/'decisions.jsonl.gz','wt',encoding='utf-8',compresslevel=1) as decisions,(out/'predictions.jsonl').open('w',encoding='utf-8') as predictions:
            for i,pair in enumerate(zip_longest(inputs,old_decisions)):
                line,old_line=pair
                if line is None or old_line is None:raise ValueError('Baseline input/decision count differs')
                item=json.loads(line);old=json.loads(old_line);cid=item['case_id']
                if cid!=old['case_id'] or cid in seen or cid not in expected_cases:raise ValueError('Case order, uniqueness or membership mismatch: '+cid)
                seen.add(cid);ref=refs[cid];old_row=before[cid];payload=item['payload'];old_result=old.get('result')
                if any(old_row[k]!=ref[k] for k in ('cve','scenario','actual_status','reference_quality')):raise ValueError('Baseline reference binding mismatch: '+cid)
                if old_result is None:raise ValueError('Cannot establish baseline plan version for failed record: '+cid)
                if old_result['decision']['status']!=old_row['prediction'] or old_result['assessment_sha256']!=old_row['assessment_sha256']:
                    raise ValueError('Baseline decision/prediction mismatch: '+cid)
                if previous_version is None:previous_version=old_result['version']
                if previous_version!=old_result['version']:raise ValueError('Baseline contains mixed engine versions')
                key=(payload['cve'],E.digest(payload['profile']))
                if key!=last_plan_key:
                    plan=E.plan(payload['cve'],payload['profile'],payload.get('product_key'));last_plan_key=key
                updated=reseal_payload(payload,plan,previous_version)
                adapted.write(json.dumps(dict(case_id=cid,payload=updated),ensure_ascii=False,separators=(',',':'))+'\n')
                row={k:ref[k] for k in ('case_id','cve','scenario','actual_status','reference_quality')}
                row.update(prediction='under_investigation',error=None)
                result=None
                try:
                    result=E.evaluate(updated)
                    if result['operator_selects_verdict'] or result['llm_used']:raise AssertionError('Automatic-only contract violated')
                    row.update(prediction=result['decision']['status'],formula_value=result['formula_value'],assessment_sha256=result['assessment_sha256'],unresolved_operands=sum(v=='unknown' for v in result['condition_values'].values()))
                    decisions.write(json.dumps(dict(case_id=cid,result=result),ensure_ascii=False,separators=(',',':'))+'\n')
                except (ValueError,TypeError,KeyError) as exc:
                    row['error']=str(exc);decisions.write(json.dumps(dict(case_id=cid,error=str(exc)),ensure_ascii=False)+'\n')
                rows.append(row);predictions.write(json.dumps(row,ensure_ascii=False)+'\n')
                transitions[(old_row['prediction'],row['prediction'])]+=1
                if old_row['prediction']!=row['prediction'] or old_row.get('error')!=row['error']:
                    trace=result['decision']['decision_trace'][0] if result else {}
                    changes.append(dict(case_id=cid,cve=ref['cve'],scenario=ref['scenario'],actual_status=ref['actual_status'],reference_quality=ref['reference_quality'],
                        product=payload['profile']['scope']['product'],build=payload['profile']['scope']['build'],before=old_row['prediction'],after=row['prediction'],
                        before_version_state=old_result['decision']['decision_trace'][0]['version_state'],after_version_state=trace.get('version_state','error'),
                        before_reason=old_result['decision']['reason'],after_reason=result['decision']['reason'] if result else row['error'],
                        source_memberships=next((t['memberships'] for t in result['decision']['decision_trace'] if t['check']=='primary_csaf_product_version_status'),[]) if result else []))
                if (i+1)%1000==0:
                    progress=dict(cases=i+1,total=37254,changed=len(changes),errors=sum(bool(r['error']) for r in rows),elapsed_seconds=round(time.monotonic()-start,2))
                    (out/'progress.json').write_text(json.dumps(progress),encoding='utf-8');print(json.dumps(progress),flush=True)
        if seen!=expected_cases:raise ValueError('Full population case coverage failed')
        if any(file_hash(base/n)!=sha for n,sha in protected.items()):raise ValueError('A baseline artifact changed during replay')
        if any(file_hash(ROOT/n)!=sha for n,sha in fingerprints.items()):raise ValueError('Engine changed during replay')
        by_scenario=defaultdict(list);by_cve=defaultdict(list)
        for row in rows:by_scenario[row['scenario']].append(row);by_cve[row['cve']].append(row)
        after=metrics(rows);scenario_metrics={k:metrics(v) for k,v in by_scenario.items()}
        report=dict(protocol=protocol,engine_version=E.VERSION,overall=after,per_scenario=scenario_metrics,
            target_membership=dict(expected=12418,evaluated=len(by_cve),excluded=0,missing=[],unexpected=[],cases_per_cve=3),
            source_fingerprints={Path(n).name:v for n,v in fingerprints.items()},llm_used=False,network_forbidden=True,
            reference_is_independent_expert_ground_truth=False,elapsed_seconds=round(time.monotonic()-start,3))
        comparison=dict(protocol=run,before_engine_version=previous_version,after_engine_version=E.VERSION,
            overall_comparison=metric_comparison(previous_report['overall'],after),
            per_scenario_comparison={k:metric_comparison(previous_report['per_scenario'][k],v) for k,v in scenario_metrics.items()},
            before_predictions=previous_report['overall']['predictions'],after_predictions=after['predictions'],
            transitions=[dict(before=a,after=b,cases=n) for (a,b),n in sorted(transitions.items())],
            changed_cases=len(changes),changed_cves=len({r['cve'] for r in changes}),
            changes_by_scenario=dict(Counter(r['scenario'] for r in changes)),
            change_reasons=dict(Counter(r['before_version_state']+' -> '+r['after_version_state'] for r in changes)),
            baseline_artifacts_preserved=True,all_observations_preserved=True,all_reference_labels_preserved=True,
            elapsed_seconds=report['elapsed_seconds'],limitations=protocol['limitations'],
            scope='This benchmark exercises nist_auto_vex directly. Other fixes (BOM product binding, separate API clock, runtime packaging) are covered by regression/integration tests, not these synthetic cases.')
        (out/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
        (out/'comparison.json').write_text(json.dumps(comparison,ensure_ascii=False,indent=2),encoding='utf-8')
        (out/'per_cve.json').write_text(json.dumps({k:metrics(v) for k,v in by_cve.items()},indent=2),encoding='utf-8')
        (out/'changed_cases.json').write_text(json.dumps(changes,ensure_ascii=False,indent=2),encoding='utf-8')
        write_csv(out/'cases.csv',rows,['case_id','cve','scenario','actual_status','prediction','reference_quality','formula_value','unresolved_operands','error'])
        write_csv(out/'changed_cases.csv',changes,['case_id','cve','scenario','actual_status','reference_quality','product','build','before','after','before_version_state','after_version_state','before_reason','after_reason'])
        render(comparison,changes,out/'comparison.html')
        completed=dict(status='complete',cases=len(rows),unique_cves=len(by_cve),errors=after['errors'],changed=len(changes),elapsed_seconds=report['elapsed_seconds'])
        (out/'progress.json').write_text(json.dumps(completed),encoding='utf-8')
        print(json.dumps(completed),flush=True)
    except BaseException as exc:
        (out/'failure.json').write_text(json.dumps(dict(error=repr(exc),evaluated_cases=len(rows))),encoding='utf-8')
        raise


if __name__=='__main__':main()
