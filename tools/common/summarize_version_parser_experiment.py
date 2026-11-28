"""Join all three full-population runs and account for the original 224 cases."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from collections import Counter,defaultdict
from html import escape
from pathlib import Path
import csv,gzip,json
from tools.item4.run_full_population_benchmark import metrics
from tools.item4.compare_full_population_benchmark import file_hash
from src.common.source_version_parser import concrete

ROOT=Path(__file__).resolve().parents[2]
RUNS={
    'original_v2':ROOT/'results/nist_population_vex_20261118/benchmark',
    'conservative_v3':ROOT/'results/nist_population_vex_comparison_20261118_v3',
    'parser_v4':ROOT/'results/nist_population_vex_comparison_20261118_v4_release',
}
HOME=ROOT/'results/nist_version_parser_20261118_v4'


def main():
    data={};reports={}
    for name,path in RUNS.items():
        rows=[json.loads(s) for s in (path/'predictions.jsonl').read_text(encoding='utf-8').splitlines()]
        index={r['case_id']:r for r in rows}
        if len(rows)!=37254 or len(index)!=37254:raise ValueError('Incomplete/duplicate run: '+name)
        report=json.loads((path/'report.json').read_text(encoding='utf-8'))
        if metrics(rows)!=report['overall']:raise ValueError('Metrics differ: '+name)
        data[name]=index;reports[name]=report
    original=data['original_v2'];conservative=data['conservative_v3'];current=data['parser_v4']
    if any(set(rows)!=set(original) for rows in data.values()):raise ValueError('Run case populations differ')
    for cid,row in original.items():
        for rows in (conservative,current):
            if any(rows[cid][k]!=row[k] for k in ('cve','scenario','actual_status','reference_quality')):
                raise ValueError('A reference/scenario changed: '+cid)
    prior=json.loads((RUNS['conservative_v3']/'changed_cases.json').read_text(encoding='utf-8'))
    audited={r['cve']:r for r in json.loads((HOME/'cases.json').read_text(encoding='utf-8'))}
    focus=[];outcomes=Counter();transitions=Counter();all_changes=[];by_scenario=defaultdict(Counter)
    for cid,row in current.items():
        before=conservative[cid];transitions[(before['prediction'],row['prediction'])]+=1
        if before['prediction']!=row['prediction'] or before.get('error')!=row.get('error'):
            all_changes.append(dict(case_id=cid,cve=row['cve'],scenario=row['scenario'],actual_status=row['actual_status'],before=before['prediction'],after=row['prediction']))
            by_scenario[row['scenario']][before['prediction']+' -> '+row['prediction']]+=1
    for row in prior:
        cid=row['case_id'];new=current[cid];analysis=audited[row['cve']]
        outcome='restored_original_status' if new['prediction']==original[cid]['prediction'] else 'still_under_investigation' if new['prediction']=='under_investigation' else 'changed_to_other_status'
        outcomes[outcome]+=1
        focus.append(dict(case_id=cid,cve=row['cve'],product=row['product'],build=row['build'],
            original=original[cid]['prediction'],conservative=conservative[cid]['prediction'],parser=new['prediction'],actual_status=new['actual_status'],outcome=outcome,
            new_version_state=analysis['new_version_state'],observed_build_concrete=analysis['observed_build_concrete'],
            remaining_primary_reason=analysis.get('remaining_primary_reason',''),
            remaining_conditions=[dict(version_text=p['version_text'],source_file=p['source_file'],status_pointer=p['status_pointer']) for p in analysis['remaining_unknown_rows']]))
    if len(focus)!=224 or sum(outcomes.values())!=224:raise ValueError('The 224-case accounting failed')
    prior_ids={r['case_id'] for r in prior}
    deferred_ids={r['case_id'] for r in all_changes if r['before']=='affected' and r['after']=='under_investigation'}
    deferred=[];deferred_reasons=Counter()
    with gzip.open(RUNS['parser_v4']/'decisions.jsonl.gz','rt',encoding='utf-8') as f:
        for line in f:
            item=json.loads(line)
            if item['case_id'] not in deferred_ids:continue
            result=item['result'];trace=result['decision']['decision_trace'][0]
            memberships=next((r['memberships'] for r in result['decision']['decision_trace'] if r['check']=='primary_csaf_product_version_status'),[])
            reason=('installed_version_not_concrete' if not concrete(result['scope']['build']) else
                'untranslated_or_qualified_source_range' if any(m['membership']=='unknown' for m in memberships) else
                'conflicting_source_statuses' if trace['version_state']=='conflicting' else 'outside_recognized_source_intervals')
            deferred_reasons[reason]+=1
            deferred.append(dict(case_id=item['case_id'],product=result['scope']['product'],build=result['scope']['build'],reason=reason,memberships=memberships))
    if len(deferred)!=len(deferred_ids):raise ValueError('Missing detailed deferral records')
    report=dict(cases=37254,unique_cves=12418,exclusions=0,all_case_ids_and_reference_labels_equal=True,
        runs={name:dict(overall=report['overall'],per_scenario=report['per_scenario'],source_fingerprints=report['source_fingerprints']) for name,report in reports.items()},
        original_224_outcomes=dict(outcomes),restored_status_counts=dict(Counter(r['parser'] for r in focus if r['outcome']=='restored_original_status')),
        conservative_to_parser_transitions=[dict(before=a,after=b,cases=n) for (a,b),n in sorted(transitions.items())],
        conservative_to_parser_changed_cases=len(all_changes),changes_outside_original_224=sum(r['case_id'] not in prior_ids for r in all_changes),
        changes_by_scenario={k:dict(v) for k,v in by_scenario.items()},
        additional_deferral_reasons=dict(deferred_reasons),
        intermediate_runs_preserved=['results/nist_population_vex_comparison_20261118_v4/interrupted.json','results/nist_population_vex_comparison_20261118_v4_final/superseded.json','results/nist_population_vex_comparison_20261118_v4_verified/interrupted.json'],
        original_run_files_preserved=True,source_validation=json.loads((HOME/'analysis.json').read_text(encoding='utf-8')),
        paired_validation=json.loads((RUNS['parser_v4']/'validation.json').read_text(encoding='utf-8')),
        run_report_sha256={k:file_hash(p/'report.json') for k,p in RUNS.items()},
        limitations=['Synthetic source-status consistency, not independent real-asset/expert accuracy.',
            'The 224-case set informed parser development, so its recovery rate is diagnostic rather than held-out accuracy.',
            'All 37,254 cases, including unresolved references and changes outside the 224-case set, are retained.',
            'Unknown vendor ordering, invalid source syntax, qualified scope and ambiguous installed builds are not guessed.'])
    (HOME/'three_way_comparison.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    (HOME/'recovery_224.json').write_text(json.dumps(focus,ensure_ascii=False,indent=2),encoding='utf-8')
    (HOME/'changes_v3_v4.json').write_text(json.dumps(all_changes,ensure_ascii=False,indent=2),encoding='utf-8')
    (HOME/'additional_deferrals.json').write_text(json.dumps(deferred,ensure_ascii=False,indent=2),encoding='utf-8')
    for filename,rows,fields in [('recovery_224.csv',focus,['case_id','cve','product','build','original','conservative','parser','actual_status','outcome','new_version_state','observed_build_concrete','remaining_primary_reason']),('changes_v3_v4.csv',all_changes,['case_id','cve','scenario','actual_status','before','after'])]:
        with (HOME/filename).open('w',encoding='utf-8-sig',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader()
            writer.writerows({k:r.get(k) for k in fields} for r in rows)
    def table(rows):return '<table>'+''.join('<tr>'+''.join('<td>'+escape(str(v))+'</td>' for v in r)+'</tr>' for r in rows)+'</table>'
    rows=[['지표','최초 v2','보수적 수정 v3','파서 보완 v4']]
    for key in ('cases','tp','fp','fn','precision','recall','abstention_rate','four_state_reference_agreement','errors'):
        values=[reports[k]['overall'][key] for k in RUNS]
        if key in ('precision','recall','abstention_rate','four_state_reference_agreement'):values=[f'{v*100:.4f}%' if v is not None else '—' for v in values]
        rows.append([key,*values])
    html='''<!doctype html><html lang="ko"><meta charset="utf-8"><title>버전 파서 보완과 37,254건 3단계 비교</title>
<style>body{font:16px/1.6 system-ui;max-width:1100px;margin:32px auto;padding:0 18px;color:#182535}table{border-collapse:collapse;width:100%;margin:18px 0}td{border:1px solid #cbd5e1;padding:7px}tr:first-child{background:#edf2f7;font-weight:bold}aside{padding:14px;background:#fff5dd}</style>
<h1>버전 파서 보완과 37,254건 전수 비교</h1>
<aside>동일 입력·정답·원천·관측 시각을 유지한 합성 원천 상태 일관성 평가입니다. 224건은 파서 개발에 사용한 진단 집합이므로 복구율은 독립 정확도가 아닙니다. 전체 모집단과 집합 밖의 변화도 모두 보고합니다.</aside>'''
    html+=table(rows)+'<h2>기존 224건</h2>'+table([['결과','건수']]+list(outcomes.items()))
    html+='<h2>v3 → v4 전체 판정 전이</h2>'+table([['이전','이후','건수']]+[[a,b,n] for (a,b),n in sorted(transitions.items())])
    html+='<h2>224건 원문 조건 유형 (중복 포함)</h2>'+table([['유형','CVE 수']]+list(report['source_validation']['category_cves'].items()))
    html+='<h2>224건 중 남은 미확정의 주 사유 (상호 배타)</h2>'+table([['사유','CVE 수']]+list(report['source_validation']['remaining_primary_reasons'].items()))
    html+='<h2>전체 집합의 추가 보류 사유</h2>'+table([['사유','사례 수']]+list(deferred_reasons.items()))
    html+='<p>기존 224건 밖의 판정 변화: '+str(report['changes_outside_original_224'])+'건.</p>'
    html+='<p><a href="recovery_224.csv">224건 상세 CSV</a> · <a href="changes_v3_v4.csv">전체 판정 변화 CSV</a> · <a href="patterns.csv">원문 표기 분석 CSV</a> · <a href="three_way_comparison.json">전체 비교 JSON</a></p>'
    html+='<p><a href="cases.json">224건 원문 조건·근거 JSON</a> · <a href="additional_deferrals.json">추가 보류 상세 JSON</a></p>'
    html+='<p>구현 근거: <a href="https://www.packageurl.org/docs/vers/specification.html">공식 VERS 구간 명세</a>. 제조사별 정렬이 불명확한 접미사·잘못된 all 범위·제품/기능 한정은 미확정을 유지합니다.</p></html>'
    (HOME/'comparison.html').write_text(html,encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('original_224_outcomes','restored_status_counts','conservative_to_parser_changed_cases','changes_outside_original_224','changes_by_scenario')},ensure_ascii=False,indent=2))


if __name__=='__main__':main()
