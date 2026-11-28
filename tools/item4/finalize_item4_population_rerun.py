"""Verify a full MoE rerun and publish comparison against the prior inventory-reviewed population."""
import argparse
from collections import Counter, defaultdict
from contextlib import closing
from html import escape
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from src.item4.evaluation import scenario_evaluation_runner as runs
from tools.item4.render_item4_scenario_run_ko import CSS, WHY, table

PREVIOUS = 'moe-inventory-review-82057dc2e68409c22f'
FILES = ('population-report.ko.html','population-report.json','changes.jsonl')
STATES = {'affected':'영향 있음','not_affected':'미영향','fixed':'수정됨','under_investigation':'조사 보류'}


from src.common.paths import source_path

def require(test, message):
    if not test:
        raise ValueError(message)


def encode(value):
    return (json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode()


def render(info):
    out = ['<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">',
           '<title>#4 합성 BOM 전수 MoE 재실행</title><style>'+CSS+'</style></head><body><main>',
           '<h1>#4 합성 BOM 전수 MoE 재실행</h1>',
           '<p>모델　'+escape(info.get('inference_model','원장 모델 지문 참조'))+'</p>',
           f'<p>ICSA 기반 합성 BOM의 CVE {info["unique_cves"]:,}개와 가상 운영 시나리오 {info["total"]:,}건을 대조했습니다. '
           '재고 역할과 교차검토 역할에 명시적 재고 완전성 정책을 반영한 입력으로 MoE를 실행했습니다.</p>',
           '<p>사람 검토 0건. 상태는 합성 시나리오의 근거에 대한 후보 판정입니다.</p>',
           '<h2>상태별 건수</h2>'+table(['상태','기존 전수본','재실행'],[
               (v,info['previous_statuses'].get(k,0),info['candidate_statuses'].get(k,0)) for k,v in STATES.items()]),
           '<h2>보류 사유</h2><p>한 시나리오에 여러 사유가 있으면 각 사유에 포함됩니다.</p>'+
           table(['사유','시나리오 수'],[(escape('재고 완전성 근거 부족' if k=='inventory_completeness_not_evidenced'
                 else WHY.get(k,k)),v) for k,v in sorted(info['hold_reasons'].items(),key=lambda p:(-p[1],p[0]))]),
           '<h2>기존 결과와의 차이</h2>'+
           table(['변경 항목','시나리오 수'],[(label,info[key]) for key,label in [
               ('status_changed','상태 변경'),('reasons_changed','사유 변경'),('status_or_reasons_changed','상태 또는 사유 변경')]]),
           table(['기존 상태','재실행 상태','시나리오 수'],[
               (STATES[a],STATES[b],n) for a,dest in info['transitions'].items() for b,n in dest.items()]),
           '<h2>전수 검증</h2><p>시나리오 ID의 누락·추가·중복 0건, CVE와 동결 입력 패킷 불일치 0건을 확인했습니다. '
           '생성 미완료 0건입니다. 사용한 코드·모델·입력 지문은 실행 원장에 기록했습니다.</p>',
           '<p><a href="changes.jsonl">시나리오별 변경 내역</a> · <a href="population-report.json">집계 JSON</a> · '
           f'<a href="/api/item4/evaluation-runs/{escape(info["run_id"])}/candidates">전수 후보 다운로드</a></p>',
           f'<p>실행 <code>{escape(info["run_id"])}</code><br>비교 실행 <code>{PREVIOUS}</code></p></main></body></html>']
    return '\n'.join(out).encode()


def finalize(run_id):
    row = runs.ledger.get_run(run_id)
    require(row['status']=='completed' and row['total']==row['completed']==row['candidate_count']==97553,
            'The full rerun must finish successfully before publication.')
    require(row['generation_method'] in {'scenario_moe_local_llm','scenario_moe_h200_llm'},'Expected actual MoE inference.')
    folder = runs.OUTPUT/run_id
    old = runs.ledger.get_run(PREVIOUS)
    old_file = runs.OUTPUT/PREVIOUS/'candidates.jsonl'
    require(runs.file_sha(old_file)==old['result']['candidates_sha256'],'The prior population fingerprint differs.')
    require(runs.file_sha(folder/'candidates.jsonl')==row['result']['candidates_sha256'],'The new export fingerprint differs.')
    from src.common.paths import sealed_source_receipt
    for key, fingerprint in row['code_hashes'].items():
        if key.endswith('.py'):
            sealed_source_receipt(key, fingerprint)
    if row.get('population_comparison'):
        for name in FILES:
            require(runs.file_sha(folder/name)==row['data_hashes'].get(name),
                    'A published population comparison has changed.')
        published=json.loads((folder/'population-report.json').read_bytes())
        require(published['run_id']==run_id and published['candidates_sha256']==row['result']['candidates_sha256'],
                'The published comparison refers to another candidate population.')
        return published
    previous = {}
    with old_file.open('rb') as stream:
        for line in stream:
            item=json.loads(line)
            require(item['id'] not in previous,'Duplicate old scenario.')
            previous[item['id']]={k:item.get(k) for k in ('cve','packet_sha256','candidate_status','reasons')}
    counts=runs.ledger.ProgressCounts()
    statuses,transitions=Counter(),defaultdict(Counter)
    cves=set()
    changed_status=changed_reasons=changed=0
    with tempfile.TemporaryDirectory(dir=folder,prefix='.comparison-') as temp:
        stage=Path(temp)
        with (stage/'changes.jsonl').open('wb') as out,(folder/'candidates.jsonl').open('rb') as stream:
            for line in stream:
                current=json.loads(line)
                require(current['id'] in previous,'Unknown or duplicate new scenario.')
                before=previous.pop(current['id'])
                require(current['run_id']==run_id and current['cve']==before['cve']
                        and current['packet_sha256']==before['packet_sha256']
                        and current['synthetic'] is True and current['generation_status']=='completed',
                        'CVE, input scope or successful generation differs.')
                counts.add(current);cves.add(current['cve']);statuses[before['candidate_status']]+=1
                transitions[before['candidate_status']][current['candidate_status']]+=1
                ds=before['candidate_status']!=current['candidate_status']
                dr=set(before['reasons'] or [])!=set(current.get('reasons') or [])
                changed_status+=ds;changed_reasons+=dr;changed+=ds or dr
                if ds or dr:
                    out.write(encode(dict(id=current['id'],cve=current['cve'],previous_status=before['candidate_status'],
                        status=current['candidate_status'],previous_reasons=before['reasons'],reasons=current.get('reasons'),
                        status_changed=ds,reasons_changed=dr)).replace(b'\n',b' ')+b'\n')
        require(not previous and len(cves)==12418,'The comparison does not cover all frozen cases.')
        distribution=counts.snapshot()
        require(all(distribution[k]==row['result'][k] for k in distribution),'Independent totals differ from ledger.')
        info=dict(run_id=run_id,previous_run_id=PREVIOUS,total=97553,unique_cves=len(cves),
                  previous_statuses=dict(statuses),transitions=dict(transitions),status_changed=changed_status,
                  reasons_changed=changed_reasons,status_or_reasons_changed=changed,**distribution,
                  independent_human_review_count=0,candidates_sha256=row['result']['candidates_sha256'],
                  previous_candidates_sha256=old['result']['candidates_sha256'],
                  finalizer_sha256=runs.file_sha(Path(__file__)))
        history=folder/'execution_history.json'
        if history.is_file():
            info['execution_history']=json.loads(history.read_bytes())
            info['execution_history_sha256']=runs.file_sha(history)
        run_report=folder/'report.json'
        if run_report.is_file():
            backend=json.loads(run_report.read_bytes()).get('backend_identity') or {}
            info['inference_model']=backend.get('model','원장 모델 지문 참조')
            info['model_revision']=backend.get('revision')
            info['backend']=backend.get('backend')
        (stage/'population-report.json').write_bytes(encode(info))
        (stage/'population-report.ko.html').write_bytes(render(info))
        hashes={name:runs.file_sha(stage/name) for name in FILES}
        if history.is_file():
            hashes['execution_history.json']=info['execution_history_sha256']
        # Install complete files before adding links to the existing completed run.
        for name in FILES:
            target=folder/name
            if target.exists():
                require(target.read_bytes()==(stage/name).read_bytes(),'An earlier comparison has different bytes.')
            else:
                (stage/name).replace(target)
        with closing(runs.ledger._connect()) as db,db:
            db.execute('BEGIN IMMEDIATE')
            saved=json.loads(db.execute('SELECT snapshot FROM runs WHERE run_id=?',(run_id,)).fetchone()[0])
            require(saved['status']=='completed' and saved['result']==row['result'],'The completed run changed.')
            summary={k:info[k] for k in ('previous_run_id','status_changed','reasons_changed','status_or_reasons_changed')}
            require('population_comparison' not in saved or saved['population_comparison']==summary,'An existing comparison differs.')
            saved['population_comparison']=summary
            for name,fp in hashes.items():
                require(name not in saved['data_hashes'] or saved['data_hashes'][name]==fp,'A recorded hash differs.')
                saved['data_hashes'][name]=fp
            db.execute('UPDATE runs SET snapshot=? WHERE run_id=?',(json.dumps(saved,ensure_ascii=False),run_id))
        pointer=dict(run_id=run_id,generation_method=row['generation_method'],
                     candidates=run_id+'/candidates.jsonl',candidates_sha256=info['candidates_sha256'],
                     report=run_id+'/population-report.ko.html',report_sha256=hashes['population-report.ko.html'],
                     comparison_baseline=PREVIOUS)
        pending=runs.OUTPUT/'current_full_population.json.tmp'
        pending.write_bytes(encode(pointer))
        pending.replace(runs.OUTPUT/'current_full_population.json')
    return info


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_id')
    print(json.dumps(finalize(parser.parse_args().run_id),ensure_ascii=False,indent=2))
