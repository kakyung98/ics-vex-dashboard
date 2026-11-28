"""Publish factual completion evidence after actual training and full inference."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
import ast
import hashlib
import json
import zipfile

ROOT=Path(__file__).resolve().parents[2]
RESULT=ROOT/'results/item4_v2_unsupervised_20261120'
DATA=ROOT/'benchmark/item4_evaluation/csaf_vex_v2'


def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def archive(destination,paths):
    manifest={name:dict(bytes=p.stat().st_size,sha256=sha(p)) for name,p in paths.items()}
    if destination.exists():
        with zipfile.ZipFile(destination) as z:
            assert z.testzip() is None
            assert json.loads(z.read('MANIFEST.json'))['files']==manifest
            for name,meta in manifest.items():assert hashlib.sha256(z.read(name)).hexdigest()==meta['sha256']
        return dict(path=str(destination),files=len(paths)+1,bytes=destination.stat().st_size,sha256=sha(destination))
    with zipfile.ZipFile(destination,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for name,p in sorted(paths.items()):z.write(p,name)
        z.writestr('MANIFEST.json',json.dumps(dict(files=manifest),indent=2)+'\n')
    with zipfile.ZipFile(destination) as z:
        assert z.testzip() is None
        for name,meta in manifest.items():assert hashlib.sha256(z.read(name)).hexdigest()==meta['sha256']
    return dict(path=str(destination),files=len(paths)+1,bytes=destination.stat().st_size,sha256=sha(destination))


def main():
    verification=json.loads((RESULT/'verification.json').read_bytes())
    report=json.loads((RESULT/'report.json').read_bytes())
    training=json.loads((RESULT/'training_complete.json').read_bytes())
    assert verification['status']=='complete' and verification['independent_rescore_passed']
    assert verification['population_cves']==12418 and verification['cases']==86926
    assert training['examples']==2717 and training['optimizer_updates']==123
    metric=report['all_cases'];precision=metric['precision_percent']
    precision_text=f'{precision:.4f}%' if precision is not None else '보류 (미확정 정답에 대한 양성 출력 또는 빈 양성 분모)'
    positive=metric['TP']+metric['FP']
    judged=100*metric['TP']/positive if positive else None
    execution=dict(**verification,report='results/item4_v2_unsupervised_20261120/report.json',
        model_adapter_sha256=training['adapter_sha256'],
        reference='conditional_synthetic_candidate_NOT_expert_gold',
        primary_metric_unchanged=True,production_agent_mulval_evaluation=False,
        judged_only_precision_percent=judged,
        judged_only_precision_is_not_primary_pass_result=True)
    write(RESULT/'execution_summary.json',execution)
    write(DATA/'actual_run_status.json',execution)
    summary_path=ROOT/'benchmark/item4_evaluation/summary.json'
    summary=json.loads(summary_path.read_bytes())
    summary.setdefault('active_benchmark',{})['actual_v2_run']=execution
    write(summary_path,summary)
    lines=[
        '# 시험 항목 4 무라벨 학습과 v2 전수 모델 평가 결과',
        '',
        '2026년 11월 20일 실제 H200 실행. 전문가 판정은 연기하고 고정된 합성 후보 정답으로 평가했다.',
        '',
        f'학습은 ICSA 70%인 2,717건의 전체 2,000,843토큰을 1회 순회했다. 정답·assistant completion·평가 자료로 학습하지 않았다. '
        f'Qwen2.5-Coder-14B의 고정 NF4 값을 BF16으로 펼친 동결 기저에 새 rank 8 q_proj/v_proj LoRA를 학습해 '
        f'{training["optimizer_updates"]}회 최적화했다. 최종 고정 체크포인트를 사용하며 후보 점수로 모델을 선택하지 않았다.',
        '',
        '원문이 비어 있는 icsa-14-269-01 한 건은 확인된 ID·URL만 모델링한 metadata-only 기록이다. '
        '긴 문서는 EOS 경계를 보존하고 겹치는 토큰 블록으로 나누어 내용을 자르지 않았다. 원문을 새로 지어내지 않았다.',
        '',
        '학습 가중치를 다시 로드해 12,418개 CVE 전체, 86,926개 사례 모두에서 실제 모델 판정을 생성했다. '
        '이 실행은 v2 증명 자료를 읽는 7종 선택형 모델 평가이다. 기존 생산 Agent 1~4·MulVAL 전체 파이프라인 평가와는 별도이다. '
        '공통 문맥의 KV를 재사용하되 사례별 서로 다른 suffix는 모두 모델에 입력했다. 실행 코드·가중치·입력·예측 해시를 기록했다.',
        '',
        f'주지표는 기존 affected 정밀도 TP/(TP+FP), 통과 기준은 85% 초과이다. TP={metric["TP"]}, FP={metric["FP"]}, '
        f'미확정 정답에 대한 affected={metric["unjudged_predicted_affected"]}, 정밀도={precision_text}, 통과={metric["target_met"]}. '
        'unknown 양성을 음성으로 바꾸거나 분모에서 숨기지 않았다. judged-only 수치는 진단용이며 주지표의 통과를 대체하지 않는다.',
        '',
        f'확정 후보만의 진단 정밀도는 {judged:.6f}%이다. 미확정 양성 7,519건은 모두 '
        'CVE별 출처 경로를 연결하지 못한 affected_control 사례이다. 이는 전체 모집단 통과를 뜻하지 않는다. '
        '확정 후보와 불일치한 1건은 CVE-2024-36270의 내장 완화조치 사례이며 상세 원본은 diagnostics.json에 있다.',
        '',
        '전체 모집단에는 학습 ICSA 관련 CVE도 포함한다. 30% 평가 ICSA는 CVE 단위 미노출 홀드아웃이 아니며 '
        '중복 CVE 889개를 보존한다. 별도 cohort_metrics.json에서 두 집단을 구분한다. 전문가 κ나 실제 현장 정확도를 측정한 결과는 아니다.',
        '',
        f'학습 어댑터 SHA-256: {training["adapter_sha256"]}',
        '',
        '결과: results/item4_v2_unsupervised_20261120/report.json 및 verification.json. '
        '전체 예측·가중치·실행 원본은 verification.json의 artifact_directory에 있다. 로컬 재채점과 납품 파일 해시 검증을 통과했다.',
    ]
    (ROOT/'docs/ITEM4_V2_ACTUAL_RUN.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    for name in ['ITEM4_CSAF_EXPERT_DESIGN.md','ITEM4_CSAF_EXPERT_MANUAL.md']:
        path=ROOT/'docs'/name;content=path.read_text(encoding='utf-8')
        notice=('> 실제 실행 추가: 70% 무라벨 학습 및 12,418개 CVE 전체 v2 모델 평가가 완료되었습니다. '
            '데이터 manifest의 training_executed=false는 생성 당시 스냅샷이며, 현재 실행은 '
            '[실제 결과](ITEM4_V2_ACTUAL_RUN.md)와 actual_run_status.json을 확인합니다. 전문가 판정은 미실시입니다.\n\n')
        if notice not in content:
            title,rest=content.split('\n',1);path.write_text(title+'\n\n'+notice+rest.lstrip(),encoding='utf-8')
    readme=ROOT/'README.md';text=readme.read_text(encoding='utf-8-sig')
    start='<!-- ITEM4_V2_ACTUAL_RUN_START -->';end='<!-- ITEM4_V2_ACTUAL_RUN_END -->'
    if start in text:
        before,rest=text.split(start,1);_,after=rest.split(end,1);text=before+after.lstrip()
    block=(f'{start}\n## #4 v2 실제 학습·전수 모델 평가 완료\n\n'
        f'무라벨 ICSA **2,717건·2,000,843토큰**, **123회 업데이트**를 완료하고 새 가중치로 '
        f'**12,418개 CVE·86,926개 사례 전체**를 실제 추론했습니다. 합성 후보 정답 기준 TP={metric["TP"]}, '
        f'FP={metric["FP"]}, unknown 양성={metric["unjudged_predicted_affected"]}, 주 정밀도 **{precision_text}**. '
        f'기존 `TP/(TP+FP)>0.85`와 unknown 양성 보류 규칙을 유지했습니다. '
        '전문가 판정은 미실시이며 생산 Agent·MulVAL 평가와 별도의 선택형 모델 평가입니다. '
        '[실행 결과](docs/ITEM4_V2_ACTUAL_RUN.md) · '
        '[검증 원장](results/item4_v2_unsupervised_20261120/verification.json).\n'+end+'\n\n')
    readme.write_text(block+text,encoding='utf-8')
    actual=Path(verification['artifact_directory']);receipts=[]
    paths={'adapter/'+p.relative_to(actual/'adapter').as_posix():p for p in (actual/'adapter').glob('*') if p.is_file()}
    paths['train_config.json']=RESULT/'train_config.json'
    for name in ['base_pin.json','run_manifest.json','evaluation_protocol.json']:
        paths[name]=actual/name
    receipts.append(archive(ROOT/'benchmark/item4_v2_trained_adapter.zip',paths))
    paths={p.relative_to(actual/'evaluation').as_posix():p for p in (actual/'evaluation').glob('*') if p.is_file()}
    for name in ['verification.json','training_complete.json','cohort_metrics.json','execution_summary.json',
                 'diagnostics.json','unjudged_affected.jsonl']:
        paths[name]=RESULT/name
    receipts.append(archive(ROOT/'benchmark/item4_v2_model_evaluation.zip',paths))
    # Preserve the earlier source delivery and publish a separately versioned,
    # trained-run source archive; model weights remain in their own ZIP.
    old=ROOT/'benchmark/전남대_Source code_csaf_v2.zip'
    if not old.exists():old=ROOT/'benchmark/전남대_Source code.zip'
    new=ROOT/'benchmark/전남대_Source code_csaf_v2_trained.zip'
    if new.exists():raise FileExistsError(new)
    updates={name:ROOT/name for name in ['README.md','tools/item4/run_item4_v2_unsupervised.py',
        'tools/item4/evaluate_item4_v2_prefix.py','tools/item4/deploy_item4_v2_unsupervised.py',
        'tools/item4/monitor_item4_v2_unsupervised.py','tools/item4/finalize_item4_v2_unsupervised.py',
        'tests/item4/test_item4_v2_unsupervised.py','docs/ITEM4_V2_ACTUAL_RUN.md',
        'docs/ITEM4_CSAF_EXPERT_DESIGN.md','docs/ITEM4_CSAF_EXPERT_MANUAL.md']}
    delivery_readme=RESULT/'DELIVERY_README.txt'
    delivery_readme.write_text('''#4 v2 실제 학습 및 전수 모델 평가 소스
ICSA 2,717건·2,000,843토큰 무라벨 학습 1회, 123 optimizer steps 완료.
새 가중치로 12,418 CVE·86,926개 사례 모두 실제 추론 및 후보 정답 채점 완료.
이것은 7종 선택형 모델 평가이며 생산 Agent 1~4·MulVAL 전체 실행과는 별도입니다.
기존 affected 정밀도 TP/(TP+FP), 85% 초과, unknown 양성 보류 정책을 유지합니다.
전문가 검증 및 κ 산출은 미실시입니다. 합성 후보 결과를 전문가 정확도로 인용하지 않습니다.
상세 결과는 docs/ITEM4_V2_ACTUAL_RUN.md 및 validation/item4_v2/report.json입니다.
학습 당시 원본 코드는 validation/item4_v2/training_worker_snapshot.py에 보존합니다.
공통 prefix 계산을 재사용한 평가 코드와 고정 프로토콜은 별도로 기록했습니다.
모델 가중치는 별도 item4_v2_trained_adapter.zip의 adapter/에 있습니다.
기저 모델은 training_complete.json의 SHA-256과 일치하는 Qwen2.5-Coder-14B NF4 스냅샷입니다.
실제 평가 로더는 동결 NF4 값을 BF16으로 펼칩니다. 다른 모델·양자화로의 대체는 동일 재현이 아닙니다.
현재 서비스 가중치는 자동 교체하지 않았습니다. 별도 모델 경로에서 검토하십시오.
벤치마크 데이터는 별도 item4_csaf_v2_dataset.zip입니다. run_manifest의 입력 해시를 대조하십시오.
검사: python -m pytest tests/item4/test_item4_v2_unsupervised.py tests/item4/test_item4_benchmark_v2.py -q
모델/평가 코드: tools/item4/run_item4_v2_unsupervised.py 및 tools/item4/evaluate_item4_v2_prefix.py
자세한 환경과 외부 의존성은 requirements 파일과 기존 설계·매뉴얼을 참조합니다.
''',encoding='utf-8')
    updates['제출용_README.txt']=delivery_readme
    updates['README.md']=delivery_readme
    for name in ['report.json','verification.json','train_config.json','training_complete.json',
                 'evaluation_protocol.json','run_manifest.json','cohort_metrics.json','training_worker_snapshot.py']:
        p=RESULT/name
        if p.exists():updates['validation/item4_v2/'+name]=p
    contents={}
    with zipfile.ZipFile(old) as source,zipfile.ZipFile(new,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as target:
        for name in source.namelist():
            if name=='DELIVERY_MANIFEST.json' or name in updates:continue
            raw=source.read(name);target.writestr(name,raw);contents[name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        for name,p in updates.items():
            raw=p.read_bytes()
            if name.endswith('.py'):ast.parse(raw.decode('utf-8-sig'),filename=name)
            target.writestr(name,raw);contents[name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        target.writestr('DELIVERY_MANIFEST.json',json.dumps(dict(files=contents,expert_review_complete=False,
            gpu_training_executed=True,v2_model_evaluation_complete=True,model_weights_included=False),indent=2)+'\n')
    with zipfile.ZipFile(new) as z:
        assert z.testzip() is None
        for name,meta in contents.items():assert hashlib.sha256(z.read(name)).hexdigest()==meta['sha256']
    receipts.append(dict(path=str(new),files=len(contents)+1,bytes=new.stat().st_size,sha256=sha(new)))
    write(RESULT/'delivery_receipts.json',receipts)
    print(json.dumps(dict(status='published',all_cases=metric,receipts=receipts),ensure_ascii=False,indent=2))


if __name__=='__main__':main()
