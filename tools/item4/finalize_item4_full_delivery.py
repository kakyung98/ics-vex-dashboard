"""Finalize factual evaluation documentation and the requested source ZIP.

This is also callable by the active job controller after verified result fetch.
It never changes reference labels, model weights, or predictions.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / 'benchmark/item4_evaluation'
OUT = ROOT / 'results/item4_full_actual_20261120'
START = '<!-- ITEM4_FULL_ACTUAL_RESULT_START -->'
END = '<!-- ITEM4_FULL_ACTUAL_RESULT_END -->'


def put_block(path, block):
    text = path.read_text(encoding='utf-8-sig')
    if START in text:
        before, rest = text.split(START, 1)
        _, after = rest.split(END, 1)
        text = before + after.lstrip('\r\n')
    path.write_text(START + '\n' + block + '\n' + END + '\n\n' + text,
                    encoding='utf-8')


def main():
    from tools.item4.verify_item4_full_actual import main as verify
    verify()
    report = json.loads((OUT / 'report.json').read_bytes())
    audit = json.loads((OUT / 'package_audit.json').read_bytes())
    independent = json.loads((OUT / 'independent_rescore.json').read_bytes())
    assert report['status'] == 'complete' and report['population_cves'] == 12418
    assert audit['passed'] and independent['passed']
    score = report['all_cases']
    assert score['cases'] == 62090
    precision = score['precision_percent']
    result = dict(report_file='results/item4_full_actual_20261120/report.json',
        status='complete', population_cves=12418,
        llm_requests=report['llm_requests'], **score,
        independent_rescore_passed=True,
        source_materialization_audit_passed=True,
        execution_error_cases=independent['counts']['execution_error_cases'],
        scope=report['metric_scope'], independent_real_asset_validation=False,
        runtime_bitwise_equivalence_asserted=False,
        test_predictions_used_to_select_checkpoint=False)
    summary = json.loads((DATA / 'summary.json').read_bytes())
    summary['evaluation'] = result
    summary['full_population_precision_percent'] = precision
    summary['full_population_target_met'] = score['target_met']
    summary['current_checkpoint_synthetic_precision_percent'] = precision
    # Leave real-deployment accuracy explicitly unmeasured.
    summary['deployed_model_precision_percent'] = None
    summary['validation']['full_population_materialization'] = audit
    (DATA / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    show = lambda value: '미확정' if value is None else f'{value:.4f}%'
    verdict = '미확정' if score['target_met'] is None else ('통과' if score['target_met'] else '미통과')
    text = (
        '전체 12,418개 CVE 실제 #4 평가 완료\n'
        f"대상: 62,090개 합성 운영 사례, 실제 LLM 생성 {report['llm_requests']:,}회.\n"
        f"TP={score['TP']:,}, FP={score['FP']:,}, 정답 미확정 Affected={score['unjudged_predicted_affected']:,}.\n"
        f"전체 정밀도={show(precision)}, 85% 초과={verdict}.\n"
        f"정답 확인 가능 Affected의 정밀도={show(score['precision_on_judged_predictions_percent'])}.\n"
        f"미확정 Affected를 모두 오탐으로 계산한 하한={show(score['conservative_precision_lower_bound_percent'])}.\n"
        f"재현율(보류 포함)={show(score['recall_percent'])}, 보류율={show(score['abstention_percent'])}.\n"
        f"정답 확인 가능={score['known_labels']:,}, 정답 미확정={score['unknown_labels']:,}.\n"
        f"실행 오류 사례={independent['counts']['execution_error_cases']:,}; 오류·보류·미확정도 모집단에 포함.\n"
        'Qwen2.5-Coder-14B NF4, 기존 FP32 VEP LoRA, 현재 자산 입력 및 실제 MulVAL/XSB를 사용했습니다.\n'
        'XGrammar 형식 제약 및 H200 SDPA 커널 설정은 runtime_metadata.json에 기록했습니다. 비트 단위 동등성을 주장하지 않습니다.\n'
        '출처 조건부 세계 4,899개 CVE와 미확정 세계를 함께 평가했습니다. 전문가 정답·실제 자산·미학습 홀드아웃 정확도 검증은 아닙니다.\n'
        '고정 정답/모델 가중치 변경 없이 모든 ID를 독립 재집계했습니다.\n'
        '결과: results/item4_full_actual_20261120/report.json 및 independent_rescore.json.\n'
        '아래 미측정·평가 전 문구와 7개 CVE 기준선은 과거 상태입니다. 이 절이 최신 전수 결과입니다.'
    )
    put_block(DATA / 'README.txt', text)
    put_block(ROOT / 'README.md', text)
    preferences=OUT/'delivery_preferences.json'
    requested=json.loads(preferences.read_bytes()).get('source_zip_requested',True) if preferences.exists() else True
    if not requested:
        (OUT/'final_delivery.json').write_text(json.dumps(dict(
            status='complete',evaluation=result,source_zip=None,source_zip_canceled_by_user=True,
            frozen_labels_and_weights_unchanged=True),ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(dict(stage='evaluation_complete',source_zip_canceled_by_user=True)),flush=True)
        return
    from tools.common.package_submission_source import main as package
    package()
    receipt = json.loads((ROOT / 'research_records/submission_source_zip_20261120.json').read_bytes())
    (OUT / 'final_delivery.json').write_text(json.dumps(dict(
        status='complete', evaluation=result, source_zip=receipt,
        frozen_labels_and_weights_unchanged=True), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(stage='evaluation_and_source_submission_complete', source_zip=receipt), ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
