"""Publish measured precision against the predeclared target without altering inputs or gold."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
import datetime,hashlib,json

ROOT=Path(__file__).resolve().parents[2]
DATA=ROOT/'benchmark/item3_evaluation'
OUT=ROOT/'results/item3_benchmark_validation_h200_20261119'


def read(p):return json.loads(p.read_text(encoding='utf-8-sig'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None
def write(p,value):p.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


def main():
    protocol=read(DATA/'precision_protocol.json');report=read(OUT/'report.json')
    audit=read(OUT/'independent_validation.json');runtime=read(OUT/'remote_runtime_integrity_final.json')
    files=read(OUT/'input_integrity_final_before_metadata_update.json')
    assert audit['passed'] and runtime['all_match']
    assert not [r for r in files['mismatches'] if r['path'].startswith('benchmark/item3_evaluation/')]
    agent=report['gold_evaluation']['agents'];baseline=report['gold_evaluation']['rules']
    m=agent['all_BOMs_latent_asset_mapping_metrics'];b=baseline['all_BOMs_latent_asset_mapping_metrics']
    independent=audit['independent_gold_mapping_counts']['agents'];assert all(m[k]==v for k,v in independent.items())
    denominator=sum(m[k] for k in ('TP','FP','unjudged','out_of_scope'))
    lower=m['TP']/denominator if denominator else None
    checks={'all_18608_cases_completed':agent['completed_BOMs']==agent['total_BOMs']==18608,
            'zero_evaluation_execution_errors':agent['execution_errors']==0,
            'nonzero_confirmed_outputs':denominator>0,
            'precision_at_least_085':lower is not None and lower>=protocol['target_precision'],
            'model_backed_evaluation_cases_present':audit['formal_evaluation_model_backed_cases']>0,
            'actual_gpu_requests_present':audit['all_benchmark_distinct_gpu_requests']>0,
            'h200_used':'H200' in report['execution_environment']['gpu'],
            'input_and_gold_hashes_preserved':True,'delivery_and_frozen_runtime_verified':True}
    assert all(checks.values()),checks
    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
    result={'protocol_id':protocol['protocol_id'],'measured_at':timestamp,'status':'pass','passed':True,
            'target_precision':protocol['target_precision'],'measured_precision':m['precision_percent']/100,
            'measured_precision_percent':m['precision_percent'],'precision_lower_bound':lower,
            'recall_on_known_positives':m['recall_on_known_positives_percent']/100,
            'recall_on_known_positives_percent':m['recall_on_known_positives_percent'],
            'counts':{k:m[k] for k in ('TP','FP','FN','unjudged','out_of_scope')},
            'confirmed_mapping_count':denominator,'completed_cases':agent['completed_BOMs'],
            'execution_errors':agent['execution_errors'],'acceptance_checks':checks,
            'method':'Hybrid identification pipeline using the existing tuned shared adapter and deterministic evidence gates; not raw LLM-only accuracy.',
            'adapter_sha256':report['execution_environment']['adapter_sha256'],
            'formal_evaluation_model_backed_cases':audit['formal_evaluation_model_backed_cases'],
            'formal_evaluation_deterministic_paths_only_cases':18608-audit['formal_evaluation_model_backed_cases'],
            'formal_evaluation_model_backed_decision_occurrences_by_role':audit['formal_evaluation_model_backed_decision_occurrences_by_role'],
            'all_benchmark_distinct_gpu_requests':audit['all_benchmark_distinct_gpu_requests'],
            'all_benchmark_distinct_gpu_requests_by_role':audit['all_benchmark_distinct_gpu_requests_by_role'],
            'model_counting_note':'GPU request counts cover the whole frozen benchmark; formal evaluation model-backed case/role counts include cached response usage.',
            'rules_baseline':{'uses_llm':False,'measured_precision':b['precision_percent']/100,
                              'precision_percent':b['precision_percent'],'recall_percent':b['recall_on_known_positives_percent'],
                              'counts':{k:b[k] for k in ('TP','FP','FN','unjudged','out_of_scope')}},
            'comparison_note':'Both meet the precision target. The agent pipeline has lower recall than the rules baseline; these results do not independently establish a tuning benefit.',
            'dataset':{'cases':18608,'controls':9304,'perturbed':9304,'sboms_changed':False,'gold_changed':False,'noise_changed':False,
                       'frozen_fingerprint_sha256':protocol['frozen_input_and_gold_fingerprint_sha256']},
            'scope':'Fixed source-derived synthetic gold; confirmed product/version/edition CVE mapping. Unknown candidates remain separate; actual installation impact is not assessed.',
            'report_file':'../../results/item3_benchmark_validation_h200_20261119/report.json',
            'independent_audit_file':'../../results/item3_benchmark_validation_h200_20261119/independent_validation.json'}
    targets=[DATA/'precision_result.json',DATA/'summary.json',DATA/'README.txt']
    before={str(p.relative_to(ROOT)):sha(p) for p in targets}
    write(DATA/'precision_result.json',result)
    summary=read(DATA/'summary.json')
    summary['precision_evaluation']={'protocol_file':'precision_protocol.json','result_file':'precision_result.json',
        'target_precision':0.85,'method':'tuned_adapter_hybrid_agent_pipeline','measured_precision':result['measured_precision'],
        'recall_on_known_positives':result['recall_on_known_positives'],'passed':True,'all_cases_evaluated':18608,
        'sbom_gold_noise_unchanged':True,'rules_baseline_uses_llm':False}
    write(DATA/'summary.json',summary)
    marker='============================================================\n정밀도 0.85 합격 기준 및 H200 전수 실측 결과'
    existing=(DATA/'README.txt').read_text(encoding='utf-8-sig').split(marker)[0].rstrip()
    section=f'''{marker}
확인일: 2026-11-20
============================================================

목표는 정밀도 0.85 이상(85% 이상)이며, 85%대에 맞추는 목표가 아닙니다.
precision_protocol.json은 전체 평가 모집단과 합격 기준을 정의합니다.
precision_result.json은 실제 에이전트 파이프라인과 규칙 기준선의 측정값입니다.
현재 18,608건 구성으로 목표를 충족하여 SBOM·정답·노이즈·사례 ID는 유지했습니다.
모든 9,304개 조건의 control 1건 + 변형본 1건을 평가했으며 사례를 골라내지 않았습니다.

측정 방법                       정밀도       재현율(알려진 양성 기준)
튜닝 어댑터 포함 파이프라인      {m['precision_percent']:.4f}%     {m['recall_on_known_positives_percent']:.4f}%
규칙 기준선(LLM/어댑터 미사용)   {b['precision_percent']:.4f}%     {b['recall_on_known_positives_percent']:.4f}%
에이전트 TP={m['TP']:,}, FP={m['FP']:,}, FN={m['FN']:,}; 실행 오류 0건.
정밀도 = {m['TP']:,} / ({m['TP']:,} + {m['FP']:,}) = {result['measured_precision']:.8f}
각 SBOM 안에서 CVE ID를 중복 제거한 뒤 전체 SBOM의 TP/FP를 합산합니다.
따라서 TP/FP는 전역 고유 CVE 수가 아니라 SBOM-CVE 연결 수입니다.
미확정 후보는 확정 매핑과 별도이며, 미확정 정답을 음성으로 바꾸지 않습니다.
확정 출력에 미판정/범위 밖 CVE가 있으면 보수적 정밀도 분모에 포함합니다.

이 결과는 독립 검증 규칙과 튜닝 모델이 결합된 파이프라인 성능입니다.
18,608건 중 모델 응답을 사용한 사례는 {audit['formal_evaluation_model_backed_cases']:,}건입니다.
직접 CPE 근거가 있거나 관측값만으로 결정되는 경로에서는 모델 추론을 생략합니다.
전체 benchmark 실행의 실제 고유 GPU 요청은 {audit['all_benchmark_distinct_gpu_requests']:,}회입니다.
모델 응답 사용 횟수에는 캐시 재사용이 포함되므로 GPU 요청 수와 구분합니다.
재현율은 규칙 기준선이 더 높았습니다. 어댑터만의 성능이나 튜닝 효과의 입증은 아닙니다.

근거: ../../results/item3_benchmark_validation_h200_20261119/report.json
독립 재집계·해시 검증: 같은 폴더의 independent_validation.json
전체 경로별 결과: 같은 폴더의 case_results.jsonl
재검증: python tools/item3/verify_item3_benchmark_delivery.py (프로젝트 루트에서 실행)
이번 실행은 sboms와 gold.jsonl의 동결 입력으로 평가했으며 추출 당시 prep DB는 필요하지 않습니다.
합성 평가셋의 결과이며 실제 설비의 영향 여부나 독립적인 현장 정확도를 입증하지 않습니다.
'''
    (DATA/'README.txt').write_text(existing+'\n\n'+section,encoding='utf-8-sig')
    receipt={'updated_at':timestamp,'before':before,'after':{str(p.relative_to(ROOT)):sha(p) for p in targets},
             'input_sboms_annotations_gold_untouched':True,'noise_and_case_population_untouched':True,
             'original_dataset_fingerprint_sha256':protocol['frozen_input_and_gold_fingerprint_sha256']}
    write(OUT/'dataset_metadata_update_receipt.json',receipt)
    write(OUT/'precision_target_result.json',result)
    print(json.dumps({'passed':True,'precision':result['measured_precision'],'recall':result['recall_on_known_positives'],
                      'model_backed_cases':audit['formal_evaluation_model_backed_cases'],'result':str(DATA/'precision_result.json')},ensure_ascii=False))


if __name__=='__main__':main()
