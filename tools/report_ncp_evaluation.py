"""Write the measured H200 results and explain the synthetic Gold's scope."""
from collections import Counter
from pathlib import Path
import json
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
job=json.loads((ROOT/'results/cloud_migration/h200_full_evaluation_job.json').read_text(encoding='utf-8'))
OUT=ROOT/'results'/Path(job['run_root']).name
summary=json.loads((OUT/'summary.json').read_text(encoding='utf-8'))
counts=Counter(str(json.loads(x)['own_cve_truth']) for x in (ROOT/'benchmark/cve_population_precision_v1/labels.jsonl').open(encoding='utf-8'))
assert counts=={'True':8439,'False':1309,'None':2670}
third=summary['item3']['deduplicated_full_output_micro']
all_four=summary['item4']['all'];test_four=summary['item4']['evaluation']
times=summary['elapsed_seconds']
def duration(seconds):
    seconds=round(seconds);return f'{seconds//60}분 {seconds%60}초'
audit=dict(population=12418,item3=dict(own_CVE_positive=counts['True'],own_CVE_negative=counts['False'],
    own_CVE_unknown=counts['None'],unknown_with_CPE_no_supported_version_witness=1099,no_CPE_oracle=1571,
    negative_selected_source_atoms_vulnerable_false=1309,selection='Minimum condition ID per CVE; first matching control SBOM',
    representative_is_not_statistical_sampling=True,full_population_uses_clean_controls=True,
    full_platform_AND_OR_configuration_not_preserved=True,independent_human_gold=False),
    item4=dict(source_conditional_CVEs=2452,worlds_each=6,unknown_source_CVEs=9966,cases=24678,
        source_semantics_independently_verified=False,real_asset_precision=None))
(OUT/'gold_method_audit.json').write_text(json.dumps(audit,indent=2),encoding='utf-8')
text=f'''# H200 전체 CVE 재평가 결과

두 항목 모두 동일한 실제 CVE **12,418개**를 빠짐없이 처리했다. 기존 예측과 과거 패킷 캐시는 가져오지 않았다. 모델과 Gold를 재학습·수정하지 않았다.

| 항목 | 실행 범위 | 정밀도 | 소요시간 |
|---|---|---|---|
| #3 SBOM–CVE 매핑 | 12,418개 입력, 중복 제거 {summary['item3']['unique_SBOM_inputs']:,}개 SBOM 입력 | 보수적 하한 **{third['precision_lower_bound_percent']:.6f}%** | {duration(times['item3'])} |
| #4 조건부 합성 운영맥락 | 12,418개 CVE, 24,678개 사례 | 전체 원시 모델 **{all_four['raw_model']['precision']*100:.6f}%**, 모델+게이트 **{all_four['model_and_gate']['precision']*100:.2f}%** | {duration(times['item4'])} |

전체 소요시간은 **{duration(times['total'])}**다. 사용자 제공 과거 12~24시간과 단순 시간 비교하면 약 {12*3600/times['total']:.1f}~{24*3600/times['total']:.1f}배다. 과거 실행의 입력·코드·캐시·채점 범위가 동일한지 검증하지 않았으므로 GPU 하드웨어만의 배속으로 해석할 수 없다. 초기 18~20분 예상보다 #3 후반 CPU 처리와 재검증에 시간이 더 걸렸다.

## #3 지표의 단위

정밀도는 출력된 SBOM–CVE 매핑 쌍을 대상으로 한다. 하나의 SBOM이 여러 CVE에 매핑될 수 있으므로 TP 수가 12,418보다 클 수 있다. 동일 입력의 반복 가중치를 줄인 중복 제거 지표를 주 결과로 사용했다.

- TP {third['TP']:,}, FP {third['FP']:,}, 미확정 양성 {third['unjudged']:,}, FN {third['FN']:,}.
- 하한: TP / (TP + FP + 미확정 양성). 출력된 미확정 매핑 {third['unjudged']}개를 모두 FP로 계산했다.
- 재현율: {third['recall_on_known_positives_percent']:.6f}%.
- 실행 오류: {summary['item3']['execution_errors']}.
- 새 실행의 실제 모델 요청: {summary['population_integrity']['fresh_inference']['item3_actual_model_requests']:,}개. 모든 CVE가 개별적으로 LLM을 호출하는 구조는 아니다. 구조적으로 확정되는 분기와 이번 실행 안에서의 동일 패킷 재사용이 포함된다.

## #4 시험 분할

전체 집계에는 학습 계열 사례가 포함된다. 별도 시험 분할 **4,012개 CVE / 6,797개 사례**의 결과는 다음과 같다.

| 방식 | TP | FP | Precision | Recall | 보류율 |
|---|---:|---:|---:|---:|---:|
| 원시 모델 | {test_four['raw_model']['TP']} | {test_four['raw_model']['FP']} | {test_four['raw_model']['precision']*100:.6f}% | {test_four['raw_model']['recall']*100:.6f}% | {test_four['raw_model']['abstention_fraction']*100:.6f}% |
| 모델+게이트 | {test_four['model_and_gate']['TP']} | {test_four['model_and_gate']['FP']} | {test_four['model_and_gate']['precision']*100:.2f}% | {test_four['model_and_gate']['recall']*100:.6f}% | {test_four['model_and_gate']['abstention_fraction']*100:.6f}% |

높은 정밀도와 높은 보류율을 함께 해석해야 한다. 실제 모델 요청 {summary['population_integrity']['fresh_inference']['item4_actual_model_requests']:,}개를 새로 수행했다. 원문 조건이 부족한 9,966개 CVE도 삭제하지 않고 보류 사례로 처리했다.

## Gold 생성 방법과 한계

#3은 공개 CPE 조건 ID를 정렬해 CVE당 첫 조건을 선택하고, 그 조건의 정상 control SBOM을 사용했다. 이는 통계적 대표 표본도, 모든 오류 주입 유형을 포함한 전수 시험도 아니다. 별도 source-only oracle이 제조사·제품·버전·에디션 조건을 비교해 expected_cves와 unknown_cves를 만들었다. 생성기와 식별기는 별도 코드지만 원천 데이터를 공유한다.

| 대상 CVE와 선택 SBOM의 관계 | 개수 |
|---|---:|
| 매핑 양성 | 8,439 |
| 매핑 음성 | 1,309 |
| CPE는 있으나 범위 소속을 입증할 버전 근거 없음 | 1,099 |
| 정확한 CPE oracle 근거 없음 | 1,571 |
| 합계 | 12,418 |

판정 가능 9,748개는 양성과 음성의 합계이며, 미확정 2,670개는 나머지 두 범주의 합계다. 확인된 음성 1,309개 모두 선택 원문 CPE가 vulnerable:false인 경우였다. 이들은 환경·전제조건 CPE가 선택된 경우다. 따라서 모든 CVE에 대해 취약 제품의 양성 예제를 확보한 구성은 아니다. CPE 원자 단위 제품 매핑이 평가 범위이며 전체 NVD 플랫폼 AND/OR 구성이나 현장 영향 여부를 입증하지 않는다.

#4는 실제 CVE 원문의 조건 초안을 사용해 2,452개 CVE마다 조건 참·거짓, 핵심 관측 누락 두 종류, 충돌, 만료의 여섯 합성 상태를 만들었다. 별도 DNF Boolean 시뮬레이터로 잠재 영향 여부와 관측만으로 판단 가능한 A/U 정답을 계산했다. 2,452×6 + 9,966 = 24,678개 사례다. 선택 경로의 완전성, 제품 적용성, 관측 불가 조건 충족 등의 가정은 합성 세계에만 적용된다. 조건 해석에 대한 독립 전문가 검토와 실제 설비 검증은 완료되지 않았다.

입력과 라벨은 별도 JSONL 파일이다. 라벨은 모델 입력으로 보내지 않았다. #4에서는 전체 예측 저장 후 라벨을 읽어 채점했다. **실제 설비 Precision은 미측정**이며, 이번 통과 결과는 해당 합성 Gold 범위에 한정된다.

## 에이전트와 재현 기록

P2(이름), P3(버전), P4(식별자)는 Qwen2.5-Coder-14B-Instruct 4비트 기본 모델과 공유 QLoRA 어댑터를 사용하고 역할 프롬프트를 구분한다. 독립 가중치 모델 세 개를 학습한 구성은 아니다. #4 조건부 합성 판정에는 별도 source-context 어댑터를 사용했다.

summary.json, population_integrity.json, protocol.json, 각 항목의 run_config.json과 재검산 보고서를 함께 보관했다. 전체 원시 예측 SQLite와 로그는 다음 클라우드 경로에 있다.

`{job['run_root']}`

워크벤치: http://127.0.0.1:18100/precision.html

기존 기록은 보존했고, 워크벤치 지표와 CVE별 저장 예측 조회는 이번 H200 실행을 표시하도록 연결했다. 평가용 GPU 예약은 해제했고 일시 중지했던 웹 서버를 복구했다. 기존 사용자 Notebook 작업은 유지했다.
'''
(OUT/'README.md').write_text(text,encoding='utf-8')
print(str(OUT/'README.md'))
