# #3 SBOM 파일 기반 train/test 절차

식별 역할과 변형 축은 I1·I2·I3으로 통일합니다. v5의 변형 사례 9,324건은 파일명·ID·annotation의 역할 표기만 변경했고, SBOM 내용·CVE 정답·분할은 유지했습니다. `data/item3_test_dataset.json`과 분할별 manifest의 해시도 함께 갱신했습니다. 이전 사례 ID로 저장된 예측은 동일한 입력 해시를 확인한 뒤 현재 이름으로 채점합니다.

현재 기준 원본은 `C:/ICS-VEX/benchmark/icsa-cpe-synthetic sbom/sbom`의 **CPE 보강 v3 문서 3,881개**입니다. 기존 v2 전체는 `benchmark/icsa-cpe-synthetic sbom-v2-backup-20261125`에 보존했습니다.

CSAF/HTML 구성요소 29,066개와 기존 CVE 관계를 유지하고, 고정 CVE DB의 `vulnerable:true` CPE 조건과 버전 경계 4개 조합을 권고문별로 중복 제거하여 NVD 구성요소 78,200개를 추가했습니다. 서로 다른 CSAF 제품에 추정으로 CPE를 붙이지 않고 출처가 구분된 별도 후보로 저장합니다. 총 107,266개 구성요소 중 CPE 필드 보유는 78,247개입니다. 전체 선언 CVE 12,418개 중 CPE DB 대상 10,847개를 모두 포함합니다. 조건의 범위 표현은 실제 설치 버전이 아니며 NVD 플랫폼 AND/OR 전체 충족도 주장하지 않습니다.

| 구분 | train | test | 전체 |
|---|---:|---:|---:|
| 기준본 SBOM | 2,340 | 1,541 | 3,881 |
| 노이즈 적용 가능한 원본 | 1,799 | 1,309 | 3,108 |
| I1 컴포넌트 변형 | 1,799 | 1,309 | 3,108 |
| I2 버전 표기 변형 | 1,799 | 1,309 | 3,108 |
| I3 식별자(CPE) 변형 | 1,799 | 1,309 | 3,108 |
| 총 입력 파일 | 7,737 | 5,468 | 13,205 |
| 대상 고유 CVE | 7,593 | 3,254 | 10,847 |
| 기준본만 있는 원본 | 541 | 232 | 773 |

현재 파생 입력은 `benchmark/item3_advisory_inputs_v5`입니다. 원본당 기준본 하나를 만들고, 세 필드를 모두 갖춘 NVD 구성요소가 있는 원본마다 같은 구성요소에 I1/I2/I3 변형을 각각 하나씩 만듭니다. 각 변형은 필드 하나만 실제로 바꾸며 정답은 기준본과 같습니다. 기존 마스킹과 표기 변형을 유지하여 유형별 전체 1,554건씩 배정합니다. train은 유형별 마스킹 900 / 표기 899, test는 654 / 655입니다. 노이즈 유형 비율은 각 분할에서도 정확히 **1:1:1**이며 no-op은 0건입니다. 적용 대상이 없는 773개와 빈 문서 7개도 기준본으로 유지합니다. 대상 CVE가 없는 문서를 음성으로 바꾸지 않습니다.

분할은 seed를 고정하고 같은 대상 CVE 또는 동일 기준본·가능한 변형 입력으로 연결된 문서를 통째로 배정합니다. 점수나 모델 예측은 사용하지 않습니다. CVE 약 7:3(7,593/3,254)을 달성했으며 CVE·동일 입력의 분할 중복은 0입니다. 제품 전체 미노출 또는 기존 학습 어댑터의 새 test 미노출은 보장하지 않습니다. 이번 작업에서 재학습이나 새 전수 성능 측정은 수행하지 않았습니다.

골드는 기존 CSAF 명시적 affected/known-not-affected 관계와 별도 NVD 조건–CVE 연결을 유지합니다. rejected CVE와 출처 충돌은 unknown으로 보존합니다. 단순히 같은 권고문에 나온다는 이유로 다른 구성요소에 CVE를 붙이지 않습니다. 이전 18,608건과 과거 H200 점수는 보존하며 새 입력의 성능으로 재사용하지 않습니다.

## 입력과 채점의 분리

2026-11-26부터 일반 서비스의 기본 에이전트 제공자도 `require_identity_review=True`를 사용합니다. 독립 근거가 검증된 제품도 I3의 실제 모델 선택을 받아야 CVE 매핑을 확정합니다. 현재 설정의 `precision_shared_14b_v1`은 튜닝한 Qwen2.5-Coder-14B 공유 어댑터를 로드합니다. 배치·CPU 분산 경로도 기본 모델 검토를 사용하고, 실행되는 I2를 정형 분류만으로 우회하지 않습니다. 제품 근거 자체가 없는 입력은 보류하며, 모델 오류를 규칙의 확정 결과로 대체하지 않습니다. `rules`는 명시적인 별도 기준선입니다. 동일 패킷의 실행 중 캐시 재사용은 실제 GPU 계산과 구분해 기록합니다. 변경 전 성능·시간 기록은 그대로 보존합니다.

`tools/item3/run_item3_test.py predict`는 SBOM 디렉터리만 탐색하며 골드·annotation을 열지 않습니다. 원본의 vulnerabilities·description·source-label·참조 URL과 식별 가능한 권고문 메타데이터를 분리한 각 JSON 파일을 읽어 웹 서비스와 같은 `src.item3.matching.sbom_candidate_service.match_candidates`에 전달합니다. 서비스의 정규화, 조건부 I1/I2/I3, 독립 근거 검증, 로컬 CVE 조회, CISA 후보 보강을 함께 사용합니다. 버전 필드의 정답 CVE 토큰 22곳도 가리고 숫자·범위 표현은 유지합니다. 100개 초과 구성요소는 문서를 버리지 않고 같은 서비스 함수를 100개 단위로 호출하며 원래 bom-ref로 결과를 합칩니다. 빈 문서는 빈 입력으로 기록합니다. `rules`는 규칙 기준선이며 `agents`는 현재 설정된 모델 제공자를 사용합니다.

`predictions.jsonl`에는 ID, 입력 파일명·SHA-256, 확정·미확정 CVE, 모델 응답 사용 여부, 실행 오류와 서비스 결과가 기록됩니다. 출력 디렉터리는 새로 만들어야 하며 기존 실행을 덮어쓰지 않습니다. 모델 응답 사용 건수에는 캐시 재사용이 포함될 수 있으므로 GPU 요청 수와 동일하지 않습니다.

`score`에서만 골드를 읽고 ID로 예측과 연결합니다. 전체 SBOM을 annotation의 해시와 대조하고 annotation과 gold의 동일성, 원본 문서당 기준본 1개와 변형본 0개 또는 3개, 같은 그룹의 동일 정답을 확인합니다. 외부 ID·중복 예측·다른 입력 해시는 오류입니다. 누락 예측은 제외하지 않고 FN과 실행 오류에 반영합니다. 일부 파일만 처리한 실행은 전수 완료나 합격으로 표시하지 않습니다.

## 생성과 검증

```powershell
python -X utf8 tools/item3/verify_rebuilt_cpe_source.py
python -X utf8 tools/item3/verify_item3_balanced_dataset.py --dataset benchmark/item3_advisory_inputs_v5
python -X utf8 tools/item3/finalize_balanced_rebuild.py
```

현재 데이터는 생성돼 있습니다. 재생성은 `rebuild_icsa_cpe_source.py`와 `build_item3_balanced_dataset.py`를 사용하되 새 출력 경로를 지정합니다. 원본 보존과 CPE 근거는 `CPE_rebuild_verification.json`, 입력·골드·분할은 `verification.json`, 스키마·실제 연산자 수는 `results/item3_balanced_v5_schema_20261125.json`으로 확인합니다. 검증은 출처·변환 재현성 검사이며 독립적인 현장 정답 정확도 검증은 아닙니다.

## 실행

프로젝트 루트에서 다음과 같이 실행합니다. 실제 모델 실행에는 기존 모델·가중치·GPU 환경이 필요합니다.

```powershell
# 1. 실제 SBOM 파일로 예측만 생성
python -X utf8 tools/item3/run_item3_test.py predict --mode agents --output results/item3_test_agents_v1

# 2. 저장된 예측을 별도로 채점
python -X utf8 tools/item3/run_item3_test.py score --predictions results/item3_test_agents_v1/predictions.jsonl --output results/item3_test_agents_v1

# 두 단계를 순서대로 실행
python -X utf8 tools/item3/run_item3_test.py run --mode rules --output results/item3_test_rules_v1

# 소수 파일 점검: 전체 모집단의 나머지는 미처리로 남으며 종료 코드는 2
python -X utf8 tools/item3/run_item3_test.py run --mode rules --limit 2 --output results/item3_test_smoke_v1
```

`--dataset` 또는 `--sboms`로 명시적 위치를 지정할 수 있습니다. 명시하지 않으면 `data/item3_test_dataset.json`이 가리키는 파생 test 폴더를 해시 검증 후 사용합니다. 현재는 `benchmark/item3_advisory_inputs_v5/test`입니다. `--split train`으로 실행하면 train 폴더를 선택하고 학습 입력 진단으로 기록합니다.

기존 `item3_precision_pipeline.py evaluate --fold test`와 `evaluate-trained`도 현재 파일 기반 실행기로 연결됩니다. `--fold evaluation`은 test의 입력 별칭으로 허용합니다. 기존 전체 모집단 감사와 과거 실행 재현 스크립트는 해당 기록의 범위와 출처를 유지합니다. train 분할의 진단 실행을 test 일반화 성능으로 표시하지 않습니다.

## 출력

| 파일 | 내용 |
|---|---|
| `run_config.json` | 입력 목록·해시, 코드·참조 데이터 해시, 실행 모드, 원본 또는 재집계 출처 |
| `predictions.jsonl` | 골드와 분리된 예측과 실행 오류 |
| `test_report.json` | 전체·control/variant·시나리오·역할별 지표, 쌍별 집계 |
| `case_scores.jsonl` | 사례별 TP/FP/FN·unjudged·out_of_scope·오류 |
| `component_scores.jsonl` | 구성요소별 채점. 다른 구성요소에 붙은 CVE를 정답으로 합산하지 않음 |
| `pair_results.jsonl` | 조건별 기준본·변형본 ID, 결과 범주와 TP/FP/FN 변화 |

확정 CVE는 SBOM 파일·구성요소 bom-ref·CVE 조합으로 중복을 제거합니다. 구성요소별 expected_cves 목록에 있는 확정 출력은 TP, 목록 밖 확정 출력은 FP, 누락한 정답은 FN입니다. CPE 범위 밖 출력도 FP에 한 번 포함되며 별도 진단 건수로 표시됩니다. 정밀도는 TP/(TP+FP)이며 확정 출력이 없으면 null입니다. 시험에서 뽑은 표본 전체가 완료돼야 합격 여부를 판정합니다.

기준본과 변형본이 모두 선택된 쌍은 양쪽의 정답 목록 일치 여부로 비교합니다. 구성요소마다 FP와 FN이 모두 0이면 일치입니다. 실행 오류는 execution_error, 실제 변형이 없으면 not_applicable입니다. 정밀도 기준은 80% 이상입니다.

## 과거 전수 결과 재집계

```powershell
python -X utf8 tools/item3/run_item3_test.py rescore-recorded --recorded-run results/item3_benchmark_validation_h200_20261119 --mode agents --output results/item3_test_recorded_agents_v1
```

원본 예측 원장과 동결 인벤토리의 해시를 검증하고, 현재 SBOM·annotation·gold가 당시 파일과 일치하는지 확인한 다음 저장된 CVE 출력을 새 형식으로 채점합니다. **새 모델 추론은 수행하지 않습니다.** 보고서에는 `prediction_origin=verified_recorded_outputs`, `inference_performed=false`를 남깁니다. 원장만으로 확인할 수 없는 모델 사용량은 미기록으로 보존합니다.

이 데이터는 공개 출처에서 만든 합성 매핑 test이며 실제 설비의 영향·악용 가능성 또는 독립적인 현장 정확도를 입증하지 않습니다.
