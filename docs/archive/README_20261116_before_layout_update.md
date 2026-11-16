> **H200 실험 기록 · 2026-11-16:** 12,418개 CVE 전수 재평가와 Gold 생성·Precision 계산 방법을 [실험 보고서](results/h200_full_population_20261116_130409/README.md), [웹 실험 페이지](site/experiments.html), [구조화 기록](research_records/h200_full_population_20261116.json)에 저장했습니다. #3 하한 99.9895%, #4 전체 원시 모델 98.8731%·검증 후 100%. 실제 설비 Precision은 미측정입니다.

> **#4 실제 CVE 기반 합성 평가 완료:** 실제 CVE 12,418개를 유지한 24,678개 운영맥락 사례를 만들고 #4 전용 QLoRA(학습 구간 256개 예제·64회 업데이트)를 수행했습니다. 별도 시험 4,012개 CVE·6,797건에서 모델 단독 정밀도 **98.846%**(TP 514, FP 6), 모델+검증기 정밀도 **100%**(TP 508, FP 0), 결합 재현율 **30.40%**, 보류율 **92.53%**입니다. 명시적인 경로·제품·관측불가 전제의 가정 아래 계산한 **조건부 합성 점수**이며 실제 설비 VEX 정밀도가 아닙니다. 원문으로 합성 세계를 구성할 수 있는 2,452개 CVE와 미확정 9,966개 CVE를 모두 보존합니다. [평가 절차·로직](docs/ITEM4_SOURCE_CONTEXT_VALIDATION.md), [시험 결과](results/item4_source_context_v1/precision_report.json), [별도 입력·Gold](benchmark/item4_source_context_gold_v2/), [원시 예측 재채점](results/item4_source_context_v1/reverification.json)을 참조하세요.

> **12,418 CVE 전수 검증 갱신:** #3은 12,418개 입력 실행 및 원시 출력 재채점을 완료했습니다. 중복 제거 5,114개 SBOM의 TP 683,591·FP 56·미확정 양성 16개를 모두 반영한 정밀도 하한은 **99.9894%**입니다. 학습 구간을 포함한 원문 기반 합성 인벤토리 점검이며 독립 실측 성능이 아닙니다. #4의 실제 설비 영향 정밀도는 미측정이며, 실제 CVE 기반 조건부 합성 평가는 위 갱신을 참조하세요. [전수 검증 보고서](results/cve_population_precision_v1/validation_report.json), [별도 입력·Gold](benchmark/cve_population_precision_v1/), [CVE별 검증 원장](results/cve_population_precision_v1/cve_validation_ledger.jsonl)을 참조하세요.

> **현재 평가 기준 변경: #3·#4 공통 모집단은 실제 CVE 12,418개입니다.**
> 이전의 #3 99.7476%와 #4 100%는 각각 부분 합성 벤치마크와 가상 CVE 논리 시험 점수입니다. 12,418개 전체 기준의 정밀도 또는 목표 달성으로 사용할 수 없습니다.
> [공통 데이터 기반](benchmark/cve_population_12418_v1/manifest.json), [범위·커버리지](results/cve_population_12418_v1/coverage_report.json), [전체 역링크](benchmark/cve_population_12418_v1/reverse_links.jsonl)를 기준으로 합니다. 입력·라벨은 분리하며, 근거가 없는 정답은 unknown으로 보존합니다. 전수 검증의 최신 상태는 위 갱신 및 보고서를 참조하세요.

# ICS-VEXForge

SBOM에서 CVE를 식별하는 **#3**과, 소스코드 없이 ICS의 운영맥락으로 VEX를 검토하는 **#4**를 제공합니다. 구현·평가 기준 갱신일은 **2026-11-16 KST**입니다.

## 실행

이 작업 PC에는 CUDA PyTorch, 모델 캐시와 아래 데이터가 준비되어 있습니다. 설치 버전은 [환경 기록](results/precision_environment.json), Python 의존성은 [requirements-precision.txt](requirements-precision.txt)를 참조하세요. GPU용 PyTorch는 별도로 설치합니다.

```powershell
python -m uvicorn src.api_server:app --host 127.0.0.1 --port 8100
```

브라우저에서 [식별·운영맥락 평가 화면](http://127.0.0.1:8100/precision.html)을 엽니다. SBOM 업로드, 현재 평가 지표, 운영맥락 검토 패킷 평가와 OpenVEX 내보내기를 사용할 수 있습니다. 기존 [#3 화면](http://127.0.0.1:8100/index.html), [#4 자산 검토](http://127.0.0.1:8100/vex-decision.html), [API 문서](http://127.0.0.1:8100/docs)도 유지합니다.

## #3 — SBOM 기반 CVE 식별

`Parsing → Orchestrator / LangGraph StateGraph → 필요한 P2·P3·P4 → Decision Validator → CVE Matching` 순서입니다. P2는 제품명, P3는 버전, P4는 식별자를 검토합니다. 구조화 CPE 조회·BM25·문자 TF-IDF 코사인 검색을 결합하며, 검색 점수나 모델의 선택만으로 제품을 확정하지 않습니다. 원본 제품·버전·edition 근거를 검증하고 지원되지 않는 버전 순서는 미확정으로 남깁니다.

원문으로 유일하게 결정되는 버전 관측 분류는 규칙으로 처리합니다. P2·P4에는 해당 역할에서 선택 가능한 후보와 근거만 전달하고, 모델은 유효한 출처 ID 응답과 미확정을 비교합니다. 실제 모델 호출과 동일한 모델 입력의 결과 재사용을 구분해 기록합니다. 최종 CVE 매핑 검증에는 원래 제품·버전·식별자 전체를 사용합니다.

모델은 로컬 캐시에 있는 `unsloth/Qwen2.5-Coder-14B-Instruct-bnb-4bit` revision `ecfc63c083900ce4f19daad695e711f38ab98fcf`입니다. Qwen2.5-Coder-14B 계열의 사전 양자화된 NF4·이중 양자화 가중치를 사용하며, 역할별 프롬프트와 공유 QLoRA 어댑터로 실행합니다. 추론 설정은 `data/identification_runtime.json`, 실제 학습 증거는 [학습 완료 기록](models/precision_roles_qwen25_14b_v1/training_complete.json)입니다.

학습은 학습 구간에서 고정 선택한 **P2/P3/P4/운영맥락 각 32개, 총 128개 예제**에 1 epoch·32 optimizer 업데이트를 수행했습니다. 원래 학습 분할 83,112건을 전부 학습한 결과가 아닙니다. 최종 체크포인트를 사용하며 시험 결과로 체크포인트를 선택하지 않습니다. 16GB GPU의 메모리 페이징을 피하기 위해 학습 중 동결된 입력 임베딩 조회를 CPU에서 수행하고, completion 위치의 loss만 계산합니다.

평가 단위는 **SBOM·구성요소·CVE 연결**이며 Precision은 `TP/(TP+FP)`입니다. 목표는 **0.8 초과**입니다. 실제 실행 환경에서의 악용 가능성은 #3 정답에 포함하지 않습니다.

| 평가 | 확인 위치 |
|---|---|
| 학습 모델의 전체 시험 결과 | [trained_evaluation/precision_report.json](results/item3_precision_v11/trained_evaluation/precision_report.json) |
| 학습 모델 진행 상태 | [trained_evaluation/status.json](results/item3_precision_v11/trained_evaluation/status.json) |
| 규칙 비교 기준선 | [rules_evaluation/precision_report.json](results/item3_precision_v11/rules_evaluation/precision_report.json) |

규칙 비교 기준선은 **18,608건 전수**, TP **70,738**, FP **186**, FN **7,422**, Precision **99.7377%**, 재현율 **90.5041%**, 실행 오류 **0건**입니다. 학습 모델 성능과 혼용하지 않습니다. 실제 자산의 독립 전문가 정답에 대한 정확도는 측정하지 않았습니다.

## 별도 #3 Gold 데이터

[benchmark/item3_gold_v11](benchmark/item3_gold_v11/)에 입력과 라벨을 분리해 저장합니다.

| 분할 | 입력 | 정답 | 수량 |
|---|---|---|---:|
| 학습 | [train/inputs.jsonl](benchmark/item3_gold_v11/train/inputs.jsonl) | [train/labels.jsonl](benchmark/item3_gold_v11/train/labels.jsonl) | 83,112 |
| 시험 | [evaluation/inputs.jsonl](benchmark/item3_gold_v11/evaluation/inputs.jsonl) | [evaluation/labels.jsonl](benchmark/item3_gold_v11/evaluation/labels.jsonl) | 18,608 |

CVE 10,847개를 7,593/3,254로 나눈 **CVE 기준 7:3 분할**입니다. 기준본과 오류본은 같은 분할에 유지하며 분할 사이의 의미상 동일 입력은 0개입니다. 원문 조건 50,860개의 양성 라벨을 별도 source-only oracle과 대조했습니다. 미확정 라벨 차이 2건은 보수적인 합집합으로 보존했으며 [차이 기록](benchmark/item3_gold_v11/label_audit_disagreements.json)에 남겼습니다.

이 Gold는 고정 NVD 조건에서 계산한 **합성·기계 라벨**입니다. 독립 전문가가 실제 설치 자산에 대해 확정한 Gold가 아닙니다. 누락·오타 사례와 미확정 정답을 평가에서 제거하지 않습니다. 미확정으로 출력한 양성은 Precision 하한의 분모에 포함하고, 출력 0개는 통과로 처리하지 않습니다.

[전체 대상 CVE의 자료 범위 원장](benchmark/item3_gold_v11/target_CVE_coverage.jsonl)은 12,418개를 유지합니다. CPE 원문이 없는 1,571개는 unknown으로 기록하며 라벨이 있는 시험 입력 수로 세지 않습니다.

실서비스 조회 원문은 [data/item3_identification_sources_v11](data/item3_identification_sources_v11/)에 별도로 저장하여 평가 라벨 없이 사용할 수 있습니다.

## #4 — 운영맥락 기반 VEX

평가 범위는 **CVE·실제 자산·제품·실행 빌드·구성·운영 모드·공격 출발점·평가 시점**입니다. 소스코드 분석, 익스플로잇 제작 또는 내부 메모리 검증을 운영자에게 요구하지 않습니다. 재고·설정·접근 규칙·운영 기록·벤더 문서로 답할 수 있는 질문을 사용하고 모름을 보존합니다.

- **NIST Vulntology:** CVE·제품·공격경로별 시나리오를 표현합니다. AND/OR/NOT·unknown·운영 관측은 프로젝트 확장에 별도로 저장합니다. 원문 의미 검토와 고정 스키마 검증 없이 native 내보내기를 허용하지 않습니다.
- **MITRE ATT&CK ICS / Asset:** 공식 ICS 20.1의 18개 자산과 기법을 조회합니다. 자산·기법 소속만으로 필수조건이나 영향 여부를 결정하지 않습니다.
- **OVAL / OpenSCAP:** 지원하는 설정·상태를 관측하고 결과 XML의 정의 ID를 검토한 조건에 연결합니다. error·not evaluated·not applicable·잘못된 자산·중복 결과는 unknown입니다.
- **MulVAL / XSB:** 출처가 있는 네트워크·서비스·취약점 사실로 공격 그래프를 만듭니다. 경로가 없다는 결과를 비영향 증거로 사용하지 않습니다.

`affected`에는 정확한 적용성, 출처·제품 범위·충분성이 검토된 시나리오, 유효한 관측 근거와 대응 조치가 필요합니다. 필수조건만 모두 참이거나 방화벽이 차단됐다는 이유만으로 최종 영향을 확정하지 않습니다. 미검토·만료·충돌·범위 불일치는 `under_investigation`으로 남깁니다. 구조적 비영향 판단도 내부 소스코드 대신 벤더 문서와 자산 구성에서 확인할 수 있는 전제 및 전체 대안 경로 검토가 필요합니다.

LLM 원문 추출 API는 모든 선택 제품별 원문 조각을 기록하며 정확한 인용·제품 범위·논리 참조를 검사합니다. 현재 공유 어댑터는 식별·상태 역할용이므로 원문 추출에는 명시적으로 base 모델을 사용합니다. **추출용 미세조정 또는 의미 정확도 검증 완료로 표시하지 않습니다.** 자동 추출은 질문·조건 초안이며 VEX 판정에 자동 승격하지 않습니다.

기존 공개 코퍼스 **12,418개 CVE** 전체를 유지합니다. 현재 원문 기반 부분 초안이 있는 CVE는 5,039개이며, 초안이 없는 7,379개는 미확정입니다. [조건 군집 결과](results/item4_condition_clusters_v1/manifest.json)는 학습 자료로만 TF-IDF와 spherical K-means를 적합해 전체 CVE에 배정합니다. 공통 질문 지지도는 고유 학습 CVE로 계산하고 부족한 조건은 개별 질문으로 남깁니다. 공유 출처 연결 그룹을 분리하면서 실제 분할은 8,406/4,012가 되었으며, 이를 정확한 7:3 분할로 주장하지 않습니다. 별도 합성 Gold의 100개 가상 취약점·제품 그룹은 정확히 70/30으로 분리합니다.

## 별도 #4 Gold와 정밀도

[benchmark/item4_operational_gold_v2](benchmark/item4_operational_gold_v2/)에 가상의 ICS 상태를 독립 Boolean 시뮬레이터로 라벨링한 **학습 4,480건·시험 1,920건**을 저장합니다. CVE-2099 식별자는 가상 시나리오용이며 실제 CVE의 사실로 사용하지 않습니다. 운영 상태 누락·만료·잘못된 범위·충돌·미검토·관측 불가 사례를 모두 포함합니다. v2는 식별자에 잠재 상태가 드러나지 않도록 불투명 ID를 사용하며, 수정은 #4 시험 추론 전에 완료했습니다. v1의 완전 관측 학습 예제 32개로 학습한 어댑터는 그대로 고정합니다. [평가 절차](docs/PRECISION_EVALUATION_PROTOCOL.md)에 변경 범위를 기록했습니다.

지표는 **자동 `affected` 출력 중 실제 영향이 있는 비율 `TP/(TP+FP) > 0.85`**입니다. 전체 모집단을 평가하며 재현율·보류율·오류·미판정 양성도 함께 보고합니다.

| 자료 | 위치 |
|---|---|
| 시험 입력 | [evaluation/inputs.jsonl](benchmark/item4_operational_gold_v2/evaluation/inputs.jsonl) |
| 시험 라벨 | [evaluation/labels.jsonl](benchmark/item4_operational_gold_v2/evaluation/labels.jsonl) |
| 판단기 단독 합성 평가 | [precision_report.json](results/item4_operational_v2/precision_report.json) |
| 학습 모델+판단기 합성 평가 | [trained_precision_report.json](results/item4_operational_v2/trained_precision_report.json) |
| 실제 자산용 빈 라벨 양식 | [real_asset_annotation_blank.json](benchmark/item4_operational_gold_v2/real_asset_annotation_blank.json) |
| 운영맥락 입력용 빈 패킷 | [operational_packet_blank.json](benchmark/item4_operational_gold_v2/operational_packet_blank.json) |
| 주석 지침 | [annotation_guidance.json](benchmark/item4_operational_gold_v2/annotation_guidance.json) |

판단기 단독 시뮬레이션 결과는 TP 285, FP 0, Precision 1.0, 재현율 약 0.326, 보류율 약 0.852입니다. **실제 ICS 자산 정확도와 LLM의 원문 의미 정확도는 미측정**입니다. 실제 자료는 예측을 보지 않은 두 검토자의 영향 주석과 필요한 불일치 조정 후 `src/item4_scoring.py`로 별도 평가합니다.

## 외부 도구 실행과 재검증

OVAL과 MulVAL은 Windows의 별도 Docker 이미지에서 실행합니다. 이 작업에서는 OpenSCAP의 실제 XML 검증·관측, MulVAL/XSB의 실제 공격 그래프 생성, 프로젝트가 생성한 MulVAL 사실의 실행을 확인했습니다. 실제 ICS 장치를 스캔하지 않았습니다.

```powershell
docker build --build-arg XSB_COMMIT=ca3f5622355620910e4e8cb53b6895354f19f3de -t ics-vex-operational-tools:20261116 containers/operational-tools
python tools/verify_operational_tools.py
```

[실행 증거](results/operational_tools_v1/verification.json), [프로젝트 사실 실행 증거](results/operational_tools_v1/project_generated_facts_verification.json), [고정 표준의 출처와 해시](data/standards/manifest.json)를 제공합니다. MulVAL의 현대 컴파일러 호환 수정은 Dockerfile에 명시했습니다.

```powershell
python -m pytest tests/test_precision_exports.py tests/test_operational_source_packets.py tests/test_real_asset_scoring.py tests/test_precision_contracts.py tests/test_identity_evidence.py tests/test_identification_routing.py tests/test_identification_wire.py tests/test_identification_batch_flow.py tests/test_context_vex_pipeline.py tests/test_unified_identification.py tests/test_grounded_identification_agents.py -q
python tools/item3_precision_pipeline.py evaluate
python tools/verify_precision_release.py
```

Gold 생성기는 기존 스냅샷을 덮어쓰지 않습니다. 모델·데이터·코드가 변경되면 시험 결과 디렉터리도 새 버전으로 분리합니다. [전체 평가 실행 상태](results/precision_evaluation_v1/status.json)를 확인할 수 있습니다.

이전 연구·학습·군집 이력과 당시 상태는 [2026-11-15 README 보관본](docs/archive/README_20261115.md)에 보존했습니다. 보관본의 과거 경로와 진행 수치는 현재 실행 상태를 의미하지 않습니다.

## 최종 학습 모델 전수 평가

#3: 18,608건, Precision **99.7476%**, 목표 80% 초과 통과. #4: 합성 시험 1,920건, TP 234, FP 0, Precision **100.0000%**, 목표 85% 초과 통과. #4 재현율 26.74%, 보류율 87.81%. 실제 ICS 영향 Precision은 미측정입니다.

평가 범위·ID 교체·재현 기준은 [평가 절차](docs/PRECISION_EVALUATION_PROTOCOL.md)를 참조하세요. 실제 자산 주석이 준비되면 `python tools/score_item4_real_assets.py --predictions predictions.jsonl --gold real_gold.jsonl --output real_precision_report.json`으로 별도 계산합니다.

통합 테스트 **109개 통과**, 서비스의 실제 학습 모델 호출, 원문 조건 추출의 인용·범위 검사, 화면의 최종 지표 표시를 확인했습니다. 저장된 원시 예측의 재채점 명령은 `python tools/verify_precision_release.py`이며 GPU 추론을 다시 실행하지 않습니다. 평가 당시 소스는 [동결 소스 압축본](results/precision_evaluation_v1/frozen_evaluation_sources.zip)에 보존했습니다. 서비스 API에는 평가 후 시점·범위 보존 및 내보내기 검증을 추가했고 [릴리스 기록](results/precision_evaluation_v1/release.json)에 전후 해시를 기록했습니다. 엄격한 코드 해시를 검사하는 전체 추론 실행기와 서비스 통합 후의 재검증 명령을 구분합니다.

[원시 예측 재채점·해시 검증](results/precision_evaluation_v1/reverification.json), [학습 모델 API 실행](results/precision_evaluation_v1/http_trained_smoke.json), [원문 추출 검사](results/precision_evaluation_v1/extraction_smoke.json)를 확인할 수 있습니다. 원문 추출 검사는 가상 예문 하나에 대한 기계적 검사이며 의미 정확도 평가가 아닙니다.
