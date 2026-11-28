# ICS-VEXForge

소스코드가 없는 ICS/OT 환경에서 SBOM으로 제품·버전·CVE를 연결하고, 원문에 근거한 운영 조건과 사용자 관측으로 VEX를 검토하는 연구 시스템입니다. **문서 갱신: 2026-11-19 KST.**

로컬 운영 판정은 [컴포넌트별 전체 흐름](docs/COMPONENT_VEX_WORKFLOW.md)을 따릅니다. 원본 BOM → 기존 P2/P3/P4 식별 → ICSA/NVD 근거·MITRE 자산 유형 → LLM VEP 추출·악용조건 그래프 및 NIST 질문 → 생성형 LLM 운영 기록 대조 → 그래프 평가·완화 검증 → OpenVEX/CycloneDX VEX입니다. 자산 유형 추정은 확인이 필요한 후보이며 조건의 참·거짓을 대신하지 않습니다.

## 현재 상태

| 구분 | 현재 자료와 상태 | 해석 범위 |
| --- | --- | --- |
| 로컬 BOM/VEX 서비스 | NIST 기반 54개 항목·167개 세부정보, CVE 12,418개 조회 | 연구용 서비스. 건강 확인은 영향 판단 정확도 검증이 아님 |
| #3 최근 분리 시험 | 8,693 CVE 학습 / 3,725 CVE 시험 | 원천 자료로 만든 합성 인벤토리. 미주석 출력 14개를 포함한 보수적 Precision 하한 99.6535% |
| #4 현재 Gold | 제품별 원문·버전·자산 역할·질문·조건식 계약을 검사하는 v5 | 근거 사슬을 통과한 CVE 6개, 미확정 12,412개. 전부 보존 |
| #4 v5 재평가 | H200 전수 추론·재채점 완료 — 12,436건, CVE 12,418개 모두 실제 호출 | 별도 시험은 확정 양성 0개로 Precision 계산 불가. 성능 목표 통과로 해석하지 않음 |
| CVE 조건 인용 추출 v3 | 동일 시험의 약지도 정확 구간 F1 91.92% | 95% 목표 미달. 교사 라벨 일치도이며 독립 의미 정확도는 미측정 |
| 기존 18개 자산 유형 | 3,881 ICSA 중 3,620개 배정 / 261개 미배정 | 탐색용 모델 추정을 포함하므로 Gold 자산 정답으로 사용하지 않음 |

#4 v4의 높은 합성 Precision에는 제품별 범위 연결과 자산 유형 미검증 문제가 있었습니다. v5는 그 수량을 유지하기 위해 미확정 조건을 채우지 않습니다. **모든 CVE의 추론 완료와 모든 CVE의 영향 정답 확보는 다릅니다.**

## 실행 환경과 시작

현재 PC의 준비된 Python 환경을 사용합니다. 로컬 검증 환경은 Python 3.10, H200 평가는 Python 3.11입니다. 의존성은 [requirements-precision.txt](requirements-precision.txt), [requirements-ncp.txt](requirements-ncp.txt)를 참고하세요. CUDA용 PyTorch, 양자화 기저 모델, 어댑터, 원천 스냅샷은 별도로 준비되어야 합니다.

Git에서 받은 대형 자료는 Git LFS로 내려받습니다.

```powershell
git lfs install
git lfs pull
python -X utf8 -B tools/serve_nist_operational_vex.py 8100
```

| 화면 | 주소 | 기능 |
| --- | --- | --- |
| BOM 작업 | [bom-vex.html](http://127.0.0.1:8100/bom-vex.html) | BOM 입력, 식별 작업, 자산·CVE 검토 |
| 운영맥락 VEX | [vex-decision.html](http://127.0.0.1:8100/vex-decision.html) | 운영 관측과 근거에 따른 검토 |
| SBOM/CVE 화면 | [index.html](http://127.0.0.1:8100/index.html) | 기존 제품·버전·식별자 조회 |
| ICSA별 합성 SBOM | [ics-sbom.html](http://127.0.0.1:8100/ics-sbom.html) | 권고문별 BOM 목록과 JSON |
| 방법론 | [nist-population-vex-method.html](http://127.0.0.1:8100/nist-population-vex-method.html) | 운영 판정 경로 설명 |
| API | [docs](http://127.0.0.1:8100/docs) | 현재 로컬 서비스 API |

2026-11-18 읽기 전용 확인에서 8100의 건강 인터페이스는 HTTP 200, `corpus_cves=12418`, `kb_components=0`을 반환했습니다. 모델은 별도 준비·로딩이 필요하며 이 확인만으로 식별·영향 판단 성능을 보증하지 않습니다. 과거 별도 자동 카탈로그 API의 18104 포트는 이번 확인 시 실행을 확인하지 못했습니다.

현재 진입점은 [tools/serve_nist_operational_vex.py](tools/serve_nist_operational_vex.py)입니다. 기반 서비스는 `local-service/sbom-vex/vex_operational_logic_20261117`이며 필요한 배포 파일은 [런타임 목록](local-service/runtime_manifest.json)에 있습니다. 검토 DB와 로그는 로컬 자료입니다. `tools.local_dataset_app:app`은 기존 기본 데이터셋 서비스이므로 위 진입점과 동일한 입력 화면이라고 가정하지 않습니다.

현재 PC의 기저 모델 캐시는 `D:\ICS-VEX-support\cache\huggingface`를 사용합니다. 어댑터의 실행 메타데이터가 가리키는 기저 모델과 실제 파일 경로·해시가 맞아야 합니다. 대형 기저 모델 전체가 Git 저장소에 포함되어 있다고 가정하지 않습니다.

## 운영정보와 VEX 판단

현재 기본 경로는 **생성형 LLM VEP 추출 → 원문·제품 범위·AND/OR/NOT 검증 → MulVAL/XSB 그래프 → 운영 관측 → 그래프 평가 → OpenVEX/CycloneDX VEX**입니다. 추출 결과 형식은 프로젝트 내부 `Vulnerability Exploitation Prerequisite` 계약입니다. [VEP 명세·실행·검증](docs/VULNERABILITY_EXPLOITATION_PREREQUISITE.md)을 참고하세요.

**NLI는 기본 실행 경로에서 제거했습니다.** 추출 결과 검증과 운영 기록 대조에 DeBERTa/NLI 또는 0.90 점수 기준을 사용하지 않습니다. 원문 기록 대조도 생성형 LLM을 사용하며 구조화 관측과 공급사 버전 비교는 유지합니다. 최종 VEX 상태는 그래프 평가 코드가 결정합니다. 모델 실패·근거 누락·제품 범위 미확정·기록 충돌은 unknown이며, 정규식 추출 또는 과거 NLI 검증 overlay로 자동 대체하지 않습니다.

현재 로컬 공유 Qwen2.5-Coder-14B 기저 모델을 사용하며 이 작업에서는 식별용 어댑터를 비활성화합니다. 명시적인 chat-completion 설정도 지원합니다. 모델 추출은 의미적 완전성 검증이 아니므로 `coverage_complete=false`를 유지합니다. 일부 경로를 차단한 것만으로 전체 비영향을 확정하지 않습니다. `fixed`는 공급사 수정 실행 버전, 검증된 운영상 차단은 완전한 근거·그래프가 있을 때 평가 범위의 `not_affected`로 구분합니다.

NIST SP 800-82r4 IPD Appendix C Tables 12–17의 54개 원천 행·167개 프로젝트 수집 세부정보 중 CVE 조건에 해당하는 질문을 연결합니다. 자산 유형은 수집 맥락이며 조건의 참·거짓을 제공하지 않습니다. MulVAL 실패 시 대체 그래프로 경로 결론을 만들지 않습니다.

상태 API는 `/api/operational-vex/llm-status`, VEP 스키마는 `/api/operational-vex/prerequisite-schema`입니다. `/api/operational-vex/nli-status`는 호환용 비활성 응답입니다. 기존 저장 평가·질문은 새 근거에 맞춰 다시 연결해야 합니다.

과거 [NLI 동결 평가](results/operational_nli_holdout_20261118_v1/report.html)는 이전 정책의 합성 시험 결과로 보존하며 새 LLM 경로의 성능으로 사용하지 않습니다. 새 경로는 계약·연결 검증과 독립적인 의미 정확도 평가를 구분합니다.

## #4 제품별 근거 Gold v5

현재 구현: [근거 연결](src/item4_gold_grounding.py), [생성기](tools/build_item4_source_context_gold.py), [검증기](tools/audit_item4_source_context.py), [평가 방법](docs/ITEM4_SOURCE_CONTEXT_VALIDATION.md).

```text
원본 CSAF 바이트·해시
  → CVE의 known_affected 제품 ID와 원래 버전 범위
  → 제품별 note 제목과 일반 설명의 적용 범위
  → 제품에 직접 연결된 자산 역할 근거
  → 원문 조건·AND/OR/NOT
  → 조건별 질문·예/아니오/모름 대응
  → 조건부 합성 관측·별도 정답
```

- `For <product>` 제목을 보존해 제품별 예외를 해당 제품에만 연결하고 일반 설명에서는 제외합니다. 제목의 버전·제품 한정을 해소하지 못하면 범위를 넓히지 않습니다.
- 제품 트리의 명시적 역할명, 제품 범위가 확인된 원문의 역할 표현, 보존된 공식 공급사 설명을 사용합니다. TF-IDF 분류·유사 제품 추정은 Gold 유형으로 가져오지 않습니다.
- 고정 18개 유형의 ID와 정의는 유지합니다. 통신 프로세서처럼 원문 역할은 확인되지만 18개 유형에 정확히 대응하지 않는 부품은 역할명과 근거를 남기고 상위 유형은 미확정으로 둡니다.
- 질문은 제한된 관측 가능 술어와 일치하는 경우에만 생성합니다. `예→참`, `아니오→거짓`, `모름→미확정`을 검증하고 원문 부정·논리 연결을 보존합니다. 공격자의 자격증명·메모리 상태 등을 충족했다고 가정하지 않습니다.
- 실제 운영자에게 답변을 수집한 데이터가 아닙니다. 관측과 잠재 상태는 합성이고 실제 설비 영향 정답은 검증되지 않았습니다. 자동 근거 계약 검사와 독립적인 사람의 의미 검증은 다릅니다.

CVE-2015-8214의 CP 342-5는 이제 제품별 PROFIBUS 접근 조건과 통신 인터페이스 모듈 역할로 연결합니다. 이전의 일반 TCP 102 조건 연결과 탐색용 Routers 추정을 이 제품의 Gold 근거로 쓰지 않습니다.

원문 조건의 핵심 상태와 관측 공개 여부로 네 사례를 만듭니다.

| 사례 | 핵심 상태 | 모델에 제공되는 관측 | 현재 A/U 계약 |
| --- | --- | --- | --- |
| 충족 관측 | 참 | 참 | A: 선택 경로의 조건부 영향 |
| 불충족 관측 | 거짓 | 거짓 | U: 영향 확정 안 함 |
| 숨겨진 충족 | 참 | 누락 | U |
| 숨겨진 불충족 | 거짓 | 누락 | U |

충돌·만료 변형은 이 평가에서 제외했습니다. 운영 엔진의 관측 품질 검사는 유지합니다. 현재 A/U 계약은 경로 불충족과 정보 부족을 모두 U로 출력하지만 원래 차이는 관측·정답 파일에 보존합니다.

[Gold v5](benchmark/item4_source_context_gold_v5/)는 12,418개 CVE 전부를 유지합니다. 네 사례를 구성한 CVE는 6개, 근거 사슬을 확정하지 못한 CVE는 12,412개로 **총 12,436건**입니다. 분할은 기존 공유 원문 그룹 기준 8,406/4,012 CVE이며 정확한 7:3으로 표시하지 않습니다. 평가 단위는 CVE별로 사전 고정한 검증 제품·경로 하나입니다. 다른 제품의 범위와 미확정 이유도 인덱스에 보존하며 모든 제품 조합의 정확도를 평가했다고 주장하지 않습니다.

6개는 실제로 원문 근거가 존재하는 CVE의 총수가 아니라 **현재 자동 근거 계약을 통과한 범위**입니다. 미확정에는 자료 부족뿐 아니라 제품 범위·역할·질문 변환·조건식 해석을 현재 규칙으로 검증하지 못한 경우도 포함합니다.

| 파일 | 내용 |
| --- | --- |
| `cve_source_records.jsonl` | 전체 CVE의 원문·제품·범위·질문·조건식·근거와 미확정 사유 |
| `cve_index.jsonl` | CVE별 분할, 선택 제품·역할, 전체 제품 연결과 사례 ID |
| `train/inputs.jsonl`, `evaluation/inputs.jsonl` | 모델에 전달하는 입력 |
| `train/labels.jsonl`, `evaluation/labels.jsonl` | 분리한 합성 정답. 미확정 영향은 null |
| `manifest.json`, `integrity_audit.json` | 수량·원천 해시·범위 재구성·질문/조건식 검사 |

원문·역할 스냅샷을 새로 수집할 때는 [수집기](tools/collect_item4_grounding_sources.py)를 사용합니다. 봉인된 Gold는 덮어쓰지 않고 새로운 버전·실행 ID로 생성합니다.

```powershell
python -X utf8 -m pytest tests/test_item4_gold_grounding.py tests/test_item4_source_recovery.py -q
python -X utf8 tools/run_item4_source_context_h200.py --run-id 20261118_product_source_gold_v5_final status
python -X utf8 tools/run_item4_source_context_h200.py --run-id 20261118_product_source_gold_v5_final fetch
```

새 독립 실행은 다음처럼 시작합니다. 동일 실행 ID는 재사용하지 않습니다.

```powershell
python -X utf8 tools/run_item4_source_context_h200.py --run-id <새_실행_ID> --build-gold start
```

새 [평가 보고서](results/item4_source_context_v3_grounded_full_population/precision_report.json)와 [저장 출력 재채점](results/item4_source_context_v3_grounded_full_population/reverification.json)을 보존합니다. 확정 조건 사례는 모두 학습 구간의 CVE에 있어 전체 집계의 TP 6·FP 0을 독립 시험 성능으로 해석하지 않습니다. 별도 시험 4,012개는 전부 미확정이며 Precision·Recall은 계산 불가, 목표 통과는 false입니다. 미확정 12,412개는 모두 보류했고 영향 정답은 null로 유지했습니다. 코드 회귀 테스트 25개와 전체 원문·제품·역할 재구성 및 질문/조건식 계약 검사를 통과했습니다.

[CP 342-5 근거 추적 예시](results/item4_source_context_v3_grounded_full_population/examples/CVE-2015-8214.json)는 원문, 제품·버전, 자산 역할, 질문, 조건식, 실제 모델 입력과 별도 합성 정답 네 개를 함께 보여줍니다.

이전 [v4 결과](results/item4_source_context_v2_full_population/)와 [v4 의미 검토](results/item4_source_context_v2_full_population/source_semantic_findings.json)는 이력으로 보존합니다. v4의 시험 Precision 99.064%와 결합 100%를 제품별 원문·자산 유형의 정확도로 해석하지 않습니다.

## #3 식별 평가와 SBOM

최근 분리 시험은 [2026-11-17 holdout v2](results/item3_holdout_7030_20261117_v2/summary.json)입니다. 연결된 CVE/제품 그룹과 중복 입력을 묶어 학습 8,693개, 시험 3,725개로 나눴고 CVE·SBOM·원천 제품 정체성의 구간 중복은 0개입니다. 새 어댑터는 학습 구간의 고유 역할 예제 1,486개로 학습했습니다. 전체 CVE를 모델 학습 예제로 사용한 것은 아닙니다.

| 시험 집계 | 보수적 Precision 하한 | 채점 가능한 출력만의 Precision | 알려진 양성 Recall |
| --- | ---: | ---: | ---: |
| 시험 3,725 CVE 행 | 99.6535% | 99.7465% | 93.1950% |
| 고유 입력 1,818개 기준 | 99.4208% | 99.7726% | 90.8213% |

출력 연결 14개가 미주석이므로 정확한 전체 Precision은 미확정입니다. 하한에서는 이 14개를 모두 FP로 취급합니다. 실제 자산·독립 사람 Gold 정확도는 검증하지 않았습니다.

[benchmark/item3_evaluation](benchmark/item3_evaluation/)은 별도의 **2026-11-16 전수 실행 자료**입니다. 학습 출신 입력을 포함하므로 위 분리 시험과 혼동하지 않습니다. `input.jsonl`과 `gold.jsonl`은 `id`로 연결하고 `results.json`은 통합 채점 보고서입니다. 원시 예측 DB와 당시 실행 스냅샷은 H200에 보존합니다.

[ICSA별 합성 SBOM](<benchmark/icsa-cpe-synthetic sbom/>)은 `ICSA → 명시 CVE → vulnerable:true CPE 조건 → BOM 컴포넌트`로 만든 별도 자료입니다. 3,881개 권고문 중 CPE 컴포넌트가 있는 BOM은 3,108개, 빈 기록은 773개입니다. 포함 고유 CVE 10,847개, CPE가 없는 고유 CVE 1,571개를 분리해 보존합니다. 여러 CPE가 실제 동시 설치 구성이나 전체 플랫폼 AND/OR 충족을 뜻하지 않습니다. CVE 연결 답을 포함하므로 그대로 블라인드 평가 입력으로 사용하지 않습니다.

제품 식별 연구 모듈은 구조화 제품·CPE 조회, BM25와 문자 3-gram TF-IDF 코사인 검색을 RRF로 결합합니다. [식별 구현](src/ics_agent_matcher_full/ics_agent_matcher/matcher.py)을 참고하세요. 검색 점수, 후보 선택, 모든 단계의 GPU 호출 여부와 최종 근거 검증은 구분합니다.

## 자산 분류와 CVE 인용 추출

기존 [18개 유형 분류](results/icsa_fixed18_reclassification/README.md)는 ICSA 3,881개와 고유 CVE 12,418개를 유지합니다. 3,620개 권고문을 배정했고 261개는 미배정입니다. 단일 원문 유형 표현으로 632개, 복수 표현 중 모델 선택으로 112개, 표현 없이 모델 추정으로 2,876개를 배정했습니다. **탐색용 배정이며 v5 Gold 유형의 근거가 아닙니다.**

지도 투영 공간의 Silhouette 0.52499와 원본 TF-IDF 공간의 0.00986은 서로 다른 지표입니다. 기준 라벨이 평가 대상에도 포함되며 독립 분류 정확도는 미검증입니다. 별도 [자유 텍스트 K=18 실험](results/icsa_role_clusters_k18/README.md)의 SVD 공간 0.55514도 기능·악용조건 정확도를 뜻하지 않습니다. 군집 소속만으로 CVE 전제나 VEX 상태를 만들지 않습니다.

[CVE 인용 추출 v3](results/cve_ner_20261117_v3/README.md)는 개발 점수로 선택한 `listwise_aux_scope` 방식의 동일 시험 약지도 정확 구간 F1이 **91.92%**입니다. 95% 목표는 미달했고 이전에 사용한 시험 구간이므로 새 독립 시험으로 부르지 않습니다. 12,418개 전부 처리 상태를 보존했으며 후보 추출 2,677개, 후보 없음 9,652개, description 미확보 89개입니다. 교사 일치도를 악용 조건의 독립 의미 정확도로 취급하지 않으며 이 출력을 v5 확정 Gold로 가져오지 않습니다.

이전 [NER v1](results/cve_ner_20261117_v1/README.md)의 18.33%, [NER v2](results/cve_ner_20261117_v2/README.md)의 44.61%도 같은 의미의 약지도 정확 구간 F1 이력입니다.

## 폴더와 재현 자료

```text
src/                         # 식별·VEX·질문·근거 연결 구현
tools/                       # 서비스, 생성·검증·학습·평가 실행기
tests/                       # 계약·논리·회귀 테스트
data/item4_grounding_v1/      # 공식 공급사 역할 근거 스냅샷
icsa/csaf/                   # 원본 권고문 JSON
site/                        # 웹 화면과 기존 정적 조회 자료
benchmark/item4_source_context_gold_v5/
benchmark/item3_evaluation/
benchmark/icsa-cpe-synthetic sbom/
results/item4_source_context_v3_grounded_full_population/
results/item3_holdout_7030_20261117_v2/
models/                      # 별도로 준비하는 모델 어댑터와 메타데이터
local-service/               # 런타임 목록에 명시한 기반 서비스
```

코드·스키마 검증, 저장 예측 재채점, 원문 해시 검증, 독립적인 의미 정확도 검증을 구분합니다. 과거 스크립트가 요구하는 입력이 현재 로컬에 모두 있는 것은 아닙니다. 예를 들어 `tools/item3_precision_pipeline.py`의 과거 경로 `item3_ics_cert_full/cves.jsonl`은 현재 로컬에 없습니다. 결과 열람과 원래 실험의 재실행 준비는 별도입니다.

## H200 연결

H200 프로젝트 루트는 `/home/irteam/data-vol1/ics-vex-migration-20261116`입니다. 새 v5 평가는 그 아래 별도 `item4-source-context-runs`에서 기존 기저 모델·어댑터를 동결해 실행합니다. 어댑터 재학습이나 시험 점수에 따른 체크포인트 선택은 수행하지 않습니다.

클라우드 웹 서비스는 포트 18100을 사용하며 로컬 포트 8100과 구분합니다. kubectl을 준비한 뒤 현재 kubeconfig 경로를 명시해 연결합니다.

```powershell
kubectl --kubeconfig .\hysage-kubeconfig.yaml port-forward pod/test-0 18100:18100 --address 127.0.0.1
```

kubeconfig·토큰은 Git에 포함하지 않습니다. 노트북 재시작, 커널·모델 준비, 서비스 재시작과 스토리지 한계는 [NCP 안내](docs/NCP_MIGRATION.md)에 있습니다. 예전 연결이 현재도 유지된다고 가정하지 않습니다.

## 보존된 이력

- [이번 전체 갱신 전 README](docs/archive/README_20261118_before_grounded_gold.md)
- [폴더 정리 전 README](docs/archive/README_20261116_before_layout_update.md)
- [이전 연구 기록](docs/archive/README_20261115.md)
- [이전 자동 추출 카탈로그](results/item4_automatic/20261116_policy05/catalog/summary.json): 전수 CVE 기록과 검증 경로 수를 구분하는 별도 실험
- [11월 16일 H200 전수 실행](results/h200_full_population_20261116_130409/summary.json): 이후 분리 시험·v5 Gold의 최신 성능으로 사용하지 않는 과거 실행
- [11월 16일 H200 전수 실행](results/h200_full_population_20261116_130409/summary.json): 이후 분리 시험·v5 Gold의 최신 성능으로 사용하지 않는 과거 실행
