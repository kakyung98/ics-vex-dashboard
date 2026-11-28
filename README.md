# ICS-VEXForge

S/HBOM을 이용해 ICS/OT 제품·버전·CVE를 식별하고 자산 운영 정보와 공개 근거를 결합해 VEX를 생성하는 연구 시스템입니다. 소스코드가 없는 환경을 기본으로 합니다.

## 용어 기준

시험 항목 #3의 식별 역할은 **I1 컴포넌트명 분석**, **I2 버전·모델 관측 분석**, **I3 CPE·PURL 식별자 검토**로 표기합니다. API 결과 키는 `i1`, `i2`, `i3`입니다. #4의 V1~V4 역할과 구분합니다.

자산의 설정·접근성·운영 기록에서 확인하는 정보는 **자산 운영 정보**로 통일하며, 영어 화면에서는 **Asset operational information**을 사용합니다. 저장된 이전 분석은 읽기·표시 단계에서 현재 역할 이름으로 변환하고 원문 인용과 제품 식별값은 보존합니다.

## 현재 실행 경로

프로젝트 루트 `C:/ICS-VEX`에서 실행합니다.

```powershell
python -B -X utf8 tools/item4/serve_nist_operational_vex.py 8100
```

| 영역 | 현재 구현 |
|---|---|
| #3 식별 | `src/item3/matching/sbom_candidate_service.py` → `identification_pipeline.py` |
| #3 에이전트 | I1 컴포넌트명, I2 버전·모델, I3 CPE·PURL 근거 검토와 별도 검증 |
| #4 분석 시작 | `src/item4/web/asset_vex_questionnaire_api.py` → `workflow/source_analysis_jobs.py` |
| #4 운영정보 질문 | `src/item4/assets/asset_observations.py` → `analysis/asset_operating_question_generation.py` |
| #4 필요 운영정보 식별 | `analysis/operating_information_requirements.py`: 개별 악용조건을 확인할 정보·자료·제약으로 변환 |
| #4 분기 질문 트리 | `analysis/operating_question_tree.py`, `web/operating_question_tree.js`: 원래 관계식에 따라 다음 질문 선택 |
| #4 조건·판단 | `analysis/exploitation_prerequisites.py`, `decision/asset_vex_assessment.py` |
| #4 현재 질문·논리 평가 | `src/item4/evaluation/source_question_benchmark.py`, `tools/item4/evaluate_source_question_contract.py`, `tests/item4/test_condition_pipeline_contract.py` |

날짜가 포함된 `local-service/` 코드도 현재 서비스가 실제로 불러옵니다. [소스 구조](src/README.md) · [실행 도구](tools/README.md)

## 항목 3 데이터와 평가

현재 원본은 `benchmark/icsa-cpe-synthetic sbom/sbom`의 CPE 보강 v3 문서 3,881개입니다. 기존 CSAF·HTML 구성요소 29,066개와 별도 NVD 후보 78,200개를 합쳐 107,266개 구성요소를 보유합니다. NVD 조건은 실제 설치 버전을 뜻하지 않습니다.

| 입력 v5 | train | test | 전체 |
|---|---:|---:|---:|
| SBOM 입력 | 7,737 | 5,468 | 13,205 |
| 대상 고유 CVE | 7,593 | 3,254 | 10,847 |

위치는 `benchmark/item3_advisory_inputs_v5`입니다. 기준본 3,881개와 I1·I2·I3별 실제 변형 3,108개씩을 포함합니다. CVE·동일 입력의 분할 중복은 0입니다. 제품 전체 미노출과 기존 어댑터의 새 test 미노출은 보장하지 않습니다.

```powershell
python -X utf8 tools/item3/run_item3_test.py run --mode agents --dataset benchmark/item3_advisory_inputs_v5/test --output results/item3_test_new_run
```

출력은 새 경로를 사용합니다. `--mode rules`는 규칙 기준선입니다. 모델에는 SBOM만 제공하고 예측 저장 후 별도 채점하며, `test_report.json`에 전체·변형별 성능과 기준본/변형본 비교를 기록합니다. 과거 18,608건 평가와 점수는 현재 v5 성능으로 재사용하지 않습니다. [입력·정답·실행 절차](docs/ITEM3_TEST_WORKFLOW.md)

시험관용 실행은 활성 test 폴더의 SBOM 파일 중 30%를 비복원 무작위 추출합니다(현재 5,468개 중 1,640개). 선택한 파일로 식별을 실행하고 해당 파일의 정답만 채점합니다. 선택 목록은 결과 폴더의 `run_config.json`, 난수 시드는 `certification_result.json`에 기록합니다. 같은 표본을 재현하려면 아래 명령에 `-Seed <기록된 숫자>`를 붙이고 전체 평가에는 `-Full`을 사용합니다.

```powershell
.\tools\item3\run_item3_certification.ps1
```

기본 `agents` 평가는 제품 후보를 확정하기 전에 I3 모델의 선택과 독립적인 사전 근거를 모두 요구합니다. 버전 범위 비교와 정답 채점은 코드가 수행합니다. 에이전트 시험의 시간 기준은 180초 미만입니다. 아래의 259.04초는 이 변경 이전에 모델 호출 없이 측정한 전체 실행 기록입니다.

2026-11-25 현재 PC(논리 CPU 24개, RAM 32GB), CPU 프로세스 8개에서 v5 test **5,468개 파일·87,576개 구성요소를 259.04초**에 완료했고 실행 오류는 0건입니다. Python 시작·종료와 결과 저장을 포함한 실측입니다. 정형 근거 우선 검증, 실행 중 동일 구성요소 재사용, 원천 조건 사전 파싱과 CPU 분산을 사용합니다. 이 입력에서 실제 LLM 호출은 0건으로, 소프트웨어 매핑 평가 결과입니다. [실측 결과](results/item3_five_minute_20261125/agents_full_07/certification_result.json) · [벽시계 시간](results/item3_five_minute_20261125/agents_full_07/process_wall_time.json)

현재 시험은 SBOM 구성요소별 정답 CVE 목록을 기준으로 채점합니다. 목록에 있는 확정 출력은 TP, 목록 밖 확정 출력은 FP, 출력하지 않은 정답은 FN입니다. 정밀도는 전체 TP를 전체 TP와 FP의 합으로 나눕니다. 기준은 80% 이상이며, 확정 출력이 하나도 없으면 정밀도는 정의되지 않습니다.

## 항목 4 운영정보 기반 악용 가능성 평가와 VEX 생성

BOM으로 식별한 CVE와 제품·버전에 공식 원문을 연결하고, 악용 조건·관계를 추출한 다음 운영자가 확인한 환경 정보로 VEX를 평가합니다. LLM은 조건과 질문을 제안하고, 코드는 인용·범위·구조를 검증하고 True/False/Unknown 논리를 계산합니다. 자동 검증은 의미 정확도나 실제 악용 성공을 보증하지 않습니다.

### 조건: AV·PR·UI·AT·IC

| 출력 항목 | 원문에서 추출하는 내용 |
|---|---|
| AV — Attack Vector | 공격자의 접근 위치·경로 |
| PR — Privileges Required | 공격 전에 필요한 동일 공격자의 인증·권한 |
| UI — User Interaction | 공격자 외 사용자가 수행해야 하는 동작 |
| AT — Attack Requirements | 공격 성립에 관련된 특정 배치·실행 요건 |
| IC — ICS 운용 조건 | 산업용 기능·프로토콜의 설정, 제어기 모드, 엔지니어링·제어 장치 연결 |

앞의 네 항목은 CVSS v4.0 개념을 원문 사실 분류에 사용합니다. IC는 프로젝트 확장이며 CVSS 지표·점수가 아닙니다. 제품·버전 적용성은 별도 게이트이고, 어느 항목에도 귀속되지 않는 운영 조건은 `OTHER`로 보존합니다.

IC는 동일 개별 악용조건의 `ics_context`에 다음 유형과 정확한 원문 `quote`를 저장합니다.

- `feature_configuration`: 명시된 산업용 기능·프로토콜의 활성화·설정
- `operating_mode`: 제어기 운전 모드·물리적 모드 선택기 상태
- `engineering_connection`: 특정 엔지니어링 워크스테이션·제어 장치 연결·구성

예를 들어 원문이 Modbus TCP 기능 활성화를 악용 경로의 조건으로 설명하면 그 사실을 하나의 조건으로 저장하고 IC로 참조합니다. 같은 조건이 AT에도 해당하면 AT와 IC가 같은 ID를 참조합니다. IC 때문에 개별 악용조건·질문·AND 항을 복제하지 않습니다. 산업용 장치에 일반 HTTP 입력이 존재한다는 사실만으로 IC를 부여하지 않습니다.

### 관계: 개별 악용조건을 공유하는 AND·OR·NOT

각 개별 악용조건은 하나의 긍정형 사실이며 `predicate`, `target`, `value`, `statement`, 원문 인용, 제품 범위, 관측 방법, 필수성, confidence를 갖습니다. 필요한 부재는 NOT으로, 실제 대체 경로는 OR로 표현합니다. 단순 나열은 AND의 근거가 아닙니다. 관계가 불명확하면 조건은 보존하고 관계를 Unknown으로 남깁니다. 원문이 설명한 한 경로를 전체 CVE의 필요충분조건으로 확대하지 않습니다.

`source_dimensions`는 AV·PR·UI·AT·IC별로 `stated`/`unknown`과 조건 ID·비필수 진술·보존 사실의 참조를 제공합니다. IC는 `ics_context`가 붙은 공유 조건을 참조합니다. 미언급은 CVSS None이나 실제 자산의 False를 뜻하지 않으며 `metric_value`는 null입니다.

### 검증 규칙과 근거 수집

모든 지원 BOM의 CVE에 동일한 근거 수집 경로를 적용합니다. CVE Description과 해당 CVE·제품에 귀속된 ICSA 및 공식 공급사 권고문을 사용할 수 있습니다. IC 근거가 CVE Description에도 존재할 수 있어 ICSA 전용으로 제한하지 않습니다. URL, 원문 해시, 정확한 인용과 CVE·제품 범위를 보존합니다.

추출과 독립 원문 재검토에 같은 IC 계약을 적용합니다. 모델이 `condition_type`과 IC 태그를 제안하고, 코드는 허용 조합·리터럴 인용·범위·중복 ID·관계 참조·관측 가능성을 검사합니다. IC 태그의 구절 단서는 보수적인 오분류 방지 검사이며 모든 산업 프로토콜이나 문장 의미를 완전히 검증하는 분류기는 아닙니다.

다음 추론은 허용하지 않습니다.

- BOM에 제품이 있으므로 기능이 활성화되어 있거나 특정 모드라고 단정
- 업종·국가·제품명·안전 영향만으로 악용 조건 생성
- 공통 보안 권고나 “PROGRAM 모드를 피하라”를 “PROGRAM 모드가 필수”로 반전
- 다른 CVE의 조건, 인증 불필요, 관리자 권한, 프로토콜·포트를 추정
- IC가 있다는 이유로 CVSS AT 값을 자동 대입하거나 악용 가능으로 확정

검증 오류는 해당 단계에서 최초 실행을 포함해 최대 3회 수정·재검증합니다. 낮은 confidence를 높이기 위한 반복 생성은 하지 않습니다. 원문 수집 실패, 관측 불가능한 필수조건, 관계 누락은 Unknown으로 보존합니다.

### 운영정보 질문과 VEX

| 단계 | 처리 |
|---|---|
| V1 | 선택한 제품 하나의 자산 유형을 잠정 분류하고 확인 자료에 연결. 실제 운영 상태를 공급하지 않음 |
| V2 | 원문에서 다섯 항목의 조건·근거·AND/OR/NOT 관계 추출 및 검증 |
| V3 | 개별 악용조건별 필요 운영정보를 식별하고 자산별 확인 자료·질문·분기 트리로 연결 |
| V4 | 제품·버전·배포 범위와 운영자 답변을 결합해 세 값 논리 및 VEX 계산 |

V2 extraction confidence >0.8, V3 question confidence >80/100을 적용합니다. 점수는 모델 자체 보고 값이며 정확도 확률이 아닙니다. IC 모드 질문에는 현재 모드·설정과 관측 시각을 확인하도록 안내합니다. 운영자는 예/아니요/모름과 자료 참조·확인 시각·기록자를 입력합니다. BOM·기본값·운영 절차로 답변을 자동 채우지 않습니다.

### 선택 제품과 CVE별 질문 트리

BOM 업로드 후 제품명과 버전 범위로 분석 대상을 선택합니다. 긴 내부 ID는 목록에 표시하지 않지만 정확한 제품 참조값으로 보존합니다. 선택 제품에 명시적으로 연결된 CVE만 V1·V2 분석과 V3 트리에 전달하며, 다른 제품과 미연결 CVE는 `analysis_scope`에 제외 대상으로 기록합니다. 원본 BOM과 기존 취약점 항목은 보존합니다. 권고문의 영향 버전 범위는 실제 설치 버전으로 취급하지 않습니다.

트리의 최상위 노드는 CVE ID입니다. V2의 AND/OR/NOT 관계를 유지하며 답변에 따라 필요한 다음 질문만 선택합니다. AND의 False, OR의 True로 결정된 부분은 건너뛰고 답변을 만들지 않습니다. 명시적 Unknown은 방문 기록만 저장하고 다른 유효한 질문으로 진행합니다. 이전 답변 수정·확인 기록 입력·전체 분기 미리보기를 지원하며, 큰 그림의 미리보기 제한은 전체 조건식 평가와 질문 선택을 제한하지 않습니다. 트리의 결과는 알려진 원문 조건식의 상태이며 최종 VEX는 V4가 판정합니다.

### 개별 악용조건 → 필요 운영정보 → 확인 자료 → 질문

`operating_information_requirements.py`는 V2가 이미 추출한 개별 악용조건을 `information_requirement`로 변환합니다. 조건 ID·CVE·구성요소·대상·원래 상태값·전체/일부 수량 조건·원문 한정사항·인용·관측 범위와 원래 확인 방법을 보존합니다. 행위자·출발지가 V2에서 별도 필드로 구조화되지 않았다면 문장에 보존하고 임의로 분리하거나 채우지 않습니다.

| 필요한 운영정보 | 확인 자료 연결과 제한 |
|---|---|
| 기능·설정·입력 가용성 | 현재 적용 설정과 정확한 입력 목록. 설치·지원·기본값만으로 현재 활성 상태를 확정하지 않음 |
| 접근·엔지니어링·정비 연결 | 동일 출발지·목적지·방향의 통신 설정, 적용 접근 규칙, 범위를 명시한 연결 기록. ACL 하나로 종단 간 도달성을 확정하지 않음 |
| 인증·권한 | 같은 행위자·작업·자원의 정책과 계정/역할 권한 기록. 관리자 역할이나 자격증명 보유를 추정하지 않음 |
| 운영 모드 | 현재 모드 표시·선택기·관측 기록. AT 범주만으로 운영 모드라고 분류하지 않음 |
| 파일 반입·입력 처리·사용자 작업 | 같은 자격을 가진 사용자의 동작·처리·정비 기록. 절차 문서만으로 동작 발생을 확정하지 않음 |
| 물리·로컬 콘솔 접근 | 해당 인터페이스의 접근 정책·현장 점검·정비 기록. 인터페이스 존재를 접근 사실로 대체하지 않음 |

V1 유형에 따라 호스트/어플라이언스, 제어·현장 장치, 네트워크 장치의 확인 자료 위치를 선택합니다. 유형이 미확정이면 원문 기반의 일반 확인 자료를 사용하고 질문을 유지합니다. 같은 자료 종류라는 이유로 자산별 질문 전체를 추가하지 않습니다. 모델에는 고정된 요구사항·확인 자료·검증 한계를 전달하며 질문의 긍정형 사실과 원래 `record_type`은 유지합니다. 요구사항·매핑 변경은 질문 캐시와 이전 답변의 재확인을 유발하고, 요구사항과 매핑은 V4 `evidence_chain`에도 포함됩니다.

질문 누락·탈락·미확인 조건은 원래 관계에서 Unknown으로 남습니다. 미확정 근거와 충돌은 `under_investigation`으로 처리하며, 알려진 경로가 차단됐다는 이유만으로 제품의 `not_affected`를 주장하지 않습니다. 조건이 없다는 결과도 악용 불가의 증거가 아닙니다.

평가 근거에는 원문·실행 해시, 공유 조건과 IC 태그, 질문·답변·확인자료, 관계식, 제품 범위와 결론을 연결합니다. 표준 내보내기는 OpenVEX와 CycloneDX VEX를 지원하며 `evidence_chain`은 프로젝트 확장 정보입니다. 분석 JSON 다운로드와 표준 VEX 내보내기를 구분합니다.

### 실행과 현재 검증 범위

- 분류 계약: `GET /api/item4/analyses/condition-taxonomy`
- 자동화·질문 계약: `GET /api/item4/analyses/automation-policy`
- 상세 모듈 안내: [src/item4/README.md](src/item4/README.md)

배포 시에는 CVE별 검증 결과를 사전 저장하고 BOM 입력에서는 조회·환경 대조를 수행하는 연결이 필요합니다. 현재 성공 캐시는 전체 원문·모델·프롬프트·스키마 등에 묶이며 새 추출은 공통 잠금의 영향을 받습니다. 다수 신규 CVE의 사용자 대기 시간과 운영 캐시 연결은 별도 운영 과제입니다.

진행 중인 12,418개 전수 검증은 **기존 네 항목·CVE Description만 사용하는 고정 코드 사본**에서 이어갑니다. 결과 위치는 `results/item4_cvss_population_20261127_full/`이고, 코드 사본은 그 아래 `frozen_workspace/`입니다. 이 실험의 H200 Nemotron 결과를 IC 확장이나 운영 기본 Qwen의 성능으로 주장하지 않습니다. IC 확장 계약 검사는 합성 응답과 실제 원문 구절로 근거 차단·질문 전달을 확인합니다. H200의 [단일 CVE 시험](results/ics_operating_extension_20261128/live_smoke_final/summary.json)에서는 IC 조건 2개를 보존했지만 독립 원문 재검토가 실패해 미확정으로 남았습니다. 독립 전문가 정답 정확도 검증과 구분합니다.

## 검증과 저장 위치

```powershell
python -B -X utf8 -m pytest tests/item4/test_operating_information_requirements.py tests/item4/test_selected_product_analysis.py tests/item4/test_operating_question_tree.py tests/item4/test_condition_pipeline_contract.py tests/item4/test_asset_aware_question_generation.py -q
node tests/item4/test_item4_questionnaire_ui.cjs
node tests/item4/test_operating_question_tree.cjs
```

`src/`는 실행·평가 구현, `tools/`는 실행 명령, `tests/`는 검사, `benchmark/`는 평가 입력, `results/`는 실행 결과, `research_records/`는 연구 스냅샷입니다. 독립 전문가 라벨과 실제 자산의 악용 정답이 부족한 부분은 확정 정확도로 보고하지 않습니다.

GitHub 최신화에서는 HWP/HWPX·엑셀·CSV 파일과 로컬 자격증명·세션 DB·추론 캐시를 제외합니다. 이 제외는 원본 데이터 삭제를 의미하지 않습니다. 별도로 보관하는 `benchmark/item4_evaluation/catalog/operator_asset_keys_clustered.csv`와 모델·원문 자료 등 로컬 실행 의존성은 실행 환경에 준비해야 합니다. GitHub Pages의 정적 화면과 로컬 API/모델을 사용하는 실제 분석을 구분합니다.

Pages 화면은 `python tools/item4/export_questionnaire_pages.py`로 갱신합니다. 로컬 API 화면을 그대로 복사하지 않고, Pages 연결 브리지를 먼저 로드하고 프로젝트 경로에 맞는 상대 리소스 주소로 내보냅니다.

2026-11-28 운영정보 요구사항 확장 검증에서는 관련 회귀 검사 **375개와 하위 사례 5개**, 운영자 입력 화면 및 분기 트리 Node 검사가 통과했습니다. 원문 조건·자료 연결·자산 범위·모름·논리 보존·변경 감지에 대한 계약 검사이며, 실제 모델의 독립 의미 정확도나 현장 악용 가능성 정확도를 측정한 결과는 아닙니다.
