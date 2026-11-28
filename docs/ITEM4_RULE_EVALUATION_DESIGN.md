# 시험 항목 #4 독립 규칙 엔진·멀티 에이전트 평가 및 데이터 스키마

개정일: 2026-11-23 / 계약 버전: `item4-rule-evaluation/1`

## 1. 적용 범위와 기존 문서와의 관계

이 개정은 시험 항목 #4의 평가 설계를 세 부분으로 정의한다. ① 네 가지 VEX 상태 라우팅 규칙의 명세와 검증, ② LLM이 원문에서 추출한 악용 조건의 타당성 평가, ③ 악용 조건과 자산 유형별 key-value의 결합·최종 라우팅 평가이다. ③은 정답 조건을 제공하는 분리 평가와 추출 오류를 포함하는 전체 평가로 나눈다.

이 개정 범위에서는 전문가 수동 라벨을 필수 전제로 두지 않는다. 대신 생성 과정을 아는 통제 원문과 구조화된 시나리오에서 독립 규칙 엔진으로 정답을 계산한다. 실제 CVE 원문을 자유롭게 해석한 결과는 별도 근거 검토가 필요한 후보이며, 인용문 일치·다중 역할 합의만으로 참인 정답으로 승격하지 않는다. 기존 문서의 전문가 검토 필수 설계와 85% 기준은 이 새 통제 평가에 적용하지 않는다. 목표는 상태별 Precision > 0.90이며 미예측 클래스의 Precision은 null이다.

기존 Nemotron 97,553건 결과와 공급사 원천 데이터는 보존한다. 이번 버전은 별도 평가 모듈·CLI이며 운영 중인 8100 서비스의 질문지·판단 정책을 자동 교체하지 않는다. 기존 API·UI의 잔존 경로 제거는 별도 마이그레이션 대상이다. 기존 결과를 새 실험 결과로 재분류하지 않는다.

## 2. 독립 규칙 엔진

엔진 구현은 `src/item4/item4_rule_contract.py`이다. 이 모듈은 모델 제공자나 모델 출력을 가져오지 않는다. 입력은 고정된 근거 사실, 정답 조건식, 자산 관측값이다. 출력은 상태, 규칙 ID, 검토한 규칙 목록, 조건별 값, 논리식 값, 근거 참조, 사실 해시이다. 순서가 있는 첫 일치 규칙을 적용한다.

| 우선순위 | 규칙 ID | 조건 | 출력 |
|---|---|---|---|
| 1 | R0 | 평가 범위 미확인, 제품 연결 실패, 또는 근거 충돌 | under_investigation |
| 2 | R1 | 대상 부재가 확인되고 현재 범위 인벤토리가 완전함 | not_affected |
| 3 | R2 | 그 외에 실행 중 배포와 정확한 실행 빌드가 확인되지 않음 | under_investigation |
| 4 | R3 | 실제 실행 빌드에 일치하는 공급사 fixed 근거 | fixed |
| 5 | R4 | 실제 실행 빌드에 일치하는 공급사 known_not_affected 근거 | not_affected |
| 6 | R5 | known_affected, 조건-제품 연결 유효, 조건식 참, 충분한 공격 경로라는 명시 전제 | affected |
| 7 | R6 | known_affected, 조건-제품 연결 유효, 조건식 거짓, 관련 경로 전체를 다룬다는 명시 전제 | not_affected |
| 8 | R7 | 위 확정 규칙 어느 것도 성립하지 않음 | under_investigation |

수정 버전의 발표만으로 설치 완료를 추정하지 않는다. 필요조건 충족만으로 충분성을 추정하지 않는다. 일부 알려진 경로가 차단된 사실만으로 전체 비영향을 선언하지 않는다. 인벤토리 완전성 누락은 완전함으로 기본 처리하지 않는다. 실제 자료에서는 충분성·경로 완전성의 명시적 증거가 없으면 해당 불리언을 false로 두며, 이 값은 LLM 동의 여부로 정하지 않는다. 이 버전의 true 값은 명시적으로 생성된 가상 세계의 전제이다.

### 2.1 3값 논리와 값 매핑

| 연산 | 참 조건 | 거짓 조건 | 나머지 |
|---|---|---|---|
| AND | 모든 항이 true | 하나 이상 false | unknown |
| OR | 하나 이상 true | 모든 항이 false | unknown |
| NOT | 입력 false | 입력 true | unknown |

자산 입력 o는 true, x는 false이다. unknown·mixed·not_applicable은 unknown이다. 조건 ID·key·target·scope_id·asset_type_id를 구분한다. 현재성 current=true와 등록 evidence_ref를 요구한다. 누락·상충·다른 대상·다른 범위·다른 자산 유형·오래된 기록은 조건을 확정하지 못한다. 비관측 공격자 자격증명 소유를 서비스 설정값으로 대체하지 않는다.

## 3. 평가 대상 멀티 구조

| 역할 | 입력 | 출력 | 평가에서의 위치 |
|---|---|---|---|
| extract | 원문, 허용 key, 자산 범위 | 긍정 원자 조건, 인용문, AND/OR/NOT 식 | 조건 추출 |
| review | 원문과 추출 초안 | supported/unsupported/unknown, 문제, 인용 | 독립 역할 검토 |
| mapping | 조건, 자산 key-value, 근거 | 조건별 true/false/unknown과 이유 | 의미·범위 매핑 |
| routing | 근거 사실, 조건, 매핑 결과, 공개 정책 | VEX 상태, 규칙 ID, 근거, 설명 | 최종 판단 |

같은 모델의 역할별 호출을 유지한다. review는 원문과 초안을 별도 프롬프트로 검토하지만 독립된 다른 모델이 아니므로 통계적 독립성은 주장하지 않는다. 모델 내부 MoE와 이 역할별 오케스트레이션은 구별한다. Nemotron은 기존 고정 모델 제공자를 연결할 수 있고, 기본 제공자는 기존 prerequisite_llm 인터페이스를 재사용한다.

## 4. 세 평가와 전체 평가

| 실행 트랙 | 모델에 제공되는 중간값 | 평가 출력 | 목적 |
|---|---|---|---|
| routing | 정답 조건과 정답 조건별 값 | 최종 상태·규칙 | ① 라우팅만 격리 |
| extraction | 원문 / 통제 변형 초안 | 추출 조건·식 / 검토 결과 | ② 추출·타당성 검토 |
| integration | 정답 조건 | 모델 매핑·최종 상태 | ③ 자산 운영 정보 값 결합과 라우팅 |
| end_to_end | 원문·자산 운영 정보 값·근거 | 추출·검토·매핑·상태 | 전체 오류 전파 |

모든 트랙에서 정답 상태와 정답 규칙은 모델 입력에서 제외한다. routing 트랙의 정답 중간값 제공과 integration 트랙의 정답 조건 제공은 명시적인 분리 평가이다. 모델의 최종 출력을 독립 엔진으로 덮어쓰지 않는다. 따라서 최종 상태의 맞고 틀림을 모델 출력 그대로 평가할 수 있다. 실제 서비스에서 엔진을 강제 게이트로 사용하면 별도의 시스템 전체 평가로 보고해야 한다.

추출은 원자 조건의 key·target·polarity를 비교하고 원문 인용을 확인한다. 논리식은 최대 7개 원자의 전체 3값 조합으로 의미 동치를 확인하여 ID 변경과 교환법칙을 허용한다. 검토 평가는 대상 치환, 인용 조작, 부정 추가, AND/OR 교체 등 통제 변형의 정답과 비교한다. 자유로운 실제 문장의 의미 정확성을 이 검사만으로 인증하지 않는다.

## 5. 데이터셋 및 평가 결과 계약

현재 자산 key 카탈로그의 18개 유형을 사용한다. AND·OR·NOT·중첩·필요조건만 있는 원문·조건 없는 원문을 생성하고 값 조합 및 결측·충돌 대조군을 만든다. 이는 실제 CVE를 사칭하지 않는 명시적인 가상 문장이다. 총 2,232개이며 affected 162, not_affected 450, under_investigation 1,512, fixed 108개이다. 이 분포는 통제 검증 분포이며 현장 발생 비율이 아니다.

학습·개발·시험 구분은 원문 논리 템플릿 계열로 분리한다. AND는 train, OR는 dev, 나머지는 test이다. 실제 CVE·제품 단위 일반화나 기저 모델 사전학습 미노출을 보장하지 않는다. 이 데이터셋으로 모델 학습은 실행하지 않았다. 동일 원문의 변형 시나리오는 동일 분할에 속한다.

상태별 TP/(TP+FP), 추출 원자 조건 Precision, 확정 매핑값 Precision, 규칙 일치 건수, 논리식 의미 일치 건수를 저장한다. 확정 출력이 없으면 Precision을 null로 기록하며 100%로 처리하지 않는다. 보류 건수·확정 판단 건수·실행 실패를 함께 보고한다. 통제 사례의 높은 Precision은 실제 현장 악용 가능성 Precision을 자동 입증하지 않는다.

## 6. 데이터 스키마: 평가 사례

명시적 JSON Schema는 `results/item4_rule_evaluation_v1/output_schemas.json`에 내보낸다. 모든 정의 객체는 추가 필드를 금지한다. 사례 본문은 필수 필드를 갖고, private 파일에만 id와 expected를 덧붙인다.

| 필드 | 자료형 | 의미·제약 |
|---|---|---|
| contract_version | string const | item4-rule-evaluation/1 |
| synthetic | boolean const true | 통제 합성 사례임을 표시 |
| scope_id | string | 평가 시점·구성·대상 범위를 식별 |
| asset_type_id | string | 카탈로그 자산 유형 A0001-A0018 |
| allowed_keys | string[] | 해당 자산 유형에 등록된 key |
| evidence_ids | string[] | 사례에서 허용된 근거 ID |
| source_id, source_text | string | 원문 근거 ID 및 통제 원문 |
| facts | object | 공급사·배포·범위·충분성·완전성 사실 |
| asset_values | object[] | 범위와 출처가 붙은 자산 key-value |
| reference | Extraction | 생성 규칙에서 얻은 정답 조건·논리식. 공개 모델 입력에서 제거 |
| template_id, split, mutation | string | 템플릿·분할·대조군. 공개 모델 입력에서 제거 |
| id | string | 사례 내용 해시 기반 식별자 |
| expected | OracleDecision | 규칙 엔진 정답. 공개 모델 입력에서 제거 |

### 6.1 facts

| 필드 | 자료형·허용값 | 의미 |
|---|---|---|
| scope_confirmed, product_bound | boolean | 범위 확정·제품 연결 |
| conflicting | boolean | 판단에 관련된 근거 충돌 |
| deployment | running / absent / unknown | 해당 구성요소 배포 상태 |
| inventory_complete | boolean | 명시적 범위 인벤토리 완전성 |
| runtime_exact | boolean | 근거의 빌드와 실제 실행 빌드 일치 |
| supplier_status | fixed / known_not_affected / known_affected / under_investigation / unknown | 일치하는 공급사 상태 |
| condition_binding_valid | boolean | 조건과 대상 제품·범위 연결이 유효함 |
| route_sufficient | boolean | 참인 조건식이 충분한 경로라는 명시 전제 |
| paths_exhaustive | boolean | 조건식이 관련 경로 전체를 표현한다는 명시 전제 |

### 6.2 asset_values 원소

| 필드 | 자료형·허용값 | 의미 |
|---|---|---|
| asset_type_id, key | string | 자산 유형과 등록 속성 |
| target | string | 인터페이스·기능·서비스 등 확인 대상 |
| scope_id | string | 해당 값의 평가 범위 |
| value | o / x / unknown / not_applicable / mixed | 긍정 원자 상태의 관측값 |
| current | boolean | 현재 평가 범위에 유효한 기록인지 |
| evidence_ref | string | 사례에 등록된 근거 ID |

## 7. 데이터 스키마: 모델 출력

### 7.1 Extraction

| 필드 | 자료형 | 의미 |
|---|---|---|
| conditions | Condition[] | 긍정 원자 조건 목록 |
| conditions[].id | string | 논리식 참조용 유일 ID |
| conditions[].key | string | 대응할 자산 속성 key |
| conditions[].target | string | 원문 조건의 구체 대상 |
| conditions[].polarity | const positive | 부정은 원자 값이 아닌 NOT 노드로 표현 |
| conditions[].quote | string | 원문에 실제 존재하는 인용문 |
| expression | Expression 또는 null | 조건 참조 또는 and/or/not 재귀식 |

Expression의 잎은 {"condition":"c1"}이다. AND/OR 노드는 {"op":"and","args":[...]} 형태로 자식이 2개 이상이고 NOT은 자식이 정확히 1개이다. 조건이 없으면 conditions=[]와 expression=null이다. 선언 조건 ID와 참조 ID가 같아야 한다.

### 7.2 Review, Mapping, Routing

| 객체 | 필드 | 자료형·의미 |
|---|---|---|
| Review | support | supported / unsupported / unknown |
| Review | issues, evidence_quotes | string[]; 발견 문제와 원문 인용 |
| Mapping | values | 조건별 매핑 객체 배열 |
| Mapping.values[] | condition_id, key | 추출 조건과 속성 연결 |
| Mapping.values[] | value | true / false / unknown |
| Mapping.values[] | reason | 해당 값으로 해석한 이유 |
| Routing | status | fixed / not_affected / under_investigation / affected |
| Routing | rule_id | R0-R7 |
| Routing | evidence_refs | 등록된 근거 ID 배열, 하나 이상 필요 |
| Routing | reason | 판단 설명 |

Mapping은 조건당 정확히 한 행이어야 하며 다른 key로 바꿀 수 없다. Review의 인용문은 원문에 존재해야 한다. 근거 없는 지원 판정과 미등록 라우팅 인용은 실행 계약 오류로 기록한다. 구조적 검증 통과가 의미 정확성의 증명은 아니다.

## 8. 데이터 스키마: 정답·실행 기록·보고서

| 객체 | 필드 | 설명 |
|---|---|---|
| OracleDecision | status, rule_id | 결정 상태·첫 일치 규칙 |
| OracleDecision | condition_values, formula_value | 조건별 근거·값 및 전체 3값 결과 |
| OracleDecision | evaluated_rules, evidence_refs | 검사한 우선순위 규칙과 근거 |
| OracleDecision | facts_sha256, policy_version, basis | 사실 해시·정책 버전·통제 정답 표시 |
| Execution | id, expected, prediction 또는 error | 사례 단위 정답·모델 출력·오류 |
| Execution | receipts | 실제 모델 식별 및 llm_used 표시. 테스트 대역은 모델 점수로 사용 금지 |
| Report | cases, model_completed, model_failed | 모집단·성공·실패 건수 |
| Report | classes | 상태별 tp/fp/predicted/precision |
| Report | extraction, mapping | 단계별 TP/FP와 Precision |
| Report | abstained, confirmed_predictions | 보류·확정 건수 |
| Report | model_performance_measured | 실제 모델 호출 성공에 따른 성능 측정 여부 |
| Manifest | data_sha256, policy_sha256, catalogue_sha256 | 재현을 위한 입력·정책·카탈로그 지문 |

파일은 results/item4_rule_evaluation_v1 아래에 저장한다. cases.private.jsonl은 정답을 포함하며 모델 접근 대상이 아니다. cases.public.jsonl은 정답과 분할 메타데이터를 제거한 입력이다. 모델별 결과는 model-routing, model-extraction, model-integration, model-end_to_end로 분리한다. 이 버전은 새로운 SQLite 테이블을 추가하지 않고 JSON/JSONL로 저장한다.

## 9. 실행·검증 및 현재 상태

생성 명령: `python tools/item4/evaluate_item4_rules.py`

자동 검사: `python -m pytest tests/item4/test_item4_rule_evaluation.py -q`

기본 제공자 평가: `python tools/item4/evaluate_item4_rules.py --run-model --track all --limit 16`

기존 Nemotron 제공자 평가: `python tools/item4/evaluate_item4_rules.py --run-model --track all --limit 16 --nemotron-manifest <기존 모델 identity JSON> --port 18128`

연결 진단 및 기존 터널 복구: `python tools/item4/diagnose_h200_connection.py --repair --evaluate`. 현재 프로세스에서 소켓이 거부되면 정상 프로젝트 터미널에서 실행한다. 진단 도구는 현재 kubeconfig 문맥을 사용하고 자격증명을 출력하지 않는다. 먼저 전송 계층, 기존 pod 상태, pod 내부 모델, 로컬 터널의 모델 ID 순서로 확인한다. 기존 H200 서비스가 정상임을 확인한 경우에만 루프백 터널을 복구한다. pod·배포·권한·인증서 검증 설정은 변경하지 않는다. 네트워크 전송 이전 실패를 인증 실패나 GPU 장애로 오인하지 않는다. 진단 결과는 h200_diagnostic.json, 새 평가 결과는 각 model-* 디렉터리에 기록한다. 모델 실행 실패가 있으면 평가 CLI는 종료 코드 2를 반환한다.

현재 구현·합성 사례 생성·26개 자동 검사가 완료되었다. 실제 LLM 성능 평가는 미실행이다. 현 도구 환경에서 127.0.0.1:18128과 :8100 모두 Windows 소켓 오류 10013으로 거부되어 H200 연결 상태는 확인하지 못했다. 이는 서버 장애의 증거가 아니다. 기존 H200 실행은 완료 기록으로 보존된다. 시험 통과 건수를 LLM Precision으로 보고하지 않는다.

이번 문서 개정은 원본 설계서 뒤에 부록으로 추가한다. 앞선 본문과 평가 정책이 충돌하는 경우 이 개정 범위에서는 본 부록을 따른다. HWP 편집 가능 원본과 PDF의 갱신 상태는 문서 생성 기록에 별도로 남긴다.
