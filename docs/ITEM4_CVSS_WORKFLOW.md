# Item #4: 선택 제품의 원문 조건과 운영정보 질문 트리

현재 입력 계약은 `item4-source-operating-input/5-information-requirements`이며 CVSS 공통 질문은 비활성이다.

## 실행 경로

1. 식별된 CVE를 포함한 CycloneDX/SPDX BOM을 받고 제품명·버전 범위로 분석 대상을 선택한다. 내부 ID는 선택값으로만 유지한다.
2. 선택한 제품의 명시적인 BOM 참조에 연결된 CVE만 남긴다. 같은 이름의 다른 버전·다른 제품·미연결 CVE를 합치지 않는다. 원본 BOM은 보존한다.
3. 선택한 제품 하나만 TF-IDF → SVD → K-means로 잠정 자산 분류한다. V2에는 이 제품의 CVE별 공개 원문과 구성요소 범위의 자산 맥락만 전달한다.
4. V2가 추출한 악용조건과 AND/OR/NOT 관계로 V3 질문 트리를 만든다. 자산별 사전은 정확히 대응하는 확인 자료를 연결하며 질문 자체를 추가하지 않는다.
5. 운영자가 현재 자산의 상태와 확인 기록을 입력한다. 트리가 필요한 다음 질문을 선택하며 V4가 제품·버전·범위·근거와 원문 조건식을 평가한다. 부족한 근거는 미확정으로 남긴다.

선택 범위는 `analysis_scope`에 제품 참조·이름·버전 범위·대상 CVE와 제외·미연결 CVE로
기록한다. 재시도·재시작 복구에서도 같은 제품 범위를 다시 적용한다. 권고문의 영향
버전 범위는 실제 설치 버전 확인값으로 취급하지 않는다. 연결된 CVE가 없으면 임의로
다른 CVE를 분석하지 않고 제품/CVE 식별 관계를 확인하도록 안내한다.

핵심 구현은 `src/item4/analysis/cvss_operational_questions.py`,
`src/item4/analysis/exploitation_prerequisites.py`, `src/item4/assets/asset_observations.py`,
`src/item4/decision/asset_vex_assessment.py`이다.

## 구형 CVSS 공통 질문 계약 — 현재 비활성

아래는 이전 계약의 참고 정보다. 현재 공통 질문 스키마 API는 410을 반환하고,
운영정보 질문은 V2 원문 조건에 근거한 경로만 사용한다.

정의 파일: `src/item4/assets/cvss_common_question_schema.json`.
API: `GET /api/item4/analyses/common-question-schema`.

| 지표 | 입력 대상 | 해석 제한 |
|---|---|---|
| AV | 평가한 공격 시작 위치에서 CVE에 필요한 네트워크·인접망·로컬·물리 접근 가능 여부 | AV:N은 인터넷 노출을 의미하지 않는다. 관련 인터페이스와 경로의 확인 범위가 불완전하면 미확정이다. |
| PR:L/H | 평가한 행위자가 대상 구성요소에서 필요한 권한을 사용할 수 있는지 | 실행 서비스 계정의 권한과 공격자의 권한을 구분한다. 자격증명 보유를 확인할 수 없으면 미확정이다. |
| PR:N | 추가 권한 질문 없음 | 인증 비활성 설정을 요구하는 조건으로 변환하지 않는다. |
| UI:R/P/A | 원문이 요구하는 사용자 동작의 가능 여부 | 실행 기록이 없다는 사실만으로 그 동작이 차단됐다고 판단하지 않는다. 구체적 동작이 없으면 미확정이다. |
| UI:N | 추가 사용자 동작 질문 없음 | 사용자가 없거나 기능이 꺼졌다는 속성을 만들지 않는다. |
| AC:H / AT:P | 원문에서 구체적인 운영 조건을 확인 | 지표만 보고 설정을 만들지 않는다. 명시적인 특수 조건 연결이 없으면 미확정 노드가 남는다. |

CVSS 3.0/3.1/4.0을 구분한다. v3에 AT를 만들지 않고, v4의 UI:P/A를 v3의 UI:R과 동일한 문자열로 덮어쓰지 않는다.
지원하는 평가가 없거나 원본 포인터 검증에 실패한 CVE도 제외하지 않는다.

설치 여부, 현재 실행 버전과 인벤토리 확인 범위는 같은 구성요소에 대해 한 번 입력한다.
인터페이스·CVE·관측 범위가 다른 접근 질문에는 같은 값을 자동 복사하지 않는다.
모든 질문은 기본값이 `unknown`이며 `o`, `x`, `unknown`, `not_applicable`, `mixed`를 보존한다.

## 특수 운영정보

운영정보의 기준 자료는 `benchmark/item4_evaluation/asset operation infomation`의 자산 유형별 XLSX 18개이다.
동결된 505개 속성 CSV는 용어·확인 자료의 참고 사전으로만 사용한다. 전체 목록을 입력 질문으로 열거하지 않는다.

특수 입력은 다음 요건을 모두 충족해야 한다.

- 해당 CVE description의 정확한 인용이 있다.
- 운영자가 확인할 수 있는 설정·접근 정책·운영 동작 등이며 관측 자료와 확인 방법이 있다.
- 실행 조건식에서 실제로 참조된다. 맥락 정보나 원문에서 불필요하다고 한 사실을 요구 조건으로 만들지 않는다.
- 구성요소·CVE·대상·관측 범위를 유지한다. 같은 이름의 다른 자산 속성에 답변을 전파하지 않는다.

각 개별 악용조건은 하나의 긍정 상태를 표현하고, 필요한 부재는 조건식의 NOT으로 표현한다.
원문이 요구하는 대안은 OR, 동시에 필요한 조건은 AND로 유지한다.
공통 접근 질문과 동일한 필수 원문 조건은 한 입력으로 연결한다. OR의 한 가지나 부정된 조건을 공통 필수 조건으로 승격하지 않는다.

특수 조건 추출은 CVE description을 사용한다. ICSA/CSAF는 제품·버전 상태와 CVSS 출처를 제공할 수 있지만, 이전 ICSA 특수 추출 결과를 새 description 추출로 표시하지 않는다.
구형 결과는 감사 자료로 남기고 명시적인 재시도 시 갱신한다. 새 입력 계약에서는 기존 응답의 범위를 다시 확인하며 예전 VEX 출력을 그대로 재사용하지 않는다.

## V3 자산 유형 기반 LLM 질문 생성

`src/item4/analysis/asset_operating_question_generation.py`가 V1의 잠정 자산 유형,
CVE 원문, V2의 고정 조건과 논리식, 이미 선택한 CVSS 공통 질문을 함께 받는다.
공통 질문은 코드가 선택하고, LLM은 추가 특수 조건의 질문과 기록 확인 방법을 작성한다.
자산 유형은 기록의 맥락을 제공하며 새로운 악용 조건의 근거가 되지 않는다.

V1 분류는 V2보다 먼저 완료한다. V2의 IC(다섯 번째 프로젝트 지표) 추출과
독립 검토에는 구성요소별 `asset_type_context`를 전달한다. 자산 유형별 기능·모드·
엔지니어링 연결의 확인 자료는 CVE 범위로 제한된 ICSA 원문을 읽고 관측 방법을
작성하는 참고 정보다. 자산 유형이나 프로필 자체는 인용 가능한 악용조건 근거가 아니다.
유형이 불명확하거나 대응 항목이 없어도 원문 조건 추출을 계속한다.

V3는 V2에서 추출한 원문 근거가 있는 악용조건만 질문으로 만든다. 각 질문의
`condition_mapping`은 조건 ID·시나리오 ID·CVE·구성요소·대상·범위와 대응 사전 키를
보존한다. 자산 유형만으로 질문을 추가하지 않는다. 시나리오 관계가 미확정인
원문 조건도 질문은 유지하되 `unmapped_source_conditions`에 관계 미확정을
남긴다. 운영자 답변만으로 원문 AND/OR/NOT 관계를 만들어내지 않는다.

각 조건을 `operating_information_requirements.py`에서 `information_requirement`로 변환한다.
원문 조건·대상·상태값·수량 조건·한정사항·범위·원래 관측 자료를 보존하고 기능/입력,
접근, 인증/권한, 현재 모드, 작업, 물리/콘솔 접근의 확인 자료와 한계를 선택한다.
AT 범주만으로 모드로 분류하지 않는다. 자산 유형에 따라 호스트·제어/현장 장치·
네트워크 장치의 자료 위치를 사용하고, 유형이 미확정이면 일반 원문 자료를 사용한다.
요구사항·`asset_record_context`·질문·원문 조건을 연결하며 자산 프로필 전체를 질문으로
열거하지 않는다. V2 IC 추출에 사용하는 자산 유형 맥락은 유지한다.
조건·대상·논리식·원래 record_type을 변경하거나 답변을 자동 입력하지 않는다.
이전 자산별 질문·엑셀·코드는 `backups/item4_asset_questions_before_condition_mapping_20261128_7c7551de/`
아래에 보존했으며 `manifest.json`으로 49개 파일의 SHA-256을 검증했다.

## V3 분기 질문 트리

운영정보 입력 화면은 `operating_question_trees`의 V2 조건식으로 다음 질문을 선택한다.
SSVC의 지표·대응 등급은 사용하지 않는다. 그래프의 분기는 각 긍정형 조건의
Yes / No / Unknown이며, NOT은 답변을 뒤집어 묻지 않고 원래 식에서 평가한다.
AND는 False, OR는 True인 하위 식이 있으면 이미 결정된 부분의 남은 질문을
건너뛴다. 건너뛴 질문에 False나 True를 자동 입력하지 않는다.

Unknown·해당없음·기록 충돌은 모두 논리적으로 Unknown이다. 운영자가
`Keep Unknown and continue`를 누르면 해당 질문을 방문한 것으로만 기록하고,
결과를 바꿀 수 있는 다른 질문으로 이동한다. 명시적 방문 기록은
`asked_question_ids`로 저장하므로 저장·재조회 후 같은 Unknown 질문을 반복하지 않는다.
이전 답변을 수정하면 필요한 질문을 다시 계산하며 원래 조건식·관측 기록은 보존한다.
공유 조건은 같은 구성요소·CVE 범위에서 한 번만 묻고, 서로 다른 시나리오는 OR 대안으로
유지한다. 관계가 미확정인 개별 조건은 별도로 질문하되 임의 AND 관계를 만들지 않는다.

기본 화면에는 현재 필요한 질문만 표시한다. `Review answered questions`로 지난 답변을
수정하고 `Show full tree`로 분기를 미리 볼 수 있다. 큰 트리의 그림은 최대 160개 노드,
40개 질문 깊이로 제한하지만 다음 질문 선택과 원본 논리 평가는 전체 식을 사용한다.
트리의 True / False / Unknown은 알려진 원문 조건식의 상태다. 원문 미확정 사항과
질문 생성 실패는 남기며, 제품·버전·관측 범위·증거 검증 및 최종 VEX는 기존 V4가 수행한다.

질문은 V2의 긍정 원문 조건을 정확히 포함한다. 조건 ID·대상·인용·범위·논리식과
Yes=True / No=False의 의미를 바꾸거나 조건을 추가할 수 없다. NOT은 서버에서만 평가한다.
사용 가능한 V2 조건이 없으면 모델을 호출하지 않고 `no_special_conditions`로 기록한다.
조건이 있는데 생성이 실패하면 질문을 임의 템플릿으로 대신 표시하지 않는다.
원래 조건은 V4에 남고 그 답은 Unknown이다. 공통 질문에 대한 답변은 계속 입력할 수 있다.

V1/V2 이후 큐 작업에서만 모델을 호출한다. 입력 계획 구성과 단순 조회는 V3를 호출하지 않는다.
기존 작업의 누락 질문은 Generate / retry missing analysis로 생성한다.
원문·V2·자산 분류·프롬프트가 바뀌면 캐시를 무효화하고 답변을 다시 확인한다.
현재 V3는 공유 Qwen 기반 모델을 사용하되 V2 어댑터와 과거 질문 어댑터를 비활성화한다.
별도로 학습된 최신 V3 어댑터라고 표시하지 않는다. 검증 오류와 원시 출력도 저장한다.

구조 검증은 자연어 의미 정확도나 현장 답변 가능성의 증명이 아니다.
[실제 모델 타당성 감사](ITEM4_LLM_VALIDITY_REPORT_20261126.md)는 원문 오류, 생성 실패,
질문의 사실·논리 보존, 확인 기록의 한계를 각각 설명한다.

## 판단의 의미

공통 질문 결과는 `requirements_met`, `known_routes_blocked`, `unknown`으로 표시한다.
이 값은 CVSS가 기술한 알려진 전제조건의 상태이며 공격 성공·모든 경로의 부재·제품 전체의 비영향을 증명하지 않는다.

V4는 공통 조건과 원문 특수 조건의 식을 AND로 결합하고, 각 CVSS 평가의 경로는 별도의 OR 대안으로 유지한다.
제품 식별, 실제 실행 버전, 원문 경로의 제품 적용 관계, 관측 범위 및 그래프 상태의 기존 검증은 유지한다.
공통 질문에 모두 O라고 답해도 특수 조건이 불명확하면 전체 결과는 미확정이다.
한 경로가 차단됐다는 이유만으로 `not_affected`를 만들지 않는다.

## 평가

```powershell
python -X utf8 -m tools.item4.evaluate_cvss_operational --output results/item4_cvss_new_run
python -X utf8 -m tools.item4.evaluate_cvss_operational --population-index --output results/item4_cvss_population_new_run
```

첫 명령은 49개의 명시적 합성 통제 사례로 질문 선택, 지표 버전, 권한·사용자 동작의 불필요 조건,
AND/OR/NOT, 미확정 전파, 대안 벡터를 검증한다. 모델을 호출하지 않으며 독립적인 LLM 추출 정확도 또는 현장 악용 가능성 정확도가 아니다.
정답은 `expected_path_state`이고 `actual_exploitable`은 null이다.

두 번째 명령은 사이트의 전체 목표 CVE를 누락 없이 색인한다. CVSS 부재, description 부재, 특수 추출 미실행도 기록한다.
색인에 있다는 사실을 LLM 추출 완료 또는 평가 완료로 집계하지 않는다. 실제 모델 추출과 독립적인 원문 조건 정답 검증은 별도의 실험이다.

실제 추출 평가 진입점은 다음과 같다. `--run-llm` 없이 실행하면 대상 목록과 실행 계획만 저장한다.
모델을 실행할 때는 현재 제공자·어댑터·GPU가 준비되어 있어야 한다. `--limit`를 지정한 실행은 전체 평가로 표시하지 않는다.

```powershell
python -X utf8 -m tools.item4.run_cvss_source_extraction --output results/item4_source_plan
python -X utf8 -m tools.item4.run_cvss_source_extraction --run-llm --gold <독립검토_조건정답.jsonl> --output results/item4_source_model_run
```

정답 행은 `cve`, `source_record_sha256`, `review_method="independent_human"`, `reviewer`, `draft`를 가진다.
`draft`에는 원문 인용이 고정된 prerequisites와 scenarios가 들어간다. 정답은 모델 입력에 전달하지 않는다.
추출된 개별 악용조건의 엄격한 구조·원문 일치율과 AND/OR/NOT 식의 동치 여부를 별도 집계한다.
실패한 추출은 사라지지 않으며, 출처가 일치하는 정답이 있으면 누락 조건으로 채점한다.
정답이 없거나 출처가 바뀐 경우에는 미채점으로 보존하고 정확도 숫자를 만들지 않는다.
식의 고유 개별 악용조건이 8개를 넘고 구조가 다르면 동치 여부는 미채점으로 기록한다.

이전 505개 질문·무작위 클러스터 응답의 집계 성능은 현재 방식의 성능으로 재사용하지 않는다.
원본 BOM·과거 annotations·scenarios·평가 결과는 역사적 재현 자료로 보존한다.

사용자 정의 지표인 '실제 악용 가능한 식별 CVE / 전체 식별 CVE'는 `tools/item4/evaluate_identified_exploitability.py`로 별도 집계한다.
실제 운영 환경의 독립 정답 true/false/null을 사용하며 미확정·실패 사례를 분모에서 제외하지 않는다.
조건식 충족이나 모델의 affected 출력을 실제 악용 정답으로 대체하지 않는다.

## 공식 정의

- https://www.first.org/cvss/v3.1/specification-document
- https://www.first.org/cvss/v4.0/specification-document
