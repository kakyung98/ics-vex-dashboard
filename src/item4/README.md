# #4 자산 운영 정보 기반 VEX

BOM으로 연결한 CVE·제품의 공식 원문에서 조건과 관계를 추출하고, 운영자 확인자료로 평가합니다. 전체 실행·검증 규칙은 [루트 README](../../README.md#항목-4-운영정보-기반-악용-가능성-평가와-vex-생성)에 있습니다.

| 폴더 | 역할 |
|---|---|
| assets/ | 자산 분류와 운영정보 입력·질문 연결 |
| analysis/ | 근거 수집, 조건·관계 추출·검증, 질문 생성 |
| decision/ | 제품 범위·세 값 논리·VEX·근거 내보내기 |
| workflow/ | BOM 분석 작업과 재개·저장 |
| models/ | 모델·어댑터·추론 제공자 |
| evaluation/ | 평가 입력·채점·실행 이력 |
| web/ | API와 화면 |

## 다섯 항목의 추출 계약

| 항목 | 내용 |
|---|---|
| AV | 공격 접근 위치·경로 |
| PR | 동일 공격자의 사전 인증·권한 |
| UI | 공격자 외 사용자의 동작 |
| AT | 특정 배치·실행 요건 |
| IC | 산업용 기능 설정·제어기 운전 모드·엔지니어링 연결 |

[prerequisite_taxonomy.py](analysis/prerequisite_taxonomy.py)는 네 CVSS 개념과 IC 출력 차원을 정의합니다. IC는 [ics_operating_conditions.py](analysis/ics_operating_conditions.py)의 프로젝트 확장이며 CVSS 점수가 아닙니다. 기존 개별 악용조건의 `ics_context`에 `kind`와 정확한 원문 `quote`를 저장하고, `source_dimensions.IC`가 해당 ID를 참조합니다. 같은 사실이 AT와 IC에 해당해도 조건·질문·논리 항을 복제하지 않습니다.

IC의 하위 유형은 `feature_configuration`, `operating_mode`, `engineering_connection`입니다. IC가 명시되지 않으면 unknown이며, 산업용 제품명·일반 HTTP 입력·공통 보안 권고만으로 IC를 만들지 않습니다. “PROGRAM 모드를 피하라”를 악용 필수조건으로 반전하지 않습니다. 구절 검사는 의미 정확도와 전체 커버리지를 보증하지 않습니다.

## 처리 경로

1. [cve_reference_sources.py](analysis/cve_reference_sources.py): CVE Description과 해당 CVE·제품에 귀속된 ICSA·공급사 원문 수집. 인용·해시·범위 보존.
2. [prerequisite_automation.py](analysis/prerequisite_automation.py): 기본 추출과 독립 재검토. 두 단계에 동일한 IC 계약 적용. 각 오류 수정 단계 최대 3회.
3. [exploitation_prerequisites.py](analysis/exploitation_prerequisites.py): 개별 악용조건·인용·범위·관계 참조 검증. 긍정형 사실과 AND/OR/NOT을 분리.
4. [operating_information_requirements.py](analysis/operating_information_requirements.py): 개별 악용조건별 필요 운영정보·대상·범위·확인 자료·한계를 구조화. 서비스/설정·접근·인증/권한·모드·작업·물리 접근을 구분하고 자산 유형별 기록 위치에 연결.
5. [asset_observations.py](assets/asset_observations.py) 및 [asset_operating_question_generation.py](analysis/asset_operating_question_generation.py): IC 메타데이터·공유 조건 ID·고정 요구사항을 유지한 질문 생성. [condition_question_contract.py](analysis/condition_question_contract.py)는 긍정형 사실·원래 관측 자료·답변 의미를 고정.
6. [assessment_evidence_chain.py](decision/assessment_evidence_chain.py): 다섯 차원·원문·IC 태그·질문·답변·논리식·최종 상태 연결.

제품명·버전 범위로 선택한 제품과 명시적으로 연결된 CVE만 분석합니다. [operating_question_tree.py](analysis/operating_question_tree.py)와 [operating_question_tree.js](web/operating_question_tree.js)는 CVE ID를 최상위 노드로 표시하고 AND/OR/NOT을 유지하면서 답변에 따라 다음 질문을 선택합니다. Unknown은 미확정으로 보존합니다.

요구사항은 `information_requirement`로 API·모델 입력·화면·V4 근거 사슬에 전달합니다. 현재 정책·역할 기록을 실제 접근·자격증명 보유로, 절차를 실제 동작 발생으로, 지원 모드를 현재 모드로 바꾸지 않습니다. 행위자·출발지가 별도 필드로 없는 경우 전체 조건 문장의 한정사항을 보존합니다. 유형이 미확정이어도 원문 조건 질문과 확인 방법은 유지합니다.

BOM 포함 여부는 현재 기능·모드·연결 상태의 답변이 아닙니다. 운영자 확인 전에는 Unknown입니다. 관측 불가능한 필수조건과 관계 누락은 평가를 차단하는 미확정 제약으로 보존합니다. 질문·추출 confidence는 모델 자체 보고 값으로 정답률이 아닙니다.

## API와 검증 범위

`GET /api/item4/analyses/condition-taxonomy`는 다섯 출력 차원과 IC의 하위 유형·공유 개별 악용조건 계약을 반환합니다. `GET /api/item4/analyses/automation-policy`는 질문·재시도 규칙을 반환합니다. 화면과 질문 패킷에도 IC 유형을 전달합니다.

현재 성공 캐시는 전체 원문·모델·정책 등에 묶입니다. CVE 사전 추출 결과를 BOM 조회와 연결하는 배포 경로와 신규 추출의 공통 잠금은 별도 운영 과제입니다. 진행 중인 12,418개 실험은 `results/item4_cvss_population_20261127_full/frozen_workspace/`의 기존 네 항목 코드를 사용합니다. 해당 실험을 IC 확장·운영 모델의 전수 정확도 결과로 재사용하지 않습니다.

```powershell
python -B -X utf8 -m pytest tests/item4/test_ics_operating_conditions.py tests/item4/test_cvss_source_taxonomy.py -q
```

합성 응답과 실제 원문 구절 검사는 계약과 오류 차단을 확인하며 독립 의미 정확도를 입증하지 않습니다. H200 단일 CVE 시험은 IC 조건 2개를 보존했으나 원문 재검토 실패로 미확정이며, 결과는 `results/ics_operating_extension_20261128/live_smoke_final/`에 있습니다. 표준 VEX 내보내기와 프로젝트 분석 JSON을 구분하고, 원문·제품·운영 범위가 불명확하면 under_investigation으로 보류합니다.
