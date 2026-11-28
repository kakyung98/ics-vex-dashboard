# #4 Jev 검토 모델 연결

2026-11-23 구현. TypeSafe의 공식 System One REST API를 이용합니다.

- API 계약: https://docs.typesafe.ai/api/system-one.md
- Choice: https://docs.typesafe.ai/primitives/choice.md
- 모델 공지: https://typesafe.ai/blog/jev-1-14

## 적용 범위

`ICS_ITEM4_REVIEW_PROVIDER=typesafe_jev`일 때 `operating-record-review` 역할을 Jev로 연결합니다. 공급사 상태, 재고, 조건, 교차 검토에 적용됩니다. 원문 조건 추출·질문 작성은 기존 모델을 사용합니다. 기본 설정은 기존 모델입니다.

여기서 공급사 상태는 로컬 CISA ICSA CSAF의 제품 트리와 CVE별 `product_status`를 SBOM 제품·버전에 연결한 정보입니다. 제조사 사이트를 매 호출마다 조회하지 않습니다. 원본 해시와 JSON 위치 검증은 기존 코드가 수행합니다.

판정과 근거 ID를 하나의 Choice로 묶습니다. 충돌은 기존 근거 그룹 전체를 인용하는 선택지로 보존합니다. 입력을 자르지 않으며 Choice 255개 초과 시 오류로 보류합니다. 확률·신뢰도가 각각 설정 기준 미만이면 unresolved/insufficient로 변환합니다. 기본 기준 0.8은 파일럿용 설정으로, 독립 정답 자료로 보정된 수치가 아닙니다. 기존의 제품 범위, 재고 완전성, 조건 논리, 인용 검증은 계속 적용됩니다.

## 실행

프로젝트 루트 PowerShell에서 TypeSafe가 발급한 키를 현재 프로세스 환경의 `TYPESAFE_API_KEY`로 제공한 뒤 설정합니다. 키를 코드나 실행 결과 파일에 기록하지 않습니다.

```powershell
$env:ICS_ITEM4_REVIEW_PROVIDER = 'typesafe_jev'
$env:ICS_JEV_MODEL = 'jev-1.14.0'
$env:ICS_JEV_MIN_CONFIDENCE = '0.8'
$env:ICS_JEV_MIN_PROBABILITY = '0.8'
```

서비스에 적용하려면 이 환경을 상속하도록 서비스를 다시 실행합니다. `prerequisite_llm.generate(..., role='operating-record-review')` 및 기본 #4 배치 공급자가 이 설정을 읽습니다. 명시적으로 전달한 별도 runner/provider는 그 호출의 공급자를 사용합니다.

동결 평가 명령도 사용할 수 있습니다. 먼저 원본 코호트에 속하는 CVE 하나로 연결을 점검하고, 전수 비교 실험은 전체 12,418개 CVE를 유지합니다.

```powershell
python -B tools/item4/run_item4_scenario_moe.py --cohort all --cve <대상-CVE>
# 전수 실행 (외부 API 호출·비용 발생)
python -B tools/item4/run_item4_scenario_moe.py --cohort all --entire-cohort
```

`--h200-port`와 함께 사용하지 않습니다. 재개할 때는 같은 공급자·모델·임계값을 설정합니다. 실행 원장에는 `scenario_moe_typesafe_jev` 방법과 모델·판정 정책 해시를 기록합니다. 호스팅 모델 가중치의 해시를 검증했다고 주장하지 않습니다. 새 실행으로 기록하며 기존 결과는 갱신하지 않습니다.

각 expert receipt의 `decision`에 원래 선택, 확률 분포, 신뢰도, 기준 통과 여부, 선택지 매핑과 사용량을 보존합니다. 캐시에도 동일하게 저장합니다. 원문 근거와 자산 운영 정보가 TypeSafe API로 전송됩니다.

해제하려면 `ICS_ITEM4_REVIEW_PROVIDER`를 `default`로 설정하고 서비스를 다시 실행합니다.

## 검증 상태

API 대역으로 역할 라우팅, 근거 결합, 충돌 그룹, 낮은 신뢰도 보류, 잘못된 응답·모델 거절, 캐시, 배치 오류 격리를 검사했습니다. 실제 API 키를 이용한 연결과 정확도·지연·비용 비교는 아직 수행하지 않았습니다.
