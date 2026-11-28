# Source-only operating questions and confidence admission

2026-11-26 사용자 요청에 따라 활성 #4에서 CVSS 공통 질문 생성·공통 조건식·공통 응답 평가를 제거했다.

## Active workflow

1. V1: 고정 TF-IDF → SVD → K-means 모델로 자산 유형을 잠정 분류한다.
2. V2: CVE description에서 원문 근거가 있는 운영자가 확인 가능한 악용 전제와 AND/OR/NOT 관계를 추출한다. CVSS 벡터나 자산 유형으로 전제를 추정하지 않는다.
3. V3: V1 자산 유형과 V2의 고정된 positive fact, 정확한 인용, 대상, 관계를 받아 대응 운영정보 질문과 확인 방법을 생성한다. 각 질문에 LLM이 0–100 정수 Confidence를 보고한다.
4. 서버는 인용·대응·구조·극성·접근 가능한 확인 방법을 검증하고 **Confidence >80**인 질문만 입력 화면에 표시한다. 80, 누락, 실패는 채택하지 않는다.
5. V4는 원래 CVE 조건식을 유지해 운영자 응답을 3값 논리로 평가한다. 묻지 못한 조건은 Unknown이며 조건식에서 제거하지 않는다. 제품·버전 근거, 실제 설치 버전, 평가 범위 등 기존 별도 게이트도 유지한다.

Confidence는 **LLM-reported, uncalibrated** 점수다. 토큰 확률·독립 평가 정답률·보정된 사건 확률이 아니다. 화면에서도 정확도 80% 이상이라고 표현하지 않는다. 높게 보고된 점수도 원문/조건 검증을 우회하지 못한다. 독립적 의미 정확도나 Confidence 보정 성능은 아직 확립되지 않았다.

원문에 명시적 운영 전제가 없거나 추출/질문 생성이 실패하면 질문이 0개일 수 있다. 원문·미해결 이유·제외 점수를 표시하며 질문 수를 늘리기 위한 기능·설정 조건을 만들지 않는다. 기능 이름만 근거로 만든 context-only 질문 프로토타입은 활성 흐름에서 제거했다.

## Compatibility and history

새 계약은 `item4-source-operating-input/1`, 질문 생성은 `item4-source-bound-questions/3`, 판단은 `item4-source-prerequisite-vex/1`이다. 이전 응답·평가는 `operating_input_history`에 보존하고 재확인을 요구한다. `/common-question-schema`는 410, `/question-policy`가 현재 Confidence 정책을 제공한다. 옛 CVSS 벤치마크와 문맥 질문 실험 결과는 연구 기록이며 현재 성능으로 사용하지 않는다.

## Dashboard

요청에 따라 대시보드의 군집 품질 점수는 **정규화 SVD 공간의 cosine Silhouette**만 표시한다. 전체 3,881개 ICSA를 포함한 값은 약 0.5551이다. 2차원 PCA 산점도는 표시용이며, 군집 지표는 16차원 원래 모델 공간에서 계산한다. BOM은 학습 코퍼스 밖의 별도 마커로 투영하며 BOM 자체의 silhouette를 만들지 않는다. 모델·원문·변환 해시를 고정하고, 별도의 원본 공간 진단은 감사 데이터에 보존한다. 군집 구조 점수는 자산 유형의 의미 정확도가 아니다.

## Verification

`tests/item4/test_source_question_confidence.py`는 80/81 경계·점수 누락·원문 조건 보존·CVSS 경로 폐기·새 API를 검사한다. UI 상호작용 검사는 낮은 점수 질문의 입력/전송 배제와 입력 변경 시 평가 무효화를 검사한다. `tools/item4/evaluate_source_question_contract.py`의 합성 사례는 LLM 추론·신뢰도 보정·실제 악용 정확도를 측정하지 않는다.
