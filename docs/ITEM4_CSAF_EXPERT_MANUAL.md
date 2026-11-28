# 시험 항목 4 벤치마크와 전문가 검토 사용 매뉴얼

> 실제 실행 추가: 70% 무라벨 학습 및 12,418개 CVE 전체 v2 모델 평가가 완료되었습니다. 데이터 manifest의 training_executed=false는 생성 당시 스냅샷이며, 현재 실행은 [실제 결과](ITEM4_V2_ACTUAL_RUN.md)와 actual_run_status.json을 확인합니다. 전문가 판정은 미실시입니다.

2026년 11월 20일 개정. 최신 데이터는 benchmark/item4_evaluation/csaf_vex_v2이다. 전체 12,418개 CVE·86,926개 사례를 보존한다. 기존 affected 정밀도 TP/(TP+FP)와 85% 초과 기준을 사용한다. 후보 정답, 전문가 골든, 모델 예측을 별도로 관리한다.

## 1. 데이터 위치와 준비

- manifest.json: 모집단·분할·수량·파일 해시와 미완료 상태.
- advisory_split.json: 학습 ICSA 2,717개, 전문가 평가 ICSA 1,164개.
- population_index.json: 12,418개 CVE와 각각의 7개 사례·대표 ICSA·분할.
- inputs.jsonl 및 sboms/: 모델 입력. sources/cve_evidence.jsonl에서 CVE별 원문과 선택 경로를 읽는다.
- candidate_labels.jsonl: 생성 의도·조건부 후보 정답. 모델과 전문가에게 제공하지 않는다.
- gold.jsonl: 전문가 확정 전 전건 null인 정답 장부.
- review/: 맹검 패킷, 평가자 A·B·조정 양식, ICSA 전체 검토 색인.
- training/corpus.jsonl: 정답 없는 자기지도 학습용 원문 text 2,717개.

데이터 생성 명령은 python -X utf8 -B -m tools.build_item4_csaf_benchmark이다. 기존 버전이 있으면 실패하도록 되어 있다. 재생성은 --output으로 새 디렉터리를 지정하며 과거 버전을 덮어쓰지 않는다. 생성기는 이전 고정 원본의 해시를 확인한다.

감사는 python -X utf8 -B -m tools.verify_item4_csaf_benchmark로 수행한다. 결과는 results/item4_csaf_v2_20261120/data_audit.json에 저장한다. 감사 통과는 모집단·입출력 분리·파일 해시·CSAF JSON 형식의 확인이며 의미 정확도 통과가 아니다.

## 2. 학습 자료 사용

학습 프로그램에는 training/corpus.jsonl의 text만 전달한다. 생성된 후보 상태·justification, gold, review 파일을 학습 입력에 합치지 않는다. causal LM의 다음 토큰 예측으로 학습하며, 사용자 정의 task의 assistant 정답을 만들지 않는다. 평가 측 원문으로 early stopping이나 체크포인트를 선택하지 않는다.

학습 수행 시 모델·토크나이저·코퍼스 해시, seed, 토큰화·길이 처리, epoch, optimizer update, 가중치 해시를 기록한다. 기존 모델은 교체하지 않고 새 가중치 경로에 저장한다. manifest의 training_executed=false는 실제 학습 기록이 확보되기 전까지 유지한다. 이 배포물에는 데이터 준비가 포함되며 GPU 학습 완료를 뜻하지 않는다.

## 3. 전문가에게 전달할 자료

평가자 A·B에게 각각 review/packets.jsonl, sources/cve_evidence.jsonl, sboms/ 및 각자의 rater_a.jsonl 또는 rater_b.jsonl 복사본을 전달한다. candidate_labels.jsonl, candidate_csaf_vex.jsonl, 모델 예측과 상대 평가 파일은 전달하지 않는다. reviewer_id는 실제 평가자를 구별하는 익명 코드로 사용한다.

1,164개 ICSA 중 13개는 목표 CVE가 없다. review/advisory_index.json에 해당 자문의 범위 확인을 기록하고 CVE별 영향 라벨이나 κ 분모에 가짜 사례를 만들지 않는다. 같은 CVE가 여러 ICSA에 있으면 중복 검토 대신 동일 사례를 색인에서 참조한다. 사례 검토는 대표 ICSA 기준 28,630개이다.

## 4. 판정 양식 작성

각 ID의 cve와 advisory_id를 변경하지 않는다. status는 affected, not_affected, under_investigation 중 하나이고 actual_affected는 각각 true, false, null이다. justifications는 해당 사유 목록이며 not_affected 외에는 빈 목록이다. 다섯 reason 필드는 yes/no/unknown으로 작성하고 yes인 사유와 justifications를 일치시킨다.

source_binding_valid, scenario_logic_valid, evidence_sufficient도 yes/no/unknown으로 작성한다. 확정 상태에는 모두 yes가 필요하다. evidence_refs에는 검토한 문서·인용 식별자를, rationale에는 원문 관계와 가상 사실에서 결론이 도출되는 이유를, reviewed_at에는 검토 시점을 기록한다. 미확인과 충돌을 false로 바꾸지 않는다.

다섯 비영향 사유는 컴포넌트 부재, 취약 코드 부재, 실행 경로 부재, 공격자 제어 불가, 제품 내장 완화이다. SBOM 누락·네트워크 차단·현재 사용자 권한 부재·외부 방화벽만으로 해당 사유를 확정하지 않는다. 합성 증명이 실제 공급사 자료가 아니라는 사실을 고려해, 가정 안에서의 논리 타당성과 실제 출처 연결을 따로 검토한다.

## 5. κ 계산과 불일치 조정

두 평가자는 협의하지 않고 최초 판정을 완료한다. 최초 파일을 보존한 뒤 아래 명령으로 κ를 계산한다. 경로 예시는 프로젝트 루트 기준이다.

python -m tools.item4_expert_review kappa --a outputs/review_a.jsonl --b outputs/review_b.jsonl --output outputs/kappa_report.json

상태와 각 사유의 비가중 κ, 일치율·혼동행렬, ICSA 단위 bootstrap 95% 신뢰구간을 확인한다. 미완료 쌍은 pending으로 표시되고 게이트는 통과하지 않는다. 단일 라벨 분포 등으로 κ가 정의되지 않으면 null이다. 제안 기준 0.80은 연구의 사전 규칙이며 보편 인증 기준이 아니다.

불일치는 제3 전문가가 조정한다. review/adjudication.jsonl의 복사본에 최종 판정·reviewer_id·시점·근거·resolution을 작성하고 independent_ratings_locked=true로 둔다. 최초 판정과 다르거나 A·B가 불일치하면 adjudicator_id는 A·B와 다른 사람이어야 한다.

python -m tools.item4_expert_review adjudicate --a outputs/review_a.jsonl --b outputs/review_b.jsonl --decisions outputs/adjudication.jsonl --output outputs/expert_gold.jsonl

두 독립 검토와 조정이 미완료면 최종 골든 생성은 거절된다. 완성된 expert_gold도 70% 문맥 측은 null로 보존한다. 합의 후 결과로 κ를 다시 계산해 최초 신뢰도로 보고하지 않는다.

## 6. 모델 예측과 기존 지표 산출

예측 JSONL은 id와 status를 포함하고 전체 86,926개 ID를 한 번씩 가져야 한다. status는 affected/not_affected/under_investigation이다. 실패 사례도 under_investigation과 오류 정보를 남기고 제외하지 않는다. 후보 정답을 읽지 않는 실행기나 현행 시스템 어댑터에서 예측 파일을 먼저 완성한다. 현재 생산 Agent 3·4가 새 합성 증명 자료를 자동 처리한다고 가정하지 않는다.

전문가 골든 채점 명령:

python -m tools.item4_expert_review score --predictions outputs/predictions.jsonl --gold outputs/expert_gold.jsonl --output outputs/expert_score.json

전체 모집단의 조건부 합성 기준선 채점은 --reference candidate를 명시한다. 이 결과는 전문가 검증 성능으로 표시하지 않는다.

python -m tools.item4_expert_review score --reference candidate --predictions outputs/predictions.jsonl --output outputs/conditional_score.json

TP는 affected 출력·골든 true, FP는 affected 출력·골든 false이다. TP/(TP+FP)>0.85가 기존 통과 조건이다. 0.85와 분모 0은 통과가 아니다. 골든 unknown에 affected를 출력하면 전체 정밀도와 통과를 보류한다. 전문가 검토가 완료된 평가 표본 성능은 expert_sample에 별도로 표시한다. 전체 CVE를 실행했다는 사실만으로 전체 전문가 정답이 생기지는 않는다.

## 7. CSAF VEX와 제출물

python -m tools.item4_expert_review export-csaf --gold outputs/expert_gold.jsonl --output outputs/expert_csaf_vex.jsonl

미검토 사례는 under_investigation이다. 검증된 not_affected만 known_not_affected와 flags의 제품 참조를 갖는다. 모든 문서는 합성 draft이고 실제 공급사 VEX로 배포하지 않는다. candidate_csaf_vex.jsonl은 생성 후보를 확인하는 별도 자료이다.

배포 ZIP에는 소스·검사·공식 스키마·문서와 포함 파일 해시를 제공한다. 벤치마크 ZIP은 별도로 제공한다. 모델 가중치, kubeconfig·비밀키, 운영 DB는 포함하지 않는다. 원본 HWP는 docs/archive/item4_csaf_v2_20261120에 백업한다. 과거 991건·89.86% 및 62,090개 운영 변형은 이력이며 이번 평가 결과가 아니다.

기준: OASIS CSAF 2.0 및 Jacob Cohen 1960. 상세 출처와 범위는 설계서를 참조한다.
