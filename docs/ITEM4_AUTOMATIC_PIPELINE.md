# #4 자동 근거 검증 및 4단계 파이프라인

작성일: 2026-11-16 KST. **사람 라벨링은 실행·조건 통과·후속 단계 진행의 필수 조건이 아니다.** 기존 수동 검토 전용 CLI는 선택적 경로로 보존한다. 독립 정답이 없는 자동 검사 결과를 실제 Precision/Recall로 표현하지 않는다.

2026-11-18 유효기간 보완: 판정과 내보내기는 서버 현재 시각으로 근거 만료를 검사한다. 요청의 `evaluated_at`은 관측 기준 시각으로 보존하며 미래 시각은 거부한다. 결과의 `evaluated_at`은 서버 판정 시각이고 입력 시각은 `observed_at`에 남긴다. 과거 시각을 제출해 만료 근거를 되살릴 수 없으며, 저장된 확정 판정도 근거가 만료되면 재평가 없이 내보낼 수 없다.

## 실행 구조

```text
불변 ICSA-CVE 원문 + 명시적 제품 참조
 → 조건 추출 A + 전체 원문 역방향 조건 탐색 B
 → 정확 인용·범위·행위자·부정·필수성 검토 + 별도 DeBERTa NLI
 → AND/OR 관계 제안 + 별도 관계·포괄성 검증
 → 자산 유형별 공통 양식 + CVE 조건별 자산 운영 정보 필드
 → 실제 자산·운영 근거·토폴로지와 대조
 → 결정적 VEX 판단 + OpenVEX 스키마 검증
```

모델은 H200에서만 실행한다. 로컬 테스트는 가상의 고정 응답을 사용하며 모델을 로드하지 않는다. 재학습은 실행 전제가 아니다. 사전학습된 체크포인트로 추론하고 자동 생성 라벨을 사람 정답으로 위장하지 않는다.

| 파일 | 책임 |
| --- | --- |
| `src/item4_automatic_contracts.py` | 과업·출력 계약·프롬프트 |
| `src/item4_model_wire.py` | 원문 인용 ID의 무손실 전송·응답 형식 |
| `src/item4_h200_model.py` | H200 생성 모델·별도 NLI·원시 응답 캐시 |
| `src/item4_h200_vllm.py` | 별도 H200 vLLM 실행기·모든 과업 JSON 문법 강제 |
| `src/item4_h200_resilient.py` | 원래 모델 ID를 보존한 유효 응답 재사용·교정된 전송 실행 |
| `src/item4_automatic.py` | 조건 근거 검증·역방향 후보 병합·원문 범위 연결 |
| `src/item4_attack_graph.py` | AND/OR 경로·포괄성 증거·3값 평가 |
| `src/item4_operational_fields.py` | 자산 유형 18개·복합 역할·CVE 필드 검증 |
| `src/item4_asset_form.py` | 모든 자산 조사 항목의 질문·자료 구조·JSON Schema |
| `src/item4_vex_engine.py` | 자산·원문 적용성·자산 운영 정보·토폴로지·OpenVEX |
| `src/item4_automatic_pipeline.py` | 전수 원장·그래프/필드 카탈로그 조립 |
| `src/item4_automatic_api.py` | 별도 loopback API |
| `tools/run_item4_automatic_h200.py` | 격리 실행·동일 코드 재개·결과 다운로드 |
| `tools/item4_vllm_server_h200.py` | 별도 가상환경·loopback 추론 서버 시작/조회/종료 |
| `tools/validate_item4_automatic_h200.py` | 전체 원장·그래프·필드 원문 대조 및 H200 통제 사례 |
| `tools/finalize_item4_automatic_h200.py` | 모델 작업 종료 후 검사·API 대조·결과 압축·아티팩트 봉인 |
| `tools/item4_automatic.py` | 조회·입력 양식·판정·내보내기·API 실행 |

## 1단계: 자동 근거 및 누락 검사

원문 바이트/텍스트 해시와 구조화 범위를 먼저 검사한다. 원문의 외부 명령은 데이터로만 취급한다. 동일 역할·동일 텍스트는 의미 추론을 재사용하지만 원래 구간의 CVE·제품 연결은 다시 검사한다. 권고문 공통 설명을 개별 CVE의 조건으로 자동 확산하지 않는다.

추출 A와 역방향 탐색 B는 서로의 답을 보지 않고 전체 텍스트를 읽는다. B의 추가 후보도 원문 검증을 거친다. 정확히 같은 주장은 병합하고 표현이 다른 주장은 보존한다. 따라서 `reverse_added_candidates`는 추가 탐색 후보 수이며 진짜 누락 건수나 Recall이 아니다.

조건이 `automatic_pass`가 되려면 다음을 모두 통과해야 한다.

1. 인용이 불변 원문에 정확히 한 번 존재하고 원래 위치를 재현한다.
2. 별도 검토 과업이 내용·필수성·행위자·부정·범위를 모두 supported로 판정한다.
3. 부정된 인증 요구나 원문에 없는 관리자 권한을 추가하지 않는 등 결정적 방어 규칙을 통과한다.
4. 다른 계열 NLI가 전체 문맥–조건과 선택한 정확 인용문–조건을 각각 entailment로 분류한다. 인용문과 전체 문맥이 정확히 같을 때만 동일 입력 판정을 재사용할 수 있다. neutral·문맥 초과는 미확인이고 contradiction은 거부한다.
5. 구조화 참조와 인용 주체가 해당 CVE·제품을 뒷받침한다.

필수조건 승인에는 보수적인 명시적 필요성 표현 검사도 사용한다. 이 정책은 서술된 공격에서 추론 가능한 조건을 놓칠 수 있다. 승인 수를 늘리려고 조용히 완화하지 않는다. 결과·완화·단순 버전 적용성은 운영조건으로 승격하지 않는다. 공격자의 실제 계정·권한 보유는 자산 계정 목록으로 증명하지 않는다.

`source-requirement-semantics/2`는 “P가 필요하지 않다”와 “P가 없어야 악용된다”를 구분한다. `requires no user interaction`, `does not require authentication` 같은 비필수성 문장은 필수조건으로 승인하지 않는다. 잘못된 술어로 분류됐더라도 조건 문장 자체가 명백한 비필수성 표현이면 거부한다. 원문의 기능 비활성 상태가 실제 필요조건으로 명시된 경우까지 무조건 부정문으로 거부하지 않는다. 거부 시 반대 조건 생성·필수성 레이블 자동 교정·VEX 발행을 하지 않는다.

강화 재검증 도구 `tools/run_item4_reanalysis_h200.py`는 봉인된 이전 원문·생성 응답·모델 해시를 먼저 대조한다. `src/item4_reanalysis.py`는 기존 통과 항목을 강등할 수만 있고 과거 거부·미확정 항목을 승격하지 않는다. 원래 NLI 문맥 판정, 생성 응답, 이전 검증 해시를 유지하며 인용문 검사 및 정책 버전을 추가한다. 조건이 강등된 경로는 조건을 지워 짧게 만들지 않고 관계 전체를 다시 검증한다. 조건·경로 추가 및 포괄성 승격이 없는지 이전 카탈로그와 비교한다. 원문 생성 응답을 다시 만들었다고 표현하지 않는다.

모델 실패·문맥 초과·잘못된 응답은 빈 조건과 구분한다. 긴 원문은 겹치는 윈도로 모두 처리하되 윈도 간 전역 관계를 확정하지 않는다. 인용을 대소문자·유사 문자열로 보정하지 않는다. 인용 ID를 정확한 원문으로 되돌리는 것은 사전에 선언된 무손실 전송이다.

전송 v4는 인용 ID를 복원했을 때의 실제 길이 제한을 문법에 반영한다. 조건·조건 검토 인용은 600자, 그래프/포괄성 인용은 해당 계약의 1,000자 제한을 적용한다. 검토 결과는 고정된 번호 키의 객체를 사용해 조건 번호 중복과 누락을 막고 중복 JSON 속성도 거부한다. 추출 응답 한도는 2,048토큰으로 기록한다. 이전 v3의 유효 응답은 원래 모델 ID와 과업·입력·원시 응답을 유지한 채 재검사해 재사용한다. 이전의 잘못된 길이·중복 검토·형식 실패를 유효 응답으로 재분류하지 않는다.

**처리 원장 완전성과 의미적 무누락은 다르다.** 원문에 언급되지 않은 실제 전제조건이나 모델들이 공통으로 놓친 조건까지 모두 찾았다는 보장은 없다.

최종 감사는 `requires`, `must`, 인증·로컬/물리 접근·사용자 상호작용 등의 원문 표현이 어떤 추출 후보의 인용에도 포함되지 않았는지 추가 검사한다. `omission_signals.jsonl`에 원문 위치와 주변 인용을 남긴다. 이 어휘 경보에는 실제 악용조건이 아닌 문장도 포함되며 확정 누락 건수로 세지 않는다. 인용이 표현을 포함하더라도 문장 안의 모든 의미를 추출했다는 보증은 아니다.

## 모델·독립성·기록

| 역할 | 모델 | 고정 revision |
| --- | --- | --- |
| 추출·역방향 탐색·필수성/관계 검토 | Qwen/Qwen2.5-7B-Instruct | `a09a35458c702b33eeacc393d103063234e8bc28` |
| 내용 지지/모순/중립 검사 | cross-encoder/nli-deberta-v3-small | `fa2804872c3b4bd748f38c0185cc85775361e735` |

출처: [Qwen 모델 카드](https://huggingface.co/Qwen/Qwen2.5-7B-Instruct), [NLI 모델 카드](https://huggingface.co/cross-encoder/nli-deberta-v3-small). 실제 가중치·설정·토크나이저 해시는 model_manifest.json에 기록한다.

Qwen의 다른 프롬프트는 가중치가 독립적인 검증기가 아니다. 별도 NLI는 다른 계열이지만 ICS 필수성에 특화해 보정된 모델이 아니다. NLI는 내용 지지의 추가 검사이며 필수성·포괄성의 단독 증명이 아니다. 점수와 argmax 레이블을 기록하고 보정된 확률로 표현하지 않는다.

`model_cache.sqlite3`에는 과업·입력·원시/복원 응답·모델 ID·실패를 저장한다. 캐시 키에 모델·프롬프트·전송 계약·입력·출력 길이를 결합한다. `unit_results.jsonl`은 두 추출 패스·검토·NLI·관계 검토를 연결한다. 캐시 재사용은 cache_hit으로 남긴다.

`model_manifest.json`의 generator와 legacy_generators는 생성·전송 정책의 등록부다. 동일한 Qwen 가중치의 정책 버전을 별도 모델 계열이나 독립 검증기로 세지 않는다. 유효 과거 응답에는 cache_origin을 붙이고 원래 ID를 새 ID로 바꾸지 않는다. 내용·필수성·행위자·부정·범위·NLI 승인 기준은 전송 교정 과정에서 유지한다. `wire_correction.json`, `wire_v4_smoke.json`에 교정 사유와 H200 통제 검사를 기록한다.

## 2단계: 공격 그래프

그래프는 `OR(AND(필수조건…))`인 CVE별 필요조건 모델이다. 공격 성공의 충분조건이나 전체 시스템 침해 시뮬레이션이 아니다. 각 조건 노드와 관계에 원문·자동 검토를 연결한다. 서로 다른 제품·원문을 임의로 AND로 묶지 않는다.

검증되지 않은 조건을 지워 경로를 단순화하지 않는다. 미확인 조건·관계·범위는 gaps에 남긴다. coverage_complete에는 원문이 악용을 모델링한 조건으로 명시적으로 제한하는 인용과 별도 검토 증거가 필요하다. 일반 악용 예시는 전체 경로 증거가 아니다. read-only의 only를 전 경로 제한으로 취급하지 않는다. 빈 그래프·실패·차단 경로 하나로 비영향을 판단하지 않는다.

## 3단계: 자산 운영 정보

고정된 ATT&CK ICS 자산 18개에서 공통 필드와 유형별 추가 필드를 구성한다. 복합 역할은 합집합으로 제공한다. 자산 유형만으로 실제 기능의 존재·활성을 판단하지 않는다. 공통 정보는 운영모드, 인터페이스별 서비스, 방향성 접근 규칙, 정비 경로, 파일 반입, 인증·역할, 물리·로컬 접근이다.

필드 구성은 [CISA 자산관리 가이드](https://www.cisa.gov/sites/default/files/2025-08/joint-guide-foundations-for-OT-cybersecurity-asset-inventory-guidance_508c.pdf), [NIST SP 800-82r3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r3.pdf)의 접근 제어·최소 기능·설정 변경·정비·매체·원격 접근을 참고한다. 구체 필드와 질문은 프로젝트 정의이며 공식 VEX 질문 목록이 아니다. 제품의 실제 설정과 효과는 제품 문서로 확인한다.

실제 입력 구조와 자산별 질문은 [자산 운영 정보 입력 계약](ITEM4_OPERATOR_INPUTS.md)에 정리했다. 상세 조사 양식은 `tools/item4_asset_form.py`로 생성·검증한다. 미확인·조사된 값·범위를 명시한 빈 목록을 구분하며 조사 양식 자체를 CVE 불성립의 증거로 승격하지 않는다.

CVE 필드는 승인 조건과 연결해 원문·행위자·필요 자료·대상/출발지·true/false/unknown 매핑을 보존한다. 관측 불가능한 공격자 보유 상태는 확정하지 않는다. 빈 필드는 미확인이다. 답변 재사용은 `common_facts.field_ids`로 명시적으로 연결할 때만 허용한다.

## 4단계: VEX

평가 단위는 CVE × 자산 × 제품/빌드 × 설정 기준 × 운영모드 × 시점이다. 운영 근거는 범위·유효 기간이 일치해야 한다. 사용자 제공 관측은 독립 측정으로 위장하지 않는다. 거짓 조건에는 `absence_assurance=enforced` 또는 `complete_scope`인 근거가 필요하다. 단순 정책이나 과거 미관측만으로 실행 불가능을 확정하지 않는다. 충돌은 보류한다.

토폴로지는 노드·방향성 서비스 접근 링크·근거로 표현한다. 선이 없으면 기본값은 미확인이다. 차단 확정에는 연결·관련 출발점·정비 경로의 포괄성과 근거가 필요하다. RDP 세션과 이후 HTTPS 요청을 단순 HTTPS 라우팅으로 합성하지 않는다.

네트워크 질의는 `network_condition_binding` 자료로 원문 조건 ID·인용 해시·대상·출발지·서비스를 명시적으로 연결해야 한다. 관계없는 서버의 차단을 해당 CVE 조건의 부정으로 사용하지 않는다. 포괄성 표시는 질의와 `network_inventory_complete` 자료 양쪽에 있어야 한다. 이 자료는 입력된 운영 기록이며 독립 측정을 의미하지 않는다.

| 근거 | 상태 |
| --- | --- |
| 원문의 known_affected 제품에 설치 식별 연결 | affected 근거 유지; 운영상 제한 별도 평가 |
| 원문의 fixed 제품에 설치 식별 연결 | fixed |
| 원문의 known_not_affected 제품에 설치 식별 연결 | not_affected |
| 포괄적 원문 그래프의 모든 적용 경로가 유효 운영 근거로 부정됨 | 기록된 배포 범위의 not_affected |
| 식별·출처·입력 부족·충돌 | under_investigation |

제품 상태는 CSAF의 명시적 참조에서 읽는다. SBOM 누락이나 버전 문자열 추정으로 비영향을 만들지 않는다. 모든 조건 참이 공격 성공의 증명은 아니다. 운영자 방화벽을 inline_mitigations_already_exist로 표시하지 않는다. 배포 범위 비영향은 impact_statement로 설명한다. OpenVEX는 고정 스키마로 검사한다. 원문·그래프·필드·입력 해시, 사용/거절 근거, 조건/경로 값을 남기며 설정·모드·빌드·경로가 바뀌면 재평가한다.

OpenVEX 제품 ID는 `urn:ics-vex:deployment-snapshot:<input_sha256>`로 평가 입력 스냅샷에 묶는다. 같은 자산 ID라도 설정·운영모드·시점·근거가 달라지면 다른 대상이다. 기존 판정을 다른 배포 상태의 전역 비영향으로 재사용하지 않는다.

## 실행 및 검증

```powershell
python tools/item4_vllm_server_h200.py --config hysage-kubeconfig.yaml start
python tools/item4_vllm_server_h200.py --config hysage-kubeconfig.yaml status
python tools/run_item4_automatic_h200.py --config hysage-kubeconfig.yaml --run-id 20261116_auto04 --backend vllm
python tools/run_item4_automatic_h200.py --config hysage-kubeconfig.yaml --run-id 20261116_auto04 --fetch
python tools/item4_catalog_service.py --catalog results/item4_automatic/20261116_auto04/catalog --port 18104
```

H200의 `item4-automatic-runs/<run-id>`에서 기존 서비스를 교체하지 않고 실행한다. 불변 v4 원문 bundle을 읽고 원본을 다시 대조한다. 같은 코드 manifest에서 `--resume`으로 재개할 수 있다. 원문이 부족한 CVE도 전수 원장에 남긴다.

최초 준비에는 `item4-vllm-venv` 가상환경의 `vllm==0.12.0`, `ziglang==0.13.0`이 필요하다. 추론 서버는 별도 환경과 포트를 사용하며 기존 서비스 코드를 교체하지 않는다. 실행 중 추가 성능 비교에서 발생한 컨테이너 메모리 부족과 기존 서비스 복구는 `recovery.json`에 기록했다. 모델 경로는 위 고정 revision을 받은 `item4-models/qwen25_7b`, `item4-models/nli_deberta_small`이다. 서버는 BF16·temperature=0·repetition_penalty=1.05·xgrammar를 사용한다. 문법 강제는 JSON 형식을 제한하며 의미 정확성을 보장하지 않는다. HF 실행과 캐시 ID를 분리한다. 과거 `20261116_auto01`의 HF 부분 실행과 `20261116_auto02`의 이전 규칙 실행은 보존하고 `20261116_auto04`에서 현재 규칙으로 전수 처리한다. 정확히 같은 모델/입력 응답의 캐시만 재사용하고 각 조건 검증·NLI·그래프는 현재 코드에서 다시 처리한다.

`20261116_auto03`에서 발견한 긴 인용·검토 번호 전송 문제는 v4에서 교정했다. `--seed-cache-run 20261116_auto03`은 그 실행의 유효 원시 응답을 출처·모델 ID와 함께 재사용한다. 모든 과거 응답을 새 정책의 생성 결과로 바꾸지 않는다. 완료된 실행 ID를 새 실행으로 덮어쓰지 않으며, 재개는 같은 코드 snapshot에서 `--resume`을 사용한다.

20261116_auto04는 고유 입력 31,503개와 원문 121,863구간을 전수 처리했고 CVE 12,418개를 보존했다. 자동 승인된 조건·필드는 각각 725개, 경로는 97개 CVE의 132개다. 전체 경로 포괄성 자동 승인 수는 0이다. 단위 검토 2개가 정상 종료되지 않아 3개 원문 구간을 보류했다. 원시 응답과 실패 사유도 보존했다. 포괄성 검사는 보수적인 only/unless 제한 표현과 별도 검토를 사용하므로, 통과 0을 원문 전체의 의미적 부재나 정확도 0으로 해석하지 않는다.

최종 감사는 요청 캐시의 과업·입력·모델/전송 정책·길이·원시/복원 응답을 대조하고, 승인 조건 725개와 경로 132개의 연결을 단위 추출 결과까지 다시 확인했다. 원문 인용 인덱스 121,863개, 제품 참조 28,711개, 모든 그래프와 필드 계획을 검사했다. 로컬 114개 회귀 검사, H200 55개 계약 검사, H200 모델 통제 사례 9개와 실제 localhost HTTP 검사가 통과했다. 독립적인 의미 정확도와 무누락은 입증되지 않았다.

`validation_report.json`은 자동 감사, `artifacts_manifest.json`은 배포 파일 해시, `code_snapshot.json`은 원래 바이트의 base64 snapshot, `environment_manifest.json`은 두 H200 환경의 패키지 버전이다. 로컬 `delivery_validation.json`은 다운로드한 30개 파일 약 440MB와 로컬 코드 34개가 봉인된 snapshot에 일치함을 확인한다. `live_api_validation.json`에는 실제 HTTP 결과를 저장했다. 이들 로컬 검사 기록은 H200 원래 산출물을 덮어쓰지 않는다.

CLI inspect는 CVE별 그래프·필드를 조회하고 case-template은 운영 입력 양식을 만든다. assess는 실제 입력을 대조하고 `--openvex-output`으로 문서를 내보낸다. 기존 파일을 덮어쓰지 않는다. API `/docs`에 요약·자산 양식·CVE별 그래프/필드·판정이 있다.

```powershell
python tools/item4_automatic.py case-template --catalog results/item4_automatic/20261116_auto04/catalog --cve CVE-2026-10001 --output results/operator_case.json
python tools/item4_automatic.py assess --catalog results/item4_automatic/20261116_auto04/catalog --cve CVE-2026-10001 --case results/operator_case.json --output results/decision.json --openvex-output results/vex.json
python -m pytest tests/test_item4_automatic.py -q
```

명령의 CVE ID는 형식 예시다. 실제 ID는 cve_index.json에서 선택한다. 빈 양식에는 실제 근거를 입력해야 한다. 자산·운영 입력이 없는 전수 실행은 카탈로그를 구축하고 자산 평가는 미수행으로 둔다. 가상 회귀 사례를 실제 설비 VEX로 발행하지 않는다.

테스트는 원문 변조·잘못된 인용·범위, 빈 결과와 실패, 역방향 후보, 행위자·NLI 중립, AND/OR·포괄성, 필드 드리프트, 만료·충돌, 정비 경로와 정책 차단, OpenVEX·API를 검사한다. 가상 응답의 계약 검증은 실제 모델 정확도 평가가 아니다. 사람 검토는 선택적 추가 감사와 보정에 사용할 수 있으며 실행 차단 조건이 아니다.
