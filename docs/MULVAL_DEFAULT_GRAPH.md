# #4의 기본 MulVAL 그래프

2026-11-19 갱신. 기본 생성기는 MulVAL/XSB이며 Python 계층은 원문 조건·제품 범위·운영 근거·unknown 및 VEX 정책을 관리한다.

## 실행 흐름

1. 제품·버전·원문에 연결된 조건식을 양극성 Datalog로 컴파일한다. 원문 조건마다 확인된 참과 명시적으로 확인된 거짓을 구분한다. NOT은 반대 극성의 근거를 요구하며 누락에서 추론하지 않는다.
2. `graph_gen.sh -r rules.P input.P -l`로 실제 MulVAL을 실행한다. 정적 구조를 먼저 구성하기 위해 조건별 양극성을 가능성으로 제출한다. 이 구조 입력은 실제 관측이나 공격 성공 사실이 아니다.
3. 실제 `VERTICES.CSV`·`ARCS.CSV`를 읽는다. 모든 유도 규칙의 ID·전제·결론과 전체 규칙/극성의 보존 여부를 검사한다. 자체 생성 그래프를 MulVAL 결과로 표시하지 않는다.
4. 검증된 운영기록을 primitive 노드에 true/false/unknown으로 주입한다. MulVAL의 AND 유도·OR 대안 구조를 평가한다. 정적 그래프 해시는 답변에 따라 변하지 않는다.
5. 각 유도 단계에 원문 인용·규칙절·관측 원문 및 해시·범위·값·미확정 조건을 연결한다. 내보내기에는 그래프 해시가 연결된다. 세부 유도 기록은 검토 JSON과 화면의 근거 상세에 남는다.

기본 목표는 원문 전제조건의 충족이다. 이를 `execCode`나 실제 익스플로잇 성공으로 변환하지 않는다. 실제 네트워크·서비스·전이 근거 없이 자산 간 공격 체인을 추가하지 않는다. 별도 `/api/precision/item4/mulval-runs`의 네트워크 fact 경로도 유지된다. 완전한 네트워크 공격 체인과 통합한 것은 아니다.

## 실행 환경

`ICSVEX_MULVAL_BACKEND`는 `auto`(기본), `native`, `docker`, `ncp`를 지원한다. auto는 로컬 graph_gen.sh, Docker, 프로젝트의 기존 NCP kubeconfig 순서로 찾는다. NCP에서는 기존 격리 PRoot 실행기를 사용하며 운영기록이나 프로파일은 전송하지 않는다. 공개 원문 참조와 해시 기반 조건·규칙만 전달한다.

- native: PATH의 `graph_gen.sh` 및 `MULVALROOT` 설정.
- docker: 기존 `ics-vex-operational-tools:20261116` 이미지. `ICSVEX_MULVAL_IMAGE`로 지정 가능.
- ncp: `ICSVEX_MULVAL_KUBECONFIG`(기본: 프로젝트의 git 제외 kubeconfig), `ICSVEX_MULVAL_REMOTE_ROOT`(기존 NCP 작업공간).
- `ICSVEX_MULVAL_CACHE`: 생성 receipt·원본 CSV·유도 기록의 내용 기반 캐시. 캐시 무결성을 확인하고 규칙을 다시 검사한다. 유효한 캐시는 실행 환경이 일시적으로 없어도 재사용할 수 있다.

실행 실패 시 `generation_status=unavailable`, 빈 노드 목록, unknown 평가를 반환한다. 경로 기반 affected/not_affected/fixed를 만들지 않는다. 검증된 미배포·공급사의 명시적 수정/비영향 버전 등 기존의 독립적인 근거 경로는 유지한다. 무결성 위반이나 조작된 유도 기록은 오류로 거부한다.

## 검증

```powershell
python -X utf8 tools/verify_mulval_integration.py
python -X utf8 -m pytest tests/test_mulval_prerequisites.py tests/test_nist_attack_graph.py tests/test_nist_auto_vex.py tests/test_nist_population_vex.py -q
node tests/test_nist_attack_graph_ui.cjs
```

`results/mulval_integration_20261118/validation_report.json`에 CVE-2010-5298(AND), CVE-2014-0198(설정), CVE-2024-3400(OR), CVE-2014-3569(미해석 입력 조건)의 24개 사례를 기록한다. 공식 공급사 원문을 새로 내려받아 기존 인용의 존재를 확인하고 원본 해시를 남긴다. 각 CVE 폴더에는 실제 MulVAL 입력·규칙·CSV·유도 기록과 사례별 판정/근거 JSON을 남긴다.

각 사례의 확인된 양극성 사실만 실제 MulVAL/XSB에 다시 제출하여 모든 의미 노드의 도출 결과를 3값 주석과 대조한다. unknown 사실은 제출하지 않으며, 양쪽 극성이 모두 유도되지 않은 상태를 unknown으로 비교한다. 구조 생성 성공만 확인하는 검사가 아니다. 해당 입력·CSV·유도 기록은 각 CVE의 `observed/`에 남는다. 생성 receipt 캐시는 프로세스 간 잠금과 원자적 쓰기를 사용하고, 원격 실행 폴더는 실행마다 분리한다.

CVE-2014-3569 원문에는 no-ssl3 빌드와 SSL v3 ClientHello 수신이 함께 등장한다. 기존 빌드 조건만으로 만든 판정은 불충분했다. 수신 조건의 검증된 자산 운영 정보 어댑터가 없으므로 원문과 함께 unknown으로 남기고 coverage를 불완전하게 둔다. 현재 세 가지 빌드 관측 모두 under_investigation이다. 자료가 실제로 없는지와 현재 변환기가 해석하지 못하는지는 구분해야 한다.

검증의 운영기록은 명시적인 합성 반사실 사례다. 실제 ICS에 대한 관측이나 독립적인 전문가 의미 검증은 수행하지 않았다. 원문 인용·논리 규칙 연결의 성공을 추출 정확도나 실설비 영향 정확도로 해석하지 않는다. 전수 생성·무결성 검증은 별도 `results/mulval_population_20261118/integrity_audit.json`의 완료 상태와 집계를 확인한다. 원문 의미 정확도와 실제 자산 정확도는 이 무결성 검사에 포함되지 않는다.

## LLM 추출 상태

기본 추출은 공급사별 확인 규칙 및 `source_logic_inference.py`·`asset_vulntology.py`·`nist_population_rules.py`의 정규식/규칙 파서다. 14B 어댑터의 학습과 검토 파이프라인 연결 코드는 구현했지만, 정확도 문턱 미달로 기본 추출기에 승격하지 않았다.

Qwen2.5-Coder-14B-Instruct LoRA 18 epoch의 개발셋 선택 체크포인트를 고정 테스트 189건에 평가했다. 원자 조건 전체 정확 일치 F1은 11.90%, 인용·유형·주체·필요성 slot F1은 70.22%, 인용 구간 F1은 83.41%다. 미라벨 테스트 1,725건은 별도 ledger에 보존하며 음성으로 쓰지 않았다. 자동 교사 표적이므로 이 수치를 독립적인 의미 정확도로 해석하지 않는다.

실제 CVE 4개에서 선택한 원문 10개를 14B 추출 → 기반 모델 검토 → DeBERTa 검토 → 관계 검토에 연결했다. 36개 후보 중 자동 수용은 0개다. 이 결과에는 모델 오류와 엄격한 필요성 표지 검사의 미확정이 함께 있으므로, 모든 후보가 의미상 틀렸다고 해석하지 않는다. 실험 overlay는 원문·미확정 근거를 보존하며 기본 경로에 반영하지 않았다.

14B 학습·추출 검토·NIST/VEX 판정·전수 생성 검증의 통합 계약은 [ITEM4_LLM_MULVAL_VEX_VALIDATION.md](ITEM4_LLM_MULVAL_VEX_VALIDATION.md)에 있다. NCP 기본 런타임은 원본 설치를 보존한 `/opt/mulval-population`이며, `ICSVEX_MULVAL_TOOL_ROOT`로 명시할 수 있다. 검토 가능한 변경은 `tools/mulval_population_runtime.patch`에 보존한다.
