# archive/ — 실행(PoC 트리거) 경로의 격리 보관소

2026-08 정적분석 전면 개편으로 **비활성화된** 파일들을 보관한다. 삭제하지 않은 이유는
과거에 실제로 수행된 실행 검증(execution-verified)의 재현 근거를 남기기 위해서다.

## 왜 격리했나

기존 시스템은 실행검증 방식(논문 기반)으로 sLLM이 PoC를 **생성**하고 샌드박스에서 **실행**해
CTF flag로 확정을 내렸다. 이 실행/트리거 경로가 보안 정책에 반복적으로 막혔다. 라이브
파이프라인은 이제 PoC를 생성·실행하지 않고 **순수 정적분석**으로만 VEX를 판정한다
(`src/vex_pipeline.py`, `src/vex_infer.py`, `docs/STATIC_VEX_LEGACY.md` 참조).

## 파일

| 파일 | 원래 역할 | 대체 |
|---|---|---|
| `exec_verify_batch.py` | C+ASan 실행 검증 배치 | 없음 — 정적 판정으로 대체 |
| `exploit_verifier.py` | Python 라이브러리 실행 검증 | 없음 |
| `build_verify_specs.py` | 실행 검증 스펙/가능성 분류 생성 | 없음 (정적 경로엔 불필요) |
| `train_poc_sllm.py` | PoC 생성 sLLM 학습 | sLLM은 이제 정적 분석가로만 사용 (`vex_infer.SllmStaticAnalyst`) |

## 과거 실측 데이터는 유지

`results/exec_verification*.json` 은 `results/` 에 그대로 둔다. 과거 execution-verified
5건(예: zlib CVE-2018-25032)의 실제 실행 결과 근거이며, `build_ground_truth.py` 가
아직 이를 읽어 해당 5건을 역사적 확정 계층으로 표기한다. 다만 **신규 판정의 확정
tier 는 `static-analysis-verified`** 이며, 실행 경로로는 더 이상 새 확정이 생기지 않는다.
