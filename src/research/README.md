# 유지 중인 오프라인 보조 모듈

현재 실행 도구의 참조를 확인한 모듈만 유지합니다. 서비스 구현은 `../item3/`, `../item4/`, `../common/`에 있습니다.

| 모듈 | 남겨 둔 이유 |
|---|---|
| `candidate_snapshot.py`, `identification_batch_flow.py` | #3 기록 재현·배치 평가 도구의 의존성 |
| `training_memory.py` | 유지 중인 학습·홀드아웃 도구의 의존성 |
| `item4_source_recovery.py` | 출처 복구·고정 근거 데이터 생성 |
| `item4_asset_english.py`, `ui/`의 남은 리소스 | 기존 UI·입력 기준 생성 도구에서 참조 |
| `item4_stage1*`, `reviewer_agreement.py` | 남아 있는 H200 검사·제출 도구의 전이 의존성 |
| `nf4_dense_cache.py` | 기존 전수 실행의 선택적 진단 도구에서 참조 |

퇴역 NER·조건 추출 실험은 2026-11-25 작업 트리에서 제거했습니다. 원본과 전용 테스트의 복구 위치는 `../../results/current_logic_cleanup_20261125/manifest.json`에 있습니다. 오래된 파일명만을 근거로 남은 모듈을 삭제하면 유지 중인 도구가 깨질 수 있습니다.
