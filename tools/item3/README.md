# #3 제품·버전·CVE 식별

데이터 분할은 **train / test**입니다. 지정 경로의 원본 3,881개를 `rebuild_icsa_cpe_source.py`로 CPE 보강하고 `verify_rebuilt_cpe_source.py`로 원본 보존·CVE DB 조건을 대조합니다. 기존 v2 전체는 별도 백업했습니다.

`build_item3_balanced_dataset.py`가 `benchmark/item3_advisory_inputs_v5`에 13,205개 실제 SBOM 입력을 생성합니다. 적용 가능한 3,108개 문서마다 실제 I1/I2/I3 변형을 하나씩 생성해 비율을 1:1:1로 맞춥니다. `verify_item3_balanced_dataset.py`가 원본·골드·실제 필드 변화·분할 중복을 전수 검사하고 `finalize_balanced_rebuild.py`가 스키마와 마스킹/표기 변형 수를 검증합니다. 생성기는 새 출력 디렉터리만 허용합니다.

기본 선택은 `data/item3_test_dataset.json`입니다. `python tools/item3/run_item3_test.py run --mode agents --output results/item3_test_agents_v1`로 실행합니다. `predict`와 `score`를 분리할 수 있습니다. 이전 데이터와 과거 결과는 보존하며 `rescore-recorded`는 과거 예측만 재집계합니다. [상세 절차](../../docs/ITEM3_TEST_WORKFLOW.md)
