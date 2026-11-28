# #3 제품 식별 및 CVE 매칭

#3은 **train / test**로 구분하고 실제 SBOM 파일을 입력으로 사용합니다.

현재 원본은 `benchmark/icsa-cpe-synthetic sbom/sbom`의 CPE 보강 v3 문서 3,881개입니다. 기존 CSAF 구성요소 29,066개를 유지하고 CVE DB의 vulnerable CPE 조건을 별도 구성요소 78,200개로 추가했습니다. 원래 CSAF 제품에 근거 없이 CPE를 붙이지 않습니다. 원본 v2 전체는 별도 백업했습니다.

- 입력: `benchmark/item3_advisory_inputs_v5/train/sboms` 7,737개, `test/sboms` 5,468개
- 대상 고유 CVE: train 7,593개 / test 3,254개. 같은 CVE·동일 입력으로 연결된 그룹은 같은 분할에 배정합니다.
- 원본마다 기준본 1개, 적용 가능한 3,108개 원본마다 I1 이름·I2 버전·I3 CPE 변형본을 각각 1개씩 만듭니다. 세 변형은 동일 구성요소의 필드 하나만 바꾸며 골드는 같습니다.
- 실제 노이즈는 각 유형 3,108건으로 1:1:1입니다. 마스킹·표기 변형을 각각 절반 유지합니다. 773개는 기준본만 만들며 no-op 변형본은 만들지 않습니다.
- 정답은 별도 `annotations/<ID>.json` 또는 `gold.jsonl`입니다. 모델 입력의 vulnerabilities·출처 설명·정답 CVE 토큰은 분리합니다.

`tools/item3/run_item3_test.py`의 `predict`는 SBOM만 읽고 서비스 함수로 예측합니다. `score`에서 골드를 읽어 SBOM × 구성요소 bom-ref × CVE 단위로 채점합니다. 명시적 CSAF/NVD 조건 연결을 양성으로 유지하며 미기재 관계는 unknown입니다. NVD 조건은 실제 설치 버전 또는 플랫폼 AND/OR 전체 충족을 뜻하지 않습니다.

기본 입력은 `data/item3_test_dataset.json`의 해시를 검증한 뒤 선택합니다. [실행·검증 절차](../../docs/ITEM3_TEST_WORKFLOW.md)를 참고하십시오. 이전 18,608건과 과거 결과는 보존하며 새 데이터셋 점수로 옮기지 않습니다. 이번에 모델 재학습·전수 성능 측정을 수행한 것은 아니며, 기존 모델의 새 test 학습 이력 중복은 미검증입니다.

기능별로 관련 모듈과 리소스를 묶었습니다.

| 폴더 | 역할 |
| --- | --- |
| [matching/](matching/) | SBOM 후보 생성, 제품·버전 식별, CPE/CVE 매칭 |
| [agents/](agents/) | I1/I2/I3 에이전트 계약, 추론 실행, 분기 및 입출력 |
| [evidence/](evidence/) | CISA/CPE 근거 검색, 색인, 버전 관측 |
| [web/](web/) | 식별 화면, 웹 작업 큐, 결과·진단 표시 |

새 코드는 기능별 패키지 경로를 사용합니다. 이전 `src.item3.모듈명` import도 같은 모듈로 연결되며 실행 상태를 중복 생성하지 않습니다. 파일 경로는 `src.common.paths.source_path()`로 확인할 수 있습니다.

전체 안내: [src/README.md](../README.md). 이동 내역: [manifest.json](../../results/functional_layout_20261123/manifest.json).
