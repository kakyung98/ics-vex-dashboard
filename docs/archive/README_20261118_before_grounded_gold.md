# ICS-VEXForge

SBOM의 제품·버전·식별자로 CVE를 연결하고, 소스코드가 없는 ICS 자산의 운영맥락으로 VEX를 검토하는 연구 시스템입니다. **문서 확인: 2026-11-16 KST.**

## 실행과 메뉴

프로젝트 루트에서 현재 PC의 준비된 Python 환경을 사용합니다. 의존성은 [requirements-precision.txt](requirements-precision.txt), NCP 환경은 [requirements-ncp.txt](requirements-ncp.txt)를 참고합니다. GPU용 PyTorch, 모델과 원천 데이터는 별도로 필요합니다.

```powershell
python -X utf8 -B tools/serve_nist_operational_vex.py 8100
```

이 진입점은 현재 개발 중인 BOM/VEX 서비스에 **NIST 표 12–17의 54개 원문 항목·167개 세부정보 입력 화면**을 연결합니다. 각 세부정보의 영어 근거·원문 열·해석상 주의를 입력란에 표시하고, 세부 ID 단위로 관측·근거를 저장합니다. 명세는 [docs/ICS_OT_profiles_v0_1.md](docs/ICS_OT_profiles_v0_1.md)이며, 이전 82개 양식의 저장값은 자동 이관하지 않습니다. 기반 서비스는 저장소 상대 경로 `local-service/sbom-vex/vex_operational_logic_20261117`의 모듈과 저장 DB를 사용합니다. 필요한 소스·템플릿·스키마는 [런타임 목록](local-service/runtime_manifest.json)에 따라 Git에 포함하며, 검토 DB와 로그는 제외합니다. 새 환경의 DB는 처음 저장할 때 생성됩니다. `tools.local_dataset_app:app`은 기본 데이터셋 서비스이므로 새 입력 화면을 사용하려면 위 진입점을 실행하세요.

GitHub에서 내려받을 때는 Git LFS로 보관하는 평가 Gold, 원천 DB, CPE 사전과 모델 어댑터도 받아야 합니다. 저장소에서 `git lfs install` 후 `git lfs pull`을 실행하세요. 전송용 대형 압축본, 원시 추론 캐시와 실행 로그는 동기화 대상에서 제외합니다. GitHub Pages 배포본에서는 방법론 메뉴와 페이지를 제외하며 로컬 개발 사이트에는 유지합니다.

| 메뉴 | 화면 | 기능 |
| --- | --- | --- |
| SBOM → CVE | [index.html](http://127.0.0.1:8100/index.html) | 제품·버전·식별자 검토와 CVE 매핑 |
| Operational VEX | [vex-decision.html](http://127.0.0.1:8100/vex-decision.html) | 자산·CVE별 시나리오와 운영맥락 검토 |
| #4 자동 운영맥락 VEX | [전용 API](http://127.0.0.1:18104/docs) | 자동 검증 카탈로그·원문 제품/인용·운영정보 양식·VEX 판정 |
| Method Overview | [sbom-to-cve.html](http://127.0.0.1:8100/sbom-to-cve.html) | 식별 방법과 근거 검증 설명 |
| Synthetic SBOM | [ics-sbom.html](http://127.0.0.1:8100/ics-sbom.html) | ICSA별 BOM 3,881개 목록·검색·JSON 보기 |
| API | [docs](http://127.0.0.1:8100/docs) | API 명세 |

NCP H200 서비스는 별도 포트 **18100**을 사용합니다. 접속·재시작은 [NCP 안내](docs/NCP_MIGRATION.md)를 참고합니다.

## 현재 폴더 구조

```text
benchmark/
├── item3_evaluation/
│   ├── input.jsonl
│   ├── gold.jsonl
│   └── results.json
└── icsa-cpe-synthetic sbom/
    ├── sbom/                     # ICSA별 BOM JSON 3,881개
    ├── index.json
    ├── linkage.jsonl
    ├── excluded.json
    ├── manifest.json
    ├── audit.json
    ├── README.txt
    └── icsa-cpe-sbom-v1.zip
```

### #3 평가 자료

[benchmark/item3_evaluation](benchmark/item3_evaluation/)은 2026-11-16 H200 평가 자료입니다.

| 파일 | 내용 |
| --- | --- |
| [input.jsonl](benchmark/item3_evaluation/input.jsonl) | SBOM 입력 12,418행. 각 행은 `id`, `cve`, `sbom`을 포함합니다. |
| [gold.jsonl](benchmark/item3_evaluation/gold.jsonl) | 별도 정답인 `expected_cves`, `unknown_cves`와 근거입니다. `id`로 입력과 연결합니다. |
| [results.json](benchmark/item3_evaluation/results.json) | 최신 지표, 검증, 12,418건의 채점, 고유 입력별 집계, FP·미확정 출력 내역입니다. |

입력·정답은 정리 당시 원본과 해시가 일치하는 **NTFS 하드 링크**로 구성했습니다. 독립 복사본이 아니므로 내용을 수정하면 같은 파일을 가리키는 다른 경로에도 반영됩니다. 단순 이름·폴더 이동은 내용을 바꾸지 않습니다. `results.json`은 통합 보고서이며 전체 원시 모델 추론 기록은 아닙니다. 약 5.63 GB의 원시 예측 DB는 H200에 보관합니다.

### ICSA별 합성 SBOM

[benchmark/icsa-cpe-synthetic sbom](<benchmark/icsa-cpe-synthetic sbom/>)은 평가 자료와 **별도로 만든 데이터셋**입니다. 기존 #3 평가 입력·Gold를 이 데이터로 교체하거나 Precision을 다시 계산하지 않았습니다.

생성 흐름은 `ICSA → 명시된 CVE → 공개 vulnerable:true CPE 조건 → BOM 컴포넌트`입니다. 같은 CVE가 여러 권고문에 있으면 각각 유지합니다. 같은 권고문 안에서는 동일 CPE·버전 범위 조건을 공유하고 `vulnerabilities[].affects[].ref`로 CVE와 컴포넌트를 연결합니다.

| 항목 | 개수 |
| --- | ---: |
| ICSA / BOM JSON | 3,881 |
| CPE 컴포넌트가 있는 BOM / 빈 기록 | 3,108 / 773 |
| 원래 고유 CVE / 권고문별 명시 횟수 | 12,418 / 15,086 |
| 포함 고유 CVE / 권고문별 포함 횟수 | 10,847 / 13,365 |
| CPE가 없어 제외한 고유 CVE / 제외 횟수 | 1,571 / 1,721 |

CycloneDX 1.6 스키마로 전체 문서를 검증했습니다. 버전 와일드카드에서 설치 버전을 만들지 않고 원본 범위를 `properties`에 보존합니다. 여러 CPE는 대안 제품·릴리스를 나타낼 수 있으며 실제 동시 설치 구성이나 전체 플랫폼 AND/OR 충족을 뜻하지 않습니다. CVE 연결 답이 들어 있으므로 그대로 블라인드 평가 입력으로 사용하지 않습니다.

`index.json`은 목록, `linkage.jsonl`은 원문 CPE·구성 경로·연결 근거, `excluded.json`은 제외 내역, `manifest.json`은 집계·출처 해시, `audit.json`은 무결성 검사입니다. **새 합성 데이터셋의 Precision은 미측정**입니다. [생성기](tools/build_icsa_cpe_sbom.py)와 [대조 검사](tools/audit_icsa_cpe_sbom.py)는 원천 스냅샷이 필요하며 기존 공개본을 보존한 뒤 사용해야 합니다.

## 식별 로직과 RAG

SBOM 파싱·CPE 해석·NVD 조회 공통 모듈은 `src/ics_agent_matcher_full/ics_agent_matcher/matcher.py`에 있습니다. 예전 루트의 `ics_agent_matcher_full` 폴더를 이 위치로 이동했으며 서비스와 벤치마크 import도 함께 변경했습니다.

`Parsing → Orchestrator → 필요한 P2/P3/P4 → Decision Validator → CVE Matching` 순서입니다. LangGraph가 각 단계 후 조건을 재검사하며 필요한 에이전트를 순차 실행합니다. P2는 제품명, P3는 버전, P4는 식별자입니다. Qwen2.5-Coder-14B 계열 NF4 기반 모델과 공유 QLoRA 어댑터를 사용하며 역할별 프롬프트·응답 계약을 구분합니다. 에이전트 단계 선택이 반드시 GPU 호출을 뜻하지는 않습니다.

제품 식별은 구조화 제품·CPE 조회, BM25, **문자 3-gram TF-IDF 코사인** 검색을 RRF로 합치는 Hybrid RAG를 사용합니다. 의미 임베딩 모델 검색은 아닙니다. 검색 후보와 근거를 에이전트에 전달하지만 검색 점수·모델 선택만으로 제품을 확정하지 않습니다.

현재 구현의 구분과 한계:

- 이름의 짧은 숫자 릴리스 계열은 상세 설치 버전의 접두부와 맞으면 충돌에서 제외합니다. 명시 버전 필드끼리는 문자열로 충돌을 검사하므로 `1.2`와 `1.2.0`이 충돌할 수 있습니다. 숫자 버전 대소 비교에서는 두 값을 같게 처리하는 것과 별개입니다.
- `>=1.0, <2.0`은 범위로 보존합니다. 일반 구성 매칭에는 포함·분리·부분 겹침 비교가 있지만 현재 #3 식별 경로는 선언 범위를 전달하지 않아 범위만으로는 미확정이 남을 수 있습니다.
- Operational VEX 웹 화면은 저장된 CVE·제품별 원문 시나리오를 조회해 운영맥락과 대조합니다. 제품 식별과 동일한 Hybrid RAG 경로는 아닙니다.

기존 VEX 기능은 NIST Vulntology, MITRE ATT&CK ICS 자산·기법, OVAL/OpenSCAP 관측, MulVAL/XSB를 활용합니다. 새 #4 자동 경로는 별도 근거 검증·AND/OR 그래프·운영정보·판정 모듈로 구성합니다. 자산 분류나 경로 부재만으로 영향을 확정하지 않으며 관측 누락·범위 불일치·충돌·만료는 미확정입니다. 사람 검토는 선택 사항이며 자동 검사를 독립 정답 정확도로 취급하지 않습니다.

## ICSA 기존 18개 유형 전수 재배정

Workstation·HMI·PLC 등 기존 **18개 유형 이름·정의·순서**와 Related Assets **43개 관계 / 중복 제거 39개 이름**을 유지합니다. ICSA **3,881개 전부**에 대표 유형 또는 미배정 상태를 부여하고, 연결된 고유 CVE **12,418개**와 원래 연결을 보존합니다. CVE는 여러 ICSA를 통해 여러 유형에 나타날 수 있습니다.

| 현재 결과 | ICSA / 점수 |
| --- | ---: |
| 대표 유형 배정 | 3,620 |
| 유형 문구 발견 | 744 |
| 단일 유형 문구로 배정 | 632 |
| 복수 유형 문구 중 모델로 대표 유형 선택 | 112 |
| 유형 문구 없이 모델로 추정 | 2,876 |
| 미배정 | 261 |
| **전수 TF-IDF / SVD3072 / source-reference LDA16 코사인 Silhouette** | **0.52499334** |
| 전수 원본 TF-IDF 코사인 Silhouette | 0.00985868 |

미배정을 별도 그룹으로 포함한 전수 점수로 **0.5 초과 / 미배정 500개 이하**를 충족합니다. 위 0.5 초과는 기준 라벨로 지도 투영한 **SVD/LDA 공간**의 점수입니다. 원본 TF-IDF 점수는 표와 같습니다. 기준 라벨 1,488개가 평가 대상에도 포함되며 독립적인 정확도 검증은 수행하지 않았습니다. Jump Host는 근거 없이 채우지 않아 18개 중 실배정 유형은 17개입니다.

문구 누락을 보완하기 위해 합성 overview의 앞부분을 잘라 사용하던 방식 대신 **CSAF 제품 트리·취약점 설명·문서 설명의 원래 필드**를 읽습니다. HMI/SCADA Server 등 약어, 단수·복수, 하이픈 변형을 처리합니다. 일반 방화벽/VPN 보안 권고, 주변 장비, 의료 PACS 등 충돌 약어는 자산 유형 근거에서 제외합니다. 문구가 하나의 유형만 지지하면 그 유형을 우선 적용하고, 여러 유형을 지지하면 후보를 모두 남긴 뒤 모델로 대표 유형을 선택합니다. 기존 단일 문구 배정 454개는 **632개**로 늘었습니다.

각 ICSA에 **실제 원문 인용·앞뒤 문맥·출처 URL·CSAF JSON 경로·문자 위치·공식 유형 정의**를 제공합니다. 모델 추정은 실제 선택과 비교 유형의 점수 차이에 기여한 양의 TF-IDF 단어를 표시합니다. 문구 일치와 모델 추정 상태를 구분하며 CVE 연결에도 상태를 유지합니다.

[방법·유형별 수량·재현·검증](results/icsa_fixed18_reclassification/README.md), [ICSA 배정·근거](results/icsa_fixed18_reclassification/assignments.json), [CVE 연결 CSV](results/icsa_fixed18_reclassification/cve_asset_memberships.csv).

## 보존된 자유 텍스트 18개 군집 — 이전 실험

다음은 별도로 보존한 ICSA 텍스트 군집 분석 결과입니다. 화면의 고정 자산 유형 분류와 구분합니다. ICSA **3,881개 전부**를 **18개 군집으로 고정**해 다시 배정했고, CVE **12,418개 전부**와 ICSA–CVE 연결 **15,086건**을 유지했습니다. 군집별 CVE는 중복 제거하며, 여러 군집에 연결된 CVE는 **1,035개**입니다. 미배정 ICSA와 미연결 CVE는 모두 0개입니다.

**방법:** ICSA 제목·CSAF 제품명·보수적으로 추출한 명시적 기능 문장 → **TF-IDF(단어 1–2그램) → SVD16 → L2 정규화 → K-means(K=18)**. SVD seed=42, K-means seed=107, n_init=10입니다. 기존의 역할 이웃 추정이나 전체 역할 사전분포는 새 군집화 입력에 사용하지 않으며, 불확실한 기능 주석으로만 보존합니다.

| 전수 3,881개 기준 지표 | 결과 |
| --- | ---: |
| **SVD16 공간 코사인 Silhouette** | **0.5551393032** |
| 원본 TF-IDF 공간 코사인 Silhouette | 0.0440281071 |
| SVD 설명분산 | 7.9238% |
| 음수 SVD Silhouette ICSA | 229 |
| 비교한 설정 / 고정 군집 수 | 42 / 18 |

**0.5 초과 목표는 SVD 축소 공간에서 충족했으며, 원본 TF-IDF 공간에서는 충족하지 않았습니다.** 설명분산이 낮고 벤더·제품군 표현이 영향을 주므로, 이 점수를 자산 기능 분류 정확도나 원본 텍스트 전체의 높은 분리도로 해석하지 않습니다. 42개 후보 모두 전수 ICSA와 K=18을 유지했습니다. 유지되는 TF-IDF 특징이 없는 7개도 제외하지 않고 불확실로 표시해 최종 분할과 점수에 포함했습니다. 낮은 점수·근거 부족 권고문을 제외하거나 정답 라벨에 맞춰 배정하지 않았습니다.

명시적인 기능 표현이 없는 ICSA는 **3,198개**이며, 중심 간 거리 차가 작은 경우까지 포함한 불확실 배정은 **3,270개**입니다. 이 불확실성을 CVE 연결에도 유지합니다. 군집명은 원문 키워드와 관찰된 역할을 참고한 표시 이름이며, 기능 근거가 부족한 다수 군집에는 `role unverified`를 붙입니다. ICSA 소속만으로 연결된 모든 CVE의 영향 자산·악용조건·VEX 상태를 확정하지 않습니다. **독립적인 의미·분류 정확도는 미검증**입니다.

[방법·군집별 수량](results/icsa_role_clusters_k18/README.md), [42개 탐색 기록](results/icsa_role_clusters_k18/tfidf_svd_search/search.json), [최종 설정](results/icsa_role_clusters_k18/tfidf_svd_search/best.json), [출처·설정·해시](results/icsa_role_clusters_k18/manifest.json), [ICSA 배정 CSV](results/icsa_role_clusters_k18/icsa_clusters.csv), [CVE–ICSA–군집 연결 CSV](results/icsa_role_clusters_k18/cve_cluster_memberships.csv)에 기록했습니다. [이전 역할 추정 기반 결과](results/icsa_role_clusters_k18/history/role_neighbor_20261116/README.md)는 별도로 보존합니다. 루트의 `cve_clusters_cisa_context_svd16.csv`는 더 이전의 CVE 단위 16개 군집 결과이며 변경하지 않았습니다.

## #4 운영맥락 VEX 개발 태스크

2026-11-16에 합의한 작업 순서입니다. 각 단계의 구현 검증과 독립적인 의미·정확성 검증을 구분하며, 기존 합성 평가 결과를 새 단계의 검증 완료로 취급하지 않습니다.

| 단계 | 작업 | 검증 | 진행 상태 |
| --- | --- | --- | --- |
| 1 | ICSA-CVE 악용조건 추출 | 정확 인용·범위·별도 검토·NLI·역방향 누락 탐색 | 구현·H200 전수 처리·원문/응답 감사 완료 |
| 2 | 악용조건 기반 공격 그래프 | AND/OR·행위자·조건 참조·포괄성 원문 증거 | 구현·12,418개 그래프 재검증·현재 124개 경로; 전체 경로 포괄성 승인 0 |
| 3 | 자산별/취약점별 운영정보 | 확인 가능성·필드 충분성·조건 매핑 | 구현·강화 검증을 통과한 673개 CVE 조건 필드·자산 유형 18개 양식 |
| 4 | 자산–ICSA&CVE–운영정보 기반 VEX | 범위·불확실성·변경 재평가·내보내기 | 구현·판정/토폴로지/OpenVEX/API 자동 검사 완료; 실자산 미평가 |

공통 원칙:

- 원문 근거가 없는 조건은 확정 추출하지 않습니다. CVSS·CWE·ATT&CK 분류, 일반 보안 지식, 완화 권고에서 필수조건을 만들어내지 않습니다.
- 정확한 인용의 존재와 인용이 조건의 의미를 뒷받침하는지는 별도 검증합니다. 모델 간 일치나 테스트 통과만으로 의미 검증 완료를 선언하지 않습니다.
- 원문 → 조건 → 그래프 관계 → 운영정보 필드 → 실제 입력 → VEX 판단의 추적 관계를 유지합니다.
- 미입력·추출 실패·원문 부재를 조건 불충족으로 바꾸지 않습니다. 그래프 경로 부재만으로 `not_affected`를 발행하지 않습니다.
- 전체 적용 시 목표 CVE 12,418개의 처리 상태를 유지하고, 원문이 부족한 CVE를 정확도 개선 목적으로 제외하지 않습니다. 독립 수동 평가 표본은 전수 처리와 구분합니다.

**현재 기본 경로는 사람 라벨링을 필수로 하지 않는 [4단계 자동 파이프라인](docs/ITEM4_AUTOMATIC_PIPELINE.md)입니다.** 모델은 H200에서 실행하며 정확 인용·별도 검토·다른 계열 NLI·역방향 탐색·관계 검증을 통과한 조건을 automatic_pass로 구분합니다. 원문 범위와 실제 운영 근거가 부족하면 후속 결과도 미확인입니다. [이전 1단계 설계](docs/ITEM4_STAGE1_EXTRACTION_DESIGN.md)와 [수동 검토 CLI](docs/ITEM4_STAGE1_RUNBOOK.md)는 선택적 경로로 보존하며 사람 승인을 자동 경로의 진행 필수 조건으로 사용하지 않습니다.

[운영정보 입력 계약](docs/ITEM4_OPERATOR_INPUTS.md)에 자산별 조사 항목과 설정 비활성화·네트워크 차단 근거 요건을 정리했습니다. `tools/item4_asset_form.py`는 상세 조사 양식을 생성·검증하고, `tools/item4_catalog_service.py`는 완성된 카탈로그의 CVE·원문 제품·입력 양식·판정 API를 별도 loopback 포트 18104에서 제공합니다.

### #4 강화 재검증 — 20261116_policy05

작업 폴더는 `D:\ICS-VEX`이며 모델 실행은 H200에서 수행합니다. 기존 생성 응답과 원문 해시는 보존하고, 전체 31,503개 입력에 강화 정책을 다시 적용했습니다. 새 조건·경로를 추가하거나 포괄성 기준을 완화하지 않았습니다. 최종 감사 및 전달 검증 결과는 해당 실행 폴더에 기록합니다.

| 항목 | 이전 auto04 | 강화 재검증 policy05 |
| --- | ---: | ---: |
| 목표 CVE / 고유 원문 입력 | 12,418 / 31,503 | 12,418 / 31,503 |
| CVE·제품에 연결된 자동 통과 조건 / 운영 필드 | 725 / 725 | 673 / 673 |
| 자동 통과 조건이 있는 CVE | 396 | 373 |
| 원문 검토 경로 / 경로가 있는 CVE | 132 / 97 | 124 / 92 |
| 전체 경로 포괄성 승인 | 0 | 0 |

기존 조건 52개가 제외됐습니다. “필요하지 않음”을 “없어야 함”이라는 필수조건으로 바꾸던 10개는 의미 방어 규칙으로 거부했습니다. 나머지 42개는 선택한 정확 인용문에 대한 NLI 검사에서 중립 34개·모순 8개로 분류됐습니다. 중립은 잘못된 조건이라는 독립 정답 판정이 아니라 인용문만으로 승인할 근거가 부족하다는 뜻입니다. 52개는 CVE·제품 범위에 연결된 조건 건수이며, 원문 입력 내 조건 건수와 다릅니다.

예를 들어 `Successful exploitation requires no system privileges and no user interaction.`은 사용자 조작이 필수조건이 아니라는 설명입니다. 이를 `no user interaction is required`라는 **충족해야 할 필수조건**으로 승인하면 안 됩니다. 반대 조건을 새로 만들어 넣지도 않습니다. 이제 전체 문맥과 선택한 인용문 모두 내용 지지 검사를 통과해야 합니다. H200에서 고유 인용문–조건 500쌍을 새로 검사했고, 인용문이 전체 문맥과 정확히 같은 307건은 동일 입력에 대한 기존 NLI 판정을 명시적으로 재사용했습니다.

[재검증 상세](results/item4_automatic/20261116_policy05/reanalysis_report.json), [제외된 조건과 CVE](results/item4_automatic/20261116_policy05/catalog_delta.json), [포괄성 미승인 사유](results/item4_automatic/20261116_policy05/coverage_funnel.json)를 보존합니다. 사람 라벨링은 필수 조건이 아니며, 자동 검사 통과를 독립 의미 정확도나 무누락 증명으로 표현하지 않습니다. 미해결 입력 2개와 전체 경로 포괄성 미확인은 유지합니다. 따라서 운영조건만으로 `not_affected`를 자동 발행할 대상도 현재 0개입니다.

로컬 회귀 검사 **135개**(로컬 모델 학습 테스트 1개 제외), H200 계약 검사 **76개**, H200 실제 모델 통제 사례 **10개**를 통과했습니다. 로컬과 H200 계약 검사는 겹치는 구현 검사이며 합산해 정확도 표본 수로 세지 않습니다. 긍정 통제 사례의 일부 조건이 보류되기도 하므로 통제 사례 통과를 추출 Recall 100%로 해석하지 않습니다. [H200 최종 감사](results/item4_automatic/20261116_policy05/validation_report.json), [다운로드 무결성 검사](results/item4_automatic/20261116_policy05/delivery_validation.json)에 아티팩트 34개·443,560,762바이트와 실행 코드 40개 파일의 일치를 기록했습니다.

[전후 응답 보존 감사](results/item4_automatic/20261116_policy05/correction_summary.json)는 원문 입력 31,503개 모두의 생성 응답·조건 내용·기존 문맥 NLI가 유지됐고 새 승인·조건·경로·포괄성 승격이 없음을 별도로 대조했습니다. [실제 HTTP 검사](results/item4_automatic/20261116_policy05/live_api_validation.json)는 새 카탈로그 제공, 원문·제품 연결, 잘못 승인됐던 비필수성 조건 제거, 미입력 판정 거부 등 7개 요청을 기록합니다. 현재 18104 API는 `policy05` 카탈로그를 제공합니다. H200 임시 모델 서버는 종료했고 기존 18100 서비스의 HTTP 200 응답을 [자원 종료 기록](results/item4_automatic/20261116_policy05/resource_closeout.json)에 남겼습니다.

### #4 이전 자동 실행 기록 — 20261116_auto04 (현재 결과로 사용하지 않음)

아래 수치는 강화 정책 적용 전의 역사 기록입니다. 잘못 승인된 비필수성 표현을 포함하므로 현재 승인 조건 수로 사용하지 않습니다.

| 항목 | 결과 |
| --- | ---: |
| 유지한 목표 CVE | 12,418 |
| 원문 구간 / 역할·텍스트별 고유 모델 입력 | 121,863 / 31,503 |
| 원문·CVE·제품 범위까지 자동 통과한 조건 / 운영 필드 | 725 / 725 |
| 승인 조건이 있는 CVE | 396 |
| 경로가 있는 CVE / 원문 검토 경로 | 97 / 132 |
| 전체 경로 포괄성 자동 승인 | **0** |
| 처리 보류 고유 입력 / 연결된 원문 구간 | 2 / 3 |
| 자산 유형 상세 양식 / 원문 제품 참조 | 18 / 28,711 |
| 로컬 회귀 / H200 계약 검사 / H200 통제 모델 사례 | 114 / 55 / 9 통과 |
| 실제 자산 평가 / 실제 자산 VEX 발행 | 0 / 0 |

**현재 자동 포괄성 정책을 통과한 CVE는 없으므로, 이 카탈로그에서 운영조건만으로 `not_affected`를 자동 발행할 대상은 없습니다.** 원문에 포괄성 근거가 절대 없다는 독립 정답 판정은 아닙니다. 빈 경로와 미확인을 비영향으로 바꾸지 않습니다. 실자산 운영정보도 아직 입력되지 않았습니다.

자동 누락 검사는 원문 표현 4,492개를 대조해 419개 입력에서 미포함 경보 493개를 기록했습니다. 이 경보에는 실제 악용조건이 아닌 문장도 포함됩니다. 역방향 추가 후보 23,461개 역시 확정 누락 수나 Recall이 아닙니다. 독립 의미 Precision/Recall은 미측정입니다. 로컬 검사에서 레거시 H200 전용 tiny 학습 테스트 1개는 제외했고, 실제 생성 모델·NLI 실행과 통제 모델 검사는 H200에서 수행했습니다. 이번 과업용 추가 학습은 하지 않았습니다.

[최종 자동 감사](results/item4_automatic/20261116_auto04/validation_report.json), [전달 무결성 검사](results/item4_automatic/20261116_auto04/delivery_validation.json), [실제 HTTP 검사](results/item4_automatic/20261116_auto04/live_api_validation.json), [CVE별 목록](results/item4_automatic/20261116_auto04/catalog/cve_index.json), [원문 연결 예시](results/item4_automatic/20261116_auto04/catalog/example_record.json)를 저장했습니다. 사용한 원시 응답은 `unit_results.jsonl.gz`, 원문 위치는 `catalog/evidence.sqlite3`에 있습니다. 전체 요청 캐시는 H200에 보존하고 해시·경로를 [자원 종료 기록](results/item4_automatic/20261116_auto04/resource_closeout.json)에 남겼습니다.

```powershell
python tools/item4_catalog_service.py --catalog results/item4_automatic/20261116_policy05/catalog --port 18104
```

전용 API는 기존 8100 검토 화면과 별도이며 현재 [http://127.0.0.1:18104/docs](http://127.0.0.1:18104/docs)에서 확인할 수 있습니다. H200 임시 추론 서버는 종료했고 기존 18100 서비스의 HTTP 200 응답을 확인했습니다. 실행 중 성능 비교에서 발생한 컨테이너 메모리 부족과 복구는 `recovery.json`에 기록했습니다. 이전 실행과 유효 응답의 원래 모델 ID·해시는 보존했습니다.

이전 1단계 H200 실행 `stage1_20261116_v4`는 CVE **12,418개**를 유지하고 ICSA 원문 **3,802개 / 121,863구간**을 처리했습니다. 규칙 baseline의 필수조건 **후보 1,301건**, 승인 **0건**, VEX 발행 **0건**입니다. 다른 역할의 원문 구간 후보를 필수조건 수에 합산하지 않습니다. 원문 파일 미확보 ICSA **79개**, CVE별 본문 미확보 **89개**도 원장에 유지했습니다. 실제 원문의 부정 표현 97건이 필수조건으로 오분류되지 않는지 재검사했습니다. 이 검사는 전체 의미 정확도 검증이 아닙니다.

[검증 보고서](results/item4_stage1/stage1_20261116_v4/validation_report.json), [누락 원문 목록](results/item4_stage1/stage1_20261116_v4/source_coverage.json), [독립 라벨링용 원문 표본](results/item4_stage1/stage1_20261116_v4/pilot_annotation_template.jsonl)을 저장했습니다. 표본은 100개 원문·3,396구간의 **미라벨 템플릿**이며 학습/개발/시험 분할이나 Gold가 아닙니다. H200의 tiny BERT CUDA 학습 회귀 테스트는 통과했지만 운영용 모델 학습과 독립 의미 Precision/Recall은 아직 미수행·미측정입니다.

## 기존 H200 평가

2026-11-16 실행은 실제 CVE **12,418개**를 공통 모집단으로 사용했습니다. **공개 원문 기반 합성 평가이며 실제 ICS 자산의 독립 정답에 대한 Precision은 미측정입니다.**

| 평가 | 결과 |
| --- | --- |
| #3 고유 SBOM 입력 | 5,114개; 원래 12,418행 중 동일 JSON 7,304행 중복 제거 |
| #3 TP / FP / 미확정 양성 | 683,488 / 56 / 16 |
| #3 Precision 보수적 하한 | `683488 / (683488 + 56 + 16)` = **99.9894669%** |
| #3 알려진 양성 기준 Recall | **99.6752%** |
| #4 전체 | 12,418 CVE / 24,678 운영맥락 사례 |
| #4 전체 모델 단독 Precision | **98.8731%**; TP 2,369 / FP 27 |
| #4 별도 시험 모델 단독 Precision | **98.8462%**; TP 514 / FP 6 |
| #4 별도 시험 모델+검증 | Precision **100%**; TP 508 / FP 0; Recall **30.4010%**; 보류율 **92.5261%** |
| 전체 실행 시간 | 약 **54분 21초** |

#3은 학습 계열 입력을 포함한 전수 점검이며 독립 미학습 시험 성능이 아닙니다. #4 별도 시험은 4,012 CVE / 6,797건입니다. 높은 Precision을 높은 탐지율로 해석하지 않으며 합성 가정과 원문 의미 검토 한계를 유지합니다. 목표는 #3 `Precision > 0.8`, #4 `affected` 출력에 대해 `Precision > 0.85`입니다.

확인 자료: [통합 #3 결과](benchmark/item3_evaluation/results.json), [웹 실험 기록](site/h200-experiment.json), [실험 화면](http://127.0.0.1:8100/experiments.html), [H200 원래 실행 요약](results/h200_full_population_20261116_130409/summary.json).

## 웹 데이터와 재실행

`site/`는 HTML·JavaScript와 정적 조회 데이터입니다. `advisories_list.json`은 목록, `advisories.json`은 통계, `advisory_details_YY.json`과 `adv/`는 권고문 상세, `asset_vulntology/`는 자산·시나리오, `published_csaf/`는 공개 CSAF 관련 자료입니다. `reverse_sbom/`와 `sbom_index.json`은 기존 정적 페이지의 BOM 보기·목록 경로를 지원합니다. 서버의 최신 BOM 원본은 `benchmark/icsa-cpe-synthetic sbom`에서 읽습니다.

최근 폴더 정리는 보관 자료를 모은 작업이며 과거 평가 실행기를 모두 새 경로로 이식한 것은 아닙니다. 과거 명령을 재실행하기 전에 입력·Gold·원천 스냅샷 경로를 확인해야 합니다. 특히 `tools/item3_precision_pipeline.py`는 Rejected CVE 목록을 위해 `item3_ics_cert_full/cves.jsonl`을 참조하지만 **현재 로컬에는 그 파일이 없습니다.** 결과 열람·BOM 웹 조회와 새 전수 추론의 재현 준비는 구분합니다. H200에는 당시 실행 원본이 별도로 보관되어 있습니다.

과거 부분 벤치마크 수치·테스트 통과 건수·옛 경로는 현재 상태로 해석하지 않습니다. 이전 루트 README는 [폴더 정리 전 보관본](docs/archive/README_20261116_before_layout_update.md), 이전 연구 이력은 [2026-11-15 보관본](docs/archive/README_20261115.md)에 있습니다.

## CVE description NER 학습·평가 — 2026-11-17

H200에서 MiniLM의 BERT 인코더에 학습 분할만 사용하는 MLM 자기지도 적응 1 epoch와 자동 라벨 기반 BIO NER 미세조정 5 epochs를 수행했습니다. CVE·권고문·동일 문장이 겹치지 않는 시험 분할의 약지도 평가에서 정확 구간 F1은 **18.33%**이며, 토큰 F1 97.73%만으로 조건 추출이 정확하다고 해석하지 않습니다. 독립 의미 정확도는 미측정이고 자동 확정용 성능은 부족합니다. 전체 12,418개 CVE의 처리 상태와 89개 description 미확보 상태를 유지했습니다.

[학습 방법·최종 평가·모델 사용](results/cve_ner_20261117_v1/README.md), [최종 평가 JSON](results/cve_ner_20261117_v1/trained_artifacts/evaluation_report.json), [NER 구현](src/cve_condition_ner.py).

## CVE condition NER v2 (2026-11-17)

Boundary-aware partial-label training and constrained BIO decoding improved exact-passage weak-label F1 from 18.33% to 44.61% on the same test split. The selected model is boundary CE epoch 8, chosen by dev F1; the CRF experiment is retained as an ablation. This is teacher agreement, not independently verified semantic accuracy.

[Analysis, evaluation and model](results/cve_ner_20261117_v2/README.md), [implementation](src/cve_condition_ner_v2.py).
