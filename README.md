# ICS-VEXForge

SBOM의 제품·버전·식별자로 CVE를 연결하고, 소스코드가 없는 ICS 자산의 운영맥락으로 VEX를 검토하는 연구 시스템입니다. **문서 확인: 2026-11-16 KST.**

## 실행과 메뉴

프로젝트 루트에서 현재 PC의 준비된 Python 환경을 사용합니다. 의존성은 [requirements-precision.txt](requirements-precision.txt), NCP 환경은 [requirements-ncp.txt](requirements-ncp.txt)를 참고합니다. GPU용 PyTorch, 모델과 원천 데이터는 별도로 필요합니다.

```powershell
python -m uvicorn tools.local_dataset_app:app --host 127.0.0.1 --port 8100
```

이 진입점은 API에 정리된 합성 SBOM 폴더를 연결합니다. `src.api_server:app`만 실행하면 이 연결이 적용되지 않습니다.

GitHub에서 내려받을 때는 Git LFS로 보관하는 평가 Gold, 원천 DB, CPE 사전과 모델 어댑터도 받아야 합니다. 저장소에서 `git lfs install` 후 `git lfs pull`을 실행하세요. 전송용 대형 압축본, 원시 추론 캐시와 실행 로그는 동기화 대상에서 제외합니다. GitHub Pages 배포본에서는 방법론 메뉴와 페이지를 제외하며 로컬 개발 사이트에는 유지합니다.

| 메뉴 | 화면 | 기능 |
| --- | --- | --- |
| SBOM → CVE | [index.html](http://127.0.0.1:8100/index.html) | 제품·버전·식별자 검토와 CVE 매핑 |
| Operational VEX | [vex-decision.html](http://127.0.0.1:8100/vex-decision.html) | 자산·CVE별 시나리오와 운영맥락 검토 |
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

VEX는 NIST Vulntology, MITRE ATT&CK ICS 자산·기법, OVAL/OpenSCAP 관측, MulVAL/XSB 공격 그래프를 활용합니다. 자산 분류나 경로 부재만으로 영향을 확정하지 않습니다. 미검토·관측 누락·범위 불일치·충돌·만료는 미확정입니다. 원문 자동 추출은 초안이며 검토 없이 확정 VEX로 승격하지 않습니다.

## 최신 H200 평가

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
