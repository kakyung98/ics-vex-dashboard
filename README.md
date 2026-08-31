# ICS-VEX — Explainable VEX for Industrial Control Systems

CISA ICS 어드바이저리에서 **역방향으로 구축한 SBOM 데이터셋** 위에서,
소스코드 확보 여부에 따라 VEX 를 판정하는 엔드투엔드 파이프라인.

> **🛡️ 2026-08 실행검증 전면 개편.** 소스코드를 확보한 CVE 는 **실제로 빌드하고
> 재현(reproducer)을 실행**해 판정한다 — 정적 추론이 아니라 **실행 증거**로 확정한다.
> 취약 버전을 격리 샌드박스에 재구성 → 재현 입력 합성 → 실행해 크래시/새니타이저/assert
> 트리거 확인. 다중에이전트 **developer→critic 루프**(빌더·익스플로이터·검증기 + 각 단계
> critic)가 **전부 로컬(Ollama, $0)** 로 돈다. 신규 확정 tier 는 `execution-verified`.
> 빌드는 되지만 트리거 미도달 시 `build-only` → `under_investigation` 폴백.

> **🧭 소스 미확보 경로.** 폐쇄 펌웨어 등 소스코드를 얻을 수 없는 CVE 는 코드 근거가
> 없으므로 상태를 **`under_investigation`** 으로 고정하고, `estimation` 하위필드와
> **SSVC 우선순위**(SEI Deployer)를 함께 부여한다. 두 경로의 판정 방법은
> [VEX Analysis Method](https://kakyung98.github.io/ics-vex-dashboard/vex-method.html) 페이지에서
> 다이어그램으로 볼 수 있다.

> **🔗 라이브 대시보드 (ICS-VEXForge)**: https://kakyung98.github.io/ics-vex-dashboard/
> SBOM을 올려(붙여넣기·업로드·드래그) CVE·VEX 즉석 분석 + 코퍼스 통계 시각화 (전부 브라우저 내 처리).
> **사이드바 6페이지**:
> - [Analyzer](https://kakyung98.github.io/ics-vex-dashboard/index.html) — SBOM→VEX + CPE 정규화(Ratcliff–Obershelp) + SSVC 우선순위 + VEX 문서(OpenVEX/CSAF) 출력
> - [VEX Analysis Method](https://kakyung98.github.io/ics-vex-dashboard/vex-method.html) — 소스 확보/미확보 두 경로의 판정 방법 다이어그램
> - [ICS Advisories-based CVE Corpus](https://kakyung98.github.io/ics-vex-dashboard/corpus.html) — Target CVE·CISA 어드바이저리·연도별 통계
> - [Source Code Available CVEs](https://kakyung98.github.io/ics-vex-dashboard/collectable.html) — 소스 수집가능 CVE(CWE/벤더/장비, 클릭 드릴다운)
> - [ICS-CERT Advisories](https://kakyung98.github.io/ics-vex-dashboard/source.html) — ICS-CERT 어드바이저리·NVD CVE 검색(어드바이저리 원문 표시)
> - [Synthetic SBOM](https://kakyung98.github.io/ics-vex-dashboard/ics-sbom.html) — KISA CycloneDX 스키마 역방향 SBOM 데이터셋(어드바이저리↔장비 링크)

---

## 왜 필요한가 — 공개 ICS 생태계에 VEX 는 사실상 없다

동기를 추정이 아니라 **전수조사**로 확인했다. CISA 공식 CSAF 저장소
([cisagov/CSAF](https://github.com/cisagov/CSAF), 전체 커밋 이력 963개)를 clone 해
OT 어드바이저리 **3,893건을 전부 파싱**한 결과(2026-08-31 기준):

| 항목 | 건수 | 비율 |
|---|---|---|
| `document.category == "csaf_vex"` | **0** | **0%** |
| `document.category == "csaf_security_advisory"` | 3,893 | 100% |
| `known_affected` | 3,890 | 99.9% |
| `fixed` | 134 | 3.4% |
| `known_not_affected` | 25 | 0.64% |
| **`flags` (CISA justification)** | **12** | **0.31%** |
| `under_investigation` | 0 | 0% |

> 같은 저장소의 **IT** 어드바이저리에는 `csaf_vex` 문서가 89건 있다.
> **CISA 는 IT 에는 VEX 프로파일을 쓰고 OT 에는 한 건도 쓰지 않는다.**

**벤더별** (OT, `flags` 사용):

| 벤더 | OT 어드바이저리 | `flags` | `known_not_affected` |
|---|---|---|---|
| Siemens | 965 | **11 (1.1%)** | 14 |
| Rockwell | 252 | 0 | 0 |
| Schneider | 233 | 0 | 5 |
| Mitsubishi / Delta / Advantech / GE / Moxa / AVEVA / ABB / Hitachi | 631 | 0 | 2 |

**사용된 justification 은 전부 코드·빌드 축이다:**

```
component_not_present                              10
vulnerable_code_not_in_execute_path                 5
vulnerable_code_not_present                         4
vulnerable_code_cannot_be_controlled_by_adversary    0   <- 환경 기반
inline_mitigations_already_exist                     0   <- 환경 기반
```

→ 실제 ICS 생태계가 `not_affected` 에 동원한 근거는 **100% 소스코드/빌드 사실**이며,
배치 환경을 근거로 삼은 사례는 **0건**이다. 이 프로젝트가 코드 축을 status 로,
운영 맥락을 SSVC 우선순위로 분리하는 근거가 여기에 있다.

### `flags` 는 언제부터 나왔나 (커밋 이력 추적)

| 시점 | 사건 |
|---|---|
| 2023-09-07 | cisagov/CSAF 저장소 개설 |
| **2024-08-22** | **OT 최초** `flags` — `icsa-24-235-03` (Mobotix), 발행과 동시 |
| 2024-11-27 | IT 쪽 `csaf_vex` 프로파일 최초 등장 |
| **2025-06-12** | **소급 백필** — 기존 어드바이저리 2건에 같은 날 `flags` 추가 |
| 2025-08-14 / 2026-01-15 / 2026-05-14 | 추가 백필 (각 1건) |
| 2026-02-12 이후 | 신규 발행 시점에 `flags` 동반 (2026년 5건 전부) |

2010–2023 의 OT 어드바이저리 2,155 건에는 `flags` 가 **한 건도 없다**.
연도별 채택률: **2024 년 3/409 (0.7%) → 2025 년 4/482 (0.8%) → 2026 년 5/345 (1.4%)**.

> 주의 — CSAF 에는 `justification` 이라는 필드명이 없다.
> CISA justification 이 들어가는 자리는 **`vulnerabilities[].flags[].label`** 이다
> (OpenVEX 는 `justification`, CycloneDX 는 `analysis.justification`).
> `flags` 는 VEX 프로파일 전용이 아니라 CSAF 공통 필드라 일반 어드바이저리에도 실릴 수 있고,
> CISA 의 HTML 어드바이저리 페이지에는 렌더링되지 않는다 — 그래서 찾기 어렵다.

**대표 사례** — [ICSA-25-191-06](https://www.cisa.gov/news-events/ics-advisories/icsa-25-191-06) /
[SSA-904646](https://cert-portal.siemens.com/productcert/csaf/ssa-904646.json) (CVE-2025-40742, CWE-598):
SIPROTEC 5 64 개 모델을 **CP300/CP100 = affected 44 / CP200 = not_affected 20** 으로 가르고,
20 개 전부에 `component_not_present` 를 붙였다. 판정 기준은 **하드웨어 세대·컴포넌트 구성**이지
고객 환경이 아니다. 다만 Siemens 는 *어떤* 컴포넌트가 없는지는 밝히지 않는다 —
**주장이지 검증 가능한 증거가 아니다.** 이 빈칸이 본 시스템의 기여점이다.
(Siemens 자체 포털 원본에도 `flags` 가 그대로 있으므로 CISA 가 덧붙인 것이 아니다.)

---

## 무엇인가

- **축**: **ICSA 어드바이저리** — ICSA 1건 = SBOM 1개 = VEX 문서 1개 (CISA CSAF 와 동일 축)
- **입력**: CycloneDX SBOM (ICS 자산의 소프트웨어 명세)
- **출력**: 컴포넌트별 CVE 식별 + VEX 판정(`영향 가능`/`비영향`/`조사 필요`) + 표준 justification + 판정 근거 문장
- **코드 확보 여부가 경로를 가른다**:

| 상태 | 경로 | VEX |
|---|---|---|
| **소스코드 확보** | 실행검증: 취약버전 빌드 → 재현(reproducer) 합성 → 실행 → 트리거 확인 | 재현 트리거 시 **`execution-verified` 확정**; 빌드만 되면 `build-only` → `under_investigation` |
| **SBOM 근거** | VDR/권고가 지목한 컴포넌트가 SBOM 에 부재 | `not_affected` + **`component_not_present`** 확정 (버전 대조 불필요 → `NOASSERTION` 이어도 성립) |
| **코드 미확보** (11,321 · 99.87%) | `under_investigation` 고정 + estimation + SSVC | 코드 근거 없음 → 상태 고정, 추정치·우선순위만 부여 |

> ⚠️ **`tier` 컬럼 주의**: SBOM 속성명이 `component:source-availability` 라서 소스 확보로 읽히지만,
> 실제로는 **OSS 카탈로그 귀속 여부**일 뿐이다([build_reverse_sbom.py:202](src/build_reverse_sbom.py:202)).
> `tier=="A"` 110 CVE 중 실제로 코드를 확보한 것은 **15 CVE**.
> (폐쇄소스 22건 — CODESYS·Interpeak/ipnet·Treck·SQL Server·.NET — 은 OSS 로 오분류돼 있던 것을
> [build_reverse_sbom.py](src/build_reverse_sbom.py) 의 `CLOSED_OSS` 로 tier E 재분류: 132→110.)
> 따라서 실행검증 게이트는 `tier` 가 아니라 `code_evidence_available`(=업스트림 저장소+커밋 확보) 이다.
> tier A 110 CVE 는 소스를 수집하면 실행검증으로 승격 가능한 **확장 후보군**이다.

- **실행검증 경로 (소스 확보 CVE)** — 코드가 있으면 정적 추론 대신 **실제 실행**으로 확정한다.
  다중에이전트 developer→critic 루프가 전부 로컬(Ollama, $0)로 돈다:
  - **① 업스트림 해석** — 컴포넌트를 저장소+취약 커밋/버전으로 매핑(CVE/NVD 레퍼런스)
  - **② 환경 재구성 (빌더 + 빌드 critic)** — 취약 버전 clone, 빌드 선행조건 해소, 격리 Docker 샌드박스에서 컴파일
  - **③ 재현 합성 (익스플로이터)** — CVE 설명·CWE·패치 diff 를 근거로 취약 경로를 타는 입력/PoC 작성
  - **④ 실행·검증 (검증기 critic)** — 샌드박스에서 실행, 크래시/새니타이저/assert 트리거 관측 시 `affected` 확정.
    동일 재현을 패치 빌드에 돌려 트리거가 사라지면 `fixed`/`not_affected` 확정 — 모두 `execution-verified`
  - 빌드는 되나 트리거를 예산 내 도달 못 하면 `build-only` → `under_investigation` 폴백

- **소스 미확보 경로 (결정트리 폐기 → estimation + SSVC)**: 소스코드가 없으면 코드 근거가
  없으므로 상태를 **항상 `under_investigation`** 으로 고정한다(과거의 Yes/No 결정트리는 제거).
  대신 두 가지를 함께 싣는다:
  - **`estimation` 하위필드** — `likely_affected` / `likely_not_affected` / `likely_fixed` /
    `unable_to_determine`. VEX 진술이 아니라 추정치이며, 출력 문서(OpenVEX/CSAF)에 반영된다.
  - **SSVC 우선순위** — SEI **Deployer** 트리(72행): Exploitation(KEV/EPSS) × System Exposure
    (배치 노출도) × Automatable(CVSS AV) × Human Impact → `defer`/`scheduled`/`out-of-cycle`/`immediate`.
    트리의 운영 맥락(노출도)을 SSVC 입력으로 흘려보내 우선순위화에 재사용한다.

### 축 = ICSA 어드바이저리 (2026-08 개편)

CISA 는 **ICSA 1건당 CSAF 문서 1개**를 발행한다. 본 시스템도 같은 축을 쓴다:

```
ICSA 1건  ->  역방향 SBOM 1개 (reverse_sbom/<icsa-id>_SBOM-CVE.json)  ->  VEX 문서 1개
```

| 축 | 개수 | 성격 |
|---|---|---|
| ICSA 어드바이저리 (수집) | **3,767** | 2010–2026 전량 |
| → CVE 포함 = SBOM 생성 | **3,695** | **문서 축** — VEX 1개씩 |
| ICSA × CVE = statement | **13,025** | **판정 축** — VEX statement 와 1:1 |
| 고유 CVE | 11,336 | 취약점 모집단 |

ICSA 당 statement 는 **중앙값 1개, 최대 490개**다. 그래서 CVE 단위 worst-case 집계
(어느 한 자산이 affected 면 CVE 전체가 affected)는 폐기했다 — VEX 는 product × vulnerability
단위이며, 같은 CVE 가 제품에 따라 갈리는 것이 VEX 의 존재 이유다.

부수 효과로 파일명이 자연 유일키(ICSA id)가 되어, 이전에 제품명 표기 차이
("SiPass integrated" vs "SiPass Integrated")로 **SBOM 이 조용히 덮어써지며 장비 50대와
그 CVE 가 유실되던 버그**가 원리적으로 사라졌다.

### CISA 원본 CSAF 와의 대조 (`tools/compare_cisa_csaf.py`)

축이 ICSA 이므로 우리 산출물과 CISA 원본이 파일 단위로 대응한다:

```bash
git clone --depth 1 https://github.com/cisagov/CSAF.git /tmp/CSAF
python tools/compare_cisa_csaf.py --csaf-repo /tmp/CSAF
```

현재 결과:

```
우리 ICSA        : 3695
CISA OT CSAF     : 3893
대조 가능 ICSA   : 3664
CISA 문서 프로파일: {'csaf_security_advisory': 3664}    <- csaf_vex 0건

CISA 가 justification 을 남긴 ICSA : 12
대조된 (ICSA, CVE) 쌍              : 18
우리도 not_affected                : 0 (0%)
```

**이 0% 는 숨기지 않는다.** 원인이 구조적이기 때문이다 — 우리 SBOM 은 어드바이저리에서
*역으로* 구성되므로, 어드바이저리가 언급한 컴포넌트만 들어 있다. 즉 "그 컴포넌트가 없다"는
사실을 담을 수 없어 `component_not_present` 가 원리적으로 발화하지 않는다.
게다가 CISA 는 같은 ICSA 안에서 **제품 모델별로** 판정을 가르는데(SIPROTEC 5: CP300 44개
affected / CP200 20개 not_affected), 우리 역방향 SBOM 에는 **모델 변형 단위가 없다.**

→ 이 18 쌍이 현재 시스템의 **외부 정답지이자 미달 지점**이다. 좁히려면 CISA CSAF 의
`product_tree` 를 역방향 SBOM 에 주입해 모델 변형 단위를 만들어야 한다.

### 모델 변형 단위 — `product_tree` 주입과 독립 유도 평가

역방향 SBOM 은 ICSA 1건을 장비 1대로 뭉갠다. 그런데 CISA/벤더는 같은 ICSA 안에서
**모델별로** 판정을 가른다 — `icsa-25-191-06` 은 SIPROTEC 5 **CP300 44개 affected /
CP200 20개 not_affected**. 모델 단위가 없으면 이 분기를 표현조차 못 한다.

`tools/inject_product_variants.py` 가 CISA CSAF 의 `product_tree` 를 SBOM 에 주입한다:

```
SBOM 1,937개에 모델 변형 24,380개 주입, 취약점 6,721건을 영향 모델로 한정
icsa-25-191-06: 컴포넌트 1개 -> 65개 (모델 64 + 장비 1), CVE-2025-40742 -> affects 44 모델
```

#### 무엇이 입력이고 무엇이 정답인가

`tools/eval_variant_derivation.py` 는 순환을 막기 위해 입력을 엄격히 제한한다.

| | 항목 | 사용 |
|---|---|---|
| **입력** | `product_tree` (모델 목록) | 허용 — 권고문에 적힌 공개 정보 |
| **입력** | `product_status.known_affected` | 허용 — 모든 자산소유자가 권고문에서 읽는 정보 |
| **정답** | `product_status.known_not_affected` | **금지** |
| **정답** | `vulnerabilities[].flags[].label` | **금지** |

유도 규칙은 자산소유자가 실제로 하는 추론 그대로다:
**내 모델이 이 CVE 의 영향 목록에 없다 → `not_affected`, 근거는 `component_not_present`.**

#### 결과

```
모델 단위 (product_id)        TP 278 / FP 676 / FN 0
                              precision 0.291 | recall 1.000 | F1 0.451
(ICSA, CVE) 쌍 단위           justification 까지 일치 10/18
```

**recall 1.000** — CISA 가 `not_affected` 로 선언한 모델을 **하나도 놓치지 않는다**.

**precision 0.291** 의 FP 676건은 전부 *CISA 가 아예 열거하지 않은* 모델이다.
`known_not_affected` 를 입력에서 뺐으므로 "영향 없음"과 "언급 안 됨"을 구별할 수 없다.
이것은 알고리즘의 결함이 아니라 **공개 데이터의 상한**이다.

**justification 10/18 의 분포가 결과를 해석해 준다:**

| 정답 label | 쌍 | 우리 일치 |
|---|---|---|
| `component_not_present` | 10 | **10 / 10** |
| `vulnerable_code_not_in_execute_path` | 5 | 0 / 5 |
| `vulnerable_code_not_present` | 3 | 0 / 3 |

즉 **제품 구조로 판정되는 건은 전부 맞히고, 소스코드 분석이 필요한 건은 전부 틀린다.**
후자 8건은 어느 컴포넌트인지조차 공개되지 않은 벤더 독점 코드다 — 18쌍 중
OSS 카탈로그로 컴포넌트를 특정할 수 있는 것은 `CVE-2023-38545`(libcurl) **단 1건**이다.
공개 데이터만으로 도달 가능한 경계가 정확히 여기다.

## ⚠️ 데이터 성격 (정직한 고지)

- **진짜**: 장비↔CVE↔CWE↔CVSS 매핑은 CISA ICS-CERT 공식 (3,765 어드바이저리, 11,336 CVE), KEV·EPSS 실신호, OSS 취약/패치 실코드(34 CVE, GitHub 픽스 커밋)
- **합성**: 장비 주변 컴포넌트 인벤토리, 배치 노출도(`exposure_synthetic: true` 로 표시)
- **추정**: 학습 타깃 `label` 의 99.96% 는 확정 판정이 아니라 **AV 기반 2차 추정치**다.
  이 추정치는 **VEX status 로 승격되지 않는다** — 배치 노출도는 CISA justification 5종 중
  어느 것의 근거도 아니고(`cannot_be_controlled_by_adversary` 는 taint 근거를,
  `inline_mitigations_already_exist` 는 제품 내부 완화를 요구한다), 여기의 노출도는 합성값이다.
  따라서 코퍼스 통계는 **증거 기반 status** 와 **추정치** 를 분리해 표시한다
  (증거 기반: `under_investigation` 11,335 / `affected` 1 / `not_affected` 0).
  실행 검증으로 확정된 건은 5건(0.04%, zlib CVE-2018-25032)뿐이다.
  주석자 불일치 노이즈(10%)는 이 추정치에만 적용하며, 확정 건은 흔들지 않는다.
- **SBOM 이 모든 컴포넌트 버전을 `NOASSERTION` 으로 기록**하므로 버전 범위 대조는 불가능하다.
  이 사실 자체가 `UNDER_INVESTIGATION` 의 주요 근거로 문장에 반영된다.
- 평가 수치는 **실세계 정확도가 아니라** 파이프라인 정합성·학습가능성 검증. 상세 한계는 [`RESULTS.md`](RESULTS.md) 참조

## 파이프라인

| 단계 | 스크립트 | 산출물 |
|---|---|---|
| CISA 어드바이저리 수집 | `tools/fetch_cisa_advisories.py` | `data/cisa_advisories.json` |
| 악용신호(KEV·EPSS) | `tools/fetch_exploit_signals.py` | `data/exploit_signals.json` |
| 역방향 SBOM | `src/build_reverse_sbom.py` | `reverse_sbom/`, `data/findings.csv` (`tier` = 소스 확보 가능성) |
| OSS 취약/패치 코드 수집 | `tools/collect_code_gh.py` | `data/code_evidence.json` |
| **라이브 SBOM→VEX 판정** | `src/vex_pipeline.py` | JSON-line 스트림 (컴포넌트↔CVE 식별 + 경로 라우팅) |
| **전 코퍼스 스윕 (source_class 분류)** | `src/vex_batch.py` | `results/vex_batch.jsonl` + `_summary.json` |
| **실행검증 대상 선별** | `tools/export_verify_candidates.py` | 소스 확보(저장소+커밋) CVE 목록 |
| **실행검증 오케스트레이터** | 빌드→재현→검증 (로컬 Ollama + Docker 격리) | `execution-verified` 판정 로그 |
| **로컬 모델 서버** | `tools/serve_poc_llm.py` | OpenAI 호환 엔드포인트 (실행검증 익스플로이터 라우팅용) |
| **동적 REST API 서비스** | `src/api_server.py` | FastAPI (SBOM→VEX·CPE 정규화·통계·검색·SSVC·VEX 문서 출력) |
| **VEX 문서 출력** | `src/api_server.py` (Analyzer) | OpenVEX v0.2.0 · CSAF 2.0(csaf_vex) — status별 필수필드 + estimation + SSVC |
| ~~소스-불가 CVE 결정트리~~ (폐기) | `src/vex_source_unavailable.py` | Yes/No 트리 제거 → `under_investigation`+estimation+SSVC 로 대체(모듈만 잔존) |
| **정적 사이트 생성 (6페이지)** | `tools/build_site.py` | `index`·`vex-method`·`corpus`·`collectable`·`source`·`ics-sbom.html` + 데이터 JSON |
| ~~검증 스펙/실행 검증~~ (격리) | `archive/*` | 과거 `results/exec_verification*.json` (역사적 근거로만 유지) |
| **Ground Truth (증거 계층)** | `src/build_ground_truth.py` | `data/vex_dataset.jsonl` |
| SecureBERT 학습·평가 | `src/train_eval_vex.py` | `results/metrics.json` |
| **SecureBERT ICS 도메인 적응(DAPT)** | `src/train_securebert_dapt.py` | `models/ics-securebert/`, `results/dapt_metrics.json` |
| **CodeBERT 코드 leg 검증** | `src/train_codebert.py`, `src/eval_two_model.py` | `results/two_model_metrics.json` |
| **CodeBERT 취약탐지 파인튜닝** | `src/train_codebert_finetune.py` | `models/codebert-vuln/` |

> **판정 경로**: 소스코드를 확보한 CVE 는 **실행검증**(빌드→재현→실행)으로 `execution-verified`
> 를 확정한다. 소스를 얻을 수 없는 CVE 는 `under_investigation` + estimation + SSVC 로 처리한다.
> 웹 콘솔의 라이브 판정은 식별·라우팅·표시를 담당하고, 실행검증 자체는 로컬 Ollama + Docker
> 격리 샌드박스에서 오케스트레이터가 수행한다.

## 주요 결과

### 데이터셋 구성 (v3, 증거 계층 기반)
| 증거 계층 | 건수 | 1차 VEX |
|---|---|---|
| `execution-verified` (빌드→재현→실행 확정) | 5 (0.04%) → 확장중 | **확정** (`affected`/`fixed`) |
| `source-available-unverified` | 31 (0.24%) | 실행검증 대상 (빌드/재현 파이프라인 투입) |
| `source-pending` | 2,115 (16.26%) | `UNDER_INVESTIGATION` (OSS 귀속, 코드 미수집) |
| `source-unavailable` | 10,854 (83.46%) | `UNDER_INVESTIGATION` (폐쇄 펌웨어) |

산출 파일 3종:

| 파일 | 건수 | 용도 |
|---|---|---|
| `data/vex_dataset.jsonl` | 13,005 | 전체 — SecureBERT 학습 |
| `data/vex_dataset_code.jsonl` | 356 | tier A 확장 후보군 — 코드 leg 실험 |
| `data/vex_ground_truth.jsonl` | 5 | **실행 검증 확정분 — 진짜 ground truth** |

### 판정 tier (개편 후)

소스코드 확보 여부가 tier 를 가른다 — 확보 시 실행으로 확정하고, 미확보 시 상태를 고정한다:

| tier | 조건 |
|---|---|
| `execution-verified` | 취약 버전 빌드 성공 + 재현(reproducer) 실행 시 트리거 관측(크래시/새니타이저/assert). 패치 빌드에서 트리거 소멸 시 `fixed`/`not_affected` 확정 |
| `build-only` | 환경은 빌드됐으나 예산 내 트리거 미도달 → `under_investigation` 폴백 |
| `under-investigation` | 소스 미확보(코드 근거 없음) → estimation + SSVC 만 부여 |

학습 타깃(`label`) 분포 — 확정 5건 + 2차 추정 13,000건:
`LIKELY_AFFECTED` 4,334 (33.3%) / `LIKELY_NOT_AFFECTED` 2,676 (20.6%) / `UNDER_INVESTIGATION` 5,995 (46.1%)

> ⚠️ **아래 모델 성능 수치는 v2 데이터셋(규칙 오라클 + 합성 음성증거) 기준이며 무효다.**
> v3 는 라벨 생성 로직이 근본적으로 바뀌었으므로 `train_eval_vex.py` /
> `eval_two_model.py` 재실행 후 재측정해야 한다.
>
> | 항목 | v2 값 | 상태 |
> |---|---|---|
> | Macro F1 (SecureBERT) | 0.904 | 재측정 필요 |
> | Calibration ECE | 0.013 | 재측정 필요 |
> | 영향→비영향 오판 | 0건 | 재측정 필요 |
> | TF-IDF baseline | 0.890 | 재측정 필요 |
> | CodeBERT 레퍼런스 매칭 | 0.971 | 유효 (데이터셋 무관, `code_evidence.json` 기반) |
> | CodeBERT 추상 취약성 분류 | 0.50 (무작위) | 유효 (정직한 음성 결과) |

## 실행검증 파이프라인 (소스 확보 CVE)

소스코드를 확보한 CVE 는 정적 추론이 아니라 **실제 빌드·재현·실행**으로 확정한다. 다중에이전트
developer→critic 루프(빌더·익스플로이터·검증기 + 각 단계 critic)가 전부 로컬(Ollama, $0)에서
돌고, 빌드/실행은 Docker 격리 샌드박스에서 이뤄진다.

**소스 확보 3분류** (실행검증 가능성이 여기서 갈린다):

| 부류 | findings | 의미 |
|---|---|---|
| `code-available` | 저장소+커밋 확보 | **실행검증 즉시 투입** (빌드→재현→실행) |
| `oss-attributed` | 2,115 | OSS(tier A/C)지만 코드 미수집 → 수집 시 승격 |
| `vendor-proprietary` | 10,854 | 폐쇄 펌웨어 → 실행검증 불가 → `under_investigation`+SSVC |

**흐름 (4단계)**:

1. **업스트림 해석** — CVE→저장소·취약 커밋/버전·빌드 선행조건 (데이터 프로세서)
2. **환경 재구성** — 취약 버전 clone → 선행조건 해소 → Docker 샌드박스 컴파일 (빌더 + 빌드 critic)
3. **재현 합성** — CWE·패치 diff 근거로 취약 경로를 타는 입력/PoC (익스플로이터)
4. **실행·검증** — 샌드박스 실행 → 트리거(크래시/새니타이저/assert) 관측 시 확정 (검증기 critic)

**빌드 파일럿 결과(2026-08)**: 소스 확보 CVE 배치에서 환경 재구성 **59/80 빌드 성공**
(`results/verify_build_batch.csv`). 빌드 성공분이 재현·실행 단계로 진입한다.

**모델 거부(refusal) 우회 — 역할별 라우팅**: 재현의 병목은 실행 차단이 아니라 익스플로잇
작성 단계에서의 모델 **거부**였다. 거부-빈발 익스플로이터만 로컬 모델로 라우팅하고
(`tools/serve_poc_llm.py`), 추론-무거운 나머지 역할은 능력 모델(로컬 32B)로 유지한다 —
전부 env 기반 라우팅이라 모델 교체는 환경변수만 바꾸면 된다.

> **능력 한계 메모**: 7B 로컬 모델은 검증기 critic 이 요구하는 실행-증거 수준을 만족 못 해
> 재현이 실패했다. 재현 단계는 로컬 32B 이상(또는 필요 시 더 큰 모델)로 올리는 것이 관건이며,
> 빌드 단계는 14B 로도 안정적이다.

## 웹 콘솔 — ICS-VEXForge

좌측 사이드바 + 메인의 **6페이지 콘솔**. 두 형태로 동일하게 제공한다.

- **정적 사이트 (GitHub Pages)** — `tools/build_site.py` 가 코퍼스를 동일-출처 JSON 으로 구워
  `index`·`vex-method`·`corpus`·`collectable`·`source`·`ics-sbom.html` 6페이지를 생성한다.
  SBOM→VEX 계산, CVE 드릴다운, CPE 정규화(Ratcliff–Obershelp), SSVC 우선순위,
  VEX 문서(OpenVEX/CSAF) 출력, 검색까지 **전부 브라우저 안에서** 돈다(백엔드 불필요).
- **동적 REST 서비스 (로컬)** — [`src/api_server.py`](src/api_server.py) (FastAPI). 같은 UI 를
  라이브 REST 로 서빙하고 Swagger 문서를 자동 제공한다.

```bash
pip install fastapi uvicorn
python src/api_server.py --port 8100   # localhost:8100 (docs: /docs) · 0.0.0.0 바인딩=LAN 접속
python tools/build_site.py             # 정적 6페이지 + 데이터 JSON 재생성 → GitHub Pages 푸시
```

**페이지 (사이드바 메뉴 순서)**

| 페이지 | 내용 |
|---|---|
| **Analyzer** (`/`) | SBOM 붙여넣기·업로드·드래그 → 컴포넌트별 CVE·VEX. **소스확보** CVE 는 실행검증(빌드→재현→실행, `execution-verified`), **소스 미확보** CVE 는 `under_investigation`+**estimation**+**SSVC**. CPE 정규화(RO) 비교, **VEX 문서(OpenVEX/CSAF) 출력** 포함 |
| **VEX Analysis Method** (`/vex-method.html`) | 소스 확보/미확보 두 경로의 판정 방법을 다이어그램으로 설명 |
| **ICS Advisories-based CVE Corpus** (`/corpus.html`) | Target CVE·CISA 어드바이저리·연도별 통계 |
| **Source Code Available CVEs** (`/collectable.html`) | 소스 수집가능 CVE(CWE/벤더/장비, 그래프 클릭 드릴다운) |
| **ICS-CERT Advisories** (`/source.html`) | **ICS-CERT 어드바이저리 검색**(어드바이저리 원문 표시) + **NVD CVE 검색**(코퍼스, 각 NVD 링크) |
| **Synthetic SBOM** (`/ics-sbom.html`) | KISA CycloneDX 스키마 역방향 SBOM 데이터셋 열람(어드바이저리↔장비 정확 링크) |

**REST 엔드포인트** (`GET /docs` Swagger)

| 엔드포인트 | 설명 |
|---|---|
| `GET /api/summary` · `/api/source_available` · `/api/by_year` · `/api/advisories` | 코퍼스 통계 (CVE 단위) |
| `GET /api/advisories/list` · `/api/cve_search?q=` | 검색 (ICS-CERT Advisories 페이지) |
| `GET /api/cves?dim=cwe&value=CWE-416&scope=source_available` | 드릴다운 (그래프 클릭 → 관련 CVE) |
| `POST /api/vex` | `{sbom, exposure}` → 컴포넌트별 CVE + 라이브 VEX(임베디드 VDR 포함) |
| `POST /api/vex_compare` | **CPE 정규화(Ratcliff–Obershelp) vs 정확매칭 CVE 비교** |

**소스 미확보 CVE — SSVC + estimation** (과거 Yes/No 결정트리는 폐기) — 소스코드를 확보할 수
없는 CVE 는 코드 근거가 없으므로 상태를 **`under_investigation`** 으로 고정하고, ① `estimation`
하위필드(`likely_affected`/`likely_not_affected`/`likely_fixed`/`unable_to_determine`)와 ② **SSVC
우선순위**(SEI Deployer: Exploitation×System Exposure×Automatable×Human Impact →
`defer`/`scheduled`/`out-of-cycle`/`immediate`)를 함께 부여한다. 배치 노출도가 SSVC 의 System
Exposure 입력으로 흘러간다. 두 값 모두 **VEX 출력 문서(OpenVEX v0.2.0 / CSAF 2.0)** 에 반영된다.

**VEX 문서 출력** — Analyzer 에서 판정을 마치면 컴포넌트별 VEX 를 **OpenVEX v0.2.0** 과
**CSAF 2.0(csaf_vex)** 두 포맷으로 내려받는다. status 별 필수필드를 채워 넣는다:
`not_affected`→justification, `affected`→remediation, `fixed`→status_notes,
`under_investigation`→estimation/status_notes.

주요 기능: **CVSS 를 "점수(등급)" 로 통일** 표시(NVD API 2.0 재수집으로 코퍼스 97% 커버),
통계 그래프 클릭 → 관련 CVE(NVD 링크), 스크롤·sticky 헤더 결과 테이블. 배포는 Python 이
도는 어디든 가능(VPS·Render·Railway). 소스 확보 CVE 의 실행검증(빌드→재현→실행)은 로컬
Ollama + Docker 격리 샌드박스에서 별도 오케스트레이터가 수행한다.

## 도메인 적응 (모델 튜닝)

프로토타입은 인코더를 동결(frozen)해 특징 추출기로 썼다. 실전형으로 다음을 진행한다:
- **SecureBERT DAPT** — CISA ICS 어드바이저리로 continued MLM → ICS 텍스트 재적응 (`train_securebert_dapt.py`)
- **CodeBERT 파인튜닝** — Devign(CodeXGLUE) 대규모 취약 코퍼스로 인코더 동결 해제 파인튜닝 → 추상 취약탐지 개선 (`train_codebert_finetune.py`)

효과는 라벨 무관 지표(MLM perplexity, Devign test F1)로 측정한다.

## 자동 업데이트

`ICS-VEX Nightly Push` (Windows 작업 스케줄러, 매일 23:30)가 변경사항을 자동 커밋·푸시한다
(`tools/nightly_push.ps1`). GitHub Pages는 푸시마다 자동 재빌드된다.

## 재현

```bash
pip install torch transformers datasets scikit-learn numpy
python tools/fetch_cisa_advisories.py     # ~25분 (3,765건 크롤)
python tools/fetch_exploit_signals.py     # ~5분 (KEV·EPSS)
python src/build_reverse_sbom.py          # findings.csv + tier(소스 확보 가능성)
python tools/collect_code_gh.py           # OSS 취약/패치 실코드 (gh 인증 필요)
python src/build_ground_truth.py          # 증거 계층 결정
python src/vex_pipeline.py --sbom results/example_sbom.json --exposure control-network
                                          # ← 라이브 SBOM→VEX (식별·라우팅). 소스 확보분은 실행검증으로
python tools/export_verify_candidates.py   # 실행검증 대상(저장소+커밋 확보) 선별
# 실행검증(빌드→재현→실행): 로컬 Ollama + Docker 격리 샌드박스 오케스트레이터
python tools/build_site.py                # 정적 웹 콘솔 6페이지 생성 (GitHub Pages)
```

> 아래는 별도의 **인코더 연구 leg**(도메인 적응 실험)로, VEX 판정 경로와 무관하다:

```bash
python src/train_securebert_dapt.py       # SecureBERT ICS 도메인 적응(DAPT)
python src/train_codebert_finetune.py     # CodeBERT 취약탐지 파인튜닝
```

## 한계

1. **실행검증은 소스 확보 CVE 에만 가능하다** — 코퍼스의 99.87%는 소스를 얻을 수 없어
   실행 확정을 만들 수 없고 `under_investigation`+estimation+SSVC 로만 처리된다. 실행검증의
   확실성은 강하지만 커버리지는 소수(소스 확보분)에 국한된다.
2. **재현 합성이 모델 능력에 좌우된다** — 빌드는 14B 로컬 모델로도 안정적이나(59/80 성공),
   재현·실행 단계는 더 큰 모델을 요구한다. 재현 미도달분은 `build-only`→`under_investigation`
   폴백이라, 실행검증 확정 수는 모델·예산에 비례한다.
3. **버전 대조 불가** — SBOM 전 컴포넌트가 `NOASSERTION`. 어떤 CVE 도 해당 장비가
   취약본을 쓰는지 확인할 수 없어, ICS 안전 우선 원칙으로 취약본을 가정한다
   (`version_unconfirmed: true`).
4. **합성 배치 맥락** — 장비↔CVE↔CWE↔CVSS만 실데이터. 노출도는 합성(`exposure_synthetic: true`).
   SSVC 의 System Exposure 입력이 이 합성값에 의존하므로, 절대 우선순위는 검증 대상이다.
5. **소스 미확보 경로는 추정** — 폐쇄 펌웨어는 실행검증에 오르지 못하고 estimation(추정치)과
   SSVC 우선순위만 부여된다. estimation 은 VEX 진술이 아니라 참고용 추정이다.

## 데이터 출처 / 라이선스

- 코드: 연구·교육용 참조 구현
- CVE/CWE/CVSS: CISA ICS-CERT (공개), NVD, FIRST EPSS, CISA KEV
- OSS 취약/패치 코드: 각 프로젝트 공개 저장소의 픽스 커밋
- 취약탐지 코퍼스: CodeXGLUE Defect Detection (Devign)
- 합성 SBOM: 본 저장소에서 생성 (실제 제품 구성 아님)
