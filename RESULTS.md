# ICS-VEX 시스템 구축·평가 결과

CISA ICS-CERT 어드바이저리에서 역방향으로 구축한 SBOM 데이터셋 위에서,
**증거 기반 VEX 판정**을 수행하고 공개 정답지와 대조한 결과.

> **기준일 2026-09-10.** 이 문서는 현재 코드·데이터와 일치한다.
> 이전 판에 있던 **추정 기반 학습 성능 수치는 §7 로 격리**했다 — 그 라벨(AV × 합성 노출도)이
> 폐기되었고, 모델 가중치도 저장소에 없어 재현 불가하기 때문이다.

---

## 1. 축 — ICSA 어드바이저리

CISA 는 **ICSA 1건당 CSAF 문서 1개**를 발행한다. 본 시스템도 같은 축을 쓴다.
그래야 산출물이 [cisagov/CSAF](https://github.com/cisagov/CSAF) 와 파일 단위로 대응한다.

```
ICSA 1건  →  역방향 SBOM 1개 (reverse_sbom/<icsa-id>_SBOM-CVE.json)  →  VEX 문서 1개
```

| 축 | 개수 | 성격 |
|---|---|---|
| ICSA 어드바이저리 (수집) | **3,767** | 2010–2026 전량 |
| → CVE 포함 = SBOM 생성 | **3,695** | **문서 축** — VEX 1개씩 |
| ICSA × CVE = statement | **13,025** | **판정 축** — VEX statement 와 1:1 |
| 고유 CVE | **11,336** | 취약점 모집단 |

ICSA 당 statement 는 **중앙값 1건, 최대 490건**. 편차가 크므로 CVE 단위 worst-case 집계
(어느 한 자산이 affected 면 CVE 전체가 affected)는 폐기했다 — 같은 CVE 가 제품에 따라
갈리는 것이 VEX 의 존재 이유다.

---

## 2. 파이프라인

| 단계 | 스크립트 | 산출물 |
|---|---|---|
| 1. 어드바이저리 수집 | `tools/fetch_cisa_advisories.py` | `data/cisa_advisories.json` |
| 2. 악용신호 수집 | `tools/fetch_exploit_signals.py` | `data/exploit_signals.json` (KEV·EPSS) |
| 3. 정답지 고정 | `tools/collect_gt_icsa.py` | `data/gt_icsa/` (CISA 원본 + manifest) |
| 4. 역방향 SBOM | `src/build_reverse_sbom.py` | `reverse_sbom/*.json`, `data/findings.csv` |
| 5. 모델 변형 주입 | `tools/inject_product_variants.py` | SBOM 에 `product_tree` 모델 단위 |
| 6. OSS 코드 수집 | `tools/collect_code_gh.py` | `data/code_evidence.json` |
| 7. ~~실행 검증~~ | **종료된 캠페인 — 재현 불가.** 러너는 b4fc1bc8 에서 제거됐다. 보존된 산출물(`results/exec_verification*.json`, `results/verify_build_logs/`)만 하류가 읽는다 | — |
| 8. 배치 판정 | `src/vex_batch.py` | `results/vex_batch.jsonl` |
| 9. Ground Truth | `src/build_ground_truth.py` | `data/vex_dataset.jsonl` |
| 10. 대조·평가 | `tools/compare_cisa_csaf.py`, `tools/eval_variant_derivation.py` | 콘솔 리포트 |
| 11. 사이트 빌드 | `tools/build_sbom_index.py`, `tools/build_site.py` | `*.html`, `*.json` |

> 3·6·7 단계가 8·9 단계보다 **먼저** 실행되어야 한다. 증거 계층과 상류 판정을 읽어
> 각 statement 의 tier 를 결정하기 때문이다.
> 11 단계의 `build_sbom_index.py` 는 `build_site.py` 가 갱신하지 않으므로 별도로 돌려야 한다.

---

## 3. 판정 규칙 — 증거만이 status 를 정한다

강한 순서로 게이트를 통과시킨다. 어느 게이트도 통과하지 못하면 `under_investigation` 이다.

| tier | 조건 | status |
|---|---|---|
| `upstream-asserted` | 벤더/CISA 가 `flags[].label` 로 이미 판정 | 그대로 채택 (출처 기록) |
| `sbom-evidenced` | 영향 컴포넌트/모델이 이 SBOM 에 부재 | `not_affected` + `component_not_present` |
| `execution-verified` | 취약 버전 빌드 → 재현 실행 → 트리거 관측 | `affected` (패치본에서 소멸 시 `fixed`) |
| `under-investigation` | 그 외 전부 | `under_investigation` |

**배치 맥락(네트워크 위치·노출도)은 status 를 정하지 않는다.** CISA justification 5종 중
배치 환경을 근거로 인정하는 항목이 없고, 토폴로지가 바뀌면 그런 판정은 조용히 거짓이 된다.
운영 맥락은 **SSVC 우선순위로만** 들어간다.

> `component_not_present` 는 버전 대조가 불필요한 유일한 justification 이다.
> 이 코퍼스는 전 컴포넌트 버전이 `NOASSERTION` 이라, 실질적으로 유일하게 성립하는 경로다.

---

## 4. 결과 — VEX 판정 (statement 13,025)

```
by status   UNDER_INVESTIGATION 13,002 (99.82%)
            LIKELY_NOT_AFFECTED     18 ( 0.14%)
            LIKELY_AFFECTED          5 ( 0.04%)

by tier     under-investigation 13,002
            upstream-asserted       18
            execution-verified       5
```

`not_affected` 18건의 justification: `component_not_present` 10 ·
`vulnerable_code_not_in_execute_path` 5 · `vulnerable_code_not_present` 3.

### 왜 99.8% 가 미확정인가 — 소스 확보 계층

| 계층 | statement | 비율 |
|---|---|---|
| `source-unavailable` (벤더 폐쇄 펌웨어) | 11,129 | 85.4% |
| `source-pending` (OSS 이나 코드 미수집) | 1,842 | 14.1% |
| `source-available-unverified` | 31 | 0.24% |
| `execution-verified` | 5 | 0.04% |
| `upstream-asserted` | 18 | 0.14% |

**85.4% 는 소스를 원리적으로 얻을 수 없다.** 이것이 결함이 아니라 ICS 도메인의 실제 조건이며,
본 연구가 겨냥하는 공백이다.

---

## 5. 공개 정답지 대조

### 5.1 정답지 자체가 거의 없다

CISA CSAF 저장소 전체(**3,984 파일**)를 전수 파싱한 결과:

| 항목 | 건수 | 비율 |
|---|---|---|
| `document.category == "csaf_vex"` (OT) | **0** | **0%** |
| `vulnerabilities[].flags` 보유 | **12** | **0.31%** |
| `known_not_affected` 보유 | 25 | 0.64% |
| `known_affected` 보유 | 3,890 | 99.9% |

`flags` 를 가진 12건은 **전부 ICSA 접두사**이며 11건이 Siemens, 1건이 Mobotix 다.
IT 어드바이저리 88건은 `csaf_vex` 프로파일이지만 `flags` 는 쓰지 않는다.

도입 시점: **2024-08-22 최초**(`icsa-24-235-03`), 2025-06-12·2025-08-14·2026-01-15·2026-05-14 소급 백필,
**2026-02 이후 신규 발행 시점에 동반**. 2010–2023 의 2,155건에는 0건.
연도별 채택률 2024 0.7% → 2025 0.8% → 2026 1.4%.

이 12건 / 18 (ICSA, CVE) 쌍을 `data/gt_icsa/` 에 원본째 고정했다.

### 5.2 상류 채택과 자체 유도의 분리

`tools/compare_cisa_csaf.py` 는 두 갈래를 절대 섞지 않는다.

```
대조 가능 ICSA : 3,664
CISA 프로파일  : csaf_security_advisory 3,664  (csaf_vex 0건)

[A] 상류 채택 (CISA CSAF 를 그대로 실은 것) : 18   justification 일치 18/18
    -> 자체 판정 성능이 아니다. 성능 지표에서 제외한다.
[B] 자체 유도 대상                          : 0
```

CISA 라벨을 먹고 CISA 라벨과 대조하면 무의미한 100% 가 나온다. 그래서 `route` 로 출처를
구분하고 [A] 를 성능에서 제외한다.

### 5.3 모델 단위 독립 유도 — 실제 성적

`tools/eval_variant_derivation.py`. 입력을 자산소유자가 권고문에서 읽는 정보로 제한한다.

| | 항목 | 사용 |
|---|---|---|
| **입력** | `product_tree` (모델 목록) | 허용 |
| **입력** | `product_status.known_affected` | 허용 |
| **정답** | `product_status.known_not_affected` | **금지** |
| **정답** | `vulnerabilities[].flags[].label` | **금지** |

유도 규칙: **내 모델이 이 CVE 의 영향 목록에 없다 → `not_affected` / `component_not_present`.**

```
모델 단위 (product_id)   TP 278 / FP 676 / FN 0
                         precision 0.291 | recall 1.000 | F1 0.451
(ICSA, CVE) 쌍           justification 일치 10/18
```

| 정답 label | 쌍 | 일치 |
|---|---|---|
| `component_not_present` | 10 | **10 / 10** |
| `vulnerable_code_not_in_execute_path` | 5 | 0 / 5 |
| `vulnerable_code_not_present` | 3 | 0 / 3 |

**제품 구조로 판정되는 건은 전부 맞히고, 소스코드 분석이 필요한 건은 전부 틀린다.**
능력 경계와 정확히 일치한다.

FP 676건은 전부 **CISA 가 열거하지 않은** 모델이다. `known_not_affected` 를 입력에서 뺐으므로
"영향 없음"과 "언급 안 됨"을 구별할 수 없다 — 알고리즘 결함이 아니라 **공개 데이터의 상한**이다.

18쌍 중 OSS 카탈로그로 컴포넌트를 특정할 수 있는 것은 `CVE-2023-38545`(libcurl) **1건뿐**이다.
나머지 17건은 CISA 도 벤더도 어떤 컴포넌트인지 밝히지 않은 독점 코드다.

### 5.4 모델 변형 주입

`tools/inject_product_variants.py` 가 CISA CSAF 의 `product_tree` 를 SBOM 에 주입한다.

```
SBOM 1,937개에 모델 변형 24,380개 주입, 취약점 6,721건을 영향 모델로 한정
icsa-25-191-06: 컴포넌트 1개 → 65개 (모델 64 + 장비 1), CVE-2025-40742 → affects 44 모델
```

주입된 affected 목록은 **상류가 알려준 사실**이다. 이를 근거로 낸 판정은 `variant:source=cisa-csaf`
로 표시되며 자체 유도와 구분된다.

---

## 6. 코드 수준 판정 — CISA 4대 질문 Q1–Q4

네 질문 모두 구현되어 소스 스냅샷 **104건** 위에서 실행됐다. (실행검증 캠페인은
106건을 시도했으나 2건 —— CVE-2021-33909, CVE-2023-32233 —— 은 CVE Processor
단계에서 즉시 실패해 소스를 받지 못했다. 코드 수준 분석의 모집단은 104다.) 공유 규칙은
`src/vex_decision.py` 한 곳에 있고, 콘솔의 **VEX Flag Decision Logic** 페이지가 그
모듈에서 생성되므로 문서와 구현이 어긋날 수 없다.

| Q | 도구 | 결과 | 면책 |
|---|---|---|---|
| Q1 취약 코드 존재 | `tools/judge_ics_cves.py` | held-out macro-F1 0.892 / ICS 쌍 0.333 | 0 |
| Q2 실행 경로 | `tools/callgraph_reach.py` | reachable 60, target-not-found 44, no-source 0 | **0** |
| Q3 공격자 통제 | `tools/taint_reach.py` | controllable 60, target-not-found 44, no-source 0 | **0** |
| Q4 인라인 완화 | `tools/mitigation_scan.py` | 104건 전부 `under_investigation` | **0** |

**소스 수준 분석은 이 코퍼스에서 아무것도 면책하지 못한다.** 이는 도구의 실패가
아니라 공개 기록의 재현이다 — CISA OT CSAF 3,984건 전체에서
`vulnerable_code_cannot_be_controlled_by_adversary` 와
`inline_mitigations_already_exist` 는 **각각 0회** 쓰였다. 여기서 살아남는 정당화
사유는 `component_not_present` 와 upstream 인용뿐이다.

### 6.1 취약 함수 지목 — 세 경로, 서로 다른 면책 권한

코드 수준 질문은 *어느 함수를* 판정할지 알아야 하고, 판정의 강도는 그 함수를
고른 근거의 강도를 넘을 수 없다. 그래서 경로를 기록하고 그것이 결론의 상한이
된다 (`data/vuln_targets.json`).

| 경로 | 방법 | CVE | 면책 가능 |
|---|---|---|---|
| A `patch` | fix 커밋이 수정한 함수 (`extract_vuln_funcs.py`, diff 캐시 `fetch_patches.py`) | 32 | 가능 |
| B `description` | NVD 설명이 지목 **&&** 그 이름이 스냅샷에 실제 정의됨 (`locate_vuln_funcs.py`) | 28 | 가능 |
| C `codebert` | Devign 파인튜닝 CodeBERT 랭킹 (`rank_codebert.py`) | 0 | **불가 — 미채택** |
| — | 미확보 | 40 | 불가 |

경로 B는 코드 문맥 필터를 건다 — 토큰이 `_`/CamelCase를 포함하거나, `foo()` 형태로
호출되거나, "the X function"으로 명시돼야 한다. 그렇지 않으면 `and`·`service`·
`process` 같은 영어 단어가 함수명과 우연히 겹쳐 잡힌다. 익스포트 매크로
(`ZLIB_INTERNAL`)와 설명이 *호출되는* 함수로 언급한 libc(`memset`)는 배제한다.

**경로 C는 측정된 음성 결과다.** 당시 확보된 타깃을 정답으로 채점하면 top-1
0.056 / top-5 0.111 / **top-20 0.148** 로, 무작위(0.021) 대비 약 7배지만 정답의
median 랭크가 4,000개 중 450위다. 이 모델은 "이 함수가 일반적으로 위험해
보이는가"에 답하지 "이 CVE의 함수인가"에 답하지 않으므로, 85%의 경우 진짜 타깃이
상위 20위 밖이다. 따라서 status 결정에 쓰지 않고 해당 CVE는 `under_investigation`
으로 둔다 (`results/codebert_rank.json`).

### 6.2 보수적 순회 — "못 찾음"을 "없음"으로 읽지 않기

정적 분석에서 **"못 찾음"과 "없음"은 똑같이 보이고**, 그 혼동은 항상 같은 방향
—— 거짓 면책 —— 으로 기운다. 실제로 네 건을 발견했고 그중 둘은 이미 판정을
내놓은 뒤에 잡혔다.

| 불완전성 | 증상 | 대가 |
|---|---|---|
| K&R 정의 | tree-sitter가 구식 C에서 ERROR를 내고 정의를 잃음 (zlib 1.2.8 `inflate.c` ERROR 89개, `inflate` 소실) | 호출 대상이 도달 불가로 보임 |
| 매크로 래핑 헤더 | `ZEXTERN int ZEXPORT inflate OF((...))` → 공개 API 3개만 인식 | 공격면이 축소돼 보임 |
| 간접 호출 | 정적 그래프는 `f()`만 봄; 디스패치 테이블·콜백 (`sqlite3_create_function(..., rtreenode, ...)`) 비가시 | **거짓 `not_affected` 6건** (Q3 초판) |
| 부분 빌드 로그 | `clang-format`과 configure 출력("gcc accepts -g... yes")을 컴파일 라인으로 셈 | **거짓 `not_affected` 5건** (Q4 초판) |

수정은 모두 같은 방향이다 — 도달 가능/컴파일됨의 범위를 **넓히기만** 하고 좁히지
않는다. K&R·매크로 서명은 정규식 스캐너가 파서를 보조하고, 주소가 참조되는 모든
함수를 오염 루트로 편입하며, 컴파일 라인은 컴파일러 토큰으로 시작하고 소스를
지명해야 하고, 로그가 프로젝트의 절반 이상을 컴파일해야 하며, 다른 번역 단위가
`#include` 하는 파일은 부재를 주장할 수 없다. 각 수정은 겨냥한 거짓 면책을 전부
제거했다.

### 6.3 Q4 판정 근거 분포 (104건 전부 보류)

```
55  쓸 만한 빌드 로그 없음
44  타깃 없음
 3  로그가 프로젝트 일부만 컴파일 — 부재를 논할 수 없음
 2  전처리기 가드는 있으나 매크로 정의 여부 확인 불가
 1  완화 증거 없음
```

전처리기 가드 사례가 규칙의 핵심이다. zlib CVE-2016-9841 은 `#ifndef ASMINF`
안에 있지만, `ASMINF` 가 `-D` 플래그에 없다는 사실은 정의 여부에 대해 아무것도
말하지 않는다 — autoconf 는 매크로를 생성된 `config.h` 에 넣지 커맨드라인에 넣지
않기 때문이다. 하드닝 플래그(`_FORTIFY_SOURCE`, 스택 프로텍터)는 설계상 면책
권한이 없다. 오염을 `abort()` 로 바꿀 뿐 DoS 는 남으므로 영향 완화이지 정당화
사유가 아니다.

---


### 6.4 타깃 커버리지 — 7 → 60

코드 수준 질문은 타깃 없이는 성립하지 않으므로, 커버리지가 Q2/Q3/Q4를 묶는
제약이다. 개선은 전부 도메인 난제가 아니라 **수집기 결함**을 고친 결과였다.

| 단계 | 누적 | 고친 것 |
|---|---|---|
| 시작 | 7 | — |
| 패치 diff 파싱 | 25 | tier-A 캐시가 6,000자에서 잘려 소스 hunk 소실 → 커밋 재수집 |
| NVD 설명 지목 (path B) | 52 | 설명이 지목한 이름 ∩ 스냅샷 정의 |
| NVD 레퍼런스 전량 | 55 | `fetch_nvd.py` 의 `references[:6]` 슬라이싱 |
| 포지 어댑터 | 55 | gitweb `a=commitdiff`, cgit, kernel.org·openssl GitHub 폴백 |
| GitHub PR 패치 | **60** | NVD 는 커밋(20)보다 PR(44)을 훨씬 자주 인용 |

면책 권한이 있는 path A 가 24 → **32** 로 늘어난 것이 실질적 이득이다.

남은 44건:

```
35  커밋 URL 이 NVD 레퍼런스 어디에도 없음 (배포판 어드바이저리·메일링리스트뿐)
16  커밋은 있으나 소스를 안 건드림 (릴리스·버전범프 커밋)
 9  파일이 스냅샷에 없음
 8  앵커 불일치 (스냅샷 버전 ≠ 패치 부모 커밋)
```

35건은 KRACK 계열·dnsmasq 2017·구버전 sqlite 같은 오래된 CVE 로, 프로젝트별
보안 페이지 파서가 필요하다 —— 범용 해법이 없는 구간이다. Fossil(sqlite)은
체크인 ID 하나로 접근 가능한 raw diff 엔드포인트가 없고 git 미러가 해시를
재작성하므로 **지원 불가**로 명시했다.

---

## 7. 데이터 성격 (정직한 고지)

**[진짜] CISA ICS-CERT 실데이터**
- 어드바이저리 3,767건 (2010–2026), 고유 CVE 11,336개
- CVE ↔ 장비(vendor/product) 매핑, CWE, CVSS v3/v4 벡터 — 전부 CISA 공식값
- KEV 149 statements, EPSS 실측
- CISA CSAF 원본 `product_tree` / `product_status` (정답지 및 모델 변형)

**[합성] 장비 주변 컴포넌트 인벤토리**
- 컴포넌트 구성은 OSS 카탈로그 귀속 + 벤더모듈 잔여로 생성
- SBOM 컴포넌트 버전은 **전 건 `NOASSERTION`** — 버전 범위 대조가 원리상 불가능하다.
  이 사실 자체가 `under_investigation` 의 주요 근거로 문장에 반영된다.
- `ics:network-exposure` 속성은 합성값이다. **판정에 쓰이지 않는다** (§7 참조).

**[제거됨] 추정 라벨**
- 이전 판의 학습 타깃은 99.8% 가 `AV × 합성 노출도` 로 만든 추정치였다. 폐기했다.
- 현재 `label` == 증거 기반 status (`UNDER_INVESTIGATION` 13,002 / `LIKELY_NOT_AFFECTED` 18 /
  `LIKELY_AFFECTED` 5). 3-class 분류 학습은 **더 이상 성립하지 않는다.**

---

## 8. 폐기된 실험 (이력 보존)

> 아래는 **현재 데이터·코드로 재현되지 않는다.** 학습 라벨이 폐기되었고
> (`models/` 의 가중치도 저장소에 없다), 남긴 이유는 무엇을 시도했고 왜 접었는지의 기록이다.

**라벨 의존 수치 — 전부 무효**
- SecureBERT 상태 분류 Macro F1 0.904 등 §5 계열 수치는 AV 추정 라벨 기준이다.
  라벨이 잠재 속성(AV·노출도)의 결정론적 함수였으므로, 그 성능은 "VEX 판정 능력"이 아니라
  **"산문에서 AV·노출도를 복원하는 능력"** 이었다. 축을 걷어낸 지금 측정 대상 자체가 없다.

**라벨 무관 수치 — 관측 자체는 유효, 다만 미재현**
- **SecureBERT ICS-DAPT**: CISA 어드바이저리 52,061 문장 continued MLM (3 epochs)
  → ICS 텍스트 perplexity 4.01 → **2.23** (−44.4%), ICS 용어 복원 0.303 → 0.386 (n=145).
  대부분의 이득이 epoch 0 에서 발생.
- **CodeBERT 파인튜닝**: Devign(~21k C 함수) 취약탐지 F1 **0.659** (문헌 수준 도달).
  그러나 "같은 함수의 취약 vs 패치 변형 구분"에는 전이되지 않음(0.457).
  → 백포트 탐지는 분류가 아니라 **레퍼런스 매칭**으로 푸는 것이 옳다는 근거.

---

## 9. 한계

1. **확정 판정이 0.18%** — 13,025 중 실행검증 5 + 상류채택 18. 나머지는 전부
   `under_investigation`. 확보한 증거의 정직한 반영이며, 늘리는 유일한 길은 실행검증
   대상 CVE 를 늘리는 것이다.
2. **자체 유도 성적은 모델 단위 재현에 한정** — §5.3 의 recall 1.000 은 "CISA 가 열거한
   모델 중 not_affected 를 놓치지 않는다"는 뜻이고, precision 0.291 은 열거되지 않은
   모델을 구별할 수 없다는 공개 데이터의 한계다.
3. **소스코드 근거 justification 은 0/8** — `not_in_execute_path`, `vulnerable_code_not_present`
   는 취약 컴포넌트가 특정되어야 하는데, 18쌍 중 17건은 컴포넌트명조차 공개되지 않았다.
4. **버전 대조 불가** — 전 컴포넌트 `NOASSERTION`. 실행검증된 CVE 조차 해당 장비가 취약본을
   쓰는지 확인할 수 없어 ICS 안전 우선 원칙으로 취약본을 가정한다(`version_unconfirmed: true`).
5. **실행 검증의 구조적 제약** — 안전 설계상 자체 완결형 라이브러리만 다룬다. ICS CVE 대부분은
   폐쇄 펌웨어라 원리상 이 경로에 오를 수 없고, 펌웨어에 번들된 OSS 만이 후보다.
6. **컴포넌트 인벤토리는 합성** — 장비↔CVE↔CWE↔CVSS 만 CISA 실데이터다. 실제 자산의 SBOM 이
   입력되면 `component_not_present` 레인의 성능은 달라진다(여기 수치는 하한이 아니다).
7. **모델 변형은 CISA 의존** — `product_tree` 가 없는 어드바이저리(전체의 절반)에서는
   모델 단위 판정이 불가능하다.

---

## 10. 재현

```bash
python tools/fetch_cisa_advisories.py     # ~25분 (3,767건 크롤)
python tools/fetch_exploit_signals.py     # ~5분 (KEV·EPSS)

git clone --depth 1 https://github.com/cisagov/CSAF.git /tmp/CSAF
python tools/collect_gt_icsa.py --csaf-repo /tmp/CSAF     # 정답지 고정

python src/build_reverse_sbom.py                          # 수 분
python tools/inject_product_variants.py --csaf-repo /tmp/CSAF

python tools/collect_code_gh.py           # OSS 취약/패치 실코드 (gh 인증 필요)
# 실행 검증은 재현 절차에 없다 - 러너가 제거되어 이 저장소만으로는 실행할 수 없다.
# 하류는 보존된 results/exec_verification*.json 을 읽는다.

python src/vex_batch.py                   # 배치 판정
python src/build_ground_truth.py          # 증거 계층 결정

python tools/compare_cisa_csaf.py --csaf-repo /tmp/CSAF   # 상류/자체 분리 대조
python tools/eval_variant_derivation.py                   # 모델 단위 독립 유도 성적

python tools/build_sbom_index.py && python tools/build_site.py
```

캐시(`data/*.json`, `results/exec_verification*.json`)가 있으면 크롤 단계는 건너뛸 수 있다.
실행 검증을 건너뛰면 `execution-verified` 계층이 비고, 상류 채택 18건만 확정으로 남는다.
