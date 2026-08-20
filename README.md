# ICS-VEX — Explainable VEX for Industrial Control Systems

CISA ICS 어드바이저리에서 **역방향으로 구축한 SBOM 데이터셋** 위에서,
**SecureBERT(맥락) + CodeBERT(코드)** 기반 설명가능 VEX 판정 시스템을
학습·평가하는 엔드투엔드 파이프라인.

> **🛡️ 2026-08 정적분석 전면 개편.** 라이브 판정 파이프라인은 PoC 를 **생성하지도
> 실행하지도 않는다.** CVE-Genie 의 developer→critic 다중에이전트 구조는 유지하되,
> Exploiter(PoC 작성·실행)와 CTF Verifier(실행→flag)를 **정적 Exploitability 분석기**와
> **정적 증거 grounding critic** 으로 치환했다. 신규 확정 tier 는 `static-analysis-verified`.
> 상세: [`docs/GENIE_STYLE_VEX.md`](docs/GENIE_STYLE_VEX.md). 비활성화된 실행 경로는
> [`archive/`](archive/) 에 격리(삭제 아님).

> **🔀 하이브리드(정적 트리아지 → 실행 재현).** 실행 검증(execution-verified) ground truth 가
> 필요한 소수 CVE 를 위해, 정적 배치가 **재현 대상만 선별**해 격리된 CVE-Genie 에 넘기는
> 하이브리드를 갖춘다: 전 코퍼스 정적 스윕([`src/vex_batch.py`](src/vex_batch.py)) → 재현 후보
> export([`tools/export_genie_candidates.py`](tools/export_genie_candidates.py)) → 역할별 모델
> 라우팅으로 CVE-Genie 실행. 재현의 병목이던 **모델 거부(refusal)** 는 거부-빈발 Exploiter 만
> 로컬 모델([`tools/serve_poc_llm.py`](tools/serve_poc_llm.py))로 라우팅해 우회한다. 상세는
> 아래 [하이브리드 실행 재현](#하이브리드-정적-트리아지--실행-재현) 절.

> **🔗 라이브 대시보드 (ICS-VEXForge)**: https://kakyung98.github.io/ics-vex-dashboard/
> SBOM을 올려(붙여넣기·업로드·드래그) CVE·VEX 즉석 분석 + 코퍼스 통계 시각화 (전부 브라우저 내 처리).
> **3페이지 탭 구성**:
> - [Analyzer](https://kakyung98.github.io/ics-vex-dashboard/index.html) — SBOM→VEX + CPE 정규화(Ratcliff–Obershelp) 비교
> - [Corpus](https://kakyung98.github.io/ics-vex-dashboard/corpus.html) — Target CVE·CISA 어드바이저리·연도별 통계
> - [Collectable CVEs](https://kakyung98.github.io/ics-vex-dashboard/collectable.html) — 소스 수집가능 CVE(CWE/벤더/장비, 클릭 드릴다운)

---

## 무엇인가

- **입력**: CycloneDX SBOM (ICS 자산의 소프트웨어 명세)
- **출력**: 컴포넌트별 CVE 식별 + VEX 판정(`영향 가능`/`비영향`/`조사 필요`) + 표준 justification + 판정 근거 문장
- **코드 확보 여부가 경로를 가른다**:

| 상태 | CVE | 경로 | 1차 VEX |
|---|---|---|---|
| **취약/패치 코드 쌍 실보유** | 15 (0.13%) | SecureBERT → CodeBERT → sLLM 정적 분석가+critic | 정적 근거 grounded 시 **static-analysis-verified 확정** |
| 코드 미확보 | 11,321 (99.87%) | SecureBERT → 도달성 → sLLM 정적 분석가 | 도달성 grounded 시 `static-reasoned`, 아니면 `UNDER_INVESTIGATION` |

> ⚠️ **`tier` 컬럼 주의**: SBOM 속성명이 `component:source-availability` 라서 소스 확보로 읽히지만,
> 실제로는 **OSS 카탈로그 귀속 여부**일 뿐이다([build_reverse_sbom.py:202](src/build_reverse_sbom.py:202)).
> `tier=="A"` 132 CVE 중 실제로 코드를 확보한 것은 **15 CVE**.
> 따라서 코드 leg 게이트는 `tier` 가 아니라 `code_evidence_available` 이다.
> tier A 132 CVE 는 코드를 수집하면 승격 가능한 **확장 후보군**으로만 의미가 있다
> (`data/vex_dataset_code.jsonl` 로 별도 export).

  - **SecureBERT** — 보안/자산 텍스트(맥락·노출) 분석. 전 건의 1차 정적 신호
  - **CodeBERT** — 소스가 있는 건만. 패치 diff 정적 대조(취약 vs 패치 분리도 신호). 실행 없음
  - **sLLM (정적 분석가)** — 패치 diff·CWE·도달성 신호로 구조화된 취약성 판단 생성 후
    grounding critic 통과 시 최종 VEX 확정. **PoC 를 생성·실행하지 않는다**
  - 대조할 코드가 없는 건을 CodeBERT 로 보내지 않는다 — 근거 없는 출력은 오탐만 만든다

- **2차 VEX 추정**: 1차가 `UNDER_INVESTIGATION` 인 건은 확보 가능한 유일한 신호인
  **CVSS Attack Vector × 배치 노출도**로 상태를 추정하고 `estimate_confidence` 를 함께 싣는다.
  이는 VEX 진술이 아니라 추정치이며, 모델 학습 타깃은 이 값이다.

## ⚠️ 데이터 성격 (정직한 고지)

- **진짜**: 장비↔CVE↔CWE↔CVSS 매핑은 CISA ICS-CERT 공식 (3,765 어드바이저리, 11,336 CVE), KEV·EPSS 실신호, OSS 취약/패치 실코드(34 CVE, GitHub 픽스 커밋)
- **합성**: 장비 주변 컴포넌트 인벤토리, 배치 노출도(`exposure_synthetic: true` 로 표시)
- **추정**: 학습 타깃 `label` 의 99.96% 는 확정 판정이 아니라 **AV 기반 2차 추정치**다.
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
| **정적 VEX 판정 (라이브)** | `src/vex_pipeline.py` | JSON-line 스트림 (SBOM→VEX) |
| **전 코퍼스 정적 스윕** | `src/vex_batch.py` | `results/vex_batch.jsonl` + `_summary.json` (source_class 분류) |
| **재현 후보 export (브리지)** | `tools/export_genie_candidates.py` | `results/genie_candidates.json` |
| **로컬 PoC 모델 서버** | `tools/serve_poc_llm.py` | OpenAI 호환 엔드포인트 (CVE-Genie Exploiter 라우팅용) |
| **동적 REST API 서비스** | `src/api_server.py` | FastAPI (SBOM→VEX·CPE 정규화·통계·드릴다운) |
| **정적 사이트 생성 (3페이지)** | `tools/build_site.py` | `index.html`·`corpus.html`·`collectable.html` + 데이터 JSON |
| ~~검증 스펙/실행 검증~~ (격리) | `archive/*` | 과거 `results/exec_verification*.json` (역사적 근거로만 유지) |
| **Ground Truth (증거 계층)** | `src/build_ground_truth.py` | `data/vex_dataset.jsonl` |
| SecureBERT 학습·평가 | `src/train_eval_vex.py` | `results/metrics.json` |
| **SecureBERT ICS 도메인 적응(DAPT)** | `src/train_securebert_dapt.py` | `models/ics-securebert/`, `results/dapt_metrics.json` |
| **CodeBERT 코드 leg 검증** | `src/train_codebert.py`, `src/eval_two_model.py` | `results/two_model_metrics.json` |
| **CodeBERT 취약탐지 파인튜닝** | `src/train_codebert_finetune.py` | `models/codebert-vuln/` |

> **라이브 판정 vs 학습 데이터**: 라이브 SBOM→VEX 판정은 `src/vex_pipeline.py` 가
> 정적분석으로 수행한다(실행 없음, 신규 확정 tier = `static-analysis-verified`).
> 학습 데이터셋(`build_ground_truth.py`)은 여전히 과거 `results/exec_verification*.json`
> 을 읽어 **역사적** execution-verified 5건을 표기하지만, 이 실행 경로는 격리(`archive/`)
> 되어 더 이상 새 확정을 만들지 않는다.

## 주요 결과

### 데이터셋 구성 (v3, 증거 계층 기반)
| 증거 계층 | 건수 | 1차 VEX |
|---|---|---|
| `execution-verified` (역사적, 격리된 실행 경로) | 5 (0.04%) | **확정** (`LIKELY_AFFECTED`) |
| `source-available-unverified` | 31 (0.24%) | `UNDER_INVESTIGATION` (정적 판정 대상) |
| `source-pending` | 2,115 (16.26%) | `UNDER_INVESTIGATION` (OSS 귀속, 코드 미수집) |
| `source-unavailable` | 10,854 (83.46%) | `UNDER_INVESTIGATION` (폐쇄 펌웨어) |

산출 파일 3종:

| 파일 | 건수 | 용도 |
|---|---|---|
| `data/vex_dataset.jsonl` | 13,005 | 전체 — SecureBERT 학습 |
| `data/vex_dataset_code.jsonl` | 356 | tier A 확장 후보군 — 코드 leg 실험 |
| `data/vex_ground_truth.jsonl` | 5 | **실행 검증 확정분 — 진짜 ground truth** |

### 정적 판정 커버리지 (개편 후)

라이브 판정은 실행 없이 정적분석으로 이뤄지므로, 커버리지는 "실행 트리거를 몇 개 작성했나"가
아니라 **정적 증거가 얼마나 결정적인가**로 정해진다:

| tier | 조건 |
|---|---|
| `static-analysis-verified` | 취약/패치 코드 쌍 보유 + 패치가 취약본과 정적으로 분리 가능 + critic grounded + 결정적 판정 |
| `static-reasoned` | 코드 쌍 없음, 그러나 도달성(AV×노출도)+CWE 추론으로 결정적 판정 grounded |
| `under-investigation` | 정적 증거 부족 |

과거 실행 검증 상한 분석(verifiable-c 101 / blocked-proprietary 21 / blocked-scope 10)과
CVE별 트리거 수작업은 [`archive/`](archive/) 로 격리됐다 — 정적 경로에서는 더 이상 필요 없다.

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

## 하이브리드: 정적 트리아지 → 실행 재현

정적 판정은 전 코퍼스를 싸게 트리아지하지만 "재현된 크래시"의 확실성은 없다. 실행 검증
ground truth 가 필요한 소수 CVE 를 위해, 정적 배치가 **재현 대상만 선별**해 격리된 CVE-Genie
로 넘기는 하이브리드를 둔다.

**소스 확보 3분류** (재현 가능성이 여기서 갈린다):

| 부류 | findings | 의미 |
|---|---|---|
| `code-available` | 36 (15 CVE) | 취약/패치 코드쌍 실보유 → CodeBERT 정적 diff + **재현 즉시 가능** |
| `oss-attributed` | 2,115 | OSS(tier A/C)지만 코드 미수집 → 수집 시 승격 |
| `vendor-proprietary` | 10,854 | 폐쇄 펌웨어 → **재현 불가**, 정적 판정에만 |

**흐름**:
```
src/vex_batch.py           # 전 13,005건 정적 스윕 (source_class 분류)
tools/export_genie_candidates.py   # 재현 후보 선별 -> results/genie_candidates.json
                                   #   ready 15 (repo+commit) / needs-code 1,716
# CVE-Genie 실행 (Docker, 격리) — Exploiter만 로컬 모델로 라우팅
tools/serve_poc_llm.py --port 8000 --served-name ics-vex-poc-sllm   # 로컬 PoC 서버
LOCAL_LLM_BASE_URL=http://host.docker.internal:8000/v1 \
LOCAL_LLM_MODELS=local-poc=ics-vex-poc-sllm EXPLOITER_MODEL=local-poc \
  python3 main.py --cve <CVE> --json <data> --run-type build,exploit,verify
```

**모델 거부(refusal) 우회 — 역할별 라우팅**: CVE-Genie 재현의 병목은 실행 차단이 아니라
클라우드 모델이 익스플로잇 작성 단계에서 **거부**하는 것이었다. 거부-빈발 Exploiter 만
로컬 모델(`poc-sllm-lora`, 거부 안 함)로 라우팅하고 추론-무거운 나머지 역할은 능력 모델을
유지한다(`cve-genie/src/agents/model_routing.py`, env 기반, 미설정 시 업스트림과 동일).

> **검증 결과(2026-08, CVE-2024-4340)**: 역할별 라우팅 **동작 확인**(Exploiter=로컬 $0,
> 나머지=o3/o4-mini), **거부 문제 해소**(로컬 모델이 PoC 정상 생성). 단 7B 로컬 모델은
> Exploit Critic 이 요구하는 실행-증거 수준을 만족 못 해 재현은 실패 — 16GB→7B 능력 한계.
> 실제 재현엔 Exploiter 를 클라우드 32~70B 로 올리는 것이 유일한 길(라우팅은 env 만 교체).

## 웹 콘솔 — ICS-VEXForge

두 가지 형태로 동일한 콘솔을 제공한다.

- **정적 사이트 (GitHub Pages)** — `tools/build_site.py` 가 코퍼스를 동일-출처 JSON 으로
  구워 `index.html`·`corpus.html`·`collectable.html` 3페이지를 생성한다. SBOM→VEX 계산과
  CVE 드릴다운, CPE 정규화(Ratcliff–Obershelp)까지 **전부 브라우저 안에서** 돈다(백엔드 불필요).
- **동적 REST 서비스 (로컬)** — [`src/api_server.py`](src/api_server.py) (FastAPI). 같은 UI 를
  라이브 REST 로 서빙하고 Swagger 문서를 자동 제공한다.

```bash
pip install fastapi uvicorn
python src/api_server.py --port 8100   # localhost:8100 (docs: /docs) · 0.0.0.0 바인딩=LAN 접속
python tools/build_site.py             # 정적 3페이지 + 데이터 JSON 재생성 → GitHub Pages 푸시
```

| 페이지 / 엔드포인트 | 설명 |
|---|---|
| `GET /` · `/corpus.html` · `/collectable.html` | 3페이지 탭 콘솔 (Analyzer / Corpus / Collectable) |
| `GET /docs` | **Swagger UI** (자동 REST 문서) |
| `GET /api/summary` · `/api/source_available` · `/api/by_year` · `/api/advisories` | 코퍼스 통계 (CVE 단위) |
| `GET /api/candidates?status=ready&top=15` | 재현 후보 |
| `GET /api/cves?dim=cwe&value=CWE-416&scope=source_available` | 드릴다운 (그래프 클릭 → 관련 CVE) |
| `POST /api/vex` | `{sbom, exposure}` → 컴포넌트별 CVE + 라이브 VEX |
| `POST /api/vex_compare` | **CPE 정규화(Ratcliff–Obershelp) vs 정확매칭 CVE 비교** |

주요 기능: SBOM 붙여넣기·업로드·드래그, **Severity 대신 CVSS v3 점수** 표시, 통계 그래프
클릭 시 관련 CVE 목록(NVD 링크). 배포는 Python 이 도는 어디든 가능(VPS·Render·Railway).
전체 3-모델 라이브 판정이 필요하면 `src/vex_pipeline.py`(SecureBERT+CodeBERT+sLLM)를 쓴다.

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
python src/build_ground_truth.py          # 증거 계층 결정 (역사적 exec 결과 포함)
python src/save_vex_model.py              # SecureBERT VexModel 저장 (정적 판정용)
python src/vex_pipeline.py --sbom results/example_sbom.json --exposure control-network
                                          # ← 라이브 정적 VEX 판정 (PoC·실행 없음)
python src/train_eval_vex.py              # SecureBERT 맥락 leg (GPU 권장)
python src/eval_two_model.py              # CodeBERT 코드 leg (tier A 만)
python src/train_securebert_dapt.py       # ICS 도메인 적응
python src/train_codebert_finetune.py     # CodeBERT 취약탐지 파인튜닝
python tools/build_site.py                # 정적 웹 콘솔 3페이지 생성 (GitHub Pages)
```

## 한계

1. **정적 확정은 실행 확정보다 근거가 약하다** — 라이브 판정은 실행 없이 정적 증거
   (코드 diff 분리도, 도달성 grounding, critic 합의)에 기반하므로, 재현된 크래시가 주는
   확실성은 없다. `static-analysis-verified` 는 "정적으로 결정적"일 뿐 실증이 아니다.
   과거 실행 확정 5건은 격리된 역사적 tier 로만 남는다.
2. **학습 타깃은 확정값이 아니라 추정치** — 모델이 배우는 `label` 의 99.96%는
   AV × 노출도로 계산한 2차 추정이다. 성능 지표는 "VEX 판정 능력"이 아니라
   "산문에서 잠재 속성(AV·노출도)을 복원하는 능력"에 가깝다.
3. **버전 대조 불가** — SBOM 전 컴포넌트가 `NOASSERTION`. 어떤 CVE 도 해당 장비가
   취약본을 쓰는지 확인할 수 없어, ICS 안전 우선 원칙으로 취약본을 가정한다
   (`version_unconfirmed: true`).
4. **합성 배치 맥락** — 장비↔CVE↔CWE↔CVSS만 실데이터. 노출도는 합성(`exposure_synthetic: true`).
   정적 도달성 판단이 이 합성값에 의존하므로, 절대 정확도는 검증 불가하다.
5. **정적 코드 신호의 한계** — CodeBERT 패치-diff 신호는 취약/패치 코드 쌍을 확보한 CVE
   에만 적용되고(대부분 OSS 컴포넌트), 배포된 실제 코드가 아니라 참조 diff 를 비교한다.
   폐쇄 펌웨어는 정적 코드 leg 에 오르지 못하고 도달성·맥락 신호로만 판정된다.
6. **추상 취약탐지 난제** — 파인튜닝해도 교차프로젝트 ~65~70%가 상한

## 데이터 출처 / 라이선스

- 코드: 연구·교육용 참조 구현
- CVE/CWE/CVSS: CISA ICS-CERT (공개), NVD, FIRST EPSS, CISA KEV
- OSS 취약/패치 코드: 각 프로젝트 공개 저장소의 픽스 커밋
- 취약탐지 코퍼스: CodeXGLUE Defect Detection (Devign)
- 합성 SBOM: 본 저장소에서 생성 (실제 제품 구성 아님)
