# ICS-VEX — Explainable VEX for Industrial Control Systems

CISA ICS 어드바이저리에서 **역방향으로 구축한 SBOM 데이터셋** 위에서,
**SecureBERT(맥락) + CodeBERT(코드)** 기반 설명가능 VEX 판정 시스템을
학습·평가하는 엔드투엔드 파이프라인.

> **🛡️ 2026-08 정적분석 전면 개편.** 라이브 판정 파이프라인은 이제 PoC 를 **생성하지도
> 실행하지도 않는다.** CVE-Genie 의 developer→critic 다중에이전트 구조는 유지하되,
> Exploiter(PoC 작성·실행)와 CTF Verifier(실행→flag)를 **정적 Exploitability 분석기**와
> **정적 증거 grounding critic** 으로 치환했다. 신규 확정 tier 는 `static-analysis-verified`.
> 상세: [`docs/GENIE_STYLE_VEX.md`](docs/GENIE_STYLE_VEX.md). 비활성화된 실행 경로는
> [`archive/`](archive/) 에 격리(삭제 아님).

> **🔗 라이브 대시보드**: https://kakyung98.github.io/ics-vex-dashboard/
> SBOM을 올려 CVE·VEX를 즉석 분석 + 시스템 평가 결과 시각화 (브라우저 내 처리)

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
| ~~검증 스펙/실행 검증~~ (격리) | `archive/*` | 과거 `results/exec_verification*.json` (역사적 근거로만 유지) |
| **Ground Truth (증거 계층)** | `src/build_ground_truth.py` | `data/vex_dataset.jsonl` |
| SecureBERT 학습·평가 | `src/train_eval_vex.py` | `results/metrics.json` |
| **SecureBERT ICS 도메인 적응(DAPT)** | `src/train_securebert_dapt.py` | `models/ics-securebert/`, `results/dapt_metrics.json` |
| **CodeBERT 코드 leg 검증** | `src/train_codebert.py`, `src/eval_two_model.py` | `results/two_model_metrics.json` |
| **CodeBERT 취약탐지 파인튜닝** | `src/train_codebert_finetune.py` | `models/codebert-vuln/` |
| 대시보드 생성 | `tools/build_dashboard.py` | `index.html` |

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
python tools/build_dashboard.py           # 대시보드
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
