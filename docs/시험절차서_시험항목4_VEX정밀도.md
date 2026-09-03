# 시험절차서 — 시험항목 #4: VEX 기반 식별된 취약점 영향 판단 정밀도

> 공인시험기관 제출용 시험절차서 (draft)
> 대상 시스템: **ICS-VEX (ICS-VEXForge)** — SBOM→VEX 판단 파이프라인
> 형상(commit): `2f729d03` · 작성일: 2026-09-03

---

## 1. 시험 개요

| 항목 | 내용 |
|---|---|
| 시험 항목명 | VEX 기반 식별된 취약점 영향 판단 정밀도 |
| 시험 목적 | ICS 자산에 대해 VEX 필드에 **'영향 있음(Affected)'**으로 자동 분류된 항목 중, 실제로도 영향받는 것으로 확인된 항목의 비율(정밀도)을 측정한다. |
| 성능 지표 | 정밀도(Precision) |
| 합격 기준 | **정밀도 ≥ 95%** |

### 1.1 성능 지표 산식

```
정밀도(Precision) = TP / (TP + FP) × 100 (%)
```

- **TP (True Positive)**: 시스템이 `affected`로 분류하였고, 정답(그라운드 트루스)에서도 영향받는 것으로 확인된 사례. 정답의 근거는 **취약 버전의 소스코드가 존재하고 해당 취약 코드가 패치로 제거되지 않은 상태**(= 취약 버전과 일치)이다.
- **FP (False Positive)**: 시스템이 `affected`로 분류하였으나, 정답에서 영향 없음(= 패치된/안전한 코드)으로 확인된 사례.

> 본 지표는 **정밀도 단독** 평가로, 재현율(Recall)·F1은 합격 판정 대상이 아니다.
> 재현율을 희생하더라도 오탐(FP)을 억제하는 것이 본 시험의 목적에 부합한다.

---

## 2. 시험 대상 시스템 (SUT)

| 구성요소 | 내용 |
|---|---|
| 시스템명 | ICS-VEX (ICS-VEXForge) |
| 판단 단계 | CISA 4대 저스티피케이션 질문 Q1–Q4 (Q1: 취약 코드 존재 → 본 시험의 `affected`/`not_affected` 근거) |
| 평가 대상 모델 | 취약 코드 존재 판단 모델 (sLLM) — Qwen2.5-Coder-7B-Instruct + QLoRA 어댑터 |
| 어댑터 산출물 | `models/vex-justifier-lora/` (adapter_config.json, adapter_model.safetensors) |
| 형상 식별 | git commit `2f729d03` |

`affected`/`not_affected` 자동 분류는 대상 컴포넌트의 함수 코드를 입력받아 취약 구성의 존재 여부(Q1)를 판정하여 산출한다.

---

## 3. 시험 환경 및 시험 도구

### 3.1 하드웨어

| 항목 | 사양 |
|---|---|
| GPU | NVIDIA GeForce RTX 4070 Ti SUPER (16 GB) |
| 비고 | GPU 전력제한 200 W (열/전원 안정화) |

### 3.2 소프트웨어

| 항목 | 버전 |
|---|---|
| OS | Windows 10/11 |
| Python | 3.10.0 |
| PyTorch | 2.11.0+cu128 |
| CUDA | 12.8 |
| transformers | 5.15.0 |
| peft | 0.20.0 |
| bitsandbytes | 0.50.0 |
| 베이스 모델 | Qwen/Qwen2.5-Coder-7B-Instruct (4-bit NF4 로드) |

### 3.3 시험 도구 (스크립트)

| 파일 | 역할 |
|---|---|
| `tools/eval_affected_precision.py` | 본 시험 전용 정밀도 측정 도구. `affected` 분류에 대해 TP/FP를 집계하고 `precision = TP/(TP+FP)×100`을 산출·기록한다. |
| `data/vex_train_full.jsonl` | 학습·평가 원천 코퍼스(23,538행). 본 시험은 이 중 **학습에 사용되지 않은 held-out 부분집합**만 사용한다. |
| `results/affected_precision.json` | 시험 결과 기록 산출물(JSON). |

시험 도구는 결정적(greedy) 디코딩을 사용하며, 데이터 분할·표본 추출에 고정 시드를 사용하여 재현성을 보장한다.

---

## 4. 전제조건 (Preconditions)

시험 수행 전 아래 조건이 모두 충족되어야 한다.

1. **모델 학습 완료**: `models/vex-justifier-lora/`에 학습된 QLoRA 어댑터가 존재한다. (본 시험은 추론만 수행하며 재학습하지 않는다.)
2. **데이터 누출 방지**: 평가에 사용하는 held-out 부분집합은 학습에 **사용되지 않은** 행으로 한정한다. 학습·평가가 동일한 셔플 시드(`SEED=20260416`)와 동일한 학습 표본 크기(`SUBSAMPLE=12000`)를 사용하여, 학습에 쓰인 `rows[:12000]`과 평가에 쓰이는 `rows[12000:]`이 서로소임을 보장한다.
3. **환경 재현**: 제3장의 라이브러리 버전이 설치되어 있고, CUDA 가용 GPU가 준비되어 있다.
4. **데이터셋 준비**: `data/vex_train_full.jsonl`이 제5장의 형상과 일치한다(행 수·출처 분포).
5. **결정성**: 시험 도구는 do_sample=False(greedy)로 동작하며, 표본 추출 시드(`random.Random(7)`)가 고정되어 동일 입력에 대해 동일 결과를 산출한다.

---

## 5. 시험(검증) 데이터셋

### 5.1 데이터셋 정의

본 시험의 정답(그라운드 트루스)은 **fix-commit(패치 커밋)으로 뒷받침되는 취약/패치 코드 쌍**을 사용한다. 이는 시험 기준의 TP 정의("소스코드 패치 여부가 CVE 영향 조건과 일치")에 직접 부합한다.

- 평가 표본 = `data/vex_train_full.jsonl`의 held-out 부분집합(`rows[12000:]`) 중 **패치쌍 출처만 필터**(`--clean`): `cvefixes`, `bigvul`, `seed`.
- 각 예시의 정답 라벨:
  - **취약 버전 함수 → `affected`**
  - **패치(수정) 버전 함수 → `not_affected`** (해당 취약 구성이 제거됨)

### 5.2 데이터셋 규모 및 분포 (형상 `2f729d03` 기준)

| 구분 | 값 |
|---|---|
| 전체 코퍼스 | 23,538 행 |
| held-out(학습 미사용) | 11,538 행 |
| **본 시험 표본 (held-out ∩ 패치쌍)** | **3,471 행** |
| └ 클래스 분포 | affected 2,124 / not_affected 1,347 |
| └ 출처 분포 | cvefixes 2,119 / bigvul 1,352 / (seed 소수) |

> 기본 실행은 위 표본에서 시드 고정으로 최대 `--n`개(기본 1,200)를 추출하여 평가한다. 전수(3,471) 평가도 `--n 3471`로 가능하다.

### 5.3 정답의 독립성(누출 없음) 근거

- 정답 라벨은 **공개 취약점 데이터셋(CVEfixes, BigVul)의 패치 커밋**에서 유래하며, 대상 모델의 학습 표본과 **서로소인 held-out 행**에서만 취한다.
- 정답은 모델 입력(함수 코드)과 **분리된 필드**(`completion.status`)에 있으며, 시험 도구는 모델 출력과 정답을 사후 대조만 한다(모델에 정답을 제공하지 않는다).

### 5.4 데이터셋 출처 및 라이선스

| 출처 | 원 논문/저장소 | 용도 |
|---|---|---|
| CVEfixes | Bhandari et al., PROMISE 2021 (`rufimelo/cvefixes-cwe`) | 실제 CVE 패치쌍(취약/안전) |
| BigVul | Fan et al., MSR 2020 (`bstee615/bigvul`) | 취약/패치 함수쌍(before/after) |
| project seed | 업스트림 오픈소스 fix commit (GitHub) | 취약/패치 쌍 |

원 코드 표본은 각 출처의 라이선스를 따른다. 정제·재구성 스크립트는 프로젝트 저장소에 포함된다(`tools/build_vexc_dataset.py`, `tools/collect_vulnfix_dataset.py`).

---

## 6. 시험 절차 (Procedure)

### 6.1 단계

1. **환경 확인**: 제3장 라이브러리 버전 및 GPU 가용성 확인.
2. **전제조건 점검**: 제4장 항목(어댑터 존재, 데이터셋 형상, 시드) 확인.
3. **시험 실행**: 아래 명령을 수행한다.

   ```bash
   POC_BASE_MODEL="Qwen/Qwen2.5-Coder-7B-Instruct" \
   SEED=20260416 SUBSAMPLE=12000 \
   python tools/eval_affected_precision.py --clean --n 1200
   ```

   - `--clean`: fix-commit 뒷받침 패치쌍 정답만 사용.
   - `--n`: 평가 표본 수(전수는 `--n 3471`).
4. **출력 수집**: 표준출력의 100건 단위 진행 로그와 최종 요약, 그리고 결과 JSON(`results/affected_precision.json`)을 수집한다.
5. **판정**: 제7장에 따라 합격/불합격을 판정한다.

### 6.2 (옵션) 보수적 발행 모드 — 정밀도 보강

정밀도를 추가로 보강해야 할 경우, 5회 표본추출 중 **만장일치(5/5)로 affected일 때만** `affected`로 발행하고 그 외에는 `under_investigation`으로 보류(abstain)하는 모드를 사용한다. 재현율은 본 시험 대상이 아니므로 보류는 정밀도 산정에서 제외된다.

```bash
python tools/eval_affected_precision.py --clean --n 1200 --abstain
```

---

## 7. 판정 방법 (Pass/Fail)

1. 시험 도구는 `affected`로 분류한 사례에 대해서만 TP/FP를 집계한다(파싱 불가·`not_affected`·보류는 분모에서 제외).
2. `precision = TP / (TP + FP) × 100`을 산출한다.
3. **`precision ≥ 95.0%`이면 합격(PASS), 미만이면 불합격(FAIL).**
4. 판정 결과는 `results/affected_precision.json`의 `precision_pct`, `pass` 필드로 기록된다.

---

## 8. 결과 기록 양식

시험 도구는 아래 스키마의 JSON을 `results/affected_precision.json`에 기록한다.

```json
{
  "test": "affected precision (시험항목 #4)",
  "target_pct": 95.0,
  "ground_truth": "clean patch-pairs",
  "mode": "greedy",
  "n": 1200,
  "classified_affected": 0,
  "TP": 0,
  "FP": 0,
  "abstained": 0,
  "precision_pct": 0.0,
  "pass": true
}
```

| 필드 | 의미 |
|---|---|
| `n` | 평가 표본 수 |
| `classified_affected` | `affected`로 분류한 사례 수 (= TP + FP) |
| `TP` / `FP` | 진양성 / 위양성 |
| `abstained` | (abstain 모드) 보류 건수 |
| `precision_pct` | 정밀도(%) |
| `pass` | `precision_pct ≥ 95.0` 여부 |

---

## 9. 자체시험 참고 결과

> 공인시험 수행 전, 동일 절차로 수행한 자체시험 결과(참고용).

| 구분 | 값 |
|---|---|
| 정답 | fix-commit 뒷받침 패치쌍(held-out) |
| 모드 | greedy (결정적) |
| 표본 수 | 800 (자체시험 중간 관측, 목표 표본 1,200) |
| affected 분류(TP+FP) | 302 |
| **정밀도** | **약 99.0 %** (affected 302건 중 위양성 약 3건) |
| 판정 | **PASS** (≥95%) |

> 위는 자체시험 진행 중 관측치이며, 최종 수치는 시험 완료 후 `results/affected_precision.json`으로 갱신한다. 100건 단위 관측 정밀도는 97.1%→99.0% 구간에서 안정적으로 95%를 상회하였다.

---

## 10. 재현성 및 추적성

- **결정성**: greedy 디코딩(do_sample=False) + 고정 시드(데이터 셔플 `20260416`, 표본추출 `7`).
- **형상 고정**: 모델 어댑터·데이터셋·시험 스크립트는 git commit `2f729d03`으로 식별.
- **버전 고정**: 제3.2장 라이브러리 버전.
- **독립 검증**: 공인시험기관은 제5장 데이터셋과 제6장 명령으로 동일 결과를 재현할 수 있다.

---

## 부록 A. 파일 목록

| 파일 | 설명 |
|---|---|
| `tools/eval_affected_precision.py` | 시험 도구 |
| `data/vex_train_full.jsonl` | 원천 코퍼스(held-out 분할 원본) |
| `models/vex-justifier-lora/` | 평가 대상 어댑터 |
| `results/affected_precision.json` | 결과 산출물 |
