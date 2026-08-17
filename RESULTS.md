# ICS-VEX 시스템 구축·평가 결과

CISA ICS 어드바이저리에서 역방향으로 구축한 SBOM 데이터셋 위에서,
SecureBERT/CodeBERT 기반 설명가능 VEX 판정 시스템을 학습·평가한 전체 결과.

실행 환경: GPU(CUDA) + torch 2.11 + transformers 4.56. 전체 파이프라인 재현 가능.

---

## 1. 파이프라인 (실행 순서)

| 단계 | 스크립트 | 산출물 |
|---|---|---|
| 1. 어드바이저리 수집 | `tools/fetch_cisa_advisories.py` | `data/cisa_advisories.json` |
| 2. 악용신호 수집 | `tools/fetch_exploit_signals.py` | `data/exploit_signals.json` (KEV·EPSS) |
| 3. 역방향 SBOM | `src/build_reverse_sbom.py` | `reverse_sbom/*.json`, `data/findings.csv` (`tier`) |
| 4. OSS 코드 수집 | `tools/collect_code_gh.py` | `data/code_evidence.json` |
| 5. 실행 검증 | `src/exploit_verifier.py`, `tools/exec_verify_c.sh` | `results/exec_verification*.json` |
| 6. Ground Truth | `src/build_ground_truth.py` | `data/vex_dataset.jsonl` |
| 7. 학습·평가 | `src/train_eval_vex.py` | `results/metrics.json`, `results/report.md`, `results/sample_vex/*.json` |

> 4·5단계가 6단계보다 **먼저** 실행되어야 한다. `build_ground_truth.py` 가 이 산출물을 읽어
> 각 finding 의 증거 계층과 모델 라우팅을 결정하기 때문이다.

---

## 2. 데이터 (진짜 vs 합성)

**[진짜] CISA ICS-CERT 실데이터**
- 어드바이저리 **3,765건** (2010–2026), 고유 CVE **11,336개**
- CVE ↔ 장비(vendor/product) 매핑, CWE, CVSS v3/v4 벡터 — 전부 CISA 공식값
- KEV(야생 악용) 149 findings, EPSS 12,937/13,005 findings

**[합성] 장비 주변 컴포넌트 인벤토리**
- 역방향 SBOM **3,103개 장비**, findings **13,005건**
- OSS-arm 2,151 (16.5%) / 벤더맥락-arm 10,854 (83.5%)
  → **폐쇄 벤더코드가 다수**임이 CISA 실데이터로 확인 (코드분석 불가 영역이 지배적)
- 소스 확보 가능성(`tier`, SBOM 속성 `component:source-availability`):
  A 356 (2.7%) / C 1,795 (13.8%) / E 10,854 (83.5%)
  → 실제로 코드 대조가 가능한 영역은 **2.7%** 에 불과하다. 이 비율이 파이프라인 라우팅을 결정한다.
- SBOM 컴포넌트 버전은 **전 건 `NOASSERTION`** — 버전 범위 대조가 원리상 불가능하다.

> 핵심 링크(장비↔CVE↔CWE↔CVSS)는 CISA 실데이터이므로, 초기의 순환논증 문제가 해소된다.

---

## 3. Ground Truth (v3 — 증거 계층 기반)

**원칙: 판정은 확보한 증거의 강도를 넘어서지 않는다.**

증거 계층은 **vuln/patched 코드 쌍의 실제 보유 여부**(`code_evidence.json`)로 정한다.

| 증거 계층 | 라우팅 | 1차 VEX | 건수 |
|---|---|---|---|
| `execution-verified` | — (확정 완료) | **확정** | 5 (0.04%) |
| `source-available-unverified` | SecureBERT → CodeBERT → sLLM | `UNDER_INVESTIGATION` | 31 (0.24%) |
| `source-pending` (OSS 귀속, 코드 미수집) | SecureBERT 종결 | `UNDER_INVESTIGATION` | 2,115 (16.3%) |
| `source-unavailable` (폐쇄 펌웨어) | SecureBERT 종결 | `UNDER_INVESTIGATION` | 10,854 (83.5%) |

코드가 없는 건을 CodeBERT 로 보내지 않는다 — 대조할 코드가 없으면 출력에 근거가 없어 오탐만 만든다.

> ⚠️ **`tier` 컬럼의 이름과 의미가 다르다.** SBOM 속성명은 `component:source-availability` 지만
> 실제 계산은 `tier = "A" if cve in oss_by_cve else "C"` — 즉 **OSS 카탈로그 귀속 여부**다
> ([build_reverse_sbom.py:202](src/build_reverse_sbom.py:202)).
> `tier=="A"` 132 CVE / 356 findings 중 실제로 코드를 확보한 것은 **15 CVE / 36 findings** 에 불과하다.
> 라우팅을 `tier` 로 게이팅하면 코드 없는 320 findings 가 코드 leg 로 잘못 들어간다.
> tier A 356건은 코드를 수집하면 승격 가능한 **확장 후보군**이며 `data/vex_dataset_code.jsonl` 로 export 한다.

### 1차 VEX (증거 기반, 표준 호환)

| 상태 | 건수 | 비고 |
|---|---|---|
| `LIKELY_AFFECTED` | 5 (0.04%) | zlib CVE-2018-25032, ASan 크래시 관측 |
| `LIKELY_NOT_AFFECTED` | 0 | 패치본으로 확인된 배치가 아직 없음 |
| `UNDER_INVESTIGATION` | 13,000 (99.96%) | 증거 부족 |

판정 사유는 CSAF VEX / OpenVEX 의 `not_affected` justification 5종 통제 어휘를 사용한다
(`component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`,
`vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`).
표준이 `affected` 에는 justification 어휘를 정의하지 않으므로(표준 필드는 `impact_statement` /
`action_statement`), 위 5종의 역대응 어휘를 확장으로 부여하고 `justification_vocabulary` 필드로
`csaf-openvex` / `extension` 을 구분한다.

### 2차 VEX 추정 (학습 타깃)

1차가 `UNDER_INVESTIGATION` 인 건은 확보 가능한 유일한 신호인 **CVSS Attack Vector × 배치 노출도**로
도달성을 계산해 상태를 추정하고, `estimate_confidence` 를 함께 싣는다. VEX 진술이 아니라 추정치다.

| 학습 타깃 `label` | 건수 |
|---|---|
| `LIKELY_AFFECTED` | 4,334 (33.3%) |
| `LIKELY_NOT_AFFECTED` | 2,676 (20.6%) |
| `UNDER_INVESTIGATION` | 5,995 (46.1%) |

주석자 불일치 노이즈(10%, κ≈0.85)는 **추정치에만** 적용한다. 실행 검증으로 확정된 건은
사실이므로 흔들지 않는다. `AFFECTED ↔ NOT_AFFECTED` 직접 전이는 구조적으로 금지된다(안전).

### v2 대비 제거된 것 — 근거 없이 합성하던 요소

| 제거 | 사유 |
|---|---|
| `neg_evidence()` | 해시로 patched·component-absent·version-out-of-range·function-disabled 를 **지어내던** 2,407건. 실증거 없음 |
| 해시 기반 모호성 꼬리 | AV 가 실제로 미기재인 건(`av==""`, 242행)으로 대체 |
| 버전 범위 대조 문장 | SBOM 전 컴포넌트가 `NOASSERTION` 이라 대조 자체가 불가능. 그 사실을 문장으로 명시하도록 변경 |
| KEV 의 gold rationale 포함 | KEV 는 어느 경로에서도 상태를 바꾸지 않는데 정답 근거로 채점되던 문제 |

**정직성 장치**: 오라클은 구조화 특징을, SecureBERT는 자연어 문장만 본다.
Attack Vector는 텍스트에 명시하지 않고 공격표면 산문으로 암시 → 모델이 추론해야 한다.

---

## 4. 모델 (README 구조 구현)

- **SecureBERT**(frozen) 문장 임베딩 → 어텐션 풀링 → 멀티태스크
  - Classification Head → 3-class VEX
  - Rationale Head → 문장별 driver 확률, `L = CE + λ·BCE`
- **CodeBERT** 보조: **tier A(소스 확보)** findings 만. 소스 미확보 건은 코드 leg 로
  넘기지 않으며 신호 자체를 생성하지 않는다(abstain)
- **Evidence Verifier + 보수적 Decision Engine**: 라우팅을 존중한다
  - `securebert-only`: SecureBERT 출력이 최종. 코드 신호를 참조하지 않는다
  - `securebert->codebert->sllm`: 코드가 있는데 신호가 weak 이면 확정하지 않고
    실행 검증으로 넘긴다. 코드 신호가 `present` 인데 모델이 NOT_AFFECTED 를 내면 보류
  - `LIKELY_NOT_AFFECTED`는 적극적 반증 근거가 선택됐을 때만 허용,
    저신뢰/충돌 → `UNDER_INVESTIGATION`
- 평가: device-disjoint split (train 10,888 / test 2,117)

---

## 5. 결과

> ⚠️ **이 절의 모든 수치는 v2 데이터셋(규칙 오라클 + 합성 음성증거) 기준이며 무효다.**
> v3 는 라벨 생성 로직이 근본적으로 바뀌었다(§3). `train_eval_vex.py` 재실행 후 재측정해야 한다.
> 특히 v2 의 `LIKELY_NOT_AFFECTED` 653건 중 다수는 합성 음성증거에서 나온 것이라,
> v3 에서는 존재하지 않는 근거로 얻은 성능이다. 아래는 이력 보존용으로만 남긴다.

### 상태 분류 (SecureBERT, test n=2,117) — **v2, 무효**

| 지표 | 값 |
|---|---|
| **Macro F1** | **0.904** |
| Calibration ECE | 0.013 (우수) |
| UNDER_INVESTIGATION 전환율 | 43.7% |
| **잘못된 LIKELY_NOT_AFFECTED** | **0건** ✅ |

| 클래스 | P | R | F1 | n |
|---|---|---|---|---|
| LIKELY_AFFECTED | 0.944 | 0.889 | 0.915 | 585 |
| LIKELY_NOT_AFFECTED | 0.919 | 0.900 | 0.910 | 653 |
| UNDER_INVESTIGATION | 0.864 | 0.910 | 0.886 | 879 |

Confusion (행=정답 [AFF, NOT, UNDER]):
```
AFF   [520,   0,  65]     <- AFFECTED 를 NOT_AFFECTED 로 오판: 0건
NOT   [  4, 588,  61]
UNDER [ 27,  52, 800]
```

**ICS 안전 핵심**: 실제로 영향받는 취약점을 "영향 없음"으로 잘못 판정한 사례 **0건**.
보수적 설계가 가장 위험한 오류를 차단함을 확인.

### 보수적 Decision Engine 효과
NOT→AFFECTED 오류를 4→1건으로 축소(경계 3건을 UNDER_INVESTIGATION으로 안전 이송), 오탐NA 0 유지.

### 근거(rationale) 추출
- Sufficiency drop: **-0.001** (선택 근거만으로 예측 유지 → 근거가 충분)
- Comprehensiveness drop: **0.592** (근거 제거 시 확신 급락 → 근거가 인과적으로 사용됨)
- 문장 P/R/F1/IoU: 1.000 *(합성 데이터에서 driver 문장이 결정적이라 자명 — 아래 한계 참조)*

### 비교
| 시스템 | Macro F1 |
|---|---|
| TF-IDF + LogReg baseline | 0.890 |
| **SecureBERT** | **0.904** |

10% 주석 노이즈로 이론적 천장이 ~0.90 → 결과가 그 근처에서 형성됨(비퇴화 확인).

### 설명가능 출력 예시 (`results/sample_vex/`)
```
CVE-2012-4704 (CODESYS Gateway) -> LIKELY_AFFECTED (0.93)
  근거: [CVE-2] 네트워크 메시지로 취약 루틴 도달  [ASSET-2] 원격 접근 가능
CVE-2012-4705 (CODESYS Gateway) -> UNDER_INVESTIGATION (0.95)
  근거: [CVE-2] 공격 전제조건이 확립되지 않음 -> 보수적 보류
```

---

## 5.5 2-모델 통합 (SecureBERT + CodeBERT)

README 설계의 코드 leg 를 실제 코드로 검증했다. OSS CVE 의 실제 취약/패치 코드를
NVD·OSV 참조의 GitHub FIX 커밋에서 수집(34 CVE, 68 스니펫)했다.

**CodeBERT 의 정직한 두 얼굴**

| 과제 | 결과 | 판정 |
|---|---|---|
| 추상적 취약성 분류 (미학습 CVE, GroupKFold) | 정확도 **0.50** (무작위 0.50) | **실패** — frozen CodeBERT 로는 "일반적 취약성"을 못 배움 |
| 레퍼런스 매칭 (변형된 배포코드 → 올바른 레퍼런스) | **0.971** (n=68) | **작동** — 의미 매칭은 표면 변형에 강건 |

**백포트 오탐 탐지 (코드 leg 의 실제 가치)**

버전은 취약하나 코드가 패치된(백포트) 케이스 16건 주입:

| | 맥락 단독 | +CodeBERT |
|---|---|---|
| 정확도 | 0.667 | **1.000** |
| 백포트 오탐 | 6건 | **0건** |
| 백포트 탐지 | — | **16/16** |

버전·맥락 매칭이 놓치는 백포트 오탐을 CodeBERT 레퍼런스 매칭이 전부 제거한다.

**근본 한계 — 코드 커버리지**

실제 코드는 OSS 34 CVE 에서만 확보되며, 그중 findings 에 존재하는 건 **tier A 356건(2.7%)** 뿐이다.
v3 는 이를 라우팅으로 못박았다:

| 경로 | 건수 | 담당 |
|---|---|---|
| `securebert->codebert->sllm` | 356 (2.7%) | 코드 대조 + 실행 검증으로 **확정 시도** |
| `securebert-only` | 12,649 (97.3%) | 맥락 leg 에서 **종결**, `UNDER_INVESTIGATION` + 2차 추정 |

즉 **두 모델 모두 사용되지만 담당이 다르다**: SecureBERT 가 소스 미확보 다수(97.3%)를 맡아
확정 대신 추정을 내고, CodeBERT/sLLM 은 소스가 있는 소수에서만 확정을 시도한다.

### 실행 검증 전량 확장 — 커버리지 상한

`tools/build_verify_specs.py` 가 tier A 132 CVE 전부에 검증 스펙을 생성하고 가능성을 분류한다.
`src/exec_verify_batch.py` 가 그 스펙을 순회하며 WSL + ASan 으로 취약/패치 대조 빌드를 수행한다
(기존 단일 CVE 하드코딩 `exec_verify_c.sh` 의 스케일 버전).

| 분류 | CVE | findings | 사유 |
|---|---|---|---|
| `verifiable-c` | 101 | 290 | WSL + ASan 대조 빌드 가능 |
| `blocked-proprietary` | 21 | 46 | CODESYS Runtime, Wind River IPnet, Treck TCP/IP, SQL Server |
| `blocked-scope` | 10 | 20 | 리눅스 커널, JVM 스택(Tomcat·log4j·Spring), .NET |

**356건 전량 검증은 원리상 불가능하다.** 상한이 290 findings(81.5%)이고
66 findings(18.5%)는 소스가 존재하지 않거나 단위 실행 검증의 범위를 벗어난다.

현재 배치 실행 결과:

| verdict | CVE |
|---|---|
| `EXPLOITABLE` | 1 (zlib CVE-2018-25032 → 5 findings 확정) |
| `NEEDS_TRIGGER` | 100 |
| `NOT_VERIFIABLE` | 31 |

ref 결정은 **픽스 커밋 차분**(`vuln = <commit>^`, `patched = <commit>`)을 1순위로 쓴다.
릴리스 태그 없이도 정확한 대조 쌍이 나오고, zlib 검증이 이 방식으로 재현됐다
(`AddressSanitizer: global-buffer-overflow`, 패치본 무증상).

남은 유일한 수작업은 **CVE별 트리거 작성**(`tools/triggers/<CVE>.c`)이다. 자동 생성이 불가능하며,
공개 PoC·패치 회귀테스트·파라미터 스윕에서 확보해야 한다. 트리거를 추가하면 코드 수정 없이
배치가 자동으로 집어 확정 계층으로 승격시킨다.

## 5.6 도메인 적응 (모델 튜닝)

프로토타입은 인코더 동결(frozen)이었다. 실전형 적응을 수행하고 라벨 무관 지표로 측정했다.

### SecureBERT ICS-DAPT (텍스트) — 명확히 통함 ✅

CISA 어드바이저리 52,061 문장으로 continued MLM (3 epochs):

| 지표 | vanilla | ICS-DAPT | 변화 |
|---|---|---|---|
| ICS 텍스트 perplexity | 4.01 | **2.23** | **−44.4%** |
| ICS 용어 복원 정확도 | 0.303 | **0.386** | +27% (n=145) |

epoch별 perplexity 4.01→2.44→2.31→2.23 (대부분 epoch 0에서, 이후 수익체감). ICS 도메인 적응이
텍스트 표현을 크게 개선함을 라벨과 무관하게 입증.

### CodeBERT 파인튜닝 (코드) — 일반 취약탐지는 학습, 미세과제는 전이 안 됨

Devign(CodeXGLUE, ~21k C 함수)으로 인코더 동결 해제 파인튜닝 (4 epochs, val 최적 체크포인트):

| 과제 | frozen | 파인튜닝 | 판정 |
|---|---|---|---|
| Devign 취약탐지 (test F1) | ~0.50 | **0.659** (acc 0.644) | 실제 취약탐지 **학습됨** (문헌 ~65% 수준) |
| 우리 vuln/patch 미세구분 | 0.50 | 0.457 | **전이 안 됨** (같은 함수 몇 줄 차이) |

**핵심**: Devign의 "함수가 취약한가"(거친 과제)는 파인튜닝으로 배웠으나(F1 0.66), 우리의 "같은 함수의
취약 vs 패치 변형 구분"(미세 과제)엔 전이되지 않았다. 따라서 백포트 탐지는 **분류가 아니라
레퍼런스 매칭(0.97, §5.5)**으로 해결하는 것이 옳다.

### 종합
- **SecureBERT**: ICS 도메인 적응이 표현을 개선(−44% ppl). 실제 배포 시 유효.
- **CodeBERT**: 일반 취약탐지 파인튜닝은 유효(0.66)하나, 미세 과제는 파인튜닝의 한계 → 레퍼런스 매칭 병행.

## 6. 한계 (정직한 명시)

1. **확정 판정이 0.04%뿐**: 실행 검증으로 확정된 건은 13,005 중 5건. 1차 VEX 진술의
   99.96%가 `UNDER_INVESTIGATION` 이다. 이는 결함이 아니라 확보한 증거의 정직한 반영이지만,
   실무 확정을 늘리는 유일한 경로는 실행 검증 CVE 수를 늘리는 것이다.
2. **학습 타깃은 확정값이 아니라 추정치**: 모델이 배우는 `label` 의 99.96%가 AV × 노출도로
   계산한 2차 추정이다. 따라서 성능 지표는 "VEX 판정 능력"이 아니라 **"산문에서 잠재 속성
   (AV·노출도)을 복원하는 능력"** 에 가깝다. 라벨이 속성의 결정론적 함수이고 속성이 문장으로
   완전히 렌더링되므로, 도달 가능한 정확도의 상한은 주석 노이즈율(10%)이 결정한다.
3. **버전 대조 불가**: SBOM 전 컴포넌트가 `NOASSERTION`. 실행 검증된 CVE 조차 해당 장비가
   취약본을 쓰는지 확인할 수 없어, ICS 안전 우선 원칙으로 취약본을 가정한다
   (`version_unconfirmed: true`). 버전 데이터가 확보되면 `adjudicate()` 가 patched 대조를 수행한다.
4. **합성 배치맥락**: 장비↔CVE↔CWE↔CVSS만 CISA 실데이터. 노출도는 합성(`exposure_synthetic: true`)이며,
   2차 추정이 이 값에 의존하므로 추정치의 절대 정확도는 검증 불가하다.
5. **실행 검증 대상의 구조적 제약**: `exploit_verifier.py` 는 안전 설계상 자체 완결형 라이브러리만
   다룬다. ICS CVE 대부분은 폐쇄 펌웨어라 원리상 이 경로에 오를 수 없고, 펌웨어에 번들된
   OSS 컴포넌트만이 후보다.
6. **AV=P 처리는 판단 유보 사항**: `TREAT_PHYSICAL_AS_UNREACHABLE`(기본 `True`)이 물리 접근
   CVE 102건을 도달 불가로 본다. 무인 변전소·원격 펌프장에서는 물리 접근이 현실적 위협이고
   표준 VEX 도 이를 자동 인정하지 않으므로, `False` 로 두어 `UNDER_INVESTIGATION` 에
   남기는 선택도 방어 가능하다.
7. **Rationale P/R=1.0은 자명**: driver 문장이 결정적으로 분리되기 때문. 의미 있는 충실도 신호는
   Comprehensiveness와 Sufficiency이다.
8. **SecureBERT ≈ baseline**: 템플릿 텍스트는 어휘적으로 분리 가능해 의미모델 이점이 작다.
   실제 CVE 산문에서 SecureBERT의 이점이 드러날 것으로 예상(향후 검증 대상).

---

## 7. 재현

```bash
python tools/fetch_cisa_advisories.py     # ~25분 (3,765건 크롤)
python tools/fetch_exploit_signals.py     # ~5분 (KEV·EPSS)
python src/build_reverse_sbom.py          # 수 초
python tools/collect_code_gh.py           # OSS 취약/패치 실코드 (gh 인증 필요)
python src/exploit_verifier.py            # 실행 검증 (Python 라이브러리)
wsl -e bash tools/exec_verify_c.sh        # 실행 검증 (C, AddressSanitizer)
python src/build_ground_truth.py          # 수 초 — 위 산출물로 증거 계층 결정
python src/train_eval_vex.py              # ~15초 (GPU)
python src/eval_two_model.py              # 코드 leg (tier A 356건)
```
캐시(`data/*.json`, `results/exec_verification*.json`)가 있으면 3단계 이후는 즉시 재현된다.
실행 검증을 건너뛰면 확정 계층이 비어 전 건이 `UNDER_INVESTIGATION` + 2차 추정이 된다.
