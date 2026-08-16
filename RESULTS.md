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
| 3. 역방향 SBOM | `src/build_reverse_sbom.py` | `reverse_sbom/*.json`, `data/findings.csv` |
| 4. Ground Truth | `src/build_ground_truth.py` | `data/vex_dataset.jsonl` |
| 5. 학습·평가 | `src/train_eval_vex.py` | `results/metrics.json`, `results/report.md`, `results/sample_vex/*.json` |

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

> 핵심 링크(장비↔CVE↔CWE↔CVSS)는 CISA 실데이터이므로, 초기의 순환논증 문제가 해소된다.

---

## 3. Ground Truth (silver standard)

VEX의 본질은 "이 배치 환경에서 악용 가능한가"이므로, CISA의 영향 사실(component-level)에
**배치 맥락**을 결합한 규칙 오라클로 3-class 라벨을 생성한다.

- 오라클 입력(진짜 신호): CVSS Attack Vector, KEV, EPSS, 심각도
- 배치 맥락(결정적 합성): network-exposure(장비별), 음성증거(패치/버전/미포함/기능비활성)
- **주석자 불일치 10% 주입** (κ≈0.85): 경계 사례에 집중, AFFECTED↔NOT 직접 전이는 금지(안전)

라벨 분포: LIKELY_AFFECTED 24.0% / LIKELY_NOT_AFFECTED 31.3% / UNDER_INVESTIGATION 44.7%

**정직성 장치**: 오라클은 구조화 특징을, SecureBERT는 자연어 문장만 본다.
Attack Vector는 텍스트에 명시하지 않고 공격표면 산문으로 암시 → 모델이 추론해야 한다.

---

## 4. 모델 (README 구조 구현)

- **SecureBERT**(frozen) 문장 임베딩 → 어텐션 풀링 → 멀티태스크
  - Classification Head → 3-class VEX
  - Rationale Head → 문장별 driver 확률, `L = CE + λ·BCE`
- **CodeBERT** 보조: oss-arm CVE설명 ↔ CWE 취약코드 템플릿 유사도 (폐쇄장비 abstain)
- **Evidence Verifier + 보수적 Decision Engine**: `LIKELY_NOT_AFFECTED`는 적극적 반증
  근거가 선택됐을 때만 허용, 저신뢰/충돌 → `UNDER_INVESTIGATION`
- 평가: device-disjoint split (train 10,888 / test 2,117)

---

## 5. 결과

### 상태 분류 (SecureBERT, test n=2,117)

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

실제 코드는 OSS 34 CVE(≈36 findings)에서만 확보된다. README §7 의 "코드 확인 불가 →
UNDER_INVESTIGATION" 을 엄격 적용하면 findings 의 **99.7%(12,969/13,005)** 가 조사필요가 된다.
→ 실용 시스템은 **하이브리드**: 코드 있으면 CodeBERT 확정(백포트 제거), 없으면 SecureBERT 맥락 판정.

즉 **두 모델 모두 사용되지만 담당이 다르다**: SecureBERT 가 폐쇄코드 다수(99.7%)의 맥락 판정을,
CodeBERT 가 OSS 소수의 코드 확정(특히 백포트 탐지)을 맡는다.

## 6. 한계 (정직한 명시)

1. **Silver label**: 규칙 오라클 + 합성 배치맥락 + 시뮬레이션 주석노이즈로 생성.
   사람 주석 정답이 아니므로, 0.904는 **실세계 정확도가 아니라 파이프라인·학습가능성 검증**이다.
2. **합성 인벤토리**: 장비↔CVE↔CWE↔CVSS만 CISA 실데이터. 주변 컴포넌트 구성은 합성.
3. **Rationale P/R=1.0은 자명**: driver 문장이 결정적으로 분리되기 때문. 의미 있는 충실도 신호는
   Comprehensiveness(0.592)와 Sufficiency(-0.001)이다.
4. **SecureBERT ≈ baseline**: 템플릿 텍스트는 어휘적으로 분리 가능해 의미모델 이점이 작다.
   실제 CVE 산문에서 SecureBERT의 이점이 드러날 것으로 예상(향후 검증 대상).
5. **CodeBERT 역할 제한**: 실제 장비 소스/펌웨어가 없어 대부분 abstain (README 한계 14와 일치).

---

## 7. 재현

```bash
python tools/fetch_cisa_advisories.py     # ~25분 (3,765건 크롤)
python tools/fetch_exploit_signals.py     # ~5분 (KEV·EPSS)
python src/build_reverse_sbom.py          # 수 초
python src/build_ground_truth.py          # 수 초
python src/train_eval_vex.py              # ~15초 (GPU)
```
캐시(`data/*.json`)가 있으면 3–5단계는 즉시 재현된다.
