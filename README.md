# ICS-VEX — Explainable VEX for Industrial Control Systems

CISA ICS 어드바이저리에서 **역방향으로 구축한 SBOM 데이터셋** 위에서,
**SecureBERT(맥락) + CodeBERT(코드)** 기반 설명가능 VEX 판정 시스템을
학습·평가하는 엔드투엔드 파이프라인.

> **🔗 라이브 대시보드**: https://kakyung98.github.io/ics-vex-dashboard/
> SBOM을 올려 CVE·VEX를 즉석 분석 + 시스템 평가 결과 시각화 (브라우저 내 처리)

---

## 무엇인가

- **입력**: CycloneDX SBOM (ICS 자산의 소프트웨어 명세)
- **출력**: 컴포넌트별 CVE 식별 + 배치맥락 기반 VEX 판정(`영향 가능`/`비영향`/`조사 필요`) + 판정 근거 문장
- **두 모델의 역할 분담**:
  - **SecureBERT** — 보안/자산 텍스트(맥락·버전·노출) 분석. 폐쇄코드 다수(≈99.7%)의 판정 담당
  - **CodeBERT** — 코드 존재/패치 여부 확인. OSS 소수에서 **백포트 오탐 제거** 담당

## ⚠️ 데이터 성격 (정직한 고지)

- **진짜**: 장비↔CVE↔CWE↔CVSS 매핑은 CISA ICS-CERT 공식 (3,765 어드바이저리, 11,336 CVE), KEV·EPSS 실신호, OSS 취약/패치 실코드(34 CVE, GitHub 픽스 커밋)
- **합성**: 장비 주변 컴포넌트 인벤토리, 배치맥락, VEX 라벨(규칙 오라클 + 시뮬레이션 주석노이즈 10%)
- 평가 수치는 **실세계 정확도가 아니라** 파이프라인 정합성·학습가능성 검증. 상세 한계는 [`RESULTS.md`](RESULTS.md) 참조

## 파이프라인

| 단계 | 스크립트 | 산출물 |
|---|---|---|
| CISA 어드바이저리 수집 | `tools/fetch_cisa_advisories.py` | `data/cisa_advisories.json` |
| 악용신호(KEV·EPSS) | `tools/fetch_exploit_signals.py` | `data/exploit_signals.json` |
| 역방향 SBOM | `src/build_reverse_sbom.py` | `reverse_sbom/`, `data/findings.csv` |
| Ground Truth | `src/build_ground_truth.py` | `data/vex_dataset.jsonl` |
| SecureBERT 학습·평가 | `src/train_eval_vex.py` | `results/metrics.json` |
| **SecureBERT ICS 도메인 적응(DAPT)** | `src/train_securebert_dapt.py` | `models/ics-securebert/`, `results/dapt_metrics.json` |
| OSS 취약/패치 코드 수집 | `tools/collect_code_gh.py` | `data/code_evidence.json` |
| **CodeBERT 코드 leg 검증** | `src/train_codebert.py`, `src/eval_two_model.py` | `results/two_model_metrics.json` |
| **CodeBERT 취약탐지 파인튜닝** | `src/train_codebert_finetune.py` | `models/codebert-vuln/` |
| 대시보드 생성 | `tools/build_dashboard.py` | `index.html` |

## 주요 결과

### 상태 분류 (SecureBERT 맥락 leg, test n=2,117, device-disjoint)
| 지표 | 값 |
|---|---|
| Macro F1 | 0.904 |
| Calibration ECE | 0.013 |
| **영향→비영향 오판** (ICS 안전 핵심) | **0건** |
| TF-IDF baseline | 0.890 |

### CodeBERT 코드 leg (2-모델 통합)
| 항목 | 값 | 의미 |
|---|---|---|
| 추상적 취약성 분류 (frozen) | 0.50 | 무작위 — 정직한 음성 결과 |
| 레퍼런스 매칭 (변형 코드) | 0.971 | 작동 — 의미 매칭 |
| 백포트 오탐 (맥락단독 → +CodeBERT) | 6건 → **0건** | 버전매칭이 놓치는 걸 코드가 제거 |

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
python tools/collect_code_gh.py           # OSS 취약/패치 실코드 (gh 인증 필요)
python src/build_reverse_sbom.py
python src/build_ground_truth.py
python src/train_eval_vex.py              # SecureBERT 맥락 leg (GPU 권장)
python src/eval_two_model.py              # CodeBERT 코드 leg 통합
python src/train_securebert_dapt.py       # ICS 도메인 적응
python src/train_codebert_finetune.py     # CodeBERT 취약탐지 파인튜닝
python tools/build_dashboard.py           # 대시보드
```

## 한계

1. **Ground Truth 미검증** — 규칙 오라클 생성 silver standard. 사람 라벨/κ 검증 미실시
2. **합성 인벤토리** — 장비↔CVE↔CWE↔CVSS만 실데이터, 주변 구성은 합성
3. **CodeBERT 코드 커버리지** — 실코드는 OSS 34 CVE에서만. 폐쇄코드는 확인 불가
4. **추상 취약탐지 난제** — 파인튜닝해도 교차프로젝트 ~65~70%가 상한

## 데이터 출처 / 라이선스

- 코드: 연구·교육용 참조 구현
- CVE/CWE/CVSS: CISA ICS-CERT (공개), NVD, FIRST EPSS, CISA KEV
- OSS 취약/패치 코드: 각 프로젝트 공개 저장소의 픽스 커밋
- 취약탐지 코퍼스: CodeXGLUE Defect Detection (Devign)
- 합성 SBOM: 본 저장소에서 생성 (실제 제품 구성 아님)
