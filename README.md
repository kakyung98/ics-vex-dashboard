# ICS-VEX — Explainable VEX for Industrial Control Systems

CISA ICS 어드바이저리에서 역방향으로 구축한 SBOM 데이터셋 위에서,
SecureBERT/CodeBERT 기반 **설명가능 VEX(Vulnerability Exploitability eXchange) 판정 시스템**을
학습·평가하는 엔드투엔드 파이프라인.

> **🔗 라이브 대시보드**: https://USERNAME.github.io/ics-vex-dashboard/
> *(GitHub Pages 활성화 후 위 URL로 접속. `USERNAME`은 실제 계정으로 대체됨)*

## 무엇인가

- **입력**: CycloneDX SBOM (산업제어시스템 자산의 소프트웨어 명세)
- **출력**: 컴포넌트별 CVE 식별 + 배치맥락 기반 VEX 판정(`영향 가능`/`비영향`/`조사 필요`) + 판정 근거
- **대시보드**: 브라우저에서 SBOM을 올려 즉석 분석 + 시스템 평가 결과 시각화 (`index.html`, self-contained)

## ⚠️ 데이터 성격 (정직한 고지)

- **진짜**: 장비↔CVE↔CWE↔CVSS 매핑은 CISA ICS-CERT 공식 데이터 (3,765 어드바이저리, 11,336 CVE), KEV·EPSS 실신호
- **합성**: 장비 주변 컴포넌트 인벤토리, 배치맥락, VEX 라벨(규칙 오라클 + 시뮬레이션 주석노이즈)
- 평가 수치(Macro F1 0.904 등)는 **실세계 정확도가 아니라** 파이프라인 정합성·학습가능성 검증
- 실제 자산 인벤토리나 벤더 공식 SBOM으로 사용/오인 금지. 자세한 한계는 [`RESULTS.md`](RESULTS.md) 6절 참조

## 파이프라인

| 단계 | 스크립트 | 산출물 |
|---|---|---|
| CISA 어드바이저리 수집 | `tools/fetch_cisa_advisories.py` | `data/cisa_advisories.json` |
| 악용신호(KEV·EPSS) | `tools/fetch_exploit_signals.py` | `data/exploit_signals.json` |
| 역방향 SBOM | `src/build_reverse_sbom.py` | `reverse_sbom/`, `data/findings.csv` |
| Ground Truth | `src/build_ground_truth.py` | `data/vex_dataset.jsonl` |
| 학습·평가 | `src/train_eval_vex.py` | `results/metrics.json`, `results/report.md` |
| 대시보드 생성 | `tools/build_dashboard.py` | `index.html` |

## 재현

```bash
pip install torch transformers scikit-learn numpy pypdf openpyxl
python tools/fetch_cisa_advisories.py     # ~25분
python tools/fetch_exploit_signals.py     # ~5분
python src/build_reverse_sbom.py
python src/build_ground_truth.py
python src/train_eval_vex.py              # GPU 권장
python tools/build_dashboard.py
```

## 주요 결과

| 지표 | 값 |
|---|---|
| Macro F1 (SecureBERT) | 0.904 |
| Calibration ECE | 0.013 |
| **영향→비영향 오판** (ICS 안전 핵심) | **0건** |
| TF-IDF baseline | 0.890 |

## 라이선스 / 데이터 출처

- 코드: 연구·교육용 참조 구현
- CVE/CWE/CVSS: CISA ICS-CERT (공개), NVD, FIRST EPSS, CISA KEV
- 합성 SBOM: 본 저장소에서 생성 (실제 제품 구성 아님)
