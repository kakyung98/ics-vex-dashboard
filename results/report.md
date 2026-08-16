# ICS VEX 시스템 평가 리포트

SecureBERT(문장-어텐션 멀티태스크) + 보수적 Decision Engine. device-disjoint split.

## 데이터셋
- 총 13005 findings | train 10888 | test 2117
- test 라벨 분포: LIKELY_AFFECTED=585, LIKELY_NOT_AFFECTED=653, UNDER_INVESTIGATION=879

## SecureBERT 원분류
- Macro F1: **0.904**
- UNDER_INVESTIGATION 전환율: 43.7%
- 잘못된 LIKELY_NOT_AFFECTED: 0건 (해당예측중 0.0%)
- per-class:
  - LIKELY_AFFECTED        P=0.944 R=0.889 F1=0.915 (n=585)
  - LIKELY_NOT_AFFECTED    P=0.919 R=0.900 F1=0.910 (n=653)
  - UNDER_INVESTIGATION    P=0.864 R=0.910 F1=0.886 (n=879)
- confusion (rows=true LIKELY_AFFECTED,LIKELY_NOT_AFFECTED,UNDER_INVESTIGATION):
  - [520, 0, 65]
  - [4, 588, 61]
  - [27, 52, 800]

## 보수적 Decision Engine 적용
- Macro F1: **0.904**
- UNDER_INVESTIGATION 전환율: 43.9%
- 잘못된 LIKELY_NOT_AFFECTED: 0건 (해당예측중 0.0%)
- per-class:
  - LIKELY_AFFECTED        P=0.949 R=0.889 F1=0.918 (n=585)
  - LIKELY_NOT_AFFECTED    P=0.919 R=0.900 F1=0.910 (n=653)
  - UNDER_INVESTIGATION    P=0.861 R=0.910 F1=0.885 (n=879)
- confusion (rows=true LIKELY_AFFECTED,LIKELY_NOT_AFFECTED,UNDER_INVESTIGATION):
  - [520, 0, 65]
  - [1, 588, 64]
  - [27, 52, 800]

## 근거(rationale) 추출
- 문장 P/R/F1: 1.000 / 1.000 / 1.000 | IoU 1.000
- Sufficiency drop: -0.001 (작을수록 좋음) | Comprehensiveness drop: 0.592 (클수록 좋음)

## 비교
- TF-IDF+LogReg baseline Macro F1: 0.890
- SecureBERT Macro F1: 0.904
- SecureBERT calibration ECE: 0.013

- 실행: cuda, 36s
