# ICS VEX system evaluation report

SecureBERT (sentence-attention multitask) plus a conservative decision engine, on a
device-disjoint split.

> **These figures rest on the retired estimate labels.** See RESULTS.md §8: the training
> target was a deterministic function of latent attributes (AV x synthetic exposure), so
> what was measured here is the ability to recover those attributes from prose, not VEX
> adjudication. Kept as a record of the experiment.

## Dataset
- 13,005 findings in total | train 10,888 | test 2,117
- test label distribution: LIKELY_AFFECTED=585, LIKELY_NOT_AFFECTED=653, UNDER_INVESTIGATION=879

## SecureBERT, raw classification
- Macro F1: **0.904**
- converted to UNDER_INVESTIGATION: 43.7%
- wrong LIKELY_NOT_AFFECTED: 0 (0.0% of those predictions)
- per class:
  - LIKELY_AFFECTED        P=0.944 R=0.889 F1=0.915 (n=585)
  - LIKELY_NOT_AFFECTED    P=0.919 R=0.900 F1=0.910 (n=653)
  - UNDER_INVESTIGATION    P=0.864 R=0.910 F1=0.886 (n=879)
- confusion (rows = true LIKELY_AFFECTED, LIKELY_NOT_AFFECTED, UNDER_INVESTIGATION):
  - [520, 0, 65]
  - [4, 588, 61]
  - [27, 52, 800]

## With the conservative decision engine
- Macro F1: **0.904**
- converted to UNDER_INVESTIGATION: 43.9%
- wrong LIKELY_NOT_AFFECTED: 0 (0.0% of those predictions)
- per class:
  - LIKELY_AFFECTED        P=0.949 R=0.889 F1=0.918 (n=585)
  - LIKELY_NOT_AFFECTED    P=0.919 R=0.900 F1=0.910 (n=653)
  - UNDER_INVESTIGATION    P=0.861 R=0.910 F1=0.885 (n=879)
- confusion (rows = true LIKELY_AFFECTED, LIKELY_NOT_AFFECTED, UNDER_INVESTIGATION):
  - [520, 0, 65]
  - [1, 588, 64]
  - [27, 52, 800]

## Rationale extraction
- sentence P/R/F1: 1.000 / 1.000 / 1.000 | IoU 1.000
- sufficiency drop: -0.001 (lower is better) | comprehensiveness drop: 0.592 (higher is better)

## Comparison
- TF-IDF + LogReg baseline Macro F1: 0.890
- SecureBERT Macro F1: 0.904
- SecureBERT calibration ECE: 0.013

- run: cuda, 36s
