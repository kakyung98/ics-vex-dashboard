# Test Item #3 — ground-truth and evaluation audit (first pass)

Nothing in the pipeline was changed. This reports what the code and the real data
say, following the review memo's rule: **separate a confirmed defect from a
hypothesis that still needs measuring, and do not inflate the 0.9490.**

Reproduce: `python tools/audit_cpe_match_gt.py` -> `results/audit_cpe_match_gt.json`.
Coverage figures are read from `results/cpe_match_precision.json` (the last scored run).

---

## A. Confirmed defects (code + data)

### A1. GT product identity is `entries[0]`, labelled `product_match=True` without a product comparison (memo problem 1)

`tools/build_cpe_match_gt.anchored_cpes()` collects every NVD CPE whose **vendor**
matches the component's publisher by substring (`pub in nv or nv in pub`) — no
product comparison. `to_gt()` then takes `rec["entries"][0]` as *the* product and
writes `"product_match": True` unconditionally.

Measured impact (re-deriving the anchored sets over all of `reverse_sbom/`):

| | pairs | share |
|---|---:|---:|
| Layer-A pairs re-derived | 32,669 | 100% |
| anchored set has **1** product (entries[0] unambiguous) | 9,636 | **29.5%** |
| anchored set has **>1** product (entries[0] is an arbitrary same-vendor pick) | **23,033** | **70.5%** |

Example — CVE-2011-3330, publisher *Schneider Electric*: the anchored set holds six
distinct products (`monitor_pro`, `opc_factory_server`, `pl7_pro`,
`telemecanique_driver_pack`, `unity_pro`, `vijeo_citect`); the GT recorded
`monitor_pro` purely because it was first. These are different products, not
spellings of one.

**Status: CONFIRMED.** In 70.5% of Layer-A pairs the GT's product field is not an
independently verified identity.

### A2. Vendor identity is substring matching, not canonical identity (memo problem 2)

`anchored_cpes` uses `pub in nv or nv in pub` after `norm()` strips case and
punctuation. There is no alias/subsidiary/OEM map. Two different vendors whose
normalised names nest (substring) would match; one real vendor with two very
different names would not. **Status: CONFIRMED as written; FP/FN magnitude from
this is not yet measured (hypothesis).**

### A3. Layer A/B is a vendor-match split, not a verified product/embedded relationship (memo problem 3)

A pair is Layer A iff `anchored_cpes` returns a non-empty set, i.e. iff some NVD
CPE for the CVE carries the component's vendor. It is Layer B otherwise. Neither
branch verifies that the ICS product *is* the NVD product (A) or that the ICS
product actually *embeds* the third-party component (B). So "Layer B = embedded
third-party" and "Layer A = the product's CPE is confirmed" are both stronger
claims than the code establishes. **Status: CONFIRMED (classification is
vendor-presence, labelled as if it were product/embedded).**

---

## B. The number 0.9490 — what it actually covers (memo problems 5, 14)

From the last scored run (`results/cpe_match_precision.json`):

| quantity | value |
|---|---:|
| precision | **0.9490** (TP 10,653 / FP 572) |
| **scored** (TP + FP) | **11,225** |
| unlabelled predictions (no GT for that component's CVE) | 134,641 |
| unadjudicable (CISA/NVD name different layers; held out) | 28,105 |
| **labelled share** | **6.45%** |

So 0.9490 is a **conditional precision over 6.45% of predictions** — lower than the
memo's quoted 8.8%. It cannot be read as the system's overall identification
precision. **Status: CONFIRMED.** The figure should always be quoted as
*conditional precision on the GT-adjudicable slice*, with the 6.45% coverage beside
it.

---

## C. What moderates A1 — the scoring does not use the GT product naively

This is essential to not overstating A1's effect on 0.9490.

`tools/eval_cpe_match_precision.load_gt` accumulates `correct_products` as a **set,
unioned across all of a component's CVEs**, and the TP/FP gate is
`product_ok = any(same_product(pred, p) for p in correct_products)`. A prediction
the name supports but that is unlabelled becomes **unadjudicable**, not FP
(`name_supports`). So a single arbitrary `entries[0]` rarely flips one pair's
verdict on its own.

But the direction of the residual risk is specific: because `correct_products` is a
**union of same-vendor products**, it is lenient — a prediction that is the *wrong*
product for this component can still pass `product_ok` if it happens to be some
other CVE's `entries[0]` pick for the same component. That would **inflate** TP.

**Status: the mitigation is CONFIRMED (in the code); the residual inflation is a
HYPOTHESIS whose magnitude is not yet measured.** Measuring it needs a per-pair
join of the SUT prediction against an independently verified product identity,
which the GT does not currently carry (that is A1).

---

## D. Not yet measured (open, from the memo)

Honestly flagged as not done in this pass, not as findings:

- Problem 4 / 13: Layer-B ∩ unadjudicable-34% intersection at record level
  (`cpe_match_eval_layerB.jsonl` × prediction log on a stable key), and whether any
  Layer-B component is actually present in its SBOM.
- Problem 15: whether the SUT identifies CVEs absent from CISA (it searches the NVD
  index, so structurally yes; the GT, being CISA-sourced, cannot score those).
- Problem 16: selection bias — are the 6.45% adjudicable predictions easier
  (model-number/CPE present) than the 93.55% unadjudicable? Needs a stratified
  sample with Correct / Incorrect / Insufficient-evidence labels and a confidence
  interval.
- Problems 8-11: SUT execution path (is the retrieval encoder actually loaded; PURL
  parsing; family/model/firmware; `cmp_ver` vendor schemes) — partially known
  (purl is deliberately excluded; retrieval is the default SUT), but not fully
  traced here.

---

## E. The headline, stated honestly

1. **0.9490 is a conditional precision on 6.45% of predictions.** Confirmed. Quote
   it that way, with coverage.
2. **The GT's product identity is unverified in 70.5% of Layer-A pairs** (arbitrary
   `entries[0]` among same-vendor products). Confirmed defect.
3. **The scorer's union-of-products gate blunts, but does not remove, A1's effect**,
   and the residual risk is *inflation* of TP, not deflation. The magnitude is
   unmeasured.

The right next step the memo asks for is a GT remedy that verifies product identity
independently (or holds the ambiguous pairs out as `ambiguous`), then a re-score —
accepting that a correct GT may move 0.9490 in *either* direction, which is a gain
in validity, not a regression.

---

## F. Remedy applied — multi-product pairs held out, re-scored

The remedy from E, implemented. A Layer-A record whose vendor anchors **>1 distinct
NVD product** is flagged `_ambiguous_product` in `build_cpe_match_gt.to_gt`
(`evidence.product_match` is then `false`, since vendor agreement does not fix the
product), and the scorer holds those records out exactly like a `conflict`: they are
never scored and never seed `correct_products`, so `entries[0]`'s guess cannot leak
back in. `applicable` stays `True` — CISA really does assert the (component, CVE); only
the product *key* is unadjudicated.

Reproduce: `build_cpe_match_gt.py --per-vendor 0 --out data/cpe_match_eval_ambig.jsonl`
then `eval_cpe_match_precision.py --data data/cpe_match_eval_ambig.jsonl`.

| | certified GT | ambiguous held out |
|---|---:|---:|
| precision | **0.9490** | **0.9909** |
| TP / FP | 10,653 / 572 | 3,387 / 31 |
| scored | 11,225 | 3,418 |
| ambiguous held out | 0 | 25,116 |
| labelled share | 6.45% | 7.77% |

**Backward-compatible:** the certified `data/cpe_match_eval.jsonl` (no `_ambiguous_product`
field) still re-scores to exactly **0.9490**, so the code change does not touch the
submitted figure — only the new, flagged GT behaves differently.

**Reading the move — it went UP, and why that is the honest direction.** Holding out the
25,116 unverified-product positives removes a slice that was scoring ~0.931 (7,266 TP /
541 FP of the held-out predictions), leaving the verified-single-product slice at 0.9909.
So the 0.9490 blend was being *deflated*, not inflated: the certified scorer charged the
SUT product-axis FPs on components where the GT's own product key was an arbitrary
`entries[0]` pick, so the SUT resolving to a *different* same-vendor product looked wrong
against an answer key that was itself unverified. (The audit's section-C inflation
hypothesis concerned TP; empirically the FP-deflation effect dominated — both can hold.)

**What 0.9909 is, stated honestly.** It is precision over the slice where the GT's product
identity is independently establishable (the vendor anchors exactly one NVD product):
3,418 scored of ~44k predictions. It is a *cleaner* number on a *smaller* base, not a
higher score on the same base. The 25,116 held-out pairs are genuinely unadjudicable from
CISA + NVD vendor-matching alone; closing them would need a third authority fixing which
product each CVE is filed against. This is the validity gain the memo asked for — the
figure moved because the measurement got more honest, not because the SUT changed.
