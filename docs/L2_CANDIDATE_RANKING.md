> Superseded on 2026-11-04: the current application uses deterministic analysis. Only final VEX explanation writing uses an LLM. The design below is historical.

# L2 candidate ranking

Contract: `l2-candidate-ranking/1`. One base Qwen3-8B ranks dictionary candidate
IDs; the previous name-generation L2 adapter is not executed in unified mode.
L3 and L4 keep their saved contracts. Legacy comparison modes are unchanged.

1. Preserve original name and model observations with source offsets. Exclude
   recognized version spans and `vers:` expressions; strip the descriptive
   `Vendor Firmware/Application` suffix from the search form only.
2. Retrieve dictionary candidates from original CPE/PURL/manufacturer/name evidence.
3. Mark candidates whose dictionary product/title does not corroborate the
   model letters/digits. Only a reviewed, vendor-scoped alias can justify such
   a change. Separator spelling is allowed; `APE1808` and `APEX1808` differ.
4. Rank supplied IDs with constrained JSON; reject invented IDs, unsupported
   evidence references, free-name outputs and conflicting candidate selections.
5. Keep all original candidates and conflicts. Ranking cannot establish product
   identity or discard competitors. L4 still applies original-evidence gates.

The web result shows preserved observations, per-candidate model conflicts and
the new untrained contract. An L2 failure retains original retrieval evidence.
This change does not filter the 264 product-family CISA CVE candidates by an
unknown installed version. That is separate applicability work.

## Training and evaluation

`tools/build_l2_ranking_data.py` creates 4,096 training, 1,024 validation and
1,024 test examples under `data/l2_candidate_ranking_v1/l2-candidates`.
This is the previous experiment's comparison budget, not a sample-size optimum.
Source: the fingerprinted local CPE dictionary. Targets are procedural
dictionary/conflict-rule references, not independent expert annotations.

Split before generating cases: vendor/product families with obvious
firmware/software suffixes removed. Positive and negative candidates stay in
one split. Unknown brand aliases may still need independent leakage review.
Controlled four-candidate pools do not measure full-dictionary retrieval recall.
The dataset audit checks candidate-family overlap and valid reference outputs.

`tools/run_l2_training.py` serializes a one-epoch QLoRA pilot with GPU admission,
rank 8, batch 1, accumulation 8 and 1,536-token maximum input/completion length.
The trainer selects checkpoints using validation loss, then compares base/tuned
generation on validation and the held-out test. The test is not used for
training/checkpoint selection. No automatic deployment follows training.

Reports: `results/l2_candidate_finetune_v1`. Metrics include grounded-output
validity, top-1 reference agreement, exact ranking agreement and abstentions.
These are synthetic agreement metrics, not real-SBOM semantic accuracy.
Independent product-level retrieval Recall@K, false acceptance, coverage,
model-identifier error rate and latency must be evaluated on reviewed cases.
