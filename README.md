# ICS-VEX — Explainable VEX for Industrial Control Systems

An end-to-end pipeline that takes an **SBOM of an ICS/OT asset** and produces a
**VEX judgment** (`affected` / `not_affected` / `under_investigation`) with a
**CISA justification** and a rationale — grounded in code and build evidence,
never in synthetic deployment context.

> **Dashboard (ICS-VEXForge)** — run it locally with `python src/api_server.py
> --port 8100`, then open http://127.0.0.1:8100/. Paste/upload an SBOM to get
> per-component CVE + VEX analysis, browse the corpus, and export OpenVEX /
> CSAF 2.0 documents — all in the browser. (This repository is private, so the
> GitHub Pages site is not published.)

---

## Why this exists — public ICS VEX is essentially absent

We confirmed the motivation by a **full survey**, not a guess. Parsing every OT
advisory in CISA's official CSAF repository ([cisagov/CSAF](https://github.com/cisagov/CSAF), 3,984 files):

| Item | Count | Share |
|---|---|---|
| `document.category == "csaf_vex"` (OT) | **0** | 0% |
| `vulnerabilities[].flags[]` (a CISA justification) | **12** | 0.31% |
| `known_not_affected` | 25 | 0.64% |
| `known_affected` | 3,890 | 99.9% |

The 12 advisories that carry a justification are **all ICSA** (11 Siemens, 1 Mobotix),
and every label they use is a **code/build** justification:

```
component_not_present                              10
vulnerable_code_not_in_execute_path                 5
vulnerable_code_not_present                         4
vulnerable_code_cannot_be_controlled_by_adversary    0   <- environment-based
inline_mitigations_already_exist                     0   <- environment-based
```

So the entire public ICS ecosystem grounds `not_affected` in **source/build facts,
never deployment context**. This project fills that gap on the asset-owner side.

### When did `flags` first appear (commit-history trace)

| Date | Event |
|---|---|
| 2023-09-07 | cisagov/CSAF repository created |
| **2024-08-22** | first OT `flags` — `icsa-24-235-03` (Mobotix), at publication |
| 2024-11-27 | first IT `csaf_vex` profile document |
| **2025-06-12** | back-fill of `flags` onto older advisories |
| 2026-02 onward | `flags` shipped with new advisories routinely |

No OT advisory from 2010–2023 (2,155 of them) carries `flags`. Adoption by year:
2024 = 0.7%, 2025 = 0.8%, 2026 = 1.4%.

---

## What it is

- **Axis: the ICS-CERT advisory (ICSA).** CISA publishes one CSAF document per
  ICSA, so we key our reverse-built SBOMs the same way, making our output
  comparable to `cisagov/CSAF` file-for-file.
- **Input:** a CycloneDX SBOM of an ICS asset.
- **Output:** per-component CVE identification + a VEX judgment with a CISA
  justification and rationale + exportable OpenVEX / CSAF documents.

```
ICSA advisory  ->  reverse-built SBOM (reverse_sbom/<icsa-id>_SBOM-CVE.json)  ->  VEX document
```

| Axis | Count | Meaning |
|---|---|---|
| ICSA advisories collected | **3,767** | 2010–2026, complete |
| → SBOMs built (advisories with CVEs) | **3,695** | one VEX document each |
| ICSA × CVE = statements | **13,025** | the judgment unit (1:1 with a VEX statement) |
| unique CVEs | **11,336** | vulnerability population |

A VEX statement is **product × vulnerability × status**, so the judgment unit is
the **statement**, never a bare CVE. Statements per advisory: median 1, max 490.
CVE-level worst-case aggregation is deliberately dropped — the same CVE can be
`affected` on one product and `not_affected` on another, which is the reason VEX
exists.

---

## The evidence ladder — what sets a status

Status is decided by evidence only, in a fixed order of strength. If no gate
passes, the status is `under_investigation`.

| Tier | Condition | Status |
|---|---|---|
| `upstream-asserted` | vendor/CISA already published a `flags` justification | adopt verbatim (provenance recorded) |
| `sbom-evidenced` | the affected component/model is absent from this SBOM | `not_affected` + `component_not_present` |
| `execution-verified` | vulnerable version rebuilt, a reproducer run, trigger observed | `affected` (or `fixed`/`not_affected` if the trigger disappears on the patched build) |
| `under-investigation` | none of the above | `under_investigation` |

**Deployment context (network position, exposure) never sets status.** No CISA
justification accepts it, and a verdict that rests on topology turns false the
moment the topology changes. Operational context enters only as an **SSVC
priority**, whose System Exposure is a value the user chooses for a real
deployment — not a synthetic number.

### The VEX-justification direction (current work)

We are moving the judgment core from a single "did it trigger?" axis to the four
CISA justification questions, answered in order:

```
Q1 vulnerable code present?      -> component_not_present / vulnerable_code_not_present
Q2 on an executed path?          -> vulnerable_code_not_in_execute_path
Q3 adversary-controllable?       -> vulnerable_code_cannot_be_controlled_by_adversary
Q4 inline mitigation present?    -> inline_mitigations_already_exist
(all pass)                       -> affected
```

An exploit PoC is the *strongest* evidence for Q2/Q3, but not the only one:
Q1 is answered from the SBOM and the fix commit, Q2/Q3 can be judged by reasoning
over the patch diff and the surrounding code, Q4 by configuration/pattern checks.
The seed dataset for this classifier is built by
`tools/build_justification_seed.py` from `data/code_evidence.json` (34 vuln/patched
code pairs). The 18 CISA-labelled ICSA justifications (`data/vex_justify_eval.jsonl`)
are kept only as a **reference list of the real published labels**, not as a scored
benchmark — see the note below on why they cannot serve as ground truth.

#### Fine-tuned judge — baseline results

To learn Q1 at scale, the seed is enlarged into a 23,538-row, class-balanced
C/C++ VEX-judgment corpus (`tools/build_vexc_dataset.py`, from DiverseVul,
PrimeVul, CVEfixes-C, BigVul, and the project seed; published as the
[`vexc-instruct`](https://github.com/kakyung98/vexc-instruct) dataset) and a
**Qwen2.5-Coder-7B-Instruct** model is QLoRA fine-tuned on it
(`tools/train_vex_justifier.py`; r=16, α=32, 1 epoch, 12k subsample). It is
evaluated greedily by `tools/eval_vex_justifier.py` on a **held-out split** —
rows the trainer never saw, separated with the training shuffle seed so there is
no leakage:

| Metric (held-out test, n=800, never trained) | Score |
|---|---|
| `affected` F1 | 0.888 |
| `not_affected` F1 | 0.897 |
| **macro-F1 / accuracy** | **0.892 / 0.892** |

This is the one honest performance number: the input is real code and the labels
are backed by the fix commit. It says the corpus teaches **Q1 (is the vulnerable
construct present?)** well. It does **not** claim Q2/Q3 — those need whole-program
context the function-level data lacks, which is why reachability goes to program
analysis (`tools/callgraph_reach.py`) and a fuzzing track, not the model alone.

> **Why there is no "CISA-gold accuracy" here.** The 18 published ICSA flags are
> **vendor assertions about proprietary product builds**, not verified facts, and
> the corresponding product source is not obtainable. A code judge cannot be
> scored against them: with no source to feed, the model only emits its default
> lean, so any such number measures nothing. They define the label vocabulary and
> motivate the task — they are not a test set.

#### Applying the judge to the ICS target population — negative result

The held-out F1 above is measured on the training corpus's own distribution. To
see what the judge does on *our* population, `tools/build_ics_groundtruth.py`
assembles the **34 CVEs** that have full vuln/patched functions in
`data/code_evidence.json` into `data/ics_gt_pairs.jsonl`.
`tools/judge_ics_cves.py` then runs the fine-tuned judge over both sides of each
pair (gold: vulnerable → `affected`, patched → `not_affected`) and joins the static
Q2 verdict from `results/callgraph_reach.json`.

The result (`results/ics_cve_judgments.json`) is a **collapse to `affected`**:

| ICS pairs, n=34 CVEs / 68 examples | Value |
|---|---|
| vulnerable side | TP 34, FN 0 |
| patched side | TN 0, FP 34 |
| `affected` recall / precision | 1.000 / 0.500 |
| **macro-F1** | **0.333** (vs 0.892 held-out) |

The judge answers `affected` for every input, so it never separates the patched
build from the vulnerable one on this data. The cause is **not** input truncation
(these functions are short — median 437 chars, none clipped) and **not** identical
pairs (all 34 differ). It is an unexplained distribution gap between the
patch-pair corpus the judge was trained on and these ICS pairs, and it is the
honest counterweight to the 0.892: **the held-out number does not transfer to the
target population as-is.** It also cannot be read as a clean test — these ICS CVEs
overlap the training corpus, so a working judge would score *optimistically* here,
not at chance.

Q2 coverage from the static call graph on the same rows: 8 `reachable`,
5 `target-not-found`, 21 with no entry. The 2 execution-verified CVEs carry no
code pair and are outside this table.

---

## The only public ICS VEX flags — 12 advisories, 18 CVEs

Across CISA's entire OT CSAF corpus, a VEX **justification flag** appears in only
**12 advisories, covering 18 (ICSA × CVE) pairs** (all ICSA: 11 Siemens, 1
Mobotix). That is the whole public ground on which "not_affected" has ever been
declared for ICS.

These flags are **vendor assertions about proprietary product builds**, decided
with whole-program knowledge (compile flags, configuration, the vendor's own call
graph) that is not published — and the product firmware source is not obtainable.
So they are a **reference**, not verifiable ground truth, and not a scored
benchmark for a code-level judge (which sees a function, not the vendor's build).
`tools/collect_gt_icsa.py` pins these labelled originals into `data/gt_icsa/` for
inspection.

### What *is* independently derivable — product structure

One part of these advisories can be reproduced from public inputs: **product
structure**. `tools/inject_product_variants.py` lifts the CISA `product_tree` into
the SBOM so model variants exist as components (e.g. SIPROTEC 5: CP300 affected,
CP200 not). `tools/eval_variant_derivation.py` then derives `not_affected` from
what any asset owner reads off the advisory (the model list + `known_affected`),
while withholding the answer fields (`known_not_affected`, `flags`):

```
model level    TP 278 / FP 676 / FN 0    precision 0.291  recall 1.000
by-label       component_not_present 10/10   |   source-reachability labels 0/8
```

Recall is perfect: every model CISA declared not-affected is recovered, and the
`component_not_present` justification lands 10/10 — because it follows from the
product list alone. The two **source-reachability** labels
(`vulnerable_code_not_in_execute_path`, `vulnerable_code_not_present`) land 0/8:
they depend on the vendor's build internals, which public data cannot supply. The
false positives are models CISA never enumerated — with the answer withheld,
"not affected" and "not mentioned" are indistinguishable, the ceiling of the
public data, not a defect. This is the clean line of the whole project:
**product structure is derivable from public data; source-level reachability is
not, and the vendor's flag for it is an assertion we cannot verify.**

---

## Execution-verification campaign (source-available CVEs)

For CVEs whose source can be obtained, we run a containerized
build → exploit → verify pipeline with a **local model (Ollama, $0)** and Docker
sandboxing. All 106 source-available CVEs were run (the 88 that built plus an
18-CVE expansion of prior build failures and never-attempted CVEs).

```
execution-verified   2   a generated PoC actually reproduced the flaw
exploit-generated   20   critic-accepted PoC, execution not reproduced
build-only          70   vulnerable environment rebuilt, no working PoC
failed              14   build could not be reproduced
── 106 total
```

The two execution-verified CVEs are **CVE-2020-8177** and **CVE-2022-32221** (both
curl) — the first exploits this local harness produced that a run actually
triggered.

The gap between critic-accepted (22) and execution-verified (2) is the point: an
LLM critic waved through 20 PoCs that a real run could not reproduce, which is
why status rests on execution, not on the critic. Failure analysis shows the 20
misses are dominated by **memory-corruption** CWEs (UAF/OOB/overflow) whose
trigger produces no observable side effect without sanitizer instrumentation,
while both successes are logic-class bugs with a visible effect.

Every run's full log and agent conversation is kept under
`results/verify_evidence/<CVE>/`; `tools/extract_pocs.py` collects the generated
PoCs into `results/pocs/` (`INDEX.md`, `index.json`) with provenance headers, and
`tools/reclassify_outcomes.py` rebuilds the summary from the authoritative run
logs.

---

## Data honesty

- **Real:** device ↔ CVE ↔ CWE ↔ CVSS from CISA ICS-CERT (3,767 advisories,
  11,336 CVEs); KEV/EPSS signals; OSS vulnerable/patched code (34 CVEs, GitHub fix
  commits); the CISA CSAF `product_tree` / `product_status` used as ground truth.
- **Synthetic:** the component inventory around each device, and the
  `ics:network-exposure` attribute — the latter is **not used for status** (it
  feeds only the SSVC priority, and even there is flagged synthetic).
- **Removed:** the earlier AV × exposure reachability estimate and the 3-class
  training target it produced. That target was 99.8% synthetic, so it measured
  attribute-recovery from prose, not VEX judgment. Details in
  [`RESULTS.md`](RESULTS.md).
- Every SBOM component version is `NOASSERTION`, so version-range comparison is
  impossible; that fact itself is a rationale for `under_investigation`, and it is
  why `component_not_present` (no version needed) is the one justification that
  survives this corpus.

---

## Pipeline

| Step | Script | Output |
|---|---|---|
| 1. Collect advisories | `tools/fetch_cisa_advisories.py` | `data/cisa_advisories.json` |
| 2. Exploit signals | `tools/fetch_exploit_signals.py` | KEV/EPSS |
| 3. Pin ground truth | `tools/collect_gt_icsa.py` | `data/gt_icsa/` |
| 4. Reverse SBOMs | `src/build_reverse_sbom.py` | `reverse_sbom/*.json`, `data/findings.csv` |
| 5. Inject model variants | `tools/inject_product_variants.py` | `product_tree` variants in SBOMs |
| 6. Collect OSS code | `tools/collect_code_gh.py` | `data/code_evidence.json` |
| 7. Execution verify | `tools/run_verify_full.ps1`, `tools/exec_verify_c.sh` | `results/verify_full/*.json` |
| 8. Batch judgment | `src/vex_batch.py` | `results/vex_batch.jsonl` |
| 9. Ground truth | `src/build_ground_truth.py` | `data/vex_dataset.jsonl` |
| 10. Compare / evaluate | `tools/compare_cisa_csaf.py`, `tools/eval_variant_derivation.py` | console reports |
| 11. Justification seed | `tools/build_justification_seed.py` | `data/vex_justify_seed.jsonl`, `data/vex_justify_eval.jsonl` |
| 12. ICS ground-truth pairs | `tools/build_ics_groundtruth.py` | `data/ics_gt_pairs.jsonl` |
| 13. Judge the ICS population | `tools/judge_ics_cves.py` | `results/ics_cve_judgments.json` |
| 14. Build site | `tools/build_sbom_index.py`, `tools/build_site.py` | `*.html`, `*.json` |

Steps 3/6/7 must precede 8/9 (they set each statement's evidence tier). Step 14's
`build_sbom_index.py` is not run by `build_site.py`, so run it separately. Steps 12/13 need the fine-tuned adapter in
`models/vex-justifier-lora` and a GPU.

---

## Web console — ICS-VEXForge

Six pages. The live server (`src/api_server.py`) renders them on the fly; the static export (`tools/build_site.py`) writes the self-contained bundle to `site/` (`site/*.html` + `site/*.json` + `site/adv/`):

- **Analyzer** — SBOM → CVE + VEX, CPE normalization, SSVC priority, OpenVEX/CSAF export
- **VEX Analysis Method** — the evidence ladder as a diagram
- **ICS Advisories-based CVE Corpus** — the four axes + per-statement verdicts
- **Source Code Available CVEs** — the 106-CVE pool and the execution-verification card
- **ICS-CERT Advisories** — advisory + NVD search
- **Synthetic SBOM** — the reverse-built SBOM dataset

Run locally:

```bash
python src/api_server.py --port 8100
```

---

## Reproduce

```bash
python tools/fetch_cisa_advisories.py
python tools/fetch_exploit_signals.py

git clone --depth 1 https://github.com/cisagov/CSAF.git /tmp/CSAF
python tools/collect_gt_icsa.py --csaf-repo /tmp/CSAF

python src/build_reverse_sbom.py
python tools/inject_product_variants.py --csaf-repo /tmp/CSAF
python tools/collect_code_gh.py

python src/vex_batch.py
python src/build_ground_truth.py

python tools/compare_cisa_csaf.py --csaf-repo /tmp/CSAF
python tools/eval_variant_derivation.py
python tools/build_justification_seed.py

python tools/build_ics_groundtruth.py
python tools/judge_ics_cves.py          # needs a GPU + models/vex-justifier-lora

python tools/build_sbom_index.py && python tools/build_site.py
```

The execution-verification step (build → exploit → verify) runs a local
Ollama + Docker sandbox orchestrator per CVE; skipping it leaves the
`execution-verified` tier empty and keeps only the upstream-asserted verdicts.

---

## Limitations

1. Confirmed verdicts are a small fraction — 2 execution-verified + 18
   upstream-asserted; the rest are `under_investigation`, an honest reflection of
   the evidence.
2. Independent model-level derivation reaches recall 1.000 but precision 0.291,
   bounded by the public data (CISA does not enumerate the not-affected models).
3. The 18 public CISA flags are **vendor assertions about proprietary builds** and
   the product source is not obtainable, so they cannot score a code-level judge;
   they are a reference vocabulary, not a test set. The judge's only honest number
   is the held-out F1 (0.892) on code-grounded patch pairs.
4. The fine-tuned judge is validated for **Q1 (presence)** only; Q2/Q3 answers from
   the model are reasoning, not proof.
5. That Q1 validation does not transfer: on the 34 ICS vuln/patched pairs the judge
   collapses to `affected` (macro-F1 0.333), so no ICS statement currently rests on
   its output.
6. Version comparison is impossible (all `NOASSERTION`).
7. Execution verification only reaches self-contained libraries; closed ICS
   firmware cannot enter that path.
8. The component inventory is synthetic; real asset SBOMs will change the
   `component_not_present` numbers.
9. Static call-graph reachability (`tools/callgraph_reach.py`) exists but is
   currently limited by vulnerable-function identification (target function known
   for only ~34 of the source-available CVEs); a fuzzing track for Q3 is future
   work.

---

## Data sources / license

CISA ICS-CERT advisories and CISA CSAF (public). OSS vulnerable/patched code from
upstream GitHub fix commits. Execution-verification corpus attribution per its
Apache-2.0 source is retained in `tools/fetch_verify_corpus.py`.
