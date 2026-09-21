# ICS-VEX — Explainable VEX for Industrial Control Systems

An end-to-end pipeline that takes an **SBOM of an ICS/OT asset** and produces a
**VEX judgment** (`affected` / `not_affected` / `under_investigation`) with a
**CISA justification** and a rationale — grounded in code and build evidence,
never in synthetic deployment context.

> **Dashboard (ICS-VEXForge)** — run it locally with `python src/api_server.py
> --port 8100`, then open http://127.0.0.1:8100/. Paste/upload an SBOM to get
> per-component CVE + VEX analysis, browse the corpus, and export OpenVEX /
> CSAF 2.0 documents — all in the browser. The same bundle is published to
> GitHub Pages (`site/**` pushes deploy automatically via
> `.github/workflows/pages.yml`).

---

## Architecture — three stages

An ICS asset SBOM becomes VEX in three stages: resolve the components, identify their
CVEs, then verify each CVE against the actual source. Each stage was rebuilt to be more
accurate and more honest than a name-similarity match or a single-model verdict.

```
ICS Asset SBOM
      │
      ▼
┌ Stage 1 · Component Resolution ──────────────────────────────┐
│  vendor/product · component/version · CPE/purl               │
│  component relationship:                                     │
│     ICS product (Siemens PLC)  ─┐                            │
│     embedded component (OpenSSL / Linux / curl) ─┘ merge     │
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌ Stage 2 · CVE Identification ────────────────────────────────┐
│  NVD CPE index → candidate CVEs                              │
│  vendor evidence + version evidence → component–CVE mapping  │
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌ Stage 3 · VEX Verification ──────────────────────────────────┐
│  CTI extraction (LLM agent) → vulnerable target resolution   │
│     (patch → description)                                    │
│  evidence: Q1 present? · Q2 reach? · Q3 control?             │
│     → evidence graph → VEX decision                          │
└──────────────────────────────────────────────────────────────┘
```

### Stage 1 — Component Resolution

Parse the SBOM into vendor/product, component/version and CPE/purl, then resolve the
**component relationship**: separate the ICS product (the device — e.g. a Siemens PLC)
from the **embedded components** it ships (OpenSSL, the Linux kernel, curl). This split
is what reaches the 27.8% of CVEs whose CPE names an embedded upstream component rather
than the product; an SBOM that lists only products cannot match them. The layering is
`src/component_resolve.py`: it classifies each component by CycloneDX `type` plus its
identifiers into `ics-product` / `product-variant` / `embedded-component`, so Stage 2
identifies each layer on its own (e.g. a CoDeSys device whose embedded CODESYS runtime
resolves to `codesys:control_runtime_system` and its 10 CVEs, separately from the
product). Component identity itself lives in `src/cpe_match_l0l3.py` (identifier-first:
purl/cpe, then exact name, then ICS display-name normalization).

### Stage 2 — CVE Identification  (`cpe_match_l0l3.py`, `build_cpe_index.py`)

- **NVD CPE index** — the full product index (13,764 products vs a 42-entry OSS KB), so
  vendor ICS products resolve at all: "Sielco Sistemi Winlog Lite <2.07.09" →
  `winlog_lite`. Candidate CVEs come from that product's NVD entries.
- **Vendor evidence** grades each candidate `anchored` / `canonical` / `co-listed`
  rather than hard-filtering (a hard filter drops the embedded layer). **Version
  evidence** decides the installed version against the NVD range as True/False/None
  (undecidable never read as False). The output is the component–CVE mapping. Measured:
  over 20,429 reverse_sbom names, exact+normalized resolves 21.2% (`results/l0l3_delta.json`).

Served live from the API (`/api/vex`); the static Pages bundle keeps the in-browser
42-KB matcher because the 18 MB index cannot ship in the browser (see `deploy/`).

### Stage 3 — VEX Verification  (source-collectable CVEs)

Keeps the CISA justification vocabulary but swaps the engines: an LLM agent structures
the CTI, then a solver / static-analysis tool **decides** each gate — the model never
emits the verdict itself; "unknown" never clears.

- **CTI extraction (LLM agent)** — `tools/cti_extract.py` (Ollama qwen2.5-coder:14b, $0)
  extracts {vulnerable component, function(s), reachability info, controllability info}
  from NVD desc + CWE + refs.
- **Vulnerable target resolution** — `tools/source_locate.py`: the CTI's function names
  when it named any, else the patch-localised targets (patch → description fallback),
  checked against `func_index`.
- **Evidence verification** — three gates, in flow order:
  - **Q1 present?** absent → not_affected / vulnerable_code_not_present
  - **Q2 reachable?** `tools/joern_reachability.py` (Joern CPG) — no → not_affected /
    vulnerable_code_not_in_execute_path  *(the earlier gate)*
  - **Q3 controllable?** `tools/z3_controllability.py` (Z3, run only when reachable) — no
    → not_affected / vulnerable_code_cannot_be_controlled_by_adversary
- **Evidence graph → VEX decision** — `tools/vex_judge_v2.py`: present ∧ reachable ∧
  controllable → affected; any gate unknown before a hard "no" → under_investigation.

Joern is a JVM tool and is not bundled (`deploy/README.md` has the install). Run over the
104 source-collectable CVEs, VEX-v2 gives 53 `affected`, 6 `not_affected` and 45
`under_investigation` (`results/vex_v2_summary.json`). The older source-level engines it
replaced — the fine-tuned Q1 judge, the static call-graph Q2 and the taint Q3 — have been
**removed** now that it is validated; some sections further below still describe that
earlier approach and are being retired.

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

### The code-level questions — see Stage 3 above

The source-level judgment (Q1 present, Q2 reachable, Q3 controllable, each settling a
CISA justification) is the **VEX-v2** pipeline in
[Stage 3 — VEX Verification](#stage-3--vex-verification): CTI extraction by an LLM
agent, `source_locate`, Joern reachability and Z3 controllability. Over the 104
source-collectable CVEs it gives **53 `affected`, 6 `not_affected`, 45
`under_investigation`** (`results/vex_v2_summary.json`); a verdict only clears on
positive evidence, so an undecided gate stays `under_investigation`.

The earlier engines that filled this section — a fine-tuned Q1 judge
(`judge_ics_cves.py`), a static call-graph Q2 (`callgraph_reach.py`) and a taint Q3
(`taint_reach.py`) — have been removed. CISA'''s fifth justification,
`inline_mitigations_already_exist`, is still not judged by this project.

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

For CVEs whose source can be obtained, we ran a containerized
build → exploit → verify pipeline with a **local model (Ollama, $0)** and Docker
sandboxing. All 106 source-available CVEs were run (the 88 that built plus an
18-CVE expansion of prior build failures and never-attempted CVEs).

> This campaign is **complete, closed, and not reproducible here.** Its evidence is
> preserved (`results/verify_full/`, `results/verify_evidence/`,
> `results/verify_full_summary.csv`), but the runners that drove the external
> container engine were removed in b4fc1bc8, and `src/exploit_verifier.py` no
> longer exists. Treat what follows as an archive, not as a pipeline stage.

**Two things from that campaign are still live**, and nothing else is:

| Still used | By | For |
|---|---|---|
| the **2 execution-verified** CVEs (CVE-2020-8177, CVE-2022-32221, both curl) | `src/vex_batch.py` | the only `affected` verdicts in the corpus resting on a run, not an argument |
| `results/verify_build_logs/` | — | preserved build output of the closed campaign |
| `data/source_snapshots/` | Q1–Q4 | the 104 source trees everything below analyses |

The campaign's other outcome labels — `exploit-generated 20`, `build-only 70`,
`failed 14` — are a **historical record of a pipeline this repository can no
longer run**. Nothing reads them except the console page that displays the
archive. They are not reproducible and are not evidence for any verdict.

One number from them still matters, as methodology rather than data: an LLM
critic accepted **22** PoCs and a real run reproduced **2**. That 20-PoC gap is
why status in this system rests on execution, never on a critic's approval.
Failure analysis shows the misses are dominated by memory-corruption CWEs whose
trigger produces no observable effect without sanitizer instrumentation, while
both successes are logic-class bugs with a visible effect.

Two of the failures — **CVE-2021-33909 and CVE-2023-32233** — died in the
CVE-processor step before any source was downloaded, so no snapshot exists for
them. That is why the code-level analysis below has a population of **104**, not
106: `data/source_snapshots/` holds the CVEs whose source was actually
collected.

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
| 7. ~~Execution verify~~ | **closed campaign, not reproducible here** — the runners were removed in b4fc1bc8. Downstream reads only the preserved `results/exec_verification*.json` and `results/verify_build_logs/` | — |
| 8. Batch judgment | `src/vex_batch.py` | `results/vex_batch.jsonl` |
| 9. Ground truth | `src/build_ground_truth.py` | `data/vex_dataset.jsonl` |
| 10. Compare / evaluate | `tools/compare_cisa_csaf.py`, `tools/eval_variant_derivation.py` | console reports |
| 11. Justification seed | `tools/build_justification_seed.py` | `data/vex_justify_seed.jsonl`, `data/vex_justify_eval.jsonl` |
| 12. ICS ground-truth pairs | `tools/build_ics_groundtruth.py` | `data/ics_gt_pairs.jsonl` |
| 13. Cache fix-commit diffs | `tools/fetch_patches.py` | `data/patches/<CVE>/<sha>.diff` |
| 14. Index snapshot functions | `tools/build_func_index.py` | `data/func_index/` (gitignored, rebuildable) |
| 15. Locate vulnerable functions (patch fallback) | `tools/extract_vuln_funcs.py`, `tools/locate_vuln_funcs.py` | `data/vuln_targets.json` |
| **VEX-v2** 1. CTI extraction | `tools/cti_extract.py --all` | `data/cti_extractions.json` (Ollama) |
| **VEX-v2** 2. Q1 source locate | `tools/source_locate.py --all` | `data/source_locations.json` |
| **VEX-v2** 3. Q2 reachability | `tools/joern_reachability.py --all` | `data/reachability.json` (Joern) |
| **VEX-v2** 4. Q3 controllability | `tools/z3_controllability.py --all` | `data/controllability.json` (Z3) |
| **VEX-v2** 5. Final VEX | `tools/vex_judge_v2.py --all`, `tools/summarize_vex_v2.py` | `data/vex_v2.json`, `results/vex_v2_summary.json` |
| Build site | `tools/build_sbom_index.py`, `tools/build_site.py` | `site/*.html`, `site/*.json` |

The VEX-v2 steps run in gate order (reachability before controllability, which only
runs where reachable); `data/vuln_targets.json` is the patch-based fallback when the
CTI does not name the vulnerable function. VEX-v2 outputs are gitignored (regenerable).

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

# VEX-v2 source-level judgment (needs Ollama running + Joern on PATH):
python tools/cti_extract.py --all
python tools/source_locate.py --all
python tools/joern_reachability.py --all
python tools/z3_controllability.py --all
python tools/vex_judge_v2.py --all && python tools/summarize_vex_v2.py

python tools/build_sbom_index.py && python tools/build_site.py
```

VEX-v2 needs a local Ollama (the CTI agent, `qwen2.5-coder:14b`) and Joern for
reachability (`deploy/README.md` has the install); until Joern is present that gate
returns `unknown` and those CVEs stay `under_investigation`.

---

## Limitations

1. Confirmed verdicts are a small fraction — 2 execution-verified + 18
   upstream-asserted; the rest are `under_investigation`, an honest reflection of
   the evidence.
2. Independent model-level derivation reaches recall 1.000 but precision 0.291,
   bounded by the public data (CISA does not enumerate the not-affected models).
3. The 18 public CISA flags are **vendor assertions about proprietary builds** and the
   product source is not obtainable, so they are a reference vocabulary, not a scored
   test set for any code-level judgment.
4. VEX-v2's Q3 rests on the **LLM's formalisation** of the CTI into a small predicate over
   labelled variables, decided by Z3 — a decision procedure over that model, not a proof
   about the real program's path constraints; 14 CVEs had no formalisable trigger and
   stay `under_investigation`.
5. VEX-v2's Q2 (Joern) is **call-graph only** (no dataflow) and falls back to the
   call-graph roots as entry points when the CTI names none; 16 oversized snapshots
   (glibc/linux/u-boot…) are skipped to `unknown` rather than risk a false clearance.
6. Version comparison is impossible **on the reverse-built SBOM corpus** — every
   component version there is `NOASSERTION`. Where real versions exist, matching
   them against NVD ranges works: `tools/eval_version_match.py` scores
   precision 100.0% / recall 98.3% / macro-F1 0.99 over 125 CVEs
   (`results/version_match.json`).
7. Execution verification only reaches self-contained libraries; closed ICS
   firmware cannot enter that path.
8. The component inventory is synthetic; real asset SBOMs will change the
   `component_not_present` numbers.
9. **NVD carries a CPE for 88.9% of these CVEs** (10,059 of 11,314; 69.6% with a
   version range), and the top vendors are ICS ones - Siemens 1,932, Schneider
   Electric 375, Rockwell 322, Advantech 275 (`results/cpe_census.json`, a full
   census, not a sample). This corrects an earlier reading of the CSAF side,
   where only 0.2% of OT products carry a CPE: the advisories omit them, NVD
   supplies them. The analyzer's CPE panel fails on ICS components not because
   CPE is unavailable but because it matches against a 42-entry OSS knowledge
   base. Pointing it at the NVD dictionary helps only part of the way: for 27.8%
   of these CVEs NVD's CPE names an embedded upstream component (the Linux kernel
   alone in 1,296; OpenSSL, glibc, curl, MariaDB), not the ICS product, so an
   SBOM that lists products without their embedded components cannot reach them
   by CPE at all. The console page **ICS-SBOM to CVE** lists all nine limits of
   CPE-based identification, each with its evidence grade, rendered from
   `results/sbom_cpe_limits.json` (`tools/measure_sbom_cpe_limits.py`).
10. **Target coverage is 105 of 106 campaign CVEs** (fix-commit hunk 75, NVD
   description 28, fix-commit hunk on a partial snapshot 2). The fix commits come from
   NVD references, the Debian security tracker's NOTE lines, a local `git log` search
   of each project's blobless mirror keyed by the commit/ticket/bug ids those
   references carry (`tools/git_grep_fix_commits.py`), and - for eight CVEs no key
   reaches - a primary advisory or the project's own patch set, each recorded with its
   evidence (`ADVISORY_FIX`; w1.fi 2022-1 and Alpine's patches cached as diffs).
   Every target added in this push was checked against the code: the function must
   contain a line the fix actually changes in the snapshot, and every name the
   extractor rule changes removed contained none. That is a consistency check, not
   proof that the target is the vulnerable function. The exceptions, stated plainly:
   - **CVE-2023-28450** (dnsmasq) has no target: its fix only lowers the
     `EDNS_PKTSZ` default in `config.h`; no function is edited.
   - **CVE-2021-33909 / CVE-2023-32233** (Linux) have only the files the fix touches,
     at the fix's parent commit (`data/partial_snapshots`). Their targets are real,
     but the source label `patch-partial` may not clear and Q2/Q3 do not run on them.
   - **CVE-2023-34035** is a Spring Security CVE whose snapshot held only
     spring-framework 6.0.9; spring-security 6.1.0 (the release Spring Boot 3.1.0
     pairs with it) was added beside it.
   - Weak targets: CVE-2021-42375's fix commit is *inferred* (Claroty names the
     trigger characters `$ { } #`; the only ash parser fix in 1.34.0 but not 1.33.1 is
     the `${#var}` one); CVE-2017-13077/13078 come from hostapd's optional AP-side
     KRACK workaround, not a protocol fix; CVE-2022-28391 was never fixed upstream and
     rests on Alpine's patch; CVE-2023-46850's fix edits `tls_process_state`, absent
     from the 2.5.5 snapshot.
11. Q3's `not-controllable` rests on arguing from absence in an incomplete static
   view. The guards above make that argument honest, but they also make it rare:
   on this corpus it never clears. A dynamic track
   (fuzzing the tainted entries) is the way to get positive evidence for Q3.

---

## Data sources / license

CISA ICS-CERT advisories and CISA CSAF (public). OSS vulnerable/patched code from
upstream GitHub fix commits. The execution-verification campaign's CVE corpus
came from a public Apache-2.0 reproduction dataset
([BUseclab/cve-genie](https://github.com/BUseclab/cve-genie), Ullah et al.),
attribution retained here.
