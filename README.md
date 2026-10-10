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
product). Component identity itself lives in `src/cpe_match_l0l3.py` (identifier-first: **model
number**, then purl/cpe, then exact name, then ICS display-name normalization).

### Stage 2 — CVE Identification  (`cpe_match_l0l3.py`, `build_cpe_index.py`)

- **Model number first** — CISA publishes a Siemens MLFB order code
  (`6GK5204-0BA00-2MB2`) on 14% of components, seven times as often as a CPE, and
  `data/model_cve_index.json` maps it straight to the CVEs the advisory declares that
  `product_id` affected by. It is the one identifier here that cannot be half-right:
  the code is a key in the index or it is not, so there is no threshold to tune and no
  way to fuzzy-match into a false positive. Measured over the components the name
  cascade gives up on, 36% declare a code and 99.3% of those resolve — 3,604 of 9,974
  abstentions recovered. In practice this is a Siemens path (7,821 of 7,993 coded
  components), a vendor optimisation rather than a general method, and
  `tp_by_path` reports it separately.
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
All 107 CVEs have the product source collected, so the analysis is **complete** for each —
none rests in `under_investigation` (the VEX spec reserves that for "not yet analysed"). VEX
puts the burden of proof on `not_affected`: **vulnerable code present in the product is
`affected` by default**, and `not_affected` must be positively *earned*. So the analyzers only
ever *downgrade* on a **sound** positive refutation; they are evidence, not required upgrade gates.

- **Q0 already patched?** `src/patch_gate.py` → **fixed** (CSAF `product_status.fixed`). Presence
  answers "is the vulnerable function here", never "is the fix here", so a snapshot taken at the
  release that *fixed* the CVE still came out `affected` — dnsmasq 2.78 for CVE-2017-14491, curl
  8.0.1 for CVE-2023-27533. The gate clears a CVE only when **two independent authorities agree**:
  the fix commit's distinctive added lines are present and its removed lines are gone
  (`tools/fixed_check`, ≥1 fix line actually found), **and** NVD's *product-matched* affected range
  no longer covers the snapshot version. Either alone mislabels — "no vulnerable lines matched" is
  produced just as readily by a failed file match as by a patched build, and a shared-code CVE's
  range list carries co-listed products' bounds (CVE-2024-6387 ships NetApp's 10.0.0 beside
  OpenSSH's, which clears an openssh 9.6p1 snapshot that sits inside openssh 8.6–9.8). Requiring
  both keeps the gate sound in the direction that matters: it may fail to clear a patched build
  (costing recall) but does not clear a vulnerable one.
- **Q1 present?** `tools/source_locate.py` — absent → not_affected / vulnerable_code_not_present.
  This is the only sound machine refutation *of presence*: if the vulnerable function is not
  defined in the collected source, the code is not present.
- **Q2 reachable?** `tools/joern_reachability.py` (Joern CPG) only *strengthens* an affected
  verdict — it does **not** refute. A collected library snapshot has no consumer, so its real
  entry points (the exported API) are outside the graph, and Joern's "not reachable from an
  in-snapshot root" false-negatives on the very functions that are the attack surface (it did so
  on zlib `inflate` and openssl `GENERAL_NAME_cmp`). "No in-snapshot path" does not meet VEX's
  burden of proof, so only a positive `reachable` is used, as an evidence tier.
- **Q3 controllable?** `tools/z3_controllability.py` (Z3) likewise only *strengthens*; it never
  refutes. Its `not-controllable` rests on the LLM's attacker-vs-environment variable labelling,
  which is unreliable and solver-indistinguishable from a genuine environment gate. (Z3 numeric
  atoms are tried as unbounded integers, then as fixed-width bit-vectors, so an overflow-driven
  trigger (CWE-190) is not mislabelled.)
- **VEX decision** — `tools/vex_judge_v2.py`: patched → **fixed**; else present ∧ not-refuted →
  **affected** (the basis records the evidence tier: Joern-reachable + Z3-controllable = strongest,
  down to presence-only); only Q1 source-absence → **not_affected**.

Joern is a JVM tool and is not bundled (`deploy/README.md` has the install). Run over the 107
source-collectable CVEs, VEX-v2 gives **103 `affected`**, **4 `fixed`**, **0 `not_affected`**, **0
`under_investigation`**. The four are the snapshots the patch gate cleared (CVE-2017-14491,
CVE-2019-11477, CVE-2023-27533, CVE-2023-27536) — **0 false clears**: every CVE the gate cleared is
one the ground truth independently labels not-affected, and no CVE labelled affected was cleared.
Sound source-only `not_affected` still needs the consumer context a library snapshot lacks, so
outside the patch gate the pipeline confirms exploitability and grades evidence rather than clearing
CVEs it cannot soundly clear. `--no-patch-gate` reproduces the earlier 107-`affected` baseline
(`data/vex_v2_pregate.json`). Because presence decides the verdict and Q2/Q3 are optional
enrichment, each verdict carries an **`evidence_tier`** that says how much source evidence backs it:

| tier | count | meaning |
|---|---|---|
| `verified` | 64 | present + Joern-reachable + Z3-controllable (strongest) |
| `reachable` | 3 | present + Joern-reachable |
| `present` | 27 | present; reachability not confirmable (oversized / library caller external) |
| `component` | 13 | component present; specific function not located |

So 67 of the 107 carry positive reachability evidence; the rest rest on confirmed presence.

**Sound `fixed` on the other side — the patch gate (`src/patch_gate.py`), now wired in as Q0.** The
107 are mostly *vulnerable-version* snapshots, which is why the code-level verdict was all
`affected`. The sound way to clear a build is not reachability but the **fix itself**: each CVE's fix
commit turns specific vulnerable lines into fixed ones, so the gate reads that exact code and
reports `fixed` when the distinctive fix lines are present and the vulnerable ones are gone. Hunks
come from the **91 downloaded fix-commit diffs** in `data/patches/`, not the 15 stored in
`data/code_evidence.json`, which is what makes the coverage usable; the hunk from the file where
`source_locations.json` put the vulnerable function is read first, because a fix commit touches more
than the vulnerability (zlib's CVE-2016-9840 commit also bumps the version string in `zlib.h`, and
judging from that hunk convicts an unrelated file). Unlike Joern reachability this needs no
consumer/entry model. `tools/fixed_check.py` remains the single-CVE CLI and
`results/vex_v2_fixed_demo.json` the zlib vulnerable-vs-patched demonstration.

The older source-level engines VEX-v2
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
| ICSA advisories collected | **3,845** | 2010–2026, complete |
| → SBOMs built (advisories with CVEs) | **3,695** | one VEX document each |
| ICSA × CVE = statements | **13,025** | the judgment unit (1:1 with a VEX statement) |
| unique CVEs | **11,550** | vulnerability population |

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

The source-level judgment is the **VEX-v2** pipeline in
[Stage 3 — VEX Verification](#stage-3--vex-verification): CTI extraction by an LLM
agent, the Q0 patch gate, `source_locate`, Joern reachability and Z3 controllability. Because
all 107 CVEs have the product source collected, the analysis is complete for each, so it gives
**103 `affected`, 4 `fixed`, 0 `not_affected`, 0 `under_investigation`**
(`results/vex_v2_summary.json`; `--no-patch-gate` reproduces the earlier all-107-`affected`
baseline). VEX makes `affected` the default for present vulnerable code and puts the burden of
proof on `not_affected`, so the analyzers only *downgrade* on a **sound** refutation — the fix
being positively present (Q0, corroborated by NVD's product-matched range) or the vulnerable
code being absent (Q1). Joern
reachability and Z3 controllability only ever *strengthen* an affected verdict: Joern
"not reachable" false-negatives on a library's own attack-surface functions (its consumer,
which defines the real entry points, is not in the snapshot — it did so on zlib `inflate`),
and Z3 "not-controllable" depends on the LLM's attacker/environment labelling. Each affected
verdict's `basis` records its evidence tier (Joern-reachable + Z3-controllable = strongest,
down to present-but-not-refuted). Sound source-only `not_affected` needs deployment/consumer
context a library snapshot lacks, so the pipeline confirms and grades rather than clearing.

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
| `data/source_snapshots/` | Q1–Q4 | the 107 source trees everything below analyses |

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

Two of the failures — **CVE-2021-33909 and CVE-2023-32233** — had originally died
in the CVE-processor step before any source was downloaded; they were later
collected directly from the upstream release tags (linux-5.13.3 / linux-6.3.1),
along with ntp 4.2.8p13 for CVE-2020-11868, bringing the code-level population to
**107**. `data/source_snapshots/` holds every CVE whose source was actually
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

## Certification test items #3 / #4 — precision, measured

Two precision metrics with an acceptance threshold, each scored against a ground truth
built **only** from authorities the system under test does not read — the test is
otherwise an identity.

| item | metric | result | acceptance | scored over |
|---|---|---|---|---|
| **#3** | SBOM → CVE identification precision | **0.9499** (TP 10,294 / FP 543) | ≥ 0.80 | 10,837 scored, uncapped ground truth |
| **#4** | VEX affected-judgment precision | **0.9310** (TP 54 / FP 4) | ≥ 0.85 | 58 of 68 GT cases, population 172 |

The evaluation datasets are bundled on their own in [`benchmark/`](benchmark/) — answer
keys, the SUT's predictions and the results, enough to re-score without running the
pipeline. `tools/build_benchmark_bundle.py` assembles it and `--check` verifies it against
the live sources, so a rebuilt ground truth cannot leave a stale copy behind unnoticed.

`benchmark/item3/by_asset/` projects the same records into one file per advisory (3,073
of them, with an `_index.json` ordered by size). The jsonl files stay as they are — they
are what the scorer reads, and splitting a scorer's input into thousands of files would
only slow it down; the per-asset view exists so a single advisory's input, answer key and
exclusions can be read together instead of grepped out of three files.

**The per-vendor cap is off.** It had held each vendor to 40 positives so Siemens (58% of
the corpus) could not dominate, but that made the figure describe a sample rather than the
corpus. Removing it took the ground truth from 7,640 to 41,868 records and the score from
0.9870 to 0.9499 — the cap had been holding back exactly the Siemens device names the
matcher is weakest on, so the lower number is the more honest one.

### One corpus, two populations — on purpose

Both items come from one corpus: CISA ICS-CERT advisories (3,845 advisories, 11,550 CVEs,
rendered as CycloneDX in `reverse_sbom/`). Their populations differ, and that is a design
constraint rather than an inconsistency.

```
CISA advisories 3,845 / CVEs 11,550              one corpus
  │
  ├── item #3   SBOM -> CVE identification       whole corpus
  │                                              precision 0.9499 (TP 10,294 / FP 543)
  │
  └── filter: source collectable  ->  172 CVEs
        │
        └── item #4   impact judgment            precision 0.9310 (TP 54 / FP 4)
```

**#3 is independent of the VEX stage and must stay so.** Identification needs no source
code, so scoping it by source availability would import a condition belonging to #4 alone.
The dependency runs one way: #4 is a stage downstream of #3, and #3 must not know anything
about it. The test document's #3 dataset says the same — an ICS SBOM, component-level
vendor/product/version, CPE/PURL where available, NVD and advisory data — with no source
condition anywhere in it.

Scoping #3 to the 104 was tried, and the numbers showed the mistake: the matcher declined
to identify 516 of 543 components (95%, against 37% over the whole corpus) because the
104's vendor-anchored components are Siemens device names, leaving 42 scored predictions
with no false positive able to fire. That run is kept in
`results/cpe_match_precision_104.json` as a record of the dead end; it is not a submitted
figure.

Every one of the 104 is nonetheless inside the corpus, spread across 97 advisories, so the
chain from #3's input to #4's verdict is traceable end to end — `icsa-16-103-01c` (Siemens
ROX II) → the embedded component → CVE-2015-7547 → the glibc snapshot → the VEX verdict.

**Population vs scored count — they are not the same number, in either item.** The
certification document fixes #4's population at 104 CVEs, and
`data/vex_population_104.json` holds exactly that set, so the figure above is measured over
it. But a ground truth earned from evidence cannot label every member: 53 of the 104 are
patch-signature-inconclusive, 5 are patch/NVD disagreements, 1 execution run did not
discriminate. Forcing the remaining cases into the score would require assuming unlabelled
CVEs are `affected` (the SUT answers `affected` for all of them, so FP becomes structurally
0 and precision is the identity 1.0), filling them from vendor assertions (a claim with no
source adjudicating a code-level verdict), or counting undecidable as FP (charging the SUT
for a gap in the answer key). So the claim is **"precision over the evidence-labelled subset
of a 104 population"**, never "precision over 104".

```
172  population (every collected snapshot)
 ├─ 113  patch signature inconclusive
 ├─   5  patch signature vs NVD disagreement -> held out as conflict
 └─   1  execution run did not discriminate
 ↓
 63  CVEs labelled  ->  68 (CVE, build) cases
 ├─  9  patched builds — source vex_judge_v2 never ran against
 └─  1  CVE with no cached verdict
 ↓
 58  scored  ->  precision 0.9310
```

Measured over the 104 the test document names instead, it is 0.9200 (TP 46 / FP 4,
`results/vex_precision_104.json`). Widening the population from 104 to 172 added 8 true
positives and no false positives, and the same four CVEs fail in both runs — the figure is
insensitive to the population, and those four are a reproducible defect rather than an
artefact of which snapshots happened to be collected.

**#3 ground truth** (`tools/build_cpe_match_gt.py` → `data/cpe_match_eval.jsonl`, 41,868
records over 6,461 CVEs and 532 vendors, uncapped) comes from CISA CSAF `affects` assertions cross-checked against NVD
applicability — never from `data/cpe_index.json`, which is what the matcher itself reads. Negatives
are authority-derived: a version at or past CISA's own fixed boundary, and a co-listed vendor's
product from the same shared-code CVE. What the figure does **not** cover:

- **91.2% of predictions carry no label.** 57% are CVEs the GT does not enumerate for that
  component; 34% are *unadjudicable* — CISA says the ICS product is affected while NVD files the CVE
  against an embedded third party (Siemens JT2Go ↔ `drawings_software_development_kit`), so the two
  authorities disagree about what the CVE is filed against, not about what the component is.
  Charging those as FPs would penalise the matcher for a gap in the ground truth.
- **41.9% of the corpus is excluded up front** (`data/cpe_match_eval_layerB.jsonl`): pairs where the
  ICS name appears nowhere in NVD, so no name-based matcher can reach the answer.
- **6,633 of 14,173 components (47%) are abstentions** — the matcher declined to identify. Legitimate
  under a precision-only metric, and disclosed because it is a free lift to the score.
- 32 CISA/NVD version-range disagreements are held out as `conflict` rather than labelled verified.
- The 377 co-listed-vendor negatives are **unreachable for this SUT** and reported as such, not
  deleted: `cves_for` returns `(product, vendor-of-that-product-entry)`, so it can never emit
  `fedoraproject:fedora` for a Siemens component. A negative has to lie inside the system's output
  space to ever fire.

**#4 ground truth** (`tools/build_vex_gt.py` → `data/vex_gt_104doc.jsonl`, 58 cases over 54 CVEs
for the 104 population; `data/vex_gt_104.jsonl` is the same build over all 107) uses
`execution_verified` and `patch_verified` only; `vendor_asserted` is excluded because a claim with no
source behind it cannot adjudicate a code-level verdict. Its `not_affected` side exists at all
because the evidence is **paired** — execution gives "vulnerable version crashes / patched version
does not", the patch signature gives "vulnerable lines survive / fix lines present" — so one record
yields two cases. A label is therefore about a **build, not a CVE**, and the 8 patched-build cases
are held out: `vex_judge_v2`'s caches are keyed by CVE, not by snapshot path, so its cached verdicts
cannot stand in for a run against `data/fixed_releases/`.

> **The gated system's #4 figure is circular, and 0.9310 is the pre-gate number.** The patch gate
> decides from the fix signature plus the NVD range — the same two authorities the GT's
> `patch_verified` labels come from. With the gate live, FP falls to 0 and precision reads 1.0000 by
> construction, not by merit; `tools/eval_vex_precision.py` detects this and prints a `!! CIRCULAR`
> warning naming the shared-oracle cases. The non-circular slice (`--independent`,
> execution-verified only) is n=1 and says nothing. So the quotable figure is measured on
> `data/vex_v2_pregate.json` (`vex_judge_v2 --all --no-patch-gate`), and the gate's own result is
> reported separately as **4 clears, 0 false clears**.

Both ground truths ship a manifest (`*_manifest.json`) recording the seed, sampling caps, evidence
mix, and every exclusion with its reason.

---

## Data honesty

- **Real:** device ↔ CVE ↔ CWE ↔ CVSS from CISA ICS-CERT (3,845 advisories,
  11,550 CVEs); KEV/EPSS signals; OSS vulnerable/patched code (34 CVEs, GitHub fix
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

## Repository layout

```
ICS-VEX/
├── src/                          core modules (15)
│   ├── api_server.py             FastAPI backend + web console (the FRONTEND string); build_site reuses it
│   ├── component_resolve.py      Stage 1 — ics-product / variant / embedded-component split
│   ├── cpe_match_l0l3.py         Stage 2 — NVD CPE L0+L3 identification
│   ├── build_reverse_sbom.py     advisory → CycloneDX 1.7 SBOM (KISA field spec)
│   ├── sbom_match.py             SBOM → CVE matching
│   ├── patch_gate.py             Q0 — already patched? fix signature + NVD range (both required)
│   ├── cpe_match_ai.py           semantic retrieval behind the string cascade (scaffolded)
│   ├── vex_batch.py / vex_pipeline.py   corpus-level VEX batch
│   └── vex_source_unavailable.py decision tree for source-uncollectable CVEs
├── tools/                        67 pipeline scripts, incl. Stage 3 (VEX-v2):
│   ├── cti_extract.py            CTI → structured info (Ollama)
│   ├── source_locate.py          Q1 presence — decides the verdict
│   ├── joern_reachability.py     Q2 reachability (optional evidence tier)
│   ├── z3_controllability.py     Q3 controllability (optional evidence tier)
│   ├── vex_judge_v2.py           hierarchy verdict + evidence_tier (Q0 patch gate first)
│   ├── fixed_check.py            patch-signature single-CVE CLI
│   ├── build_cpe_match_gt.py · eval_cpe_match_precision.py   test item #3 GT + scorer
│   ├── fetch_cpe_dictionary.py   NVD CPE dictionary, --vendors scopes it to the 932 the corpus uses
│   ├── build_cpe_match_dataset.py  title<->cpe training pairs, negatives by field swap
│   ├── collect_snapshots_nvd.py  snapshots for CVEs the hand catalog never covered
│   ├── split_benchmark_by_asset.py  benchmark/item3/by_asset/, one file per advisory
│   ├── build_vex_gt.py · eval_vex_precision.py               test item #4 GT + scorer
│   ├── summarize_vex_v2.py       results/vex_v2_summary.json
│   ├── build_func_index.py · extract_vuln_funcs.py · oss_repos.py   source index / collection map
│   ├── build_site.py · build_cpe_index.py · build_sbom_index.py     static site + indexes
│   └── fetch_*.py · collect_*.py                                     data collection
├── data/                         caches, snapshots, indexes (most gitignored, regenerable)
│   ├── source_snapshots/<CVE>/   107 collected source trees (gitignored)
│   ├── code_evidence.json        fix hunks (vuln vs patched) → feeds fixed_check
│   ├── nvd_cache.json · cisa_advisories.json · vuln_targets.json
│   └── {cti_extractions,source_locations,reachability,controllability,vex_v2}.json  (VEX-v2 caches, gitignored)
├── reverse_sbom/                 3,845 advisory → CycloneDX SBOMs
├── results/                      eval outputs (vex_v2_summary.json, vex_v2_fixed_demo.json, …)
├── site/                         static dashboard: 10 HTML + JSON, auto-deployed to GitHub Pages
├── deploy/                       Joern / deployment notes
├── .github/workflows/pages.yml   deploys site/ on push to main
└── README.md · RESULTS.md · requirements.txt
```

Data/output directories are gitignored where regenerable (`.gitignore` lists them); the code
lives in `src/` and `tools/`, the deployed dashboard in `site/`.

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
| **VEX-v2** 5. Final VEX (Q0 gate incl.) | `tools/vex_judge_v2.py --all`, `tools/summarize_vex_v2.py` | `data/vex_v2.json`, `results/vex_v2_summary.json` |
| **VEX-v2** 5b. Pre-gate baseline | `tools/vex_judge_v2.py --all --no-patch-gate --out data/vex_v2_pregate.json` | `data/vex_v2_pregate.json` |
| **VEX-v2** (opt) Patch-signature CLI | `tools/fixed_check.py --cve X --snapshot D` | `results/vex_v2_fixed_demo.json` |
| Test item #3 | `tools/build_cpe_match_gt.py`, `tools/eval_cpe_match_precision.py` | `data/cpe_match_eval.jsonl`, `results/cpe_match_precision.json` |
| Test item #4 | `tools/build_vex_gt.py --population data/vex_population_104.json --out data/vex_gt_104doc.jsonl`, `tools/eval_vex_precision.py --gt data/vex_gt_104doc.jsonl --sut data/vex_v2_pregate.json` | `data/vex_gt_104doc.jsonl`, `results/vex_precision_104.json` |
| Build site | `tools/build_sbom_index.py`, `tools/build_site.py` | `site/*.html`, `site/*.json` |

In VEX-v2 the **patch gate (Q0) runs first** and the **presence check (Q1) decides the rest**;
reachability (Joern) and controllability (Z3) are optional and only set the `evidence_tier`.
`data/vuln_targets.json` is the patch-based fallback when the CTI does not name the vulnerable
function. Keep `data/vex_v2_pregate.json` around: it is the baseline the only non-circular test
item #4 figure is measured on, since the gate and that GT's `patch_verified` labels share an
oracle. VEX-v2 outputs are gitignored (regenerable).

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
python tools/fetch_patch_refs.py && python tools/fetch_patches.py   # Q0 patch gate inputs
python tools/vex_judge_v2.py --all && python tools/summarize_vex_v2.py
python tools/vex_judge_v2.py --all --no-patch-gate --out data/vex_v2_pregate.json

# certification test items #3 / #4 — ground truth, then precision
python tools/build_cpe_match_gt.py && python tools/eval_cpe_match_precision.py
python tools/build_vex_gt.py --population data/vex_population_104.json --out data/vex_gt_104doc.jsonl
python tools/eval_vex_precision.py --gt data/vex_gt_104doc.jsonl --sut data/vex_v2_pregate.json

python tools/build_sbom_index.py && python tools/build_site.py
```

VEX-v2 needs a local Ollama (the CTI agent uses `qwen2.5-coder:14b`; the Z3 formaliser
uses the general `qwen2.5:14b`) and Joern for reachability (`deploy/README.md` has the
install). Joern only ever *strengthens* an affected verdict (a positive `reachable` is the
top evidence tier); it never refutes, because "not reachable from an in-snapshot entry" is a
false negative for a library whose caller is external. Where Joern is absent or cannot build a
CPG, the verdict falls back to the `affected` presence-baseline rather than `under_investigation`.

The Q0 patch gate needs no model — it reads `data/patches/*/*.diff` and the NVD range cache
(`data/cve_version_ranges.json`) directly. Score test item #4 against
`data/vex_v2_pregate.json`, not the gated output: the gate and that ground truth's
`patch_verified` labels rest on the same two authorities, so the gated run reads 1.0000 by
construction and the scorer prints a `!! CIRCULAR` warning saying so.

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
   about the real program's path constraints. It therefore only ever *strengthens* an
   affected verdict (a not-controllable result depends on the LLM's attacker/environment
   labelling, which is unreliable, so it is never used to clear a CVE).
5. VEX-v2's Q2 (Joern) is **call-graph only** (no dataflow) and falls back to the
   call-graph roots as entry points when the CTI names none. Because a collected library has no
   consumer, "not reachable from an in-snapshot root" is a **false negative** for its exported
   attack-surface functions (seen on zlib `inflate`, openssl `GENERAL_NAME_cmp`), so Q2 is used
   only to *strengthen* (positive `reachable`), never to refute. Oversized snapshots
   (glibc/linux/u-boot…) that cannot build a CPG likewise stay on the `affected` presence-baseline.
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
