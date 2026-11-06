# ICS-VEXForge

Local ICS/OT **SBOM → CVE candidates → evidence-based VEX review**.
Updated **2026-11-06 (KST)**. Retained experiments are not current independent accuracy.

**Current execution policy:** product/CVE identification, CWE routing, source
analysis, condition/function extraction, operational questions and answer
assessment use deterministic rules. Only the final VEX explanation uses an LLM.

## Run

```powershell
cd C:\Users\user\Desktop\ICS-VEX
python -m pip install -r requirements.txt
python src/api_server.py --host 127.0.0.1 --port 8100
```

Keep the terminal open while using the application; `Ctrl+C` stops it. If port
8100 is already in use, open the existing local application instead of starting
a second server. Dependency installation is not needed for every startup.

Open [the local analyzer](http://127.0.0.1:8100/index.html). Supply CycloneDX or
SPDX JSON, identify candidates, then start the CWE-first review. Identification
accepts up to 100 components per job.

Only final VEX writing requires compatible CUDA/PyTorch, the local Qwen3-8B base
referenced by the writer configuration, and `models/vex-writer-qwen3-8b-v1/`.
Its model-loading dependencies are listed in `requirements-training.txt`.
Identification and operational review do not require analysis adapters or a GPU.
For a fresh GitHub checkout, first build the generated CPE dictionary with
`python tools/refresh_cpe_feed.py`. The current 156 MiB dictionary is kept locally
and is not distributed as a Git blob; its importer and provenance are included.
For optional C/C++ compiler-backed analysis, run `python tools/setup_clang.py` (requires 7-Zip), or set
`ICSVEX_CLANG`.

[GitHub Pages](https://kakyung98.github.io/ics-vex-dashboard/) serves the English
interface/public snapshots. Select **Connect local backend** for analysis.
Pages does not host FastAPI, inference, uploaded source or weights.

The shared light workspace theme lives in `src/ui_theme.py`: charcoal navigation,
white cards on a gray canvas, lime actions and lavender analysis accents. All
primary pages use the same shell, including the embedded identification widget.
The analyzer leads with upload and review actions; model/evidence settings and
long technical explanations use expandable sections. Methodology maps use larger
cards, role icons and separate expandable stage details. Input IDs, evidence
checks and export behavior remain shared with the backend workflows.

## #3: deterministic SBOM → CVE candidates

L2/L3/L4 use original SBOM evidence and local dictionaries only. No LLM, base
model, adapter, model critic or model fallback runs during identification.

| Stage | Processing |
| --- | --- |
| L2 | Preserve model identifiers; retrieve CPE candidates with BM25/character matching and rank fusion; keep competitors |
| L3 | Preserve versions, revisions and provenance; reject conflicts and unverified CPE versions; synthetic/range evidence is not installation proof |
| L4 | Accept only a unique dictionary identity supported by original evidence, with no unresolved vendor/type/identifier conflict |
| CVE lookup | Merge separately attributed NVD and CISA candidates; retain component links and unknown applicability |

`metadata.component.cpe` receives separate CPU asset analysis; identifiers are not
inherited by dependencies. Asset and component findings enter VEX review.
Legacy method names (`base`, `tuned`, `evidence_llm`) are compatibility aliases for
the deterministic path; they cannot enable analysis inference.

CPE syntax, dictionary membership, type conflicts and missing evidence are shown
in the result. Unsupported escaped CPEs remain unresolved. The local flattened
NVD cache cannot prove full platform AND/OR applicability. An empty result is not
proof of safety. Input SBOM vulnerability answers are not identification ground truth.

## #4: CWE-first CVE → VEX

**LLM policy: final VEX explanation writing only.** Qwen3-8B plus the VEX-writer
adapter is loaded lazily at that final stage. Other adapters and analysis-model
queues are disabled. Existing model files and historical reports are retained.

1. Preserve reported CWE IDs and derive all Pillar paths from pinned **CWE v5.0**:
   984 weaknesses, 10 Pillars.
2. Combine **Pillar + specific CWE + CVE/advisory evidence** using the versioned
   `cwe-evidence-v2.1` policy. It has an individual record for all 944 mapped active
   detailed CWEs. Pillars group records; they never supply a blanket source requirement.
3. Follow four evidence workflows (corrected 2026-11-05):
   - **Source only:** supplied source → language-aware AST/patch checks; optionally Clang/LLVM for configured C/C++ builds.
   - **Source + operating context:** source analysis, then required operator facts.
     Explicit CVE/advisory references to network/remote access, authentication,
     privileges, configuration, enabled features or user/physical interaction trigger this conservative context requirement.
   - **Required source missing:** `under_investigation`; no questionnaire or writer bypass.
   - **Operating context only:** source-linked rule questions, installed-build
     facts and supporting records. Unknown answers remain unknown.
4. Accumulate source and operating evidence under the same CVE case ID.
   Required evidence missing or conflicting decisions → `under_investigation`.
   Completing a branch is not proof of exploitability or independent verification.
5. Author only after the required evidence branches have submitted results.
   Identical evidence is not authored twice. Preserve both branch records and their history.
6. **Routing unresolved:** retain `under_investigation`, without a questionnaire bypass.
7. Code locks status/scope. The writer drafts an explanation; validation rejects
   changed IDs/status, invalid references, malformed output and repetition.
8. Preserve each CVE's branch result. Merge VEX into a copy of the original
   CycloneDX SBOM; standalone OpenVEX/CSAF are available. SPDX uses standalone VEX.

The evidence policy now separates **implementation properties**, **observable
deployment records**, and **specialist/unspecified evidence**. Explicit detailed
rules take precedence; otherwise the nearest explicit detailed ancestor applies,
with equally specific requirements combined. A separate 26-type operational
allowlist prevents inheritance from accidentally treating Java declarations as
runtime permissions. There is no “no operational rule → source required” fallback.

The baseline table has **728 source-requiring**, **26 operational**, and **190
specialist/mechanism-unresolved** profiles. These are project policy assignments,
not independent gold, accuracy, or final CVE-route counts. Some entries have
official Prohibited/Discouraged CVE mapping usage; these assignment guidelines
are informational and do not block analysis of the reported CWE. Explicit
CVE implementation/configuration evidence can refine eligible profiles: a generic
weak crypto label is unresolved, a documented configurable TLS mechanism can use
operating records, and a risky embedded implementation does not become a setting.

Every record retains its definition, all Pillars, rule/ancestor path, evidence
facts, official platform/detection suggestions and mapping cautions, plus source
and policy hashes. Official detection suggestions are not mandatory analysis rules.
Unknown or mechanism-unresolved CWEs cannot be hidden by another mapped CWE in
the same CVE. Mapping usage alone never makes a reported CWE unresolved.

See the [detailed criteria and limitations (Korean)](docs/CWE_ROUTING_CRITERIA.md),
[all 944 policy records](docs/CWE_EVIDENCE_POLICY_V2.md),
[JSON](data/cwe_routing/v2/profiles.json), [CSV](data/cwe_routing/v2/profiles.csv),
and the [official Pillar grouping](docs/CWE_PILLAR_GROUPS_V5.md).
The criteria document's section 3 now lists all 10 Pillar aggregates and every
detailed CWE membership. Its main assignment table separates direct/inherited
evidence rules from optional CWE-assignment metadata. Section 5 explains why the
same guidance grade can lead to different routes without blocking analysis.
Section 4 traces 8 locally cached CVEs and 12 constructed
controls through the actual router. [Reproducible inputs and outputs](data/cwe_routing/v2/criteria_results.json)
retain rule paths, literal evidence spans and missing evidence. These outputs are
not independently adjudicated labels or classification accuracy.
Rebuild with `python tools/build_cwe_evidence_policy.py`.
The web's **VEX Decision Logic → Search all 944 CWE profiles** shows the policy;
each CVE route also exposes **Why this route?** with its actual evidence and rule.
Changed policy versions/hashes require a new review without deleting historical evidence.

| Evidence | Permitted conclusion |
| --- | --- |
| Compiler-backed supported targets absent in declared complete product/build scope, no blockers | Scoped `not_affected / vulnerable_code_not_present` |
| Compiler-backed targets unreachable from complete declared roots, no blockers | Scoped `not_affected / vulnerable_code_not_in_execute_path` |
| Exact vendor-fixed build + scoped operator-attested installation record | `fixed`, retaining deployment-verification limits |
| Required mapping, source/build, routing or facts unresolved | `under_investigation` |

Reachability does not establish attacker control/exploitation. Disabled features
or network controls are not code absence. Advisory `likely_*` labels are separate
from standard VEX. Source completeness/deployed binary identity are not independently
attested. Joern, CodeQL, taint and symbolic feasibility are not implemented.

### Source text analysis (not firmware binaries)

Upload a ZIP containing **C, C++, Python, Java, SQL, JavaScript, Go, R or Ruby**
source. No executable, interpreter runtime or build database is required for
source parsing. `src/multilang_source.py` uses the pinned
[Tree-sitter language pack](https://github.com/xberg-io/tree-sitter-language-pack/tree/v0.13.0)
to record function/routine definitions, byte spans, file/line locations, control
constructs and syntax-derived call candidates. Comments and string literals are
not treated as executable calls. Parser errors, unresolved/ambiguous calls and
file/language coverage remain visible. No uploaded code or build script runs.

The source analyzer selector supports `auto` (default), `syntax` (no compilation)
and `clang` (C/C++ build evidence). Auto uses Clang/LLVM for C/C++-only projects
with supplied compilation settings; otherwise it parses source directly. A
blocked compiler attempt falls back to syntax evidence and retains its diagnostics.
Mixed-language projects use source AST analysis so non-C/C++ files are not silently
excluded. Explicit Clang on a mixed project blocks negative verdicts.

**AST support is not complete semantic analysis for every language.** Name-based
same-file call candidates are not a CFG/runtime reachability proof. Dynamic
dispatch, import linking, framework entry points, taint and cross-language FFI
are unresolved; SQL dialects, quoted procedure bodies and dynamic SQL have
additional coverage limits. Syntax analysis never clears missing/unreachable
targets as `not_affected`. Scoped negative source decisions remain restricted to
the guarded compiler-backed path.

Default APIs: `/api/item4/start`, `/api/item4/{review_id}/questions`,
`/api/item4/{review_id}/answers`, `/api/item4/reviews/{review_id}` and guarded
`/api/source/judge`. Older direct arm endpoints are compatibility interfaces.
SQLite retains reviews/questionnaires for 24 hours and completed identification
jobs for seven days, including across backend restart.
See [the #4 contract](docs/CWE_FIRST_ITEM4.md).

## Models and retrieval

Only `vex-writer` is permitted by `src/inference_policy.py`. The final writer
receives a locked status, product, CVE, evidence IDs and analysis scope. It cannot
change the decision. Invalid/repetitive drafts are rejected and at most one
corrective writing attempt is made; rule evidence can still be exported.

Condition/function extraction uses literal source spans and pattern rules. These
partial observations do not establish a complete exploitation-condition set or
independently verified CVE-to-function mapping. Source review never consumes old
LLM mapping caches. Operational questions use source-linked CWE templates, and
answers are summarized by rules. Exact vendor-fixed builds plus scoped attested
installation records can support `fixed`; unverified reports retain investigation.
Legacy model-generated questionnaires must be regenerated before answer submission.

Model runtime loads the writer adapter directly; L2/L3/L4 or operational adapter
files are not prerequisites. GPU memory is required only for writing. If the
writer is unavailable, the assigned status/evidence remain available for export.
No independent vector-RAG or Claude/Gemini service is connected. Retrieval uses
CPE/NVD/CISA indexes and the pinned source catalog.

## Datasets and training

Earlier L2/L3/L4/operational training datasets and reports are historical experiments, not active inference dependencies.

Maintained dataset paths are resolved by `src/dataset_paths.py`. Public SBOM
readers use `sbom_index.json.source_directory` under `data/public_sbom/`.
Tests consume this retained snapshot; they do not reproduce retired-corpus
performance figures. The retained `operational_curriculum_v3` and
`operational_review_benchmark_v2` belong to earlier training/annotation work;
operational inference and its model queues are now disabled.
Old preparation/repair entry points verify the retained benchmark without
recreating deleted inputs. Frozen manifests keep their historical provenance.

Refresh the CPE dictionary with `python tools/refresh_cpe_feed.py`. It verifies
the official NVD 2.0 bulk publication, applies API modifications through a pinned
UTC cutoff, and atomically publishes non-deprecated entries for the corpus's
vendors. Provenance and progress are in `data/cpe_feed/provenance.json` and
`results/cpe_dictionary_refresh.json`. The CPE dictionary refresh does not update
the separate CVE applicability index or make earlier evaluation scores current.

| Historical dataset snapshot | Train | Validation | Test | Reference status |
| --- | ---: | ---: | ---: | --- |
| #3 L2 (legacy name contract) | 4,096 | 1,024 | 1,024 | Historical NVD-derived/procedural |
| #3 L3 | 4,096 | 1,024 | 1,024 | Procedural versions/abstention |
| #3 L4 | 4,096 | 1,024 | 1,024 | Dictionary/procedural |
| #4 v3 unique real CVEs | 800 | 100 | 100 | Independent references pending |
| #4 source-required predictions | 675 | 76 | 89 | Policy predictions, not gold |
| #4 operational predictions | 31 | 10 | 5 | Policy predictions, not gold |
| #4 unresolved routing | 94 | 14 | 6 | Deferred |

#4 has **1,000 unique CVEs**, reused in **1,840 simulated control-flow scenarios**.
Scenarios do not assert complete source exists. Role queues inherit the original
group split: zero cross-split group overlap, without established vendor/product-family
independence.

**Independent gold: 0. Real-CVE train-ready v3 examples: 0. Real-CVE supervised
training has not started.** Separate experimental operational-role pretraining
started on 2026-11-02, 22:53 KST, using controlled synthetic data: 800/100/100 per
role; both runs/evaluations finished on 2026-11-03 at 00:12 KST. These were
experiments on the previous model-generated question/assessment contract.
Their adapters are not used by the current rule pipeline, and their scores do
not measure its accuracy.
See [run details and progress paths](docs/ITEM4_ROLE_TUNING.md).
Only 46 inputs currently qualify for operator review; expansion and policy
adjudication are needed before reliable per-type training/evaluation claims.

Retained historical sets: source fixtures 800/100/100; conditions 386/59/50;
writer 800/100; operational curricula 800/100 per role. Their targets/weights are
not qualified for the new #4 contract. Legacy hashes are registered.
See [the inventory](docs/DATASET_INVENTORY.md).
Rebuild queues: `python tools/build_item4_v3.py`.

## Cohen’s κ and evaluation

Cohen’s κ measures **two-rater categorical agreement corrected for chance**:
`κ = (p_o - p_e) / (1 - p_e)`. It is not accuracy or proof of correct labels.
See the [official definition](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.cohen_kappa_score.html).

Use **independent, pre-adjudication ratings** on fixed aligned units, separately
for routing, condition/function support, question support, operator answerability
and VEX status, and separately by split. Report raw agreement, sample size,
label marginals, confusion, missing/unmatched units and group-bootstrap uncertainty.
Missing ratings differ from explicit `unknown`; single identical-category ratings
have undefined κ. No universal κ threshold establishes annotation correctness.

```powershell
python tools/eval_reviewer_agreement.py --a reviewer-a.jsonl --b reviewer-b.jsonl --output results/reviewer-agreement.json
```

The tool rejects adjudicated ratings, duplicate/misaligned units and identical
rater identities. Claude/Gemini agreement is **cross-model agreement**, not human
agreement or gold. Metadata cannot prove blinding/independence.
**Current κ: unavailable — no independent paired ratings collected.**
See [the rating protocol](docs/REVIEWER_AGREEMENT.md).

## Historical research and current evaluation limits

Operational input expansion found 563 eligible real CVEs: 385 train candidates,
63 validation, 48 test and 67 quarantined split-bridge cases. These remain
unlabelled. Current extraction uses source-span rules and operational assessment
uses deterministic evidence gates. The historical Clang campaign processed all
267 snapshots (222 partial / 45
blocked; 174 with project functions); all remain under investigation. The first
same-base pilot completed 24 operational and 16 mapping cases. Only two mapping
outputs passed their contract and both remained uncertain. Its LLM source-search
and mapping follow-ups are retired; the current source path excludes their caches.
Bounded LLVM def-use
paths support input-influence review but cannot prove non-controllability.
See [scope, limits and live progress](docs/LLM_REMEDIATION_RUN.md).

Evaluate routing, extraction, questions, assessment and authoring separately.
Report unsafe clearances, coverage and deferral alongside precision/recall.

## Verification and limitations

- CWE evidence policy, multilingual-source, four-workflow and writer-only regression on 2026-11-06: **295 passed**, including
  rejection of non-writer model roles, model-free identification aliases,
  rule questionnaires, operating evidence, writer contracts and compiler checks.
  All 944 profiles retain reported CWEs and route independently of assignment
  guidance grades. Discouraged/Prohibited metadata no longer blocks analysis.
  Software tests are not independently labelled CVEs or model accuracy.
- A historical model-based #4 smoke produced common/specific questions for one eligible CVE and
  excluded a source-required case. Acceptance required presentation normalization;
  raw strict format failed. Semantic accuracy was not measured. See `results/item4_v3_smoke/`.
- A historical #3 smoke completed eight components / 24 tuned calls without stage errors;
  this is integration coverage, not independent real-device accuracy.
- Historical condition-span literal support fell **85.86% → 54.50%** after tuning.
  The old candidate campaign's 77.12% scorable-subset precision failed its 80%
  criterion. Neither is a current unified-pipeline accuracy claim.
- A previous writer failed repetition checks. Rejected drafts remain excluded.
- **267** means collected CVE-associated source directories. Historical pycparser
  completed 0/267. The new Clang campaign processed 267/267; complete product/build
  applicability and exploitability verification are not established.
- Browser visual QA was restricted. Static/API/compiler checks do not establish
  visual quality or semantic correctness.
- Current live API verification completed rule-based CoreTec identification and
  a rule questionnaire without model inference. That single identification run
  took 6.18 seconds and returned 2 unique CVE candidates / 5 component links;
  this is a smoke observation, not a general latency or accuracy benchmark.
  See `results/writer_only_runtime_verification.json`. Actual GPU writer generation
  was not exercised in that verification; writer contracts use controlled outputs.

Historical reports remain in `results/four_hour_run_20261101/OUTCOME.json` and
`results/item3_identification_v2_run/summary.json`; retain frozen inputs/raw failures.

```powershell
python -m pytest tests -q
node tests/pages_bridge_test.cjs
node tests/shared_vex_export_test.cjs
```

## Workspace cleanup

Historical cleanup plans and verification are retained under `results/`.
The user executed the 2026-11-02 plan locally; its recorded logical size was
3,144.74 MiB, not measured physical recovered space. Old allowlists are dated
records and do not define current deletion targets. Current model requirements
are the Qwen base referenced by the writer and `models/vex-writer-qwen3-8b-v1/`.
Retired analysis weights are not inference dependencies. Preserve source/data
provenance and private review records when preparing any new cleanup plan.

## Corpus and publication

Snapshot recorded 2026-11-02: **3,881** CISA records, **3,879** collected advisories/
live synthetic SBOMs and **12,418** advisory CVEs. Two fetch failures remain
explicit; 17 advisory CVEs were missing from retrieved NVD feeds. Synthetic
inventories are not measured device data.

`sbom_index.json` selects the live `data/public_sbom/` snapshot. The overlapping
historical cohort was removed; readers now resolve the retained public snapshot.
Source commits, timestamps,
hashes and exclusions are retained in freshness metadata/refresh reports.

```powershell
gh api repos/cisagov/CSAF/commits/develop --jq .sha
python tools/refresh_public_corpus.py --commit <40-character-SHA>
python tools/build_pages_frontend.py
python tools/publish_pages_frontend.py
```

Restart after refresh. The publisher updates only explicit public assets, without
staging local work or uploading private reviews/source/weights. See
[corpus refresh](docs/PUBLIC_CORPUS_REFRESH.md). Request schemas are in `/docs`;
optional live NVD lookup reads the server-side `NVD_API_KEY`.

## Source map

| Path | Responsibility |
| --- | --- |
| `src/api_server.py` | FastAPI entry and generated UI |
| `src/candidate_web.py`, `src/unified_identification.py` | #3 jobs and L2/L3/L4 orchestration |
| `src/identity_retrieval.py`, `src/identity_evidence.py`, `src/identity_versions.py` | Retrieval, original-evidence acceptance and versions |
| `src/cwe_taxonomy.py`, `src/cwe_evidence_policy.py`, `src/vex_routing.py`, `data/cwe_evidence_policy_v2.json` | Official hierarchy, 944 detailed evidence profiles and CVE-specific routing |
| `src/item4_review.py` | Durable #4 review and mixed-branch aggregation |
| `src/rule_analysis.py`, `src/cve_source_evidence.py` | Literal source-span extraction, rule questions and answer summaries |
| `src/vex_roles.py` | Evidence packets, locked-decision authoring and writer validation |
| `src/source_evidence.py`, `src/multilang_source.py`, `src/clang_source.py` | Source AST, patch evidence and optional C/C++ build/CFG analysis |
| `src/operational_questions.py`, `src/operational_versions.py` | Rule questionnaire lifecycle, answers and scoped version evidence |
| `src/inference_policy.py`, `src/identification_agents.py`, `src/llm_output_schema.py` | Writer-only model boundary, lazy writer loading and output constraints |
| `src/sbom_vex.py`, `src/sbom_schema.py`, `src/review_store.py` | Export, schema validation and persistence |
| `src/reviewer_agreement.py`, `tools/eval_reviewer_agreement.py` | Pre-adjudication κ reporting |
| `data/item4_v3/`, `docs/CWE_FIRST_ITEM4.md` | Retained #4 cohort and current routing contract |
| `site/` | Generated public assets; edit generators instead |

Sources: [CISA CSAF](https://github.com/cisagov/CSAF),
[NVD feeds](https://nvd.nist.gov/vuln/data-feeds),
[CWE downloads](https://cwe.mitre.org/data/downloads.html), and upstream repositories
recorded in provenance. Third-party licenses remain applicable.

Source coverage on the dataset page is computed from nonempty CVE snapshot
folders intersected with the current advisory corpus. Compiler attempt coverage
comes separately from the selected Clang campaign. Missing local source does not
establish proprietary licensing or unobtainability. Snapshot presence establishes
neither vulnerable-version applicability nor whole-product build completeness.
