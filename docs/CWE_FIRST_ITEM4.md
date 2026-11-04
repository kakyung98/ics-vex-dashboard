# #4 CWE-first evidence routing

Updated 2026-11-05 with four evidence workflows. User-selected basis: **Pillar + specific CWE + CVE / advisory evidence**.
The previous question “Do you have source?” no longer selects the default method.
No VEXGen attribution or TIX output is used.

## Runtime contract

1. Preserve each CVE's reported CWE IDs. Derive all Pillar ancestry paths using
   `ChildOf` edges in official CWE View 1000. Never replace the reported CWE by a Pillar.
2. Apply `data/item4_routing_policy_v1.json`. Explicit code-causality weakness
   ancestors or memory/concurrency evidence require source. Supported operational
   rules require both a specific CWE ancestry and matching CVE/advisory text.
3. Multiple CWEs: any source requirement wins; otherwise any unresolved mapping
   defers. A bare Pillar or missing/unsupported CWE is unresolved.
4. Source required + no source: immediately assign `under_investigation` with a
   missing-source rationale. **No extraction, operational question or writer call.**
5. Source supplied: language-aware AST source analysis runs for the required group
   (C, C++, Python, Java, SQL, JavaScript, Go, R, Ruby). No binary is required.
   Auto mode uses Clang/LLVM only for configured C/C++-only builds; otherwise it
   uses Tree-sitter source parsing. Syntax call candidates cannot authorize
   absence/unreachability clearance; dynamic/import/SQL coverage remains incomplete.
   Explicit context terms (remote/network access, authentication, privileges,
   configuration, enabled/disabled features, user interaction, local attacker or
   physical access) require a subsequent operating review. Exact triggering spans
   are retained. This is conservative routing, not complete condition extraction.
   Missing function mappings, compilation or scope blockers cannot establish absence.
6. Operator review uses deterministic source-span extraction and source-linked
   CWE rule templates with common/specific scopes. Operators supply observed
   facts and records. Answer summaries and version/evidence gates are rules.
   No question generator, assessment model, critic or base fallback is called.
7. Existing evidence/version gates lock the standard status before the trained
   writer drafts an explanation. A missing-source case cannot be cleared by facts
   supplied for another CVE on the same component.
8. A durable master review retains both branches, the original SBOM, policy/taxonomy
   hashes and per-CVE results. CycloneDX export merges every reviewed CVE into a
   copy of the original inventory. SPDX retains standalone VEX export.

## Four workflows and one decision

| Workflow | Ordered evidence | Missing evidence behavior |
| --- | --- | --- |
| 1. Source only | Source/build/path result | Retain analysis blockers |
| 2. Source → operating context | Source result, then operator records | No final authoring until both results exist |
| 3. Required source missing | No source result | `under_investigation`, no operator-answer bypass |
| 4. Operating context only | Rule questionnaire and installed-build records | Unknown facts remain unresolved |

Route schema 2 records separate `source_required` and `operational_required` axes,
`workflow_branch`, `entry_direction` and `workflow_policy_version=four-branch-v1`.
Unresolved routing remains an additional deferral, not a fifth evidence workflow.
Review schema 4 retains per-CVE `branch_evidence`, `evidence_progress` and an
append-only evidence hash/history. The original case ID is shared across stages.
Reopening an unchanged questionnaire retains IDs and restores submitted answers.
Operating-only questionnaires do not change the source requirement. There is no
custom-implementation escalation question or separate operating-to-source route.
Existing five-path reviews require a new review; their historical evidence is retained.

One deterministic combination step locks the status. Missing required results or
conflicting non-deferred branch statuses keep `under_investigation`; neither the
writer nor component-specific SBOM version merging may bypass that lock. A
submitted but inconclusive branch remains inconclusive evidence. Final writing
is permitted for its under-investigation explanation after both required results
exist. The writer receives summaries and references from both branches. Repeated
submission of identical evidence reuses the prior authoring result.

These changes do not introduce an `affected` classifier, independent operator
verification, exhaustive prerequisite coverage or a reviewed 944-CWE policy matrix.
The dataset counts below describe the earlier routing snapshot, not new four-path
ground truth or a revalidated benchmark.

The official hierarchy classifies weaknesses; **MITRE does not prescribe this
source/operational routing policy**. The current conservative fallback requires
source for specific weaknesses with known Pillar ancestry but no supported
operational rule. That fallback is a project choice, not proof that source is
technically indispensable. The narrow operational set needs expert policy review.

Official sources: [CWE downloads](https://cwe.mitre.org/data/downloads.html),
[View 1000](https://cwe.mitre.org/data/slices/1000.html),
[CWE glossary](https://cwe.mitre.org/documents/glossary/index.html).
Pinned catalog v5.0: 984 weakness records, 10 Pillars. Snapshot XML/ZIP hashes are
stored separately from project policy hashes; `defusedxml` parses the catalog.

## Operator question limits

Common topics come from the matched weakness-type rule, such as configured
protocols, enabled documented services and observable access paths. They are
topic proposals, not independently established necessary exploit conditions.
Specific questions cite the supplied CVE/advisory sources.

The new role prohibits source-function, taint, CFG, buffer/patch correctness,
attack reproduction and secret requests. Code validates scopes, source IDs,
lengths and certain unsupported question patterns. These checks **do not prove
semantic support or operator answerability**; independent review remains required.
A trailing citation annotation may be removed only when it repeats valid IDs already in the structured evidence field; the exact presentation change and original output are retained. This is not counted as strict model-format success or semantic validation.
Rejected questions are not replaced by fabricated facts or generic templates.
Installed product/version facts are collected once per component. `likely_*`
assessments remain advisory; unsupported standard verdicts stay under investigation.

## Dataset migration

Rebuild: `python tools/build_item4_v3.py`.
Output: `data/item4_v3/manifest.json`, split case/scenario files and six role queues.
Existing #4 source fixtures, curricula and weights are retained and registered as
**legacy, unqualified for this contract**. Real-CVE #4 supervised tuning has not
started. Separate new-contract controlled synthetic operational-role pretraining
launched on 2026-11-02; see [its scope and status](ITEM4_ROLE_TUNING.md).

| Unit | Train | Validation | Test |
| --- | ---: | ---: | ---: |
| Unique CVE inputs / routing annotation | 800 | 100 | 100 |
| Source-required policy predictions / source queue | 675 | 76 | 89 |
| Operational predictions / question and assessment queues | 31 | 10 | 5 |
| Unresolved routing | 94 | 14 | 6 |
| Extraction queue for potentially analyzable cases | 706 | 86 | 94 |
| Simulated branch scenarios / authoring queue | 1,475 | 176 | 189 |
| Independently adjudicated / train-ready examples | 0 | 0 | 0 |

There are **1,000 unique CVEs**, not 1,840 independent CVEs. Each source-required
CVE receives two control-flow variants: source missing / hypothetically supplied.
Actual complete source is not asserted. Missing-source `under_investigation` is
a structural policy expectation, never independent exploitability gold.
Authoring annotations include code-only deferrals for output completeness; runtime
does not call the writer for these cases.

All role rows and scenarios inherit the original CVE group split. Cross-split
group overlap is zero; vendor/product-family disjointness is not established.
Independent references are null. Old targets are not copied as new gold.
Only 46 CVEs currently qualify for operator review; this is too small/imbalanced
to claim a balanced new operational fine-tuning or reliable per-type evaluation.
Expand eligible types after adjudicating routing, rather than duplicating rows.

## Separate evaluation gates

- **Routing:** independent labels for source-required / operational / unresolved;
  report confusion matrix, macro F1, coverage, false-operational routing and deferral.
- **Extraction:** independently marked condition/function spans, literal support,
  semantic precision/recall and invented-condition rate. Missing mentions are not absence.
- **Questions:** common/specific coverage, CVE support, operator answerability,
  unnecessary/duplicate questions and unsupported-feature rate. Source linkage
  alone is insufficient. Derive future common templates from train only.
- **Assessment:** evidence-grounded advisory labels, unknown handling,
  counterfactual consistency and unsafe clearance rate, separated by branch.
- **Authoring/export:** locked-status consistency, evidence references, repetition,
  unsupported claims, schema validity and component binding. A well-formed draft
  is not a correct VEX determination.

Two independent reviewers and adjudication should establish references before
new SFT and held-out scoring. External Claude/Gemini API integration remains
deferred per the user's instruction; no external review is claimed.

## Main implementation files

- `src/cwe_taxonomy.py`, `tools/cache_cwe_taxonomy.py`: pinned official hierarchy.
- `src/vex_routing.py`, `data/item4_routing_policy_v1.json`: auditable project policy.
- `src/item4_review.py`: durable per-CVE routing and mixed-branch aggregation.
- `src/item4_questions.py`: common/specific operator-facing LLM contract.
- `src/api_server.py`: `/api/item4/start`, `/api/item4/{id}/questions`,
  `/api/item4/{id}/answers`, `/api/item4/reviews/{id}` and guarded source integration.
- `src/method_flows.py`, `src/source_decision_page.py`: English UI flow and boundaries.

Older direct source / operational endpoints remain compatibility interfaces for
historical experiments; the default webpage uses the CWE-first master review.

## Verification on 2026-11-02

168 automated tests passed, including mixed-branch preservation, source-group
locking, source absence without model calls, branch-scoped operator questions,
truncated-output retry and original CycloneDX binding. Frontend/export JS checks
passed. Public deployment run 41451653142 completed successfully.

A real local Qwen smoke for CVE-2026-64893 generated both common/specific questions;
a source-required fixture was excluded. The questions were accepted **after
presentation normalization** of duplicate trailing source-ID annotations. Raw
model format success was false. Original failures/attempts are retained under
`results/item4_v3_smoke_attempt1`, `...attempt2`, and the latest `...smoke`.
This one-case contract smoke is not semantic accuracy, operator-answerability,
or independent held-out performance. No new fine-tuning or external model API
review was performed for this contract. Browser visual QA was unavailable due
to the saved browser policy; static generation and code/API checks were used.
