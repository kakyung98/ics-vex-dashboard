# Separate learning and evaluation for operational review

> Updated target protocol: [NO_SOURCE_RESEARCH_PLAN.md](NO_SOURCE_RESEARCH_PLAN.md).
> It adds common-template / LLM / hybrid comparisons, human pre-adjudication
> agreement, independent scenario labels and scoped locked-decision safety tests.

Status 2026-11-02: deployed base inference is connected and smoke-tested.
Experimental curriculum adapter training has started separately; no real-CVE
accuracy score or deployment approval is claimed. See
`results/operational_role_finetune_v2/queue_status.json` for live status. The existing condition extractor and VEX writer are different
trained roles and their old metrics do not validate these new stages.

## Two targets

| Role | Input | Learning target | Independent evaluation |
| --- | --- | --- | --- |
| Question generation | CVE Description, CVSS/CWE context, product | Necessary operating facts expressed as answerable questions, with supporting spans | Condition coverage, unsupported assumptions, operator answerability, non-leading wording, literal evidence support |
| Operational assessment | Same CVE, stored questions, operator answers and evidence | Scoped advisory likelihood, cited facts, uncertainty and missing information | Per-class precision/recall/F1, confusion matrix, unsafe clearance, abstention/coverage, supported explanation claims |

Use separate LoRA adapters on the shared Qwen base. Compare base and tuned
predictions on identical frozen inputs, schema, prompts and token budgets. Keep
the condition extractor and VEX writer fixed while measuring these new roles;
then measure the complete chain separately. A generated explanation is not a
label. Exact wording agreement is not a semantic question-generation metric.

## Current input cohort

Version 2 in `data/operational_review_benchmark_v2/` supersedes version 1 for
future real-CVE annotation/training. The v1 audit found 28 cross-split
near-duplicate candidates and empty CVSS/CWE annotation fields. V2 conservatively
groups same-advisory connected components and all 67 candidate pairs across the
whole cohort (character TF-IDF cosine >=0.85). It retains 800/100/100 allocation,
585 groups, maximum group size 247, zero cross-split group overlap, and pins the
20 external-review development inputs to train. CVSS is available for 961 CVEs,
CWE for 930; other entries remain missing. Shared vendors/product families and
semantic independence still need review. No original frozen input was changed.

Separate **fictional curriculum v2**, in `data/operational_curriculum_v2/`, has
800 training and 100 validation cases for each role; it contains no real CVE
test labels. Training scenarios have 200 examples per advisory class, shuffled
independently of feature-family names. V1 curriculum was rejected before training
because family identity could reveal the label. V2 still shares a generation
grammar across splits, so its evaluation is controlled structural agreement,
not real-world generalization or independent exploitability correctness.
The two 1-epoch QLoRA runs are serial, with base/tuned validation on the same
100 controlled inputs per role. Outputs go to
`models/{operation-questions,operation-assessment}-qwen3-8b-curriculum-v2` and are
not deployed. The real-CVE benchmark remains pending. External APIs stay off.

`data/operational_review_benchmark_v1/manifest.json` freezes **1,000 real local
NVD CVE inputs**, allocated 800 train / 100 validation / 100 test. These are new
operational-review annotation inputs, not the existing synthetic source-code
programs or the earlier authoring/extraction training rows. All labels are
pending; `adjudicated_examples=0`, `training_started=false` and
`accuracy_evaluated=false` are explicit.

The allocation is an annotation-budget target at 80:10:10, not a power calculation
or evidence of enough rare dangerous cases. It keeps CVE IDs and identical
normalized descriptions disjoint. Near duplicates, shared advisories and product
families still need a similarity/group audit before training. Product-family
disjointness is NOT claimed. Reserve a separate family/vendor-disjoint stress
set for generalization. Previously inspected Satel CVEs are development-only and
excluded. All operating scenarios for one CVE inherit its split.

For each CVE, reviewers must establish explicit necessary conditions and any
AND/OR alternatives, supporting spans, question intent, and realistic operating
scenarios. Mark scenarios as observed or synthetic; invented scenario facts may
be used for controlled tests only with that provenance, never as observed asset
facts. Include unknown/missing answers, contradictory reports, evidence-free
assertions, disabled-vs-absent features, reported-vs-verified patches, unknown
versions, alternative attack paths and mitigation-only cases.

Two independent human reviewers annotate without seeing the model answer;
disagreements go to an adjudicator. Preserve individual ratings and the final
adjudication. Do not turn generated draft questions, rule labels or another
LLM's vote into independent gold. Gold requires source review and the full
operating scenario. Pending rows cannot be used for reliability claims or
silently converted into supervised targets.

## Evaluation implementation

`src/operational_evaluation.py` and `tools/eval_operational_roles.py` reject
pending/weak/model-only gold. Question semantic ratings are supplied by human
reviewers, bound to the exact prediction hash. Automatic quote checking is
reported separately. A missing prediction counts as missing coverage; an
invalid/absent assessment stays in the denominator. The assessment report
includes every class, dangerous `likely_affected → likely_not_affected` errors,
all unsupported clearances, abstention/invalid rate and decision coverage.

The question gold JSONL has `id`, `split: test`, `description`,
`required_conditions: [{id, ...}]` and adjudication metadata. Predictions use
`{id, questions: [{question, evidence, ...}]}`. Question-review JSONL adds the
prediction SHA-256 and one rating per question: `condition_ids`,
`operator_answerable`, `no_unsupported_assumptions`, `non_leading`. Assessment
gold/predictions use an operating-scenario `id` and advisory `assessment`.
Gold metadata includes `review_status: adjudicated`, at least two distinct
`reviewers`, an `adjudicator`, and
`annotation_basis: human_reviewed_source_and_scenario`.

```powershell
python tools/eval_operational_roles.py --role assessment --gold adjudicated-test-scenarios.jsonl --predictions tuned-test-predictions.jsonl --output results/operational-assessment-test.json
python tools/eval_operational_roles.py --role questions --gold adjudicated-test-cves.jsonl --predictions tuned-test-questions.jsonl --question-reviews independent-question-reviews.jsonl --output results/operational-questions-test.json
```

The numeric semantic question scores require adjudicated ratings of the actual
predictions; an LLM-based semantic matcher is not substituted. Explanation
faithfulness and operator usability still need their own human rubric; the
current scoring utility does not claim to automate those evaluations.

## Acceptance and timing

Choose acceptance thresholds before the final test, based on operational risk.
Do not optimize on the held-out test or exclude abstentions to raise precision.
Report confidence intervals and class counts. Even **zero** dangerous errors
among 100 genuinely affected independent cases has a Wilson two-sided 95% upper
bound around **3.7%**. A 100-CVE mixed-class test is weaker still. About 381
independent affected cases with zero such errors are needed for that upper bound
to fall below 1%; this is a planning calculation, not a reliability guarantee.

Implementation, supervised tuning and automated comparison are provisionally
3–5 working days including the remaining earlier work, excluding annotation
waiting time. Two-reviewer dataset adjudication can dominate calendar time;
2–4 weeks is a provisional staffing-dependent estimate, not a completion promise.
Time the first 20 CVEs and their scenarios before fixing the full schedule.
Until independently adjudicated targets exist, do not launch another weak-label
run and present it as verified operational reasoning.

## Claude / Gemini review option

The two external models may act as independent-of-each-other **model reviewers**:
they receive identical CVE inputs and never each other's proposals. Use their
span-grounded suggestions to create training drafts, flag disagreement and
prioritize human checks. Cross-model agreement is labeled model consensus / weak
reference, not `human_reviewed_source_and_scenario`, and cannot pass the strict
human-gold evaluation gate above. In particular, review every negative-clearance
proposal and do not count a model-assigned name as a human reviewer.

`python tools/export_operational_blind_review.py` creates identical 20-CVE **train
only** pilot packets in `results/operational_blind_review_pilot/`. It makes no
external API calls, contains no user operational records, and does not expose
the held-out test. API dispatch needs explicit configured provider credentials
and model IDs; neither provider is currently connected. Keys belong in local
environment variables, never in chat, reports, public Pages or Git.

Automatic API review was selected by the user. Configure the four user-level
environment variables with `tools/Set-ReviewApiConfig.ps1` in your own PowerShell
window, then run:

```powershell
python tools/run_operational_cross_review.py --check
python tools/run_operational_cross_review.py --limit 20
```

The runner requires `ANTHROPIC_API_KEY`, `GEMINI_API_KEY` (or `GOOGLE_API_KEY`),
`CLAUDE_REVIEW_MODEL` and `GEMINI_REVIEW_MODEL`. Model IDs are explicit so no
unverified default or surprise model substitution is billed. It sends each pilot
CVE to both providers independently, uses key headers rather than URL secrets,
disables redirects and retains response/model/usage/input hashes. Existing
receipts prevent silent repeat billing; retries need `--retry-incomplete`.
Failures and literal-quote/schema rejections remain incomplete, not agreement.
Span overlap is a diagnostic, not semantic agreement or human gold. All outputs
remain `trainable: false` until a separate annotation quality/adjudication step.

Only exported **public CVE inputs** are sent by this pilot, not uploaded source
or user operating records. It never dispatches the remaining 980 cases
automatically. Provider costs and latency must be measured on this pilot before
deciding a full-run budget. Current status: missing both keys and model IDs,
therefore zero external model calls; this is not a completed external review.
