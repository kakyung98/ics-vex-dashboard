# CVE-specific operational questionnaires

> Target direction: [NO_SOURCE_RESEARCH_PLAN.md](NO_SOURCE_RESEARCH_PLAN.md).
> Train-derived templates, hybrid questions and independent RQ1–RQ3 evaluation
> are planned there. The current implementation below does not yet provide all
> of those stages.

Updated 2026-11-02. The no-source analyzer uses this flow:

1. Resolve CVE Description, CVSS, CWE context and pinned CISA CSAF statements.
2. Attempt the trained condition/function extractor. Preserve any rejected raw
   output. When quotation or condition-scope checks fail, a separate base-model
   source-ID selection attempt is validated against the supplied catalog; the
   server resolves exact quotations. This is not a repair of invented quotes.
3. Generate up to six source-linked operational questions using the shared
   Qwen3-8B base. Reject attack-label-as-feature questions, invented privilege
   requirements, duplicate version questions and requests to decide whether
   exploitation succeeds. One corrective regeneration is allowed, with both
   attempts retained. Fully identical duplicate question records are collapsed
   with a normalization log while the original raw prediction is retained;
   conflicting duplicate metadata and invalid-source rows still reject the set.
   Structural/source checks are not semantic certification.
4. Collect actual product family, installed version, presence and an attested
   installation record once per component. Add a system patch-confirmation
   question per CVE. Missing fields remain unknown; the LLM never invents facts.
5. Compare explicit vendor product statuses or explicit fixed-version statements
   against that component. Unlisted custom versions remain unknown; no lexical
   version ordering or inferred product family is used.
6. Generate an advisory operational assessment. Evidence gates produce a separate
   effective explanation; an unsupported raw `likely_affected` explanation cannot
   be combined with a downgraded `likely_cannot_determine` result.
7. The trained VEX writer receives that effective decision and explanation.
   Token-level JSON constraints complement reference/status/quotation checks.
   Optional `missing_evidence` is retained as metadata; missing required fields
   and unsupported fields still reject the draft. Explanations are length-bounded,
   repeated sentences are rejected, and one corrective authoring attempt is
   allowed. Failed raw outputs and attempt input hashes remain in the review log.
8. Merge accepted decisions into a copy of the original CycloneDX document,
   preserving components/dependencies/metadata, and validate against cached
   official schemas. Standalone OpenVEX/CSAF and a separate review log remain
   available. The original input file is never modified.

`POST /api/oc/questions` takes `cves`, `product`, `simulation`, and optionally an
`identification_job`. With a job ID, the server uses the stored candidate handoff
instead of trusting replacement client CVEs. Existing cached CVE facts take
precedence over supplied Description/vector text. A nonexistent local CVE can
use explicitly supplied facts; these are input data, not verified official facts.

`POST /api/oc/answers` takes `plan_id`, server-issued question IDs in
`answers`, and component-reference-keyed `component_facts` containing `present`,
`product_name`, `installed_version`, `evidence`, `attested`. Clients cannot submit
new questions, a decision rule or a VEX status. Foreign IDs and invalid answers
are rejected. The old per-CVE version field is deprecated and hidden in the UI.

Plans/reviews are persisted locally in `results/runtime_sessions.sqlite3` for
24 hours; completed identification jobs persist for seven days. Memory caches
are bounded but eviction/restart does not delete persisted completed work.
Interrupted identification jobs require a rerun. Operational records are not
published to Pages. `GET /api/oc/reviews/{plan_id}/sbom` retrieves the merged
CycloneDX export while the review is retained. SPDX input retains standalone
VEX export; embedded SPDX VEX is not implemented.

## Likelihood and standard status

The advisory vocabulary is `likely_affected`, `likely_not_affected`,
`likely_mitigated`, `likely_cannot_determine`. It is not the standard VEX enum.
An accepted model likelihood still requires human review. If generation or
assessment fails, no answer is supplied, or no cited answered item has a
supporting record, the effective likelihood is `likely_cannot_determine`.

The standard status remains `under_investigation` unless every active scoped
component matches an explicit vendor-fixed version and has an operator-attested
installation record. That supports a **scoped `fixed`** result; it is still an
operator report, not independently verified deployment identity. A disabled
feature/firewall, unsupported patch assertion or unknown version cannot become
verified `not_affected`. Export fanout preserves unknown status for other BOM
component occurrences; a fixed finding must not propagate to unconfirmed rows.

The legacy `/api/oc/judge` and candidate `/oc` routes retain the earlier structured
OC evaluator for compatibility/experiments; they do not implement this new
questionnaire contract. The interactive analyzer now uses `/questions` then
`/answers`. CWE is classification context only. This implementation does not
pretend to analyze a patch diff when no diff has been supplied to the question
generator, or invent a vulnerable function absent from the CVE text.

## Model and verification limits

The deployed question generation and operational assessment still use **base
inference** and have not been independently evaluated for accuracy. Separate
experimental curriculum training completed 2026-11-02; its adapters are not
automatically activated or independently validated. Both deployed roles share the existing locked quantized
base; extraction and authoring retain their respective trained adapters. Base
question/assessment generation uses 6,144 input / 1,536 output token limits with
no silent input truncation. The writer uses 6,144 input / 1,536 output tokens. Over-budget
packets fail visibly; inputs are never silently truncated.

`tests/test_operational_questions.py` exercises case/answer/writer binding,
unknown handling, quote/reference rejection, cross-plan answer rejection and
expiration with mocked inference. `tools/smoke_operational_questions.py` calls
the running real server and saves `results/operational_questionnaire_gpu_smoke.json`.
It submits **no operational facts**: this verifies actual calls and failure
handling, not exploitability accuracy. Do not use the model's own answers or
likelihoods as independent evaluation ground truth.

The latest real-server development smoke generated four operational questions
for CVE-2026-101024, accepted the question schema/quotes and assessment schema,
and accepted a writer draft in 95.8 seconds (including cold model loading).
With all answers unknown it retained `likely_cannot_determine` and standard
`under_investigation`. Description extraction was still rejected; this is NOT a
fully accepted extraction-to-authoring chain or a performance benchmark.

Separate supervised-role targets and independent evaluation are specified in
[OPERATIONAL_ROLE_EVALUATION.md](OPERATIONAL_ROLE_EVALUATION.md). The 1,000-CVE
800/100/100 input cohort has a corrected version 2 with advisory/near-duplicate
group separation and CVSS/CWE enrichment; its human labels are still pending.
