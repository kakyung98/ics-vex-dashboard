> Superseded routing, 2026-11-02: the active #4 flow first checks Pillar +
> specific CWE + CVE/advisory evidence. Missing required source immediately
> defers; only eligible operational cases enter the questionnaire. See
> [CWE-first revision](CWE_FIRST_ITEM4.md). The evaluation principles below still
> apply; previous source-unavailable-first routing is historical.

# No-source operational VEX: research direction

Status: **adopted design direction; not a deployment or performance claim**.
Recorded 2026-11-02 from the user-supplied `논문작성방향.md`.
The supplied document is retained unchanged in Downloads. Existing experimental
datasets, model outputs and published historical scores are not relabelled.

## Target pipeline

```text
Pinned CISA ICSA CSAF corpus
  -> grouped train / validation / test split
  -> training-only template discovery and versioned template registry

CVE / component case
  -> vendor-first CVSS + CWE classification context + advisory evidence
  -> select common templates in code
  -> generate additional CVE-specific questions with source-linked evidence
  -> validate citations and consolidate compatible duplicates
  -> collect actual operator facts, records and unknown answers
  -> classify evidence as applicability / mitigation / priority / insufficient
  -> apply reviewed, scoped decision rules with explicit uncertainty
  -> lock standard VEX status and evidence
  -> LLM writes explanation; reject unsupported or repetitive drafts
  -> CycloneDX + VEX, standalone OpenVEX/CSAF and review log
```

This direction supersedes an LLM-only operating questionnaire. LLMs propose
questions and draft explanations; they do not invent asset facts or change a
locked status. The failed v1 free-quotation extractor is not evidence of an
improved tuned model, or a sufficient authority for new negative decisions.

## Implemented versus required

| Area | Current implementation | Target work |
| --- | --- | --- |
| Shared case/evidence chain | Implemented | Preserve throughout the new flow |
| LLM operating questions | Base inference with citation/schema guards | Add training-derived common templates and the three comparison arms |
| Common template discovery | Not completed | Train-only advisory mitigation clustering; review and freeze resulting questions |
| Source-bound evidence | Catalog IDs and server-resolved quotations | Retain exact source offsets/hashes and independently review condition meaning |
| Product/version input | Shared component facts and explicit vendor fix checks | Retain provenance; add reviewed applicability predicates without guessing ordering |
| Standard status | Conservative code gates; explicit scoped fixed evidence supported | Add qualified applicability/refutation rules; no blanket clearance from controls |
| VEX authoring | Locked decision; validation and bounded retry | Resolve the remaining repetitive unknown-case draft failure |
| Real-CVE gold labels | Pending | Two independent human annotators; agreement before adjudication |
| Operating-role curricula | Fictional controlled training completed; not deployed | Do not equate curriculum agreement with real-CVE performance |
| Independent model review | Deferred at user request | Auxiliary review later; not a substitute for human inter-rater agreement |

## Evidence and decision policy

Classify each fact and question before using its answer:

- **Applicability:** explicit product, version, affected feature/configuration,
  or a vendor-supported necessary condition. Retain source and asset scope.
- **Mitigation:** segmentation, filtering, account restrictions and similar
  controls. Record these separately; they do not change standard VEX status in
  this research policy.
- **Priority:** confidentiality, process/safety impact, redundancy and recovery
  context. These affect review/remediation priority, not vulnerability absence.
- **Insufficient:** missing answers, unsupported necessity, contradictory records
  or an unknown required installation fact. Defer the relevant conclusion.

A disabled feature is not automatically a refutation. A decisive negative
finding requires a supported necessary-condition relationship, the corresponding
asset record, and a clear scope. An LLM-inferred requirement alone cannot grant
that authority. Source existence checks do not validate semantic necessity.

Likewise, product/version or reachability evidence must not be described as
verified runtime exploitation. Define what each standard status means for this
study and evaluate that claim rather than changing meanings between cases.

Retain AND/OR alternatives, negation and necessary-versus-suggested conditions.
Do not silently interpret every extracted condition as one exhaustive AND list.
Unknown handling applies to decision-relevant facts: a complete supported
refutation can be decisive despite an unrelated unknown answer. An unknown
required condition cannot be silently converted to yes or no.

The benchmark's adjudicated gold conditions are **evaluation references**, not
inputs to the tested runtime. If human-approved per-CVE rules are required in a
deployment experiment, declare that human input and evaluate the corresponding
human-assisted scope separately; do not inject held-out gold as an oracle.

## Templates, sources and reproducibility

- Treat Appendix A as seed questions for review, not already validated or
  empirically discovered templates.
- Derive mitigation phrase clusters and edit templates using training material
  only. Freeze template IDs, wording, selection rules and source hashes before
  validation/test generation.
- CVSS and CWE select candidate topics. They do not establish a CVE-specific
  feature, an administrator role or a complete exploit prerequisite set.
- Prefer the vendor CSAF vector where present; retain NVD vectors and report
  conflicts/missing values. Do not silently turn CVSS versions into each other.
- IEC 62443 / NIST SP 800-82 clause mappings require source verification.
  Record edition, section and support type. Unverified mappings remain pending;
  do not fabricate clause references or claim standards compliance.
- LLM-specific questions cite a stable passage ID and exact offsets. The server
  supplies the quotation. Measure relevance/necessity separately from mechanical
  citation correctness; copied source text can still support a wrong question.
- Freeze model/adapters, prompts, decoding settings, source catalog, template
  version and input hashes. If generating 3–5 times, specify the replicate/seed
  protocol and report run variation without treating repeated CVEs as new cases.

## Data split and annotation

Split by connected groups that prevent shared advisories and near-duplicates
crossing partitions. Product-family or vendor holdout is a stronger, separate
generalization test; advisory grouping alone does not establish it.

The existing real-CVE v2 cohort has 800/100/100 inputs and zero adjudicated labels.
Its manifest explicitly says product-family and vendor disjointness are false.
Audit it against this new protocol before reuse. Reuse is not automatically
authorized as a clean vendor-held-out benchmark. Do not alter frozen prior tests
to make the new split appear historical.

Use an approximately 20-case development pilot outside the main evaluation.
Two human evaluators independently annotate conditions, condition/question
mapping, question relevance/answerability and ambiguous scenario verdicts.
Preserve the pre-adjudication records. One author reviewing twice, or two LLM
outputs, must not be reported as two independent human raters.

Define fixed annotation units before computing Cohen's kappa. Free-form condition
inventories have different lengths; align the claim/category units and report
span/condition agreement separately. Report raw agreement, prevalence, sample
size and uncertainty as well as kappa. A target of 0.7 is not automatic proof of
gold-label correctness. Retain disagreements and unresolved cases explicitly.

## Operator simulation and scenario labels

Construct constrained scenario fact tables from independently reviewed advisory
conditions. Include satisfied conditions, supported refutations, unknowns,
conflicting records and mitigation-only changes. Exclude impossible combinations
of mutually exclusive versions/configurations.

The simulated operator receives only the question and scenario facts, without
the gold VEX label or the target system's prediction. Facts not in the table
must produce unknown. Validate a stratified sample of the simulated answers
manually, including negative/unknown and safety-relevant cases.

Scenario truth and predictions must not come from the same runtime decision
function. Review scenario labels independently; a shared-code consistency check
is an implementation test, not independent exploitability accuracy. Keep pilot
cases, repeated scenarios and the same CVE grouped during evaluation.

## RQ1–RQ3 evaluation

| RQ | Comparison | Required measurements |
| --- | --- | --- |
| RQ1 | Common templates | Judgment-condition recall by type; uncovered condition types |
| RQ2 | Template only / LLM only / hybrid | Condition recall, question precision, operator answerability, unsupported assumptions, repetition and run variation |
| RQ3 | Always defer / Description-only LLM / base versus tuned under the same contract | Per-status confusion matrix, macro metrics, unsafe clearance, deferral/coverage and counterfactual consistency |

Use the same source inputs, scenario facts, shared asset fields and annotation
policy across comparison arms. Score mitigation/priority questions separately;
asking about a firewall does not automatically cover a necessary CVE condition.
Duplicate questions cannot earn repeated coverage credit.

Report both safety denominators: (1) unsafe not_affected predictions among
gold-affected cases and (2) incorrect cases among predicted not_affected cases.
Also report erroneous fixed/combined clearance, so relabelling an unsafe result
as fixed cannot escape the safety metric. Always report coverage and deferral
alongside precision; always-defer is a useful zero-coverage control, not a
successful automation result. Cluster uncertainty estimates by CVE/advisory,
not by repeated question or scenario rows.

## Literature/standards corrections to the supplied draft

1. Do not say all existing tools require source or container access.
   cve-bin-tool explicitly accepts SBOM/component lists and binaries. Compare
   operational-question generation and evidence-based disposition capabilities
   individually. Name the control **always-defer**, not “cve-bin-tool behavior”.
2. CVSS v4 AT is not a generic indicator for every special vulnerable
   configuration. FIRST explicitly distinguishes those configurations from AT.
   Obtain CVE-specific configuration requirements from the advisory evidence.
3. A physically copied quotation is not a semantic correctness metric. Retain
   the v1 quotation-regression result and evaluate the new selection contract
   separately on unchanged held-out inputs.

Primary references checked 2026-11-02:

- [CVE Binary Tool official overview](https://cve-bin-tool.readthedocs.io/en/latest/README.html)
- [FIRST CVSS v4 FAQ](https://www.first.org/cvss/v4.0/faq)
- [OpenVEX specification](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)

## Implementation order

1. Freeze the grouped corpus/splits and annotation guide; retain the pilot split.
2. Define versioned applicability/mitigation/priority question contracts and a
   training-only seed/template registry with verified references.
3. Implement template-only, LLM-only and hybrid generation under one interface;
   retain deterministic citation validation and compatible deduplication.
4. Implement scoped evidence predicates and the conservative locked-decision
   rules. Do not promote unreviewed LLM condition hypotheses into clearance.
5. Build the independently labelled scenario/operator evaluation harness and
   baseline comparisons. Obtain human labels before claiming semantic accuracy.
6. Train only from qualified training labels; compare base/tuned with identical
   contracts and report the complete chain separately from individual roles.

External Claude/Gemini API dispatch remains deferred. This plan does not activate
the experimental operating adapters, create gold labels, retrain a model or
change production VEX verdicts by itself.
