# Independent annotation agreement

Nominal, unweighted Cohen's kappa is `(p_o - p_e) / (1 - p_e)`. Observed agreement
is corrected using the two raters' empirical category frequencies.
[Official definition](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.cohen_kappa_score.html).

Freeze unit IDs, category vocabulary, rubric and evidence versions before rating.
Keep each independent response **before discussion/adjudication**. Distinct names
alone do not establish independent/blind review. Preserve disagreements.

| Task / dimension | Fixed unit | Suggested nominal labels |
| --- | --- | --- |
| Routing / source_requirement | CVE | source_required, operational_review, undetermined |
| Extraction / condition_support | Pre-aligned source claim | supported, unsupported, uncertain |
| Extraction / function_mapping | Pre-aligned target claim | supported, unsupported, uncertain |
| Questions / source_support | Frozen generated question | supported, unsupported, uncertain |
| Questions / operator_answerability | Frozen generated question | answerable, not_answerable, uncertain |
| Decision / vex_status | CVE × component × scenario | affected, not_affected, fixed, under_investigation |

Do not compare different questions under the same ID. Align free-form claims/spans
first; report span/condition coverage separately. The tool checks unit metadata,
not semantic equivalence or whether reviewers saw each other's answers.

Use one JSONL file per reviewer. Format illustration, not an actual rating:

```json
{"unit_id":"case-1:routing","case_id":"case-1","group_id":"advisory-group-1","split":"test","task":"routing","dimension":"source_requirement","rater_id":"actual-reviewer-a","rater_kind":"human","phase":"independent","label":"source_required"}
```

The second reviewer uses matching unit/case/group/split/task/dimension metadata.
Use null for missing labels. Explicit uncertainty is a category, not missingness.
Use the dataset's advisory/near-duplicate group ID for clustered uncertainty.

```powershell
python tools/eval_reviewer_agreement.py --a reviewer-a.jsonl --b reviewer-b.jsonl --output results/reviewer-agreement.json --bootstrap 1000 --seed 42
```

Outputs include per-stratum kappa, sample size, raw/chance agreement, marginals,
confusion, missing pairs and unmatched IDs. Incomplete pairs are excluded but
counted; systematic missingness can bias agreement. Validate the rubric vocabulary
before ingestion: the generic calculator accepts strings and cannot detect a
misspelled category.

Bootstrap intervals resample whole `group_id` clusters. Report undefined resamples;
percentiles condition on defined estimates and may be unstable for small/imbalanced
strata. Fewer than two groups, zero bootstrap repetitions or all undefined resamples
yield no interval. No paired ratings or a single identical category yield null
kappa, never an invented zero or perfect score.

Do not pool different tasks/dimensions/splits into a headline kappa. Statuses are
nominal, so no ordinal weights are used. Kappa is not accuracy, correct gold or a
safety guarantee. No universal 0.7/0.8 threshold establishes correctness.

Human reviewers use `rater_kind: human`. Later Claude/Gemini reviews use `model`
and are reported as **cross-model agreement**. Do not mix human/model files or
present model consensus as human gold. External APIs remain deferred; the tool
makes no model calls.

Current #4 v3 independent paired ratings: **0; kappa unavailable**. The calculator
is implemented; no real agreement score has been measured. Adjudicated final
references are for subsequent model evaluation, not substitutes for original ratings.
