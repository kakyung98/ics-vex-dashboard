# Full-population automatic operating VEX

The 2026-11-18 logic corrections use `source-bound-operational-auto-vex/3`.
BOM profiles must preserve the regenerated component's product and build at
save, assessment and export. An unresolved competing version-status row keeps
version applicability unknown. The separate four-stage API also uses server
time for evidence validity and rejects expired definitive exports.

The subsequent version-parser work uses `source-bound-operational-auto-vex/4`
and `source-version-parser/2`. It reinterprets each row's preserved
`version_text` without modifying the frozen compiled catalog or source hashes.
The source-present decision trace records the parser version and the newly
computed row memberships. Numeric VERS intdot intervals, explicit underscore
conjunctions and bounded pipe sequences are supported. Generic versions use
only sound reflexive comparisons when ordering is undefined. Vendor-specific
ordering, qualified product/operating scope, invalid VERS all constraints and
nonconcrete installed builds stay unknown. In particular, observed `5.x`,
`R15x`, `master` or an affected-range expression is not an installed version.

The parser follows the [VERS interval specification](https://www.packageurl.org/docs/vers/specification.html)
and the [published general types](https://raw.githubusercontent.com/package-url/www.packageurl.org/main/website/docs/vers/vers-types.md).
It does not treat every pipe as OR or assign an invented natural ordering to
arbitrary vendor suffixes. `tests/test_source_version_parser.py` includes
boundary, exclusion, interval, ambiguity and independent integer-set tests.

The final parser replay is
`results/nist_population_vex_comparison_20261118_v4_release/`, with the
three-way report at `results/nist_version_parser_20261118_v4/comparison.html`.
All 37,254 cases and 12,418 CVEs are retained with no evaluation errors.
Original facts, labels, source bytes and the frozen clock are unchanged; only
plan hashes are resealed after checking question-plan equality except for the
engine version. `validation.json` verifies every output and reconstructed metric.

| Metric | Original v2 | Conservative v3 | Parser v4 |
| --- | ---: | ---: | ---: |
| Affected precision | 100% | 100% | 100% |
| Overall affected recall | 34.2256% | 33.1446% | 33.3799% |
| Overall abstention | 53.9835% | 54.5847% | 54.3807% |
| Four-state agreement on resolved references | 65.4463% | 64.5911% | 64.8813% |

Of the 224 cases deferred by v3, 98 return to their original status (54 affected,
44 fixed) and 126 remain unknown. Outside that development set, another 13
become affected and 35 become unknown (22 nonconcrete installed versions and
13 untranslated/qualified source ranges). Thus v3 to v4 has 146 transitions;
all occur in source-present cases. The 224-case recovery is diagnostic because
those cases informed parser development, not a held-out accuracy measurement.

Two earlier intermediate attempts and a completed pre-whitespace-regression
run are retained with interruption/supersession markers. The final unchanged
evaluator used byte-identical temporary source copies after a 200-case pilot
matched all full assessment hashes, to avoid slow-volume metadata access.
`storage_validation.json` verifies 36 copied source files, unchanged engine
code and identical result-copy hashes. Final reports live on the project drive.
The final regression suite passed 319 tests and 731 subtests.

The original frozen 37,254-case report below describes the earlier engine
fingerprints and is preserved. A paired replay for the corrected engine is at
`results/nist_population_vex_comparison_20261118_v3/comparison.html` and
`comparison.json`. It retains all 12,418 CVEs, observations, source records,
reference labels and the original evaluation clock. Only `plan_sha256` is
resealed after checking complete plan equality except for the engine version.
`comparison_runner.py` preserves the executed runner. `replay_protocol.json`
pins the adapted inputs and exact reference copies; `validation.json` checks
coverage, labels, artifact preservation and metrics reconstructed from outputs.

| Metric | Previous engine | Corrected engine |
| --- | ---: | ---: |
| Cases / evaluation errors | 37,254 / 0 | 37,254 / 0 |
| Affected precision | 100% | 100% |
| Overall affected recall | 34.2256% | 33.1446% |
| Overall abstention | 53.9835% | 54.5847% |
| Four-state agreement on resolved references | 65.4463% | 64.5911% |

All 224 changed cases are source-present cases: 147 affected and 77 fixed
predictions become under investigation because competing version rows remain
untranslated. Component-absent and evidence-missing outputs do not change.
These changes increase abstention and reduce measured recall/agreement; they
do not establish improved real-world accuracy or prove the earlier fixed
claims were factually wrong. This replay calls the automatic evaluator directly;
BOM product binding, the separate API's clock and runtime packaging fixes are
covered by regression/integration tests rather than these synthetic inputs.

The target is the original **12,418 CVE IDs** in `asset_vulntology.catalogue()`. The eight manufacturer-specific adapters are specializations, not a whitelist. Every target passes through the source compiler and the same production evaluator. No CVE is removed because its source, product/version binding or operating conditions are incomplete.

## Inputs and decisions

The BOM identifies a component and candidate CVEs. The operator binds the actual asset instance and current evidence, then selects deployment, running-version and source-specific operating enums. Request validation rejects VEX status records, manually asserted predicate truth and arbitrary question IDs. Neither the runtime nor the experiment calls an LLM.

`src/nist_population_rules.py` binds original source product identities and preserves source AND/OR/NOT relations. Narrow enum adapters handle supported configuration atoms and recorded access paths. Unobservable attacker credentials, ambiguous relations and untranslated conditions stay unknown. `src/nist_auto_vex.py` combines exact component deployment, observed running-version applicability, evidence validity and the three-valued formula. Asset type never establishes a predicate by itself.

Source CSAF status rows retain the exact source filename, JSON pointers and SHA-256. Only explicit known_affected, fixed, known_not_affected and under_investigation memberships are used. Recommended/first_fixed entries do not become open-ended fixed ranges. Being outside an affected range does not establish not_affected. Unknown version ordering, overlapping contradictory statuses and unbound source models stay unresolved. Generic configuration-negative formulas cannot prove global non-exploitability because extraction is not exhaustive; complete inventory absence can still establish a scoped not_affected result.

The optional 54-row / 167-detail NIST catalogue remains available with English evidence. Operators answer only the CVE-relevant executable questions. Evidence identifiers, excerpts, scope and timestamps are provenance metadata; free prose is not interpreted for a verdict.

## Reproduction

Run commands from `D:\ICS-VEX`:

```
python -m pytest tests/test_nist_selectable_answers.py tests/test_nist_auto_vex.py tests/test_nist_auto_bom_integration.py tests/test_nist_population_vex.py -q
python -m tools.run_full_population_benchmark
python -m tools.render_population_vex_report
```

To repeat the paired comparison, choose a new output directory (existing
comparison directories are never overwritten):

```
python -m tools.compare_full_population_benchmark --output results/nist_population_vex_comparison_20261118_v3_repeat
python -m tools.verify_full_population_comparison --output results/nist_population_vex_comparison_20261118_v3_repeat
```

`tools/build_population_vex_catalogue.py` builds a **new versioned** catalogue from all 3,802 local CSAF documents and original source records. It refuses to overwrite an existing catalogue. `tools/build_full_population_benchmark.py` prepares three cases per original CVE and freezes inputs/reference hashes in `protocol.json`; it refuses to overwrite a frozen protocol. Do not change frozen inputs to improve a score. The runner checks exact CVE membership, three cases per ID, frozen hashes and unchanged engine/compiler/validation fingerprints, blocks network connections, and retains evaluation errors and unresolved references.

Current artifacts are under `results/nist_population_vex_20261118/benchmark/`: frozen `inputs.jsonl.gz`, separate `references.jsonl`, exact `population.json`, `protocol.json`, full `decisions.jsonl.gz`, `predictions.jsonl`, all-case `cases.csv`, `per_cve.json` and aggregate `report.json`. The public local UI report is `/nist-population-vex-method.html`; existing review-guide URLs resolve to it. Historical eight-rule reports are not whole-population results.

## Evaluation boundary

The 37,254 cases cover source-present, component-absent and evidence-missing worlds for every CVE. Reference labels are read from raw CSAF source status with a separate reference version interpreter; the evaluator does not produce its own labels. Source-present labels explicitly assume every latent prerequisite is satisfied, while operator inputs expose only representable facts. Missing source conditions therefore cause abstention or false negatives. Unresolved reference cases remain present, and an affected prediction without a resolved reference counts against precision.

This is a synthetic source-status consistency experiment, **not independent semantic, expert or real-world accuracy validation**. CSAF files are machine-extracted and can contain errors. The compiler and reference pipeline share the source corpus and project authorship. Three cases from the same CVE are correlated. Report full-population precision together with recall, abstention, unresolved references and per-scenario counts; never describe an earlier eight-CVE result as validation of all 12,418 CVEs.
