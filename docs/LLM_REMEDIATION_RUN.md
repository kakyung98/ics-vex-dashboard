# Autonomous remediation: items 3, 4, 6, 8 and new source campaign

Current cleanup note (2026-11-03): the free-quotation and old operational
adapter weights are retired. Historical results below are preserved; they are
not instructions to reload the retired models. The runtime free-quote loader
and its training CLI role are disabled.

Started 2026-11-02 KST. LLM outputs remain proposals, not independent gold.
Existing operational-role training continues; research inference waits for that
queue to finish and claims the same GPU admission lease.

## Item 3: expand operational data

`tools/expand_operational_pool.py` scans all 12,527 cached CVEs with pinned CWE
ancestry and hash-checked CISA CSAF summaries. It finds **563** policy-eligible
operational CVEs, compared with 46 in the old 1,000-CVE random cohort.

| Partition | CVEs |
| --- | ---: |
| Train input candidates | 385 |
| Validation inputs | 63 |
| Test inputs | 48 |
| Quarantined frozen-split bridges | 67 |

Global advisory connections, existing frozen groups, exact descriptions and
eligible-cohort character TF-IDF near-duplicates are grouped. If a new connection
bridges multiple old frozen splits, the whole component is quarantined instead
of silently moving test cases into training. No old annotation files change.
These 563 inputs are not 563 gold references. All real `train_ready` flags remain
false. Multiple simulated scenarios must not be counted as independent CVEs.

`data/operational_expansion_v1/manifest.json` records the source hashes and splits.
The first queued LLM pilot selects up to 24 training CVEs, round-robin by routing
rule and with distinct global groups. It prepares condition selections, common/
specific questions, same-base critique and counterfactual safety probes.

## Item 4: stop generating evidence quotations

The active `vex_roles.extraction` defaults to **source-ID selection**, not the
regressed free-quotation adapter. The server resolves selected IDs into original
text. Unknown IDs, policy-invalid conditions and unmentioned function identifiers
are rejected, without falling back to invented quotations.

The default same-base condition critic separately reviews support, necessity and
alternatives. Unsupported/context-only claims are filtered from effective condition
candidates without rewriting their original quotations; original selections and
critic output remain recorded. Failed critic contracts defer extraction. This is
not independent verification. `ICSVEX_CONDITION_SELF_REVIEW=0` is an explicit
comparison switch; it does not create gold or clearance authority.

The old adapter remains an explicit comparison path using
`ICSVEX_EXTRACTION_STRATEGY=legacy_quotes`. Historical free-quote tests explicitly
select that mode; separate tests exercise the deployed source-ID default.

Literal grounding is now enforced by construction. This must **not** be reported
as improving the old 54.50% model quotation metric to 100% accuracy. Selection
completeness and semantic necessity are still unverified. `can_refute` stays false.

## Item 6: operational-answer reliability

`src/operational_guardrails.py` defers advisory labels when installed product/version
applicability is unresolved, questions/assessment fail their contract, no actual
operating answer has a supporting record, the model cites only system patch
questions, or identical questions have conflicting answers.

The raw model suggestion is retained separately. Exact scoped vendor-fixed-build
evidence retains its existing formal fixed-status gate. Neither an LLM advisory
label nor an operator assertion becomes verified source absence.

Queued real-CVE probes simulate all-unknown answers, yes answers without records,
and unknown installed versions. These have **policy safety expectations**, not
independent exploitability gold. Both raw model output and code-gated output are
recorded, so code safeguards cannot conceal model errors.

## Item 8: function mapping and input influence

`research-source-map` selects only supplied compiler-backed project function IDs
and Description/patch evidence IDs. Code checks literal function mentions and
matching patch-function/file context. A mapping can remain uncertain; neither a
valid ID nor a patch-header match proves complete CVE causality.

When proposals become available, `src/source_mapping_assist.py` can add candidate
names to uploaded-source analysis only after a unique path and full source-file
SHA-256 match. It never adds them to the independently referenced target set;
the existing source evidence gate prevents LLM-only candidates from authorizing
absence/unreachability clearance. Changed source bytes invalidate reuse.

`research-control` proposes input/guard/sink candidates from supplied code facts.
It cannot emit a standard VEX status or a non-controllability proof. Research
results retain `attacker_control: unknown` until supported by appropriate evidence.

`src/source_dataflow.py` adds bounded LLVM def-use analysis, including exact-address
loads/stores and direct interprocedural parameter/return dependencies. It records
dependency paths under explicitly declared parameter sources. A real collected
zlib unit produced a `compress` parameter → `compress2` parameter dependency;
this is a tool smoke, **not** localization or exploitation proof for that CVE.

No-path results remain unknown. General alias/heap effects, external calls,
concurrency, path feasibility and actual attacker-input provenance remain limits.
Negative VEX authority is disabled for this module. See
[LLVM alias analysis](https://llvm.org/docs/AliasAnalysis.html) and
[Clang data-flow introduction](https://clang.llvm.org/docs/DataFlowAnalysisIntro.html).

CLI example:

```powershell
python tools/analyze_source_dataflow.py --root path/to/source --file unit.c --source entry:0 --target target_function --output results/dataflow.json
```

## Item 7: fresh 267-snapshot Clang campaign

Current run: `results/source_clang_batch_v3/`; the current pointer is
`results/current_source_campaign.json`. The new run does not reuse the old
pycparser verdicts. Two CPU workers run alongside GPU training, with bounded
translation units and per-snapshot timeouts.

Early attempts exposed a nullable source-location path and incorrect LLVM Windows
backslash/hex decoding. Both were corrected and regression-tested. Earlier runs
remain diagnostic attempts, not current coverage results. SDK-emitted inline
functions are counted separately from functions bound to collected project files.

Missing compilation databases use explicit **discovery** configurations, never
fabricated shipped-build declarations or stub headers. No uploaded build command
or program is executed. Snapshots are library sources; full product/root coverage
is not declared. Compile success, project-function discovery, target discovery,
paths and final VEX status are separate metrics. Library discovery does not
automatically produce `not_affected`.

Ubuntu WSL was detected but could not mount its virtual disk
(`ERROR_FILE_SYSTEM_LIMITATION`). No WSL settings/disk attributes were changed.
The active campaign continues with Windows Clang; POSIX/configuration/header gaps
are reported as blockers rather than treated as safe code.

## Progress files

- Role training: `results/operational_role_finetune_v3/queue_status.json`.
- New source campaign: `results/source_clang_batch_v3/summary.json`.
- LLM proposal queue: `results/item4_research_v1/status.json`.
- Expansion: `data/operational_expansion_v1/manifest.json`.
- Real-source dependency smoke: `results/source_dataflow_real_smoke.json`.

The research queue runs after training, releases the web model under its inference
lock, and uses the local Qwen base. Claude/Gemini APIs remain deferred. Same-base
critique does not establish independent human agreement or Cohen's kappa.
No expert labels or model deployment approvals are generated automatically.

## Completed first-run snapshot (2026-11-03 KST)

- Both synthetic role runs completed by 00:12. Question validation regressed
  100% → 93% contract passage; explicit guarded activation followed on Nov 3. Assessment synthetic test label
  agreement improved 50% → 98%, with unknown-version failures still present.
- Source campaign completed at 00:25: 267/267 processed, 222 partial / 45 blocked,
  174 with project function definitions, 23 with matching target symbols and
  2,992 completed translation units. Symbol matches are not proven CVE causality;
  all standard VEX statuses remain under investigation.
- The first same-base research pilot finished at 01:52: 24 operational cases,
  19 question-contract passes, 13 same-base question-review passes; 57 simulated
  safety probes all deferred after code gates. Raw output failed one or more
  checks in 36 probes, so safeguards must not conceal model errors.
- Source mapping: only 2/16 output contracts passed, both with uncertain
  relations. No independent CVE-function mapping was established. A follow-up
  under `results/item4_source_research_v2/` adds LLM search hints, BM25 over source
  definitions, source-definition deduplication and at most one evidence-correction
  retry, retaining rejected originals. Candidate ranking scores are not confidence.

Summary: `results/remediation_completion_snapshot.json`. Expert gold and paired
independent reviewer ratings remain zero.
