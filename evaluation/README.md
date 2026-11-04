# evaluation/ — one command for test items #3 and #4

```bash
python evaluation/run_eval.py
```

That prepares each item's evaluation dataset, scores the system against it, checks the
result against the figure on record, and writes a visual report to
`evaluation/out/report.html`. No arguments needed.

```
evaluation/
├── run_eval.py    entry point — datasets -> scoring -> report
├── datasets.py    makes sure the right answer key is in place (and refuses if not)
├── report.py      self-contained HTML + inline-SVG report
└── out/           generated: report.html, results.json, run.json  (gitignored)
```

## What it does, in order

1. **Dataset.** Builds the ground truth if it is missing, then verifies the file on disk
   against the record count its own manifest records. A disagreement is **fatal**, not a
   warning.
2. **Score.** Calls `src/cert_eval`, which calls the same `score()` functions the CLI
   scripts and the web console use. This folder contains **no scoring rules at all**.
3. **Reproduction check.** Compares the measured figure against the one recorded in
   `src/cert_eval.ITEMS[...]["reference"]`, at 4 decimal places.
4. **Component axes.** Measures the learned component inside each item (below). These run
   in seconds because they read caches, so they are not opt-in.
5. **Report.** Writes `out/report.html` — stat tiles, per-vendor charts, the evidence-tier
   mix, the false-positive cases, and the component axes.

## The component axes

Each headline figure contains a trained model whose own error rate the headline does not
show. **Neither axis is a certification figure** — they decompose one, and the report says
so where they are rendered.

| component | tool | what it answers |
|---|---|---|
| #3's encoder | `tools/eval_encoder_contribution.py` | how much of 0.9490 is the encoder? |
| #4's LLM | `tools/eval_cti_localization.py` | does it name the function the fix edits? |

**#3's encoder moves the fourth decimal place.** Run the string cascade alone and it
scores 0.9499; with retrieval behind it, 0.9490. The encoder answers 392 of the 6,633
components the cascade declines and is right on 92.5% of them. Its own retrieval metrics
are poor (top-1 recall 0.056) and its fine-tuning regressed the frozen encoder, which is
why it ships behind a recall-safe gate — `cpe_ai_threshold_sweep.json` shows the same
retrieval at **0.2636** when trusted openly, and its precision-optimal cell recovers
exactly the 392 the shipped SUT recovers, so that sweep is the record of the gate being
chosen rather than an alternative to it.

**#4's LLM is load-bearing and was unmeasured.** `vex_judge_v2` decides at Q2, and Q2
needs a function somebody names first — for 83 of the 267 CVEs that is the LLM, including
33 of the 142 scored verdicts (23.2%). The only prior check was that the name *exists* in
the tree, which a model answering `main` would also pass. Against the fix commit's own
edited functions it agrees **0.5526** exactly, **0.7895** at file level.

Read that figure as *agreement with the fix*, not accuracy: a fix sometimes lands in the
caller or a helper while the vulnerable function is untouched. CVE-2020-1967 is the case —
the model named `SSL_check_chain`, which is the documented vulnerable function, and the fix
edits its helper `tls1_check_sig_alg`. Every disagreement is listed individually for that
reason. Unlike the Q3/Q4 axis this key **is** two-sided, so the precision describes the
model rather than the key.

## Options

| flag | what for |
|---|---|
| `--items 3,4,q34` | which items to run (default `3,4`) |
| `--rebuild` | rebuild the ground truths first (slow; flags are pinned, see below) |
| `--reuse` | reuse the committed result JSONs instead of measuring — for iterating on the report. Marked as reused in the output and in the report. |
| `--out DIR` | write somewhere other than `evaluation/out/` |

Item #3 takes roughly 8 minutes: it identifies products for 14,173 components against
the full NVD CPE index. Items #4 and q34 are instant — they score a stored verdict cache.

## Why the builder flags are pinned

This is the part worth reading before trusting a rebuild. Every ground-truth builder in
this repo has a default that produces a **different, also-valid** dataset:

- `build_cpe_match_gt.py` defaults to `--per-vendor 40`. That cap is the retired sampling
  policy: it holds each vendor to 40 positives so Siemens (58% of the corpus) cannot
  dominate — and in doing so it withholds exactly the Siemens device names the matcher is
  weakest on. A capped rebuild scores about **0.9870** instead of 0.9490 and looks like an
  improvement. It is a smaller measurement wearing a bigger number.
- `build_vex_gt.py` defaults to writing `data/vex_gt_104.jsonl`, the retired 104-CVE
  population, not the full collected-source one.

So `datasets.py` pins the full command (`--per-vendor 0 --seed 20261007`,
`--out data/vex_gt_all.jsonl`) rather than letting the defaults decide, and checks the
result against its manifest afterwards.

It also refuses to build when a builder's **inputs** are absent. A builder handed a
missing cache does not fail — it writes a thinner answer key, and a thinner answer key
scores higher. That is the quiet failure the prerequisite check exists to catch.

## Which variant each item is scored on, and why

- **#3 — the default SUT** (string cascade with retrieval behind it), not the cascade
  alone. The cascade alone is the ablation: it abstains on 6,633 of 14,173 components and
  the correct answer was reachable in the index for every one of them.
- **#4 — pre-gate.** With the patch gate live the same scope reads 0.9930, but the gate
  decides from the fix signature plus the NVD range — the same two authorities the ground
  truth's `patch_verified` labels come from. Agreement on a shared oracle is structural,
  not earned, so that figure is **circular** and the scorer flags it. The honest headline
  is the pre-gate one.
- **q34 — a supplementary disclosure**, not a certification item, and it currently
  **FAILS** its own bar (Q3 has 2 contradictions). It is run and published failing because
  it is the only axis on which Joern and Z3 are measured at all, and removing the criterion
  because the engine fails it would delete the measurement that justifies keeping Q3
  non-deciding.

## Reading the report

Two things in it are easy to misread, so they carry their own notes on the page:

- **Precision and abstention are one result.** A vendor the matcher mostly declines to
  identify scores well on the little it answers — Honeywell reads 1.0000 over 6 scored
  predictions having abstained on 83% of its components. The two charts sit side by side
  for that reason, and the vendor order is locked to corpus share rather than to either
  score, because a table sorted by score invites reading its top row as the result.
- **Neither figure covers its whole population.** Both answer keys are earned from
  evidence and evidence does not reach every member. Forcing the remainder in would mean
  counting undecidable as a false positive, or assuming the unlabelled are positives — and
  for #4 the pre-gate SUT answers `affected` for nearly all of them, so FP would become
  structurally 0 and precision the identity 1.0.

## Exit code

`0` when every requested item scored, `1` when any was skipped or failed. The acceptance
verdict itself (PASS/FAIL) does **not** set the exit code — a FAIL is a measurement, not
a crash, and q34 is expected to fail.
