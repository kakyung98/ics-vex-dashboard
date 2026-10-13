# ICS-VEX — build and evaluation results

Evidence-based VEX adjudication over an SBOM dataset reconstructed backwards from
CISA ICS-CERT advisories, compared against the public ground truth.

> **As of 2026-09-10.** This document matches the current code and data.
> The **estimate-based training figures** carried by earlier editions are **isolated in
> §7** — their labels (AV x synthetic exposure) were retired, and the model weights are
> not in the repository, so they cannot be reproduced.

---

## 1. The axis — ICSA advisories

CISA publishes **one CSAF document per ICSA**. This system uses the same axis, so that
its output corresponds file-for-file with [cisagov/CSAF](https://github.com/cisagov/CSAF).

```
1 ICSA  ->  1 reverse SBOM (reverse_sbom/<icsa-id>_SBOM-CVE.json)  ->  1 VEX document
```

| axis | count | nature |
|---|---|---|
| ICSA advisories (collected) | **3,767** | all of 2010-2026 |
| -> contains a CVE = SBOM generated | **3,695** | **document axis** — one VEX each |
| ICSA x CVE = statement | **13,025** | **adjudication axis** — 1:1 with a VEX statement |
| distinct CVEs | **11,336** | the vulnerability population |

Statements per ICSA run to a **median of 1 and a maximum of 490**. The spread is wide
enough that worst-case aggregation per CVE (if any one asset is affected, the whole CVE
is affected) was abandoned — the same CVE splitting by product is the reason VEX exists.

---

## 2. Pipeline

| step | script | output |
|---|---|---|
| 1. collect advisories | `tools/fetch_cisa_advisories.py` | `data/cisa_advisories.json` |
| 2. collect exploit signals | `tools/fetch_exploit_signals.py` | `data/exploit_signals.json` (KEV, EPSS) |
| 3. pin the ground truth | `tools/collect_gt_icsa.py` | `data/gt_icsa/` (CISA originals + manifest) |
| 4. reverse SBOM | `src/build_reverse_sbom.py` | `reverse_sbom/*.json`, `data/findings.csv` |
| 5. inject model variants | `tools/inject_product_variants.py` | per-model `product_tree` in the SBOM |
| 6. collect OSS code | `tools/collect_code_gh.py` | `data/code_evidence.json` |
| 7. ~~execution verification~~ | **a closed campaign — not reproducible.** The runner was removed in b4fc1bc8; only the preserved output (`results/exec_verification*.json`, `results/verify_build_logs/`) is read downstream | — |
| 8. batch adjudication | `src/vex_batch.py` | `results/vex_batch.jsonl` |
| 9. ground truth | `src/build_ground_truth.py` | `data/vex_dataset.jsonl` |
| 10. comparison and evaluation | `tools/compare_cisa_csaf.py`, `tools/eval_variant_derivation.py` | console report |
| 11. site build | `tools/build_sbom_index.py`, `tools/build_site.py` | `*.html`, `*.json` |

> Steps 3, 6 and 7 must run **before** steps 8 and 9: those read the evidence tier and the
> upstream verdicts to decide each statement's tier.
> In step 11, `build_sbom_index.py` is not refreshed by `build_site.py` and has to be run
> separately.

---

## 3. The adjudication rule — only evidence sets a status

Gates are tried strongest first. A statement that passes none of them is
`under_investigation`.

| tier | condition | status |
|---|---|---|
| `upstream-asserted` | the vendor or CISA already adjudicated it via `flags[].label` | adopted as-is (source recorded) |
| `sbom-evidenced` | the affected component or model is absent from this SBOM | `not_affected` + `component_not_present` |
| `execution-verified` | build the vulnerable version -> run the reproducer -> observe the trigger | `affected` (`fixed` when it disappears in the patched build) |
| `under-investigation` | everything else | `under_investigation` |

**Deployment context (network position, exposure) does not set a status.** None of CISA's
five justifications accepts deployment as grounds, and a verdict resting on it goes
quietly false the moment the topology changes. Operational context enters **only as SSVC
priority**.

> `component_not_present` is the only justification that needs no version comparison.
> Every component version in this corpus is `NOASSERTION`, which makes it effectively the
> only path that can be established at all.

---

## 4. Results — VEX adjudication (13,025 statements)

```
by status   UNDER_INVESTIGATION 13,002 (99.82%)
            LIKELY_NOT_AFFECTED     18 ( 0.14%)
            LIKELY_AFFECTED          5 ( 0.04%)

by tier     under-investigation 13,002
            upstream-asserted       18
            execution-verified       5
```

Justifications behind the 18 `not_affected`: `component_not_present` 10,
`vulnerable_code_not_in_execute_path` 5, `vulnerable_code_not_present` 3.

### Why 99.8% is undetermined — the source-availability tiers

| tier | statements | share |
|---|---|---|
| `source-unavailable` (closed vendor firmware) | 11,129 | 85.4% |
| `source-pending` (OSS, code not yet collected) | 1,842 | 14.1% |
| `source-available-unverified` | 31 | 0.24% |
| `execution-verified` | 5 | 0.04% |
| `upstream-asserted` | 18 | 0.14% |

**For 85.4% the source cannot be obtained in principle.** That is not a defect but the
actual condition of the ICS domain, and it is the gap this work is aimed at.

---

## 5. Comparison against the public ground truth

### 5.1 There is almost no ground truth to compare against

Parsing the entire CISA CSAF repository (**3,984 files**):

| item | count | share |
|---|---|---|
| `document.category == "csaf_vex"` (OT) | **0** | **0%** |
| carries `vulnerabilities[].flags` | **12** | **0.31%** |
| carries `known_not_affected` | 25 | 0.64% |
| carries `known_affected` | 3,890 | 99.9% |

All 12 documents that carry `flags` are **ICSA-prefixed**; 11 are Siemens and 1 is
Mobotix. The 88 IT advisories use the `csaf_vex` profile but do not use `flags`.

Adoption timeline: **first on 2024-08-22** (`icsa-24-235-03`), retroactive backfills on
2025-06-12, 2025-08-14, 2026-01-15 and 2026-05-14, and **shipped with new publications
from 2026-02 onwards**. Zero across the 2,155 advisories of 2010-2023. Adoption by year:
2024 0.7% -> 2025 0.8% -> 2026 1.4%.

Those 12 documents and 18 (ICSA, CVE) pairs are pinned verbatim in `data/gt_icsa/`.

### 5.2 Upstream adoption and own derivation are kept apart

`tools/compare_cisa_csaf.py` never mixes the two.

```
comparable ICSAs : 3,664
CISA profile     : csaf_security_advisory 3,664  (csaf_vex 0)

[A] upstream-adopted (carried straight from CISA CSAF) : 18   justification match 18/18
    -> not own adjudication performance. Excluded from the metrics.
[B] own derivation                                     : 0
```

Feeding on CISA labels and then comparing against CISA labels yields a meaningless 100%.
So `route` records the provenance and [A] is excluded from performance.

### 5.3 Per-model independent derivation — the real score

`tools/eval_variant_derivation.py`. Inputs are restricted to what an asset owner can read
from the advisory.

| | item | use |
|---|---|---|
| **input** | `product_tree` (the model list) | allowed |
| **input** | `product_status.known_affected` | allowed |
| **answer** | `product_status.known_not_affected` | **forbidden** |
| **answer** | `vulnerabilities[].flags[].label` | **forbidden** |

Derivation rule: **my model is not in this CVE's affected list -> `not_affected` /
`component_not_present`.**

```
per model (product_id)   TP 278 / FP 676 / FN 0
                         precision 0.291 | recall 1.000 | F1 0.451
(ICSA, CVE) pairs        justification match 10/18
```

| ground-truth label | pairs | matched |
|---|---|---|
| `component_not_present` | 10 | **10 / 10** |
| `vulnerable_code_not_in_execute_path` | 5 | 0 / 5 |
| `vulnerable_code_not_present` | 3 | 0 / 3 |

**Everything decided by product structure is right, and everything needing source analysis
is wrong.** That matches the capability boundary exactly.

All 676 false positives are models **CISA did not enumerate**. With `known_not_affected`
withheld from the input there is no way to tell "not affected" from "not mentioned" — not
an algorithmic defect but **the ceiling of the public data**.

Of the 18 pairs, the component can be identified from the OSS catalogue in exactly
**one**: `CVE-2023-38545` (libcurl). The other 17 are proprietary code whose component
neither CISA nor the vendor disclosed.

### 5.4 Model-variant injection

`tools/inject_product_variants.py` injects CISA CSAF's `product_tree` into the SBOM.

```
24,380 model variants injected into 1,937 SBOMs, narrowing 6,721 findings to affected models
icsa-25-191-06: 1 component -> 65 (64 models + 1 device), CVE-2025-40742 -> affects 44 models
```

An injected affected list is **a fact supplied by upstream**. A verdict resting on it is
marked `variant:source=cisa-csaf` and kept distinct from own derivation.

---

## 6. Code-level adjudication — Q2-Q4

The source-level pipeline is now the VEX-v2 engines: an LLM structures the CTI, and the
solvers decide — Joern for reachability (Q3), Z3 for controllability (Q4), orchestrated by
`tools/vex_judge_v2.py`. It runs over the **267** collected-source CVEs. (This supersedes
the earlier execution-verification campaign of 104 snapshots; the retired engines
`callgraph_reach.py` / `taint_reach.py` are gone, and the 5 historical execution-verified
records are kept only as a historical conclusive tier — see §8.) CISA's fifth
justification, `inline_mitigations_already_exist`, is not adjudicated.

The gate hierarchy is the central design choice: **Q2 presence decides; Q3 and Q4 are
optional and only grade the evidence tier, never refuting.** A library snapshot has no
consumer in it, so "not reachable from an in-snapshot root" false-negatives on the attack
surface itself. The shared rule lives in one place, `src/vex_decision.py`, and the
console's **VEX Flag Decision Logic** page is generated from that module, so the documented
rule and the executed rule cannot diverge.

| Q | engine | result over 267 | decides? |
|---|---|---|---|
| Q2 presence | `tools/source_locate.py` | present 222, component_only 45 | **yes** — present -> affected |
| Q3 reachability | `tools/joern_reachability.py` (Joern CPG) | reachable 168, unknown 51, not-reachable 4 | no (tier only) |
| Q4 controllability | `tools/z3_controllability.py` (Z3) | controllable 213, environment-dependent 9, unknown 1 | no (tier only) |

Of the 168 `reachable`, 157 rest on a CTI-named entry point and 11 on the snapshot's
call-graph roots (a weaker basis, recorded in each verdict's detail). The resulting
evidence tiers over the 267: `verified` 144, `present` 63, `component` 45, `reachable` 11,
`patch-verified` 4. Final verdicts: `affected` 263, `fixed` 4.

**Source-level analysis clears nothing on this corpus**, and that is by design, not
weakness: Q3/Q4 never refute. It also reproduces the public record — across all 3,984 CISA
OT CSAF documents, `vulnerable_code_cannot_be_controlled_by_adversary` and
`inline_mitigations_already_exist` have each been used **zero times**. The only
justifications that survive here are `component_not_present` and upstream citation.

> **Q4 used to report `not-controllable` on 9 CVEs. It no longer does, and that is the
> honest reading.** Every one of those refutations became satisfiable once the LLM's own
> `environment_fixed` defaults were unpinned — the model had written a default its own
> trigger contradicts (`max_recursion_depth < 100` pinned to exactly 100; `table_info == 0`
> pinned to 1). They are now reported as `environment-dependent`, not as refutations. On
> this corpus Z3 refutes nothing.

### 6.0 Are the solvers measured? The Q3/Q4 agreement axis

Because Q2 presence decides the verdict, Joern and Z3 contribute **0** to item #4's
precision figure. They are measured on a separate axis
(`tools/eval_q34_agreement.py`, ground truth `data/vex_q34_gt.jsonl`, 285 labels) whose
authorities sit outside this repository: a component's shipped **public headers** for
reachability, and **NVD CVSS AV/UI** for controllability. This is a supplementary
disclosure, not a certification item.

| | labels | scored | contradictions | recall | verdict |
|---|---:|---:|---:|---:|---|
| Q3 — Joern | 75 | 58 | **2** | 0.9655 | **FAIL** |
| Q4 — Z3 | 210 | 166 | 0 | 1.0000 | PASS |

The acceptance criterion is **contradictions == 0**, not recall or precision. Neither of
those can carry a bar here: the answer key is one-sided (a public header cannot say an
internal function is *un*reachable, and CVSS cannot say an input is *not* attacker-chosen),
so a precision reads 1.0000 by construction and a recall threshold is passed outright by a
solver that answers "yes" to everything. The harm this pipeline can take is
one-directional — an over-positive solver clears nothing and is safe, while an
over-refuting one produces false clearances — so the bar is placed there: the solver must
never assert the negative where an outside authority asserts the positive.

**Q3 fails, and is published failing.** Joern returned `not-reachable` on only 4 CVEs, and
2 of those 4 contradict the authority: `GENERAL_NAME_cmp` (CVE-2020-1971) and zlib's
`inflate` (CVE-2022-37434) are both declared in a shipped public header. Half of what Joern
refuted on this corpus is wrong — which is precisely why Q3 must never decide, and the
measurement that justifies the gate hierarchy above.

### 6.1 Naming the vulnerable function — three routes, different clearance rights

A code-level question has to know *which function* it is judging, and the strength of the
verdict cannot exceed the strength of the grounds on which that function was picked. So
the route is recorded and becomes the ceiling on the conclusion
(`data/vuln_targets.json`).

| route | method | CVEs | may clear |
|---|---|---|---|
| A `patch` | the functions the fix commit edited. Fix commits come from NVD references, the Debian security tracker, the projects' own security data (curl.se, openssl-library.org, w1.fi), a local `git log` search of project history (`git_grep_fix_commits.py`), and commit messages carrying the CVE ID (`extract_vuln_funcs.py`, diff cache `fetch_patches.py`) | 75 | yes |
| A `patch-partial` | as A, but only the files the fix touched, collected at the fix's parent commit (2 Linux CVEs) | 2 | **no** — the whole program is absent |
| B `description` | the NVD description names it **and** that name is actually defined in the snapshot (`locate_vuln_funcs.py`) | 28 | yes |
| C `codebert` | Devign-finetuned CodeBERT ranking (`rank_codebert.py`) | 0 | **no — not adopted** |
| — | not obtained (CVE-2023-28450: the fix changes only a `#define` default) | 1 | no |

Route B applies a code-context filter — the token must contain `_` or CamelCase, be called
as `foo()`, or be written as "the X function". Without it, ordinary English words like
`and`, `service` and `process` are caught by coinciding with a function name. Export
macros (`ZLIB_INTERNAL`) and libc functions the description mentions as being *called*
(`memset`) are excluded.

**Route C is a measured negative result.** Scored against the targets available at the
time, it reached top-1 0.056 / top-5 0.111 / **top-20 0.148** — about 7x random (0.021),
but the median rank of the correct answer was 450th of 4,000. The model answers "does this
function look generally dangerous", not "is this the function of this CVE", so in 85% of
cases the real target falls outside the top 20. It is therefore not used to decide a
status and those CVEs stay `under_investigation` (`results/codebert_rank.json`).

### 6.2 Conservative traversal — not reading "not found" as "not there"

In static analysis **"not found" and "not there" look identical**, and the confusion
always leans the same way — towards a false clearance. Four instances were found, two of
them after a verdict had already been issued.

| incompleteness | symptom | cost |
|---|---|---|
| K&R definitions | tree-sitter emits ERROR on old-style C and loses the definition (zlib 1.2.8 `inflate.c`: 89 ERRORs, `inflate` lost) | the callee looks unreachable |
| macro-wrapped headers | `ZEXTERN int ZEXPORT inflate OF((...))` -> only 3 public APIs recognised | the attack surface looks smaller |
| indirect calls | a static graph sees only `f()`; dispatch tables and callbacks (`sqlite3_create_function(..., rtreenode, ...)`) are invisible | **6 false `not_affected`** (first Q4 run) |

Every fix moves the same way — it only **widens** what counts as reachable, never narrows
it. A regex scanner assists the parser on K&R and macro signatures, and every
address-taken function is admitted as a taint root. Each fix removed the false clearances
it was aimed at, in full.

### 6.3 Target coverage — 7 -> 105 / 106

A code-level question does not exist without a target, so coverage is the constraint that
binds Q3/Q4. Most of the gain came not from domain difficulty but from fixing **defects in
the collector and the extractor**.

The table below is the historical record of that work on the 104/106-snapshot campaign;
the routes and fixes it describes are the same localization methodology now applied over
the current **267** collected-source CVEs (Q2 present 222, component_only 45).

| step | cumulative | what was fixed |
|---|---|---|
| start | 7 | — |
| patch diff parsing | 25 | the tier-A cache truncated at 6,000 chars and lost source hunks -> commits re-collected |
| NVD description naming (path B) | 52 | names the description gives, intersected with snapshot definitions |
| all NVD references | 55 | `references[:6]` slicing in `fetch_nvd.py` |
| forge adapters | 55 | gitweb `a=commitdiff`, cgit, kernel.org and openssl GitHub fallbacks |
| GitHub PR patches | 60 | NVD cites PRs (44) far more often than commits (20) |
| project primary sources | — | fix commits from curl.se JSON (all 6 confirmed real fixes), commit links in openssl-library.org advisories |
| commit-message search | — | commits carrying the CVE ID in the message (GitHub search, 11 hits of 37 — doc and test commits are filtered by the verification below) |
| git hunk headers | 70 | recovered 4 cases where the extractor read macros like `ZLIB_INTERNAL` and `PREFIX` as function names |
| local `git log` search | 78 | searching per-project blobless mirrors by the references' commit, Fossil, ticket and bug keys. An issue number is bound to that project's repository only (in Terrapin, another project's `#445` mis-matched an OpenSSH commit) |
| Debian tracker NOTEs | 88 | upstream fix links for CVEs where NVD cites no commit. Corrected a pattern that read bugzilla `show_bug.cgi?id=` as a commit |
| extractor defect fixes | 101 | K&R definitions (zlib 1.2.12 `inflate` lost), functions moved between files (OpenSSH `subprocess`), `.c.in`, Perl (`c_rehash`) and Java, first-parent diffs of merge commits |
| fixes cited by primary advisories | 103 | u-boot, busybox, dropbear and spring commits, the w1.fi 2022-1 patch, Alpine patches (not fixed upstream) — grounds recorded in `ADVISORY_FIX` |
| partial snapshots (kernel) | 104 | only the files the fix touched, at the fix's parent commit. `patch-partial` may not clear and Q3/Q4 are not run |
| parser and context corrections | **105** | a `'}'` inside a literal ended a function early (ash `readtoken1`), tree-sitter ranges cut by error nodes, function headers in a hunk's leading context (CVE-2021-33909 `seq_buf_alloc`), spring-security 6.1.0 added |

**Baseline correction — some of the original 60 had no grounds.** Three were removed for
having the wrong target outright: CVE-2021-3517 and -3518 were entirely test functions
(`test_xmlIO` and friends, in the root's `testapi.c`), and CVE-2023-48795 (Terrapin, whose
snapshot is dropbear) produced a function by applying libssh2's `src/packet.c` diff to
dropbear's merely identically-named `packet.c`. Four more carried functions that appear
nowhere in the fix diff (`sftp_packetlist_flush` x3, `nodePush`) and were removed as
misattributions.

**Extraction rule changes**

- Release commits excluded — 24% of cached diffs (26 of 108) were release or version-bump
  commits. They are dropped when the same CVE has a real fix commit.
- The majority-vote baseline was dropped in favour of the **union** of functions the fix
  commits touch. The baseline's membership changed with the number of cached diff copies.
  The union errs in the safe direction — Q3/Q4 may clear only when *every* target is
  unreachable.
- Anchor attribution = the occurrence **nearest the hunk**, not the first in the file.
- Test files at the root (`testapi.c`, `runtests.c`) excluded; hunk context from header
  files excluded from the vote (it is only a nearby prototype).
- **Whether two files are the same file is decided by content** — at least 50% of the
  diff's identifiers must appear in the candidate file. Path-shape rules were wrong in both
  directions (OpenBSD's `usr.bin/ssh/` and the portable root are the same file; libssh2's
  `src/packet.c` and dropbear's `packet.c` are not). On the decisive cases the identifier
  overlap split 0.8 / 1.0 / 1.0 against 0.13 / 0.10. Contributor names in licence comments
  are excluded from the identifiers.

**Verification** — measured against the function names git writes on each hunk, restricted
to those that actually exist in the snapshot, all 40 patch-grounded cases with context have
targets that contain every function the fix touched (mean 1.000). This is an **internal
consistency measure**, not proof that a target is the vulnerable function. CVE-2023-46850
is weak: its fix edits `tls_process_state`, which does not exist in 2.5.5, so the target
was inferred across a later refactor.

**Routes measured and rejected** — inter-release diffs (1 of 12 passed the gate), OSV's
`fixed` SHA (points at release commits), CodeBERT ranking (top-20 recall 0.148).

**70 -> 105 verification** — every newly obtained target was checked for "does a line the
fix actually changed fall inside that function in the snapshot", and every name the rule
changes dropped from an existing target (25 changes) turned out to be context noise
containing none of the changed lines (libssh2 `sftp_packet_ask`, libxml2 `xmlBufferCat`
and so on). This too is a consistency check.

The one remaining case and the weak targets:

```
1   CVE-2023-28450  the fix changes only the EDNS_PKTSZ default in config.h - no function edited
    CVE-2021-33909, CVE-2023-32233  partial snapshots (patch-partial) - may not clear, Q3/Q4 not run
    CVE-2021-42375  fix commit inferred (Claroty's trigger characters $ { } # <-> the ${#var} parsing fix)
    CVE-2017-13077/13078  AP-side KRACK workaround commits - not a protocol fix
    CVE-2022-28391  not fixed upstream; the Alpine patch is the basis
    CVE-2023-46850  the fix edits tls_process_state, which is absent from 2.5.5
```

---

## 7. What the data is (stated plainly)

**[real] CISA ICS-CERT data**
- 3,767 advisories (2010-2026), 11,336 distinct CVEs
- CVE <-> device (vendor/product) mapping, CWE, CVSS v3/v4 vectors — all official CISA values
- KEV 149 statements, measured EPSS
- original CISA CSAF `product_tree` / `product_status` (ground truth and model variants)

**[synthetic] the component inventory around the device**
- Component composition is generated from OSS catalogue attribution plus a vendor-module
  remainder.
- Every SBOM component version is **`NOASSERTION`**, which makes version-range comparison
  impossible in principle. That fact is itself written into the statements as a primary
  reason for `under_investigation`.
- The `ics:network-exposure` attribute is synthetic. **It is not used in adjudication**
  (see §7).

**[removed] estimated labels**
- 99.8% of the earlier edition's training targets were estimates built from `AV x synthetic
  exposure`. They were retired.
- `label` now equals the evidence-based status (`UNDER_INVESTIGATION` 13,002 /
  `LIKELY_NOT_AFFECTED` 18 / `LIKELY_AFFECTED` 5). **Three-class classification training no
  longer holds.**

---

## 8. Retired experiments (kept as a record)

> None of the below **reproduces on the current data and code.** The training labels were
> retired and the weights under `models/` are not in the repository. They are kept as a
> record of what was tried and why it was dropped.

**Label-dependent figures — all void**
- The §5-series figures such as SecureBERT status classification Macro F1 0.904 rest on
  the AV-estimated labels. Because the label was a deterministic function of latent
  attributes (AV, exposure), that performance was not "VEX adjudication ability" but
  **"ability to recover AV and exposure from prose"**. With the axis removed there is
  nothing left to measure.

**Label-independent figures — the observations hold, but are not reproduced**
- **SecureBERT ICS-DAPT**: continued MLM over 52,061 sentences of CISA advisories (3
  epochs) -> ICS-text perplexity 4.01 -> **2.23** (-44.4%), ICS term recovery 0.303 ->
  0.386 (n=145). Most of the gain occurs in epoch 0.
- **CodeBERT finetuning**: vulnerability detection on Devign (~21k C functions) F1
  **0.659**, at the level of the literature. It did not transfer to "tell the vulnerable
  and patched variants of the same function apart" (0.457) — grounds for solving backport
  detection as **reference matching** rather than as classification.

---

## 9. Limitations

1. **0.18% of verdicts are conclusive** — 5 execution-verified plus 18 upstream-adopted out
   of 13,025. Everything else is `under_investigation`. That is an honest reflection of the
   evidence obtained, and the only way to raise it is to raise the number of CVEs that can
   be execution-verified.
2. **The own-derivation score covers per-model reproduction only** — §5.3's recall 1.000
   means "among the models CISA enumerated, no `not_affected` is missed", and precision
   0.291 is the limit of public data: models that were not enumerated cannot be told apart.
3. **Source-grounded justifications are 0/8** — `not_in_execute_path` and
   `vulnerable_code_not_present` require the vulnerable component to be identified, and in
   17 of the 18 pairs not even the component name is public.
4. **Version comparison is impossible** — every component is `NOASSERTION`. Even for an
   execution-verified CVE there is no way to confirm the device runs the vulnerable build,
   so ICS safety-first assumes it does (`version_unconfirmed: true`).
5. **Execution verification is structurally limited** — by safety design it handles only
   self-contained libraries. Most ICS CVEs are closed firmware and cannot reach this path
   in principle; only OSS bundled into firmware is a candidate.
6. **The component inventory is synthetic** — only device <-> CVE <-> CWE <-> CVSS is real
   CISA data. With a real asset SBOM as input the `component_not_present` lane would
   perform differently (the figures here are not a lower bound).
7. **Model variants depend on CISA** — per-model adjudication is impossible for advisories
   with no `product_tree`, which is half of them.

---

## 10. Reproducing

```bash
python tools/fetch_cisa_advisories.py     # ~25 min (crawls 3,767 advisories)
python tools/fetch_exploit_signals.py     # ~5 min (KEV, EPSS)

git clone --depth 1 https://github.com/cisagov/CSAF.git /tmp/CSAF
python tools/collect_gt_icsa.py --csaf-repo /tmp/CSAF     # pin the ground truth

python src/build_reverse_sbom.py                          # a few minutes
python tools/inject_product_variants.py --csaf-repo /tmp/CSAF

python tools/collect_code_gh.py           # real vulnerable/patched OSS code (needs gh auth)
# Execution verification is not in the reproduction steps - the runner was removed and
# cannot be run from this repository alone. Downstream reads the preserved
# results/exec_verification*.json.

python src/vex_batch.py                   # batch adjudication
python src/build_ground_truth.py          # decide the evidence tiers

python tools/compare_cisa_csaf.py --csaf-repo /tmp/CSAF   # upstream/own split comparison
python tools/eval_variant_derivation.py                   # per-model independent derivation

python tools/build_sbom_index.py && python tools/build_site.py
```

With the caches present (`data/*.json`, `results/exec_verification*.json`) the crawl steps
can be skipped. Skipping execution verification leaves the `execution-verified` tier empty,
and only the 18 upstream-adopted verdicts remain conclusive.
