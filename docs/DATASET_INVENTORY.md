# Dataset inventory

Verified against local files/manifests on 2026-11-02 (Asia/Seoul).
Units differ; counts below must not be added as independent CVE/asset cases.
Older versions/backups are excluded from active task totals.

## Active #4 revision: CWE-first v3

`data/item4_v3/manifest.json` supersedes older #4 task contracts. #3 is unchanged.
The later tables describe retained historical experiments, not new-contract SFT.

| Input / policy-predicted branch | Train | Validation | Test | Total |
| --- | ---: | ---: | ---: | ---: |
| Unique real CVEs | 800 | 100 | 100 | 1,000 |
| Source required | 675 | 76 | 89 | 840 |
| Operator questions eligible | 31 | 10 | 5 | 46 |
| Routing unresolved | 94 | 14 | 6 | 114 |
| Simulated control-flow scenarios | 1,475 | 176 | 189 | 1,840 |
| Independently adjudicated gold / train-ready | 0 | 0 | 0 | 0 |

The 1,840 scenarios reuse the same 1,000 CVEs. Source-required cases get supplied /
missing-source control-flow variants, without claiming an actual complete source
artifact exists. Extraction, routing, source, questions, assessment and authoring
annotation queues are role-scoped and retain the original group split. The 46
operator cases are insufficient for a balanced new SFT/evaluation claim; collect
additional eligible types after independently validating this routing policy.
All reference targets remain null. Old synthetic programs/weights are retained,
registered by manifest hash and explicitly unqualified for this new contract.
See [the revision details](CWE_FIRST_ITEM4.md).

## Real operational input expansion

`data/operational_expansion_v1/` scans all 12,527 cached CVEs and yields 563
policy-eligible operational candidates: 385 train inputs / 63 validation / 48 test
/ 67 quarantined global groups that bridge original frozen splits. This overlaps
the original real cohort and must not be added as an independent new population.
Labels remain pending; `train_ready_count=0`. A same-base LLM proposal/critique
pilot is queued for training-only cases, not independent gold generation.
See [the remediation scope](LLM_REMEDIATION_RUN.md).

## Separate experimental #4 role pretraining

`data/operational_curriculum_v3/` contains 1,000 explicitly fictional cases shared
by question and assessment roles: each has 800 train / 100 validation / 100 held-out
synthetic test rows. These are separate from the real-CVE v3 annotation cohort,
not independent expert gold and not automatically deployed. Training launched
2026-11-02 at 22:53 KST; live completion is recorded in
`results/operational_role_finetune_v3/queue_status.json`.
See [the training protocol](ITEM4_ROLE_TUNING.md).

## Retained test items #3 and #4 experiments

Here evaluation means held-out test inputs, separately from validation used for
model selection. Sizes describe prepared inputs, not independent verified gold
or completed evaluation. Synthetic corpus size and training/split sizes overlap.

| Category | #3 SBOM to CVE identification | #4 CVE to VEX review/authoring |
| --- | --- | --- |
| Synthetic data | Current advisory-derived SBOMs: 3,879; frozen earlier snapshot: 3,845 (overlapping). Three agent task sets: 18,432 procedural/NVD-derived records | Source-program fixtures: 1,000; operational fictional scenarios: 900 shared by two roles. Condition extraction and authoring have additional mixed/controlled task references; no independent overall synthetic-case total is claimed |
| Training | 12,288 task rows: L2/L3/L4 each 4,096 | 3,586 task rows: source facts 800 + conditions 386 + authoring 800 + questions 800 + assessment 800 |
| Validation | 3,072 task rows: each agent 1,024 | 459 task rows: 100 + 59 + 100 + 100 + 100 |
| Prepared evaluation/test | 3,072 agent task rows: each agent 1,024. Integrated evaluation processed 14,173 component inputs; these are a different unit | Source fixtures 100 + condition cases 50 = 150 role-specific held-out inputs. No separate held-out test yet for authoring or the two operational curriculum roles |

The pending **real** operational benchmark is separate: 800 train / 100 validation /
100 test CVE inputs, zero adjudicated labels. These are not added to #4 supervised
training totals. An independent expert-labelled final VEX test is not ready.
Prepared #4 task rows total 4,195; #3 task rows total 18,432. Reuse between roles
prevents interpreting their sum as independent assets/CVEs.

## Collected and derived corpus

| Dataset | Count | Unit / boundary |
| --- | ---: | --- |
| CISA advisory records | 3,881 | 3,879 collected, 2 historical fetch failures |
| Unique advisory CVEs | 12,418 | Unique IDs across current advisories |
| Local NVD cache | 12,527 | 12,401 advisory CVEs + 126 other cached CVEs; 17 advisory IDs absent |
| Current synthetic SBOMs | 3,879 | Advisory-derived inventories, not measured deployed assets |
| Frozen earlier SBOM cohort | 3,845 | Overlaps current snapshot; not an additional independent cohort |
| Collected source snapshots | 267 | CVE-associated directories, not 267 distinct software products or successful exploitability analyses |
| Generated source programs | 1,000 | 800 train / 100 validation / 100 frozen test; real dependency sources with synthetic program structure |

Source records: `results/public_corpus_refresh.json`,
`results/public_sbom_refresh.json`, `data/cisa_advisories.json`,
`data/nvd_cache.json`, `data/source_training_sw/manifest.json`.
The 267-directory count is from `data/source_snapshots/`.

## Prepared model task records

| Task | Train | Validation | Test | Total | Reference basis |
| --- | ---: | ---: | ---: | ---: | --- |
| L2 name normalization | 4,096 | 1,024 | 1,024 | 6,144 | NVD-derived and procedural |
| L3 version normalization | 4,096 | 1,024 | 1,024 | 6,144 | Procedural version transformations/abstention |
| L4 CPE identification | 4,096 | 1,024 | 1,024 | 6,144 | Dictionary candidates and procedural references |
| Source structural facts | 800 | 100 | 100 | 1,000 | Synthetic source-program fixtures, not affected-status gold |
| Description conditions / function mentions | 386 | 59 | 50 | 495 | Partial rule spans and controlled synthetic text |
| VEX authoring | 800 | 100 | — | 900 | Assigned decisions and controlled/simulated evidence packets |
| Operational questions, curriculum v2 | 800 | 100 | — | 900 | Fictional controlled scenarios; no real-CVE test claims |
| Operational assessment, curriculum v2 | 800 | 100 | — | 900 | Same controlled scenarios, separate task targets |
| Task-record sum | 15,874 | 3,531 | 3,222 | 22,627 | Not independent cases; preparation does not mean training/evaluation completed |

Source-fact and VEX-authoring records reuse source fixtures. The two new
operational roles share 900 underlying fictional scenarios, producing 1,800
task records. Thus 22,627 is a role-specific row count, not unique CVEs or assets.
No separate authoring/operational held-out test is claimed where the table shows
an em dash. Stored tests are not necessarily evaluated tests.

## Pending real-CVE operational benchmark

`data/operational_review_benchmark_v2/`: 1,000 real CVEs, allocated
800 train / 100 validation / 100 test. This is separate from fictional curriculum
training. There are **zero adjudicated labels** and no training on these pending
rows. These 1,000 IDs are a subset of the existing CVE corpus, not new collected
CVEs, and are not included in the 22,627 supervised-task row sum.

The repaired cohort has 585 advisory/near-description groups, zero cross-split
group overlap, CVSS available for 961 entries and CWE for 930. Shared product or
vendor disjointness is not established. V1 and V2 contain the same underlying
1,000 CVE inputs and must not be counted twice. The 20-case Claude/Gemini pilot
is a subset pinned to train, not 20 new cases. API dispatch remains deferred.

## Older CPE experiments retained on disk

- CPE training pairs: 537,054 (268,527 positive / 268,527 negative).
- Main CPE applicability benchmark: 41,868 (32,488 true / 9,380 false).
- 104-advisory subset benchmark: 1,114 (557 true / 557 false).
- The ambiguous benchmark also reports 41,868 and is a variant, not an
  independently collected set to add to the main benchmark.

These are older CPE/encoder experimental records, not training inputs to the
two new operational roles. Counts come from `data/cpe_match_*manifest.json`.
Code unit/API tests (previously reported as 60 tests) are software checks and
are not included in any dataset count here.
