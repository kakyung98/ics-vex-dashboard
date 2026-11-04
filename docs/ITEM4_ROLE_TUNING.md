# #4 operational-role experimental pretraining

Started 2026-11-02, 22:53 KST. This run trains two separate rank-8 LoRA adapters
on the existing Qwen3-8B base, sequentially on the local RTX 4070 Ti SUPER.

| Role | Contract | Train / validation / held-out synthetic test |
| --- | --- | --- |
| `item4-questions` | Source IDs, common + specific scopes, short operator-facing questions | 800 / 100 / 100 |
| `operation-assessment` | Advisory label, answer references, uncertainty and record provenance | 800 / 100 / 100 |

Data: `data/operational_curriculum_v3/`. The two roles share 1,000 fictional cases;
2,000 role rows are not 2,000 independent CVEs. These are explicitly controlled
synthetic premises, **not** the 1,000 real CVEs in `data/item4_v3/`.
All real independent labels and paired reviewer ratings remain zero.

Question topics cover six operational policy families: cleartext transport, weak
cryptography, missing authentication, password policy, cookie configuration and
resource permissions. Every fixture must route to operational review. All targets
carry separate common/specific scopes and supplied source IDs, not generated quotes.

Assessment fixtures distinguish present prerequisites, explicit simulated variant
absence, reversible disabling/filtering, unknown answers, missing records and
unresolved installed-version applicability. These controlled labels do not prove
that an arbitrary real CVE has an exhaustive conjunction of prerequisites.
Advisory `likely_*` outputs do not control the standard VEX verdict.

## Training and evaluation

- Base weights are frozen; each role gets its own LoRA. One epoch, rank 8,
  learning rate 5e-5, batch 1 / accumulation 8, maximum sequence 2,048.
- Completion-only loss masking is checked. Labels must fit without truncation.
- Validation selects the checkpoint. Train/validation/test case and family groups
  are separated; construction grammar is shared, so this is not independent
  semantic generalization or unseen-vendor evaluation.
- Base and tuned models are compared on validation using the same raw greedy
  decoder and output budget; generation batches are bounded at four.
- The separate synthetic test is read only **after** checkpoint selection. Its
  hash and the selected adapter hash are retained. Test results do not select
  weights, thresholds or hyperparameters in this run.
- Question checks cover the new contract, strict format/no normalization, both
  scopes, source references and prohibited developer-analysis wording. These are
  implementation checks, not complete semantic support or answerability judgments.
- Assessment checks cover answer IDs, all-unknown safety, missing-version safety,
  concise output and controlled reference-label agreement. Independent human
  semantic evaluation and Cohen's kappa remain unavailable.

Preflight passed for both roles; the associated code regression suite passed 179
tests. This does not mean model training or held-out evaluation has finished.

## Progress and artifacts

- Queue: `results/operational_role_finetune_v3/queue_status.json`.
- Role progress/config/logs: `results/operational_role_finetune_v3/<role>/` and
  the adjacent `<role>_stdout.log`, `<role>_stderr.log`.
- Completed evaluations: role `validation_report.json` and `heldout_report.json`.
- Outputs: `models/item4-questions-qwen3-8b-item4-v3/` and
  `models/operation-assessment-qwen3-8b-item4-v3/`.

The queue owns GPU admission while running. The restarted backend remains
available for corpus browsing, but model inference is temporarily refused.
The lease is released on queue completion/failure. No external model APIs run.

**Explicit deployment (2026-11-03).** The user authorized activating both experimental adapters. Training reports remain immutable.
Synthetic-format improvements do not qualify the new adapters as real-CVE
decision models. Preserve failures and obtain independent real annotations before
claiming semantic accuracy or replacing the deployed roles.

Question-role training/validation and its one-time synthetic test have completed.
Validation contract passage was base 100/100 versus tuned 93/100: a regression.
The separate synthetic test passed 100/100 for both; this does not erase the
validation regression or establish real-CVE accuracy. The candidate is deployed with checks and a base-model fallback, despite this recorded limitation.
Answer-assessment training and evaluation finished on 2026-11-03 at 00:12 KST.
Its synthetic test label agreement was base 50/100 versus tuned 98/100;
unknown-version safety was 98/100, so two failures remain. Both roles are now activated experimentally; neither result is independent real-CVE accuracy. Do not adjust this run using
its observed test outcomes; a future changed experiment needs an appropriate
fresh evaluation protocol.

Reproduction commands (do not start a second queue while one is active):

Activation is recorded separately in `data/operational_runtime_models.json` with
weight hashes. The runtime loads both v3 adapters on the shared quantized base.
It retains rejected outputs, performs at most one corrective question attempt,
then one base fallback with the rejection reasons. A same-base critic rejects
unsupported or developer-only questions; uncertain support remains explicitly
review-required. The assessment fallback cannot override the deterministic VEX
gates. Set `ICSVEX_OPERATIONAL_MODEL_MODE=base` for an explicit rollback.

The first real-CVE activation check loaded the question adapter successfully but
rejected all three questionnaire attempts, including the base fallback, for
asking installed-version questions already collected separately. This demonstrates
guard behavior, not model quality. Follow-up base correction now includes these
errors. Real answer-assessment API verification was blocked by automatic approval
review (`blocked by policy`, no detailed reason supplied); it is not reported as
passed. Unit regression and model activation are separate from that pending check.

```powershell
python tools/build_item4_operational_curriculum.py
python tools/train_grounded_role.py --role item4-questions --item4-curriculum --experimental-curriculum --preflight-only --max-length 2048 --generation-batch-size 4
python tools/train_grounded_role.py --role operation-assessment --item4-curriculum --experimental-curriculum --preflight-only --max-length 2048 --generation-batch-size 4
python tools/run_item4_role_queue.py
```

The builder refuses to overwrite the frozen curriculum; reuse its existing files
for reproduction. The queue requires both preflight reports and will not overwrite
existing output weights. A failed run requires diagnosis, not automatic restart
or silent selection using held-out results.
