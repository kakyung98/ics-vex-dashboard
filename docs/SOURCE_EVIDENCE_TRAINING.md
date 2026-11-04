# Source-evidence LLM fine-tuning

Historical experiment; not part of the deployed pipeline. The adapter is retired
and selected for removal. Retraining now requires an explicit `--out` directory.
The paths below document the original experiment, not active dependencies.

This run trains application-source fact extraction. It does **not** train CVE
Description exploit-condition extraction, a final VEX judge, or VEX prose generation.
The L2/L3/L4 identification adapters are separate and are not overwritten.

## Run

`python -u tools/train_source_evidence.py --out <explicit-research-output-directory>`

- Local base: `C:/Users/user/Desktop/ICS-VEXForge/models/Qwen3-8B`.
- New adapter: `models/source-evidence-qwen3-8b-v1`.
- Training/validation: 800 / 100 SFT conversations under
  `data/source_training_sw/sft`.
- Test100: not loaded, scored, or used to select a checkpoint.
- 4-bit NF4 QLoRA, rank 8, seven projection modules, bf16, batch 1 with
  accumulation 8, learning rate 1e-4, sequence limit 1280, seed 20261101.
- Maximum 3 epochs; evaluate/save every 50 optimizer updates; minimum validation
  loss selects the checkpoint; early stopping after two non-improving checks.
- Prompt tokens are masked. Only assistant JSON answer tokens receive loss.
- Token lengths are checked before training. No labels are truncated.
- Local files only; no model upload or remote training service.

## Targets

`dependency_linked`, `api`, `api_reachable_from_main`,
`additional_api_guard_present`.

The additional guard excludes the shared 256-character main-input cap by an
explicit task definition. These targets describe application API structure, not
reachability of a verified CVE site or a proof of non-exploitability.

## Progress and outputs

- `results/source_evidence_finetune_v1/status.json`: current phase, PID, optimizer
  step, elapsed time, and latest metrics. This is the progress source of truth.
- `run_config.json` in the same directory: data hashes, package versions,
  sequence lengths, and answer-mask check.
- `validation_report.json`: after training, base vs selected adapter generation
  results on the validation set; exact and field accuracy, schema validity, raw
  predictions. This is validation, not independent test performance.
- `models/source-evidence-qwen3-8b-v1/training_complete.json`: emitted only after
  training, adapter saving and validation reporting succeed.
- Console logs: `results/source_evidence_finetune_v1_stdout.log` and `_stderr.log`.

Do not treat a running PID, low training loss or an existing checkpoint as a
completed, validated model. Deployment is separate; this run does not replace the
live web models. The data contains synthetic template variants, and the already
inspected frozen test100 is a regression suite rather than a newly blinded test.
