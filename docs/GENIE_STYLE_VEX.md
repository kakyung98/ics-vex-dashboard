# Genie-style SBOM → VEX pipeline (static-analysis edition)

Restructures the ICS-VEX methodology into a CVE-Genie–style **developer + critic**
multi-agent architecture, driven by three models — **SecureBERT**, **CodeBERT**, and
an **sLLM** (Qwen2.5-Coder-7B + LoRA) — but decides VEX **purely by static analysis**.

> **2026-08 redesign.** The system no longer generates or executes proof-of-concept
> exploits. The CVE-Genie *Exploiter* (write + run a PoC) and *CTF Verifier*
> (execute → capture a flag) are replaced by a **static exploitability analyst** and a
> **static-evidence grounding critic**. Nothing is built, nothing is triggered,
> nothing is executed. This removes the execution/trigger path that kept getting
> blocked by security policy, and grounds VEX in static evidence instead.

## Key idea

SecureBERT and CodeBERT are **encoders** (classifiers), not agentic LLMs. Only the
sLLM is generative — and here it is used as a *static analyst*, not an exploit writer.
The design is a **hybrid**: a deterministic orchestrator routes each finding; the
sLLM runs a Genie-style developer→critic loop over static evidence; the encoders act
as specialized signals; and the "verifier" is a grounding check on the static
evidence rather than an execution oracle.

## Role mapping (CVE-Genie ↔ static ICS-VEX)

| CVE-Genie stage (execution) | Static ICS-VEX implementation |
|---|---|
| Processor / Knowledge Builder | same — CVE desc, CWE, patch diff, advisories, affected versions → structured KB (already static) |
| Builder (rebuild + run env) | **Presence & Reachability analyzer** — is the component/version present? is the flaw reachable given CVSS AV × deployment exposure? No build, no run. |
| Exploiter (generative PoC, ReAct) | **sLLM static exploitability analyst** — structured assessment (root cause, precondition, adversary-controllability, reachability, exploitability). **No exploit code emitted.** |
| Exploit / Verifier Critic | **static grounding critic** — is the verdict supported by the evidence? `not_affected` needs counter-evidence; flags overreach; one ReAct refine pass. |
| CTF Verifier / Flag Checker | **VEX adjudicator** — fuses static signals into a status + CSAF/OpenVEX justification. Confirmed tier = **static-analysis-verified** (not execution-verified). |

## Flow

```
SBOM (CycloneDX)
  [1] Knowledge Builder      match components/versions → CVEs → KB sentences
  [2] Presence+Reachability  component present? AV × exposure reachable?      [gate]
      └─ unreachable / AV:P → terminate: NOT_AFFECTED
                              (vulnerable_code_cannot_be_controlled_by_adversary)
  [3] SecureBERT context leg (live)   → VEX signal + rationale                [signal]
  [4] CodeBERT code leg (live, if pair)→ static patch-diff signal             [signal]
  [5] sLLM static exploitability (live)→ structured assessment (no PoC)       [developer]
  [6] static critic (ReAct loop)       → grounded? refine once               [critic]
  [7] VEX adjudicator                  → status + CSAF/OpenVEX justification  [verdict]
      → code pair + separable fix + grounded critic = static-analysis-verified
```

## Evidence tiers (new findings)

| Tier | Condition |
|---|---|
| `static-analysis-verified` | vuln/patched code pair present, fix statically separable from the flaw, critic grounded, decisive verdict |
| `static-reasoned` | no code pair, but reachability (AV × exposure) + CWE reasoning give a grounded decisive verdict |
| `under-investigation` | insufficient static evidence to decide |

## Files

| File | Role |
|---|---|
| `src/save_vex_model.py` | trains + **persists** the SecureBERT VexModel → `models/vex-model/vexmodel.pt` |
| `src/vex_infer.py` | live wrappers: `SecureBertVex`, `CodeBertRefMatch`, `SllmStaticAnalyst` (`assess_exploitability` / `critique` / `adjudicate_vex`). `SllmPoc.gen_poc` is a hard-stop shim. |
| `src/vex_pipeline.py` | orchestrator: SBOM → matching → presence/reachability → 3-model static stages → developer/critic loop → per-finding VEX (JSON-line stream) |
| `archive/` | the deactivated execution path (PoC generation, exec-verify batch, verify-spec builder). See `archive/README.md`. |

## Run

```bash
python src/save_vex_model.py                     # once: persist the VEX classifier
python src/vex_pipeline.py --sbom results/example_sbom.json --exposure control-network
python src/vex_pipeline.py --sbom <sbom> --no-sllm   # deterministic estimate only (fast)
```

Or use the **ICS-VEXForge webapp** → *SBOM → VEX* tab. It runs `vex_pipeline.py` in
the system Python (torch + CUDA + the models) and streams results. The webapp needs
no change — the redesigned CLI drops `--exploit` and is called the same way.

## Requirements

torch + CUDA, transformers, peft, bitsandbytes (4-bit sLLM). Base models cached:
`ehsanaghaei/SecureBERT`, `microsoft/codebert-base`, `Qwen/Qwen2.5-Coder-7B-Instruct`.

## Honesty note

Every stage is static. No exploit is generated and nothing is executed, so a verdict's
confidence comes from **static evidence quality** (code-diff separability, reachability
grounding, critic agreement) — not from a reproduced crash. The confirmed tier for new
findings is `static-analysis-verified`. The 5 historical `execution-verified` records
(from the now-archived execution path) remain in `results/exec_verification*.json` as a
separate, clearly-labeled historical tier; no new execution-verified findings are
produced.
