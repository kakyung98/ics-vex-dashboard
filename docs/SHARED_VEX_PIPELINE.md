> Superseded on 2026-11-04: the current application uses deterministic analysis. Only final VEX explanation writing uses an LLM. The design below is historical.

# Shared extraction, evidence decision and VEX authoring

Updated 2026-11-02 in `src/vex_roles.py`. Both eligible evidence branches use
source-ID extraction and the trained VEX writer. The free-quotation adapter is
retired; its loader and training CLI role are disabled. Historical free-quotation
fixtures remain for regression testing without loading those weights. The pipeline
is ICS-VEXForge's implementation; it does not produce a separate intermediate
document or a paper-specific priority score.

```text
SBOM/CVE handoff
  -> CWE-first routing (missing required source / unknown routing defers)
  -> base source-ID selection: condition/function candidates
  -> server-restored quotations + schema/source/policy validation
  -> source-required: Clang evidence; eligible operational cases: operator facts
  -> deterministic scoped VEX decision
  -> exact decision + evidence IDs + missing evidence packet
  -> vex-writer-qwen3-8b-v1: generated explanation draft
  -> JSON / identity / decision / evidence-reference / simulation checks
  -> displayed draft, original CycloneDX + VEX, and OpenVEX/CSAF export
```

## Actual runtime connection

The interactive no-source path now adds per-CVE tuned-adapter question generation,
operator answers and advisory assessment before the shared authoring step. See
`OPERATIONAL_QUESTIONNAIRE.md` for endpoints, provenance and status limits. Those
two roles use experimental v3 adapters, with a base-model fallback on rejection;
question support and operator answerability receive same-base review. The older OC APIs
below remain compatibility evaluators; they are not the questionnaire UI flow.

- `/api/source/judge`, `/api/oc/judge` and
  `/api/cve-match/jobs/{job_id}/oc` prepare the same case structure and finalize
  through the same authoring validator. `/api/vex-review/models` reports saved
  adapter availability. Existing frontend requests use the pipeline by default.
- Legacy comparison input matches its training: `{vulnerability, description}`. The
  active source-ID contract receives a pinned evidence catalog. CVSS, CWE,
  source/build evidence and asset facts are handled separately by their evidence
  engines rather than silently changing the trained extractor's input contract.
- `src/identification_agents.py` reuses one quantized Qwen3-8B base and its GPU
  lock for L2/L3/L4 plus the two grounded adapters. Complete saved adapters load
  on demand. Identical Description extraction can be cached in memory; VEX
  decisions and writing are recomputed for the product/evidence case.
- Runtime generation is deterministic. The legacy Description extractor allows
  3,072 input / 768 output tokens; authoring allows 6,144 / 1,536, and base
  source-ID/question/assessment roles allow 6,144 / 1,536. No input is silently
  truncated. Writer strings are length-bounded; invalid or repetitive writing
  gets at most one corrective attempt, with failed output retained. These settings differ from the earlier
  training-run validation; the old validation scores are not new runtime scores.

## Evidence and failure rules

Every case retains its case ID, input hash, raw model output, validation checks,
adapter identity/hash, rule result, writer evidence packet and generated draft.
The writer sees the assigned status/justification and can cite only supplied IDs.
It does not receive permission to make a different applicability decision.

Unsupported quotes, malformed JSON, invalid categories or a violated extraction
policy reject that extraction. Rejected text/functions do not enter the source
analysis. Mentioned functions remain candidates; LLM-only mappings cannot
authorize absence/unreachability clearance.

Accepted condition candidates enter operational review as explicitly unverified
OC5 conditions (`unknown`, `may_refute: false`). Their literal presence in the
Description does not verify semantics or that an asset satisfies/refutes them.
CWE remains classification/review guidance and cannot refute a CVE. An affected
decision is deferred if Description extraction failed; independently supported
scoped refutations retain their own evidence and limits.

The authoring validator checks structure, exact vulnerability/product/status/
justification, supplied evidence IDs and simulated-scenario disclosure. It does
not establish unrestricted prose's semantic truth. All generated documents are
review drafts. Rejected/unavailable authoring is shown explicitly; no fake model
explanation is substituted. The rule rationale remains available separately.
Exports use accepted drafts and evidence IDs, mark review requirements and use
CSAF draft tracking for these results.

## Ground truth and evaluation

The runtime does not read training/test answer keys. Connecting the roles does
not create ground truth. Independent case-level labels must bind a CVE/product/
build to reviewed condition spans, vulnerability-site mappings, source/context
facts, an adjudicated VEX status and supported explanation claims. A model's
previous output is not an independent answer key.

`tests/test_shared_vex_pipeline.py` verifies both branch connections, case/evidence
binding, caching without decision reuse, rejection of unsupported quotes and
protection against writer status changes using explicitly mocked inference.
Ordinary tests never load the GPU. The standalone command below exercises actual
saved adapters on fictional benign fixtures and records failures as failures:

```powershell
python tools/smoke_shared_vex_pipeline.py
```

The actual wiring smoke is `results/shared_vex_pipeline_gpu_smoke.json`. In the
first actual run both branches called the real adapters; both extracted a
nonliteral condition and were rejected, while both writer drafts passed
structural/decision/citation checks. Thus the model calls and rejection paths
were verified, but the two model chains were not fully accepted. This smoke is
not real CVE accuracy or a replacement for independent end-to-end evaluation.
