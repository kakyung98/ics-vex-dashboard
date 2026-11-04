> Superseded on 2026-11-04: the current application uses deterministic analysis. Only final VEX explanation writing uses an LLM. The design below is historical.

# Unified SBOM-to-CVE identification

Updated 2026-11-02. Main implementation: `src/unified_identification.py`.

The UI and default API requests use `agent_mode: unified`. One Qwen3-8B runtime
switches among the saved L2/L3/L4 adapters. The evidence retrieval and validation
code remains in the same pipeline. No new training or independent accuracy result
is claimed by connecting these parts.

| Stage | Trained-model contract | Code contribution |
| --- | --- | --- |
| L2 | `{name, supplier}` → normalized name or abstention | Expand dictionary retrieval; preserve original identity evidence |
| L3 | `{raw_version}` → preserved version or abstention | Check exact leading-v/whitespace normalization; keep revisions and conflicts |
| L4 | `{normalized_name, candidates, lookup_error}` → vendor/product or abstention | Check supplied candidates, ambiguity, component type and original-evidence agreement |

## Acceptance rules

- L2 proposals are search hints. They are not dictionary facts, exact input
  matches, reviewed aliases or authority to change manufacturer.
- Retrieval uses BM25, character trigrams and reciprocal-rank fusion over the
  original observations plus the proposed search string. Acceptance features
  continue to derive from the original SBOM and reviewed sources.
- L3 processes an explicit version field or a documented explicit observation
  such as `purl.version`. Name-only versions remain provisional. A changed vendor
  revision is rejected; model abstention keeps version applicability unknown.
- A valid L3 output does not resolve conflicting observations or attest a
  synthetic inventory's installed build.
- L4 receives actual dictionary candidates for the proposed product, filtered
  only by explicit conflicts and component type. The complete retrieved pool
  remains available to the independent code gate.
- Final identity acceptance requires a valid L4 selection **and** the same unique
  identity supported by original dictionary/vendor/product evidence. An LLM
  selection cannot break a supplier-only tie or override identifier conflicts.
- If the L4 context contains more than 12 competing identities, defer with
  `candidate_context_overflow`; do not truncate competitors to manufacture a
  unique result. The execution record explicitly marks this skipped model call.
- Model failures remain visible. Original candidates and CISA advisory links can
  still be returned, but are not silently promoted to accepted NVD identities.

## Provenance and handoff

Each stage retains raw output, adapter mode, input hash, schema status and code
guard result. L3 also records the raw version source. Results use architecture
`unified-identification-v1`; component-to-CVE handoff carries model-stage checks,
version observations, acceptance rules and dictionary hashes into VEX review.

Old `evidence`, `evidence_llm`, `rules`, `base`, and `tuned` API modes remain for
historical experiments. The current UI exposes one identification pipeline;
these compatibility modes are not alternative buttons or default branches.

## Verification scope

`tests/test_unified_identification.py` covers all three calls, proposal
contamination, revision loss, supplier/manufacturer ambiguity, PURL provenance,
synthetic versions, unavailable models, context overflow and default API handoff.
Unit tests use injected providers and never allocate the GPU.

`tools/smoke_unified_identification.py` invokes actual saved adapters through the
default local API, using explicit simulated fixtures and the earlier EasyIO
advisory-derived input. Latest successful run: `results/unified_identification_smoke_retry/`. The first loading-failure artifact is retained separately.
Integration execution, guarded acceptance and independent real-device accuracy
are different measurements. The new pipeline has not been independently scored.
