# Current system map

Updated 2026-11-02. Workspace: `C:/Users/user/Desktop/ICS-VEX`.
This is a map of implemented code, not a claim of independent VEX accuracy.

## Request flow

```text
Original CycloneDX/SPDX JSON
  -> POST /api/cve-match/jobs
  -> candidate_web.submit -> candidate_match.match_candidates
     -> default: unified_identification.run_unified
        -> trained L2 name proposal + dictionary BM25/character retrieval
        -> trained L3 version preservation + original revision/conflict checks
        -> trained L4 selection + unique original-evidence identity agreement
        -> historical CPU / rules / base / tuned API modes for reproduction only
     -> NVD candidate lookup + vendor/product-linked CISA candidates
  -> GET /api/cve-match/jobs/{id}/vex: bind candidates to component occurrences
  -> vex_roles.prepare: condition/function extraction and stable case IDs
     -> source available:
        source upload -> patch/build review -> Clang/LLVM graph analysis
        -> scoped evidence decision
     -> no source:
        source-linked questions -> operator facts and records
        -> explicit vendor product/version comparison
        -> advisory assessment -> effective gated decision/explanation
  -> vex_roles.finish: trained VEX writer receives the assigned decision
  -> ground/schema/identifier/reference checks
  -> original CycloneDX copy + component-bound VEX; schema validation
  -> review log / CycloneDX+VEX / standalone OpenVEX / standalone CSAF
```

The original SBOM's existing vulnerability list is not an identification answer
key. A candidate match is not proof of installed-version applicability. Unknown
product/version, incomplete source, or unverified operating facts remain explicit.

## Code reading guide

All paths below are relative to the workspace above.

| Area | Main files and entry functions |
| --- | --- |
| Application | `src/api_server.py`: `build_app`, `make_page`, `main`; `/docs` shows current request models |
| Candidate jobs | `src/candidate_web.py`: `submit`, `get_job`; `src/candidate_match.py`: `match_candidates` |
| Unified L2/L3/L4 responsibilities | `src/unified_identification.py`: `run_unified`; shared gates in `src/identity_evidence.py`: `validate_identity`, `lookup_cves`; retrieval and version handling in `src/identity_retrieval.py`, `src/identity_versions.py` |
| Old tuned agents | `ics_agent_matcher_full/ics_agent_matcher/matcher.py`, `src/identification_tasks.py`, `src/identification_agents.py` |
| Candidate evidence sources | `src/candidate_snapshot.py`, `src/candidate_advisories.py`, `src/public_corpus.py` |
| Shared extraction/authoring | `src/vex_roles.py`: `extraction`, `prepare`, `decision_packet`, `finish` |
| Exact source catalog | `src/cve_source_evidence.py`: `documents`, `catalog`, `resolve_selection`; rejected legacy quotations remain in the audit output |
| Source intake | `src/source_intake.py`: `extract_zip`, `index_tree`; intake indexing is distinct from compiler-backed analysis |
| Source decision | `src/source_evidence.py`: `inspect_build`, `patch_evidence`, `review` |
| Compiler-backed graph | `src/clang_source.py`: `frontend_flags`, `ir_graph`, `build`, `assess`; old syntactic approximation in `src/source_cfg.py` |
| No-source questions | `src/operational_questions.py`: `create`, `_validate_questions`, `assess` |
| Installed version facts | `src/operational_versions.py`: `assets_for`, `validate_facts`, `compare_case`, `formal_version_status` |
| CWE context | `src/cwe_context.py`; classifications are context, not proof of exploit prerequisites |
| LLM execution | `src/identification_agents.py`: `LocalIdentificationAgents.grounded_role`, `get_runtime`; serialized adapter switching on one local GPU base |
| Output contracts | `src/grounded_role_tasks.py`, `src/llm_output_schema.py`; token constraints complement server validation |
| Embedded VEX | `src/sbom_vex.py`: `merge`; per-component scope and logged input-copy normalizations |
| Document validation | `src/sbom_schema.py`; pinned schemas in `.tools/cyclonedx-schemas/` |
| Persistence | `src/review_store.py`; local `results/runtime_sessions.sqlite3`, not public deployment |
| Frontend | `src/api_server.py` generated template, `src/candidate_widget.py`, `src/pages_bridge.js` |
| Deployment | `tools/build_pages_frontend.py`, `tools/publish_pages_frontend.py`; explicit public asset manifest only |

`api_server.py` also contains older OC/VEX evaluators for compatibility. The
interactive no-source path uses `/api/oc/questions` then `/api/oc/answers`, not
the older `/api/oc/judge`. Source review uses `/api/source/upload` then
`/api/source/judge`. Do not assume every function in the server is on the current
interactive path.

## Decision boundaries

- Source-present: identified target absence or unreachability can support a
  scoped negative finding only with the required complete product/root scope
  and no blocking analysis gaps. A reachable function is not automatically an
  exploitable CVE. Missing CVE/function mapping is not function absence.
- No-source: the LLM generates questions, never asset facts. Version fields are
  collected once per component. Explicit vendor fix + operator-attested installed
  version/record may support scoped `fixed`; other unverified conclusions remain
  `under_investigation`. Custom vendor version ordering is not guessed.
- Raw model likelihood and the effective gated explanation are distinct. The
  writer receives the effective explanation and cannot change the assigned
  status or product/CVE IDs. Rejected drafts remain visible and excluded from
  accepted document text.
- CycloneDX export preserves the original inventory in a copy, adds reviewed
  per-component `vulnerabilities[].analysis`, and increments the BOM revision.
  Known source-format corrections are logged. A fixed result for one component
  must not clear other unconfirmed component occurrences. SPDX retains standalone
  VEX export; embedded SPDX VEX is not implemented.

## Models and retrieval: implemented versus proposed

The runtime currently shares **one Qwen3-8B base**, with role-specific adapters.
The default unified L2/L3/L4 path and VEX authoring use their trained adapters.
Extraction defaults to base-model source-ID selection with server-restored text;
the regressed free-quotation adapter remains an explicit legacy comparison.
Dictionary retrieval and original-evidence checks gate
identification proposals. Historical modes remain API-only compatibility paths. The source structural-facts adapter is a separate completed experiment;
the current compiler-backed decision does not depend on that model. Operational
question/assessment v3 adapters are activated experimentally, with validated
base fallback and a same-base question critic. Source-ID extraction and the critic
use base inference. Neither the critic nor synthetic scores establish independent accuracy.
The historical optional candidate ranker is not part of the unified default. New contracts are not validated by old training scores.

Retrieval currently includes a local CPE dictionary search, NVD/CISA snapshots,
and a pinned per-CVE source catalog. This is not an independently evaluated
end-to-end vector-RAG system. Existing embedding artifacts do not establish that
vector retrieval is active. SQLite is session persistence, not the RAG database.

A separate-model verifier and expanded RAG are proposed extensions. Claude/Gemini
API dispatch is deferred, as requested. Role adapters on the same base do not
constitute independent verification. Compare single model, single model + RAG,
and separate-model verification + RAG on the same fixed, independently labelled
test cohort before claiming an improvement.

## Data and verification locations

- Public facts: `data/cpe_index.json`, `data/nvd_cache.json`,
  `data/cisa_advisories.json`, `data/upstream_csaf_latest.zip`.
- Live synthetic SBOM index: `sbom_index.json`; selected documents under
  `data/public_sbom/`, resolved by `src/dataset_paths.py`. The deleted historical
  SBOM cohort is no longer an input dependency.
- Source/patch material: `data/source_snapshots/`, `data/fixed_releases/` and the
  paths recorded by source evidence. Counts of collected CVE folders are not
  counts of successful whole-product analyses.
- Weights: `models/`; datasets and metrics are documented in
  `docs/DATASET_INVENTORY.md` and role-specific documents.
- Current repair checks: `tests/test_review_repairs.py`,
  `tests/test_llm_output_schema.py`, `tests/test_shared_vex_pipeline.py`.
- Actual GPU repair smoke: `tools/smoke_review_repairs.py`; latest artifacts in
  `results/review_repairs_gpu_constrained_v2/`. Read `status.json` first:
  generation/format acceptance is not semantic accuracy and a running smoke is
  not a completed success.
- Automated/deployment receipt: `results/review_repairs_verification.json`.
  Implementation tests, synthetic validation and independent model accuracy are
  different measurements.

Unified pipeline details: [UNIFIED_IDENTIFICATION.md](UNIFIED_IDENTIFICATION.md).
