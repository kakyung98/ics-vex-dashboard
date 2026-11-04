> Historical Evidence v3 foundation. The deployed default now combines these guards with trained L2/L3/L4; see [UNIFIED_IDENTIFICATION.md](UNIFIED_IDENTIFICATION.md).

# Evidence v3 implementation

Implemented 2026-11-02. This is a new inference contract, not the earlier v2
adapter experiment. Existing v2 weights/data/results remain unchanged and
selectable as legacy comparison methods.

## Runtime flow

1. Parse CycloneDX/SPDX fields. Preserve name, version, supplier, manufacturer,
   PURL, CPE, type, field evidence IDs and input hashes. Do not collapse a
   manufacturer into a supplier. Never read input `vulnerabilities` as answers.
2. L2 groups actual dictionary releases by `(part, vendor, product)`. Candidate
   retrieval combines BM25 token scores and character-trigram retrieval using
   reciprocal-rank fusion (RRF). Display up to 20 candidates, retaining all
   exact/identifier/alias competitors for ambiguity checks. Ranking scores and
   heuristic boosts are **not probabilities**, fitted confidence or optimal
   hyperparameters.
3. L3 records source-specific version observations, raw values and spans from
   fields, identifiers and names. Names/ranges are provisional; source conflicts
   block confirmation. Synthetic advisory inventories never attest installed
   versions. The raw reported spelling remains available for comparison.
4. L4 checks dictionary existence, explicit manufacturer, component/CPE part,
   reviewed vendor-scoped aliases, conflicting names/PURLs/CPEs and competing
   identities. Supplier alone cannot disambiguate vendors. A CPE existing in the
   dictionary alone does not link an unknown name to that product. A unique
   supported identity passes the strong-evidence rule; others remain ambiguous,
   conflicting or insufficient.
5. Query CVEs at product scope; compare original version/platform predicates
   separately. Unsupported ordering, unknown versions and unobserved platform
   prerequisites remain unknown. Local flattened configurations remain unknown.
   CISA exact vendor/product phrase retrieval is a separate source, retaining
   whether manufacturer or supplier anchored the link.
6. Candidate-to-VEX handoff preserves identity checks, version observations and
   dictionary hash. The writer receives a scoped identification summary, not
   permission to turn a candidate into affected/fixed/not_affected.

## Model roles and methods

| API `agent_mode` | Implementation | Model claim |
| --- | --- | --- |
| `evidence` | CPU retrieval, version analysis, deterministic evidence validation | Default; no LLM call |
| `evidence_llm` | Same evidence gates plus optional local Qwen base review | New `identity-ranker` contract, **not fine-tuned** |
| `rules` | Original normalization/lookup rules | Legacy baseline |
| `base` | Original L2/L3/L4 contracts, base Qwen | Legacy baseline |
| `tuned` | Original L2/L3/L4 contracts and v2 adapters | Legacy v2; old scores do not validate v3 |

The optional review returns supplied candidate IDs, supplied evidence IDs and
literal version spans only. Invalid IDs/references are rejected; invalid spans
cannot become facts. It reorders candidates without deleting competitors and
cannot override acceptance. No new candidate-ranker training is claimed. The
two completed operational curriculum adapters are unrelated and not substituted.
The existing shared GPU lock/model is reused; Claude/Gemini APIs stay off.

## Registry and provenance

`data/cpe_dictionary.jsonl` is the CPE retrieval source even if CVE lookup is live.
Its hash is recorded. Live mode does not silently refresh the dictionary.
Escaped CPE names are not currently parsed by the underlying strict parser;
those records are not invented or repaired. Missing dictionary coverage does
not imply safety. Source snapshot age/coverage remains an operational limitation.

`data/identity_aliases_v3.json` starts **empty**. Supported records need a reviewed
status, reviewer, HTTPS source, alias, vendor and (for product aliases) target
product. Product aliases require explicit vendor scope for acceptance. No LLM
memory is used to declare company ownership, OEM or embedded-library mappings.
The accepted alias set has its own hash. Unknown relationships remain unknown.

## Version comparison

- PURL parsing: installed `packageurl-python`; namespace is not a CPE vendor.
- PEP 440: `packaging.version`, when the ecosystem explicitly identifies it.
- SemVer: strict numeric core, prerelease ordering and build metadata handling.
- Debian: `python-debian` comparator, preserving epoch/revision semantics.
- RPM: ASCII EVR segment comparison, including epoch, release, tilde and caret;
  malformed/unsupported EVRs remain unknown.
- Custom/vendor ordering: unknown until an explicit comparator is supplied.

Specification references: [PURL](https://github.com/package-url/purl-spec),
[NVD products/match criteria](https://nvd.nist.gov/developers/products),
[CVE versions](https://github.com/CVEProject/cve-schema/blob/main/schema/docs/versions.md),
[Debian ordering](https://www.debian.org/doc/debian-policy/ch-controlfields),
[RPM ordering](https://rpm.org/docs/6.0.x/man/rpm-version.7).
Conformance examples are tested; exhaustive conformance is not claimed.

## Evaluation and calibration

`tools/eval_identity_evidence.py` audits 14,326 unique legacy input variants
without reading a reference ID during retrieval. This differs from the earlier
14,173-component frozen v2 campaign: input grouping and comparison units differ.
The new tool measures reference Recall@20, top-1 agreement, selected-reference
agreement and coverage. Missing/conflicting reference axes stay explicit.
The legacy exact-name baseline is paired on the same scorable inputs; it is not
a rerun of the tuned v2 model. A bounded `--llm --limit 20` development option
supports comparison on identical inputs; it is not a full-population LLM test.

These legacy references frequently name another co-listed/embedded product.
For example a raw Rockwell 1756-EN2T input can have a CompactLogix 1769 reference.
Therefore reported disagreement is a review finding, not automatically a false
identification. The audit is **development reference agreement, not independent
real-SBOM precision**. Retain failures and scores rather than relaxing the
scorer or declaring them verified success. Input/dictionary/code hashes and
code-change detection make final audit runs reviewable.

`tools/calibrate_identity_evidence.py` accepts only human-adjudicated validation
rows, rejecting weak/model/test labels. It proposes score/margin thresholds using
a Wilson lower bound and coverage requirement. A proposal does not activate
fuzzy acceptance; independent held-out confirmation is still required. No such
independently labelled calibration set exists yet, so fuzzy acceptance remains
disabled. Old task accuracy and LLM self-reported confidence are not substitutes.

`tools/prepare_identity_annotation_queue.py` exports 300 blind review inputs
with no system ranking or legacy answer included. They are still advisory-derived
inputs, not newly collected real assets. Labels and splits stay pending until
identity adjudication/grouping; add independent real SBOM cases before making
a real-world accuracy claim. External provider review remains deferred.

## Verification artifacts

- `tests/test_identity_evidence.py`: vendor ambiguity, evidence conflicts,
  field provenance, provisional/range versions, component types, reviewed alias
  scope, version comparators, unknown handling, model-invented IDs, calibration
  gates, CPU jobs and VEX handoff.
- `results/identity_evidence_v3_reference_audit.json`: full reference audit and
  fingerprinted input-level results; not a trusted semantic accuracy score.
- `results/identity_evidence_v3_smoke/`: actual local HTTP CPU and GPU model calls.
  The supplied EasyIO fixture returns five processed components, zero errors,
  two unique CISA candidates / ten links, with applicability unknown. The curl
  Qwen-base smoke records an actual accepted ranking response, a grounded product
  and 87 local candidates with unknown applicability. These are wiring/regression
  checks, not independent precision estimates.

No saved models, uploaded sources, private results or annotation proposals are
published to Pages. The exported UI uses the connected local backend for analysis.
