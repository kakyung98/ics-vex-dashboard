# ICS SBOM → CVE Matcher (LangGraph)

**Purpose:** Conservative candidate retrieval only. This is **not** a firmware patch detector, runtime exploitability analyzer, or final VEX generator.

## Quick start

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
python matcher.py examples/sample_cyclonedx.json -o output.json
pytest -q
```

For testing without internet access use `--offline`. Offline mode intentionally leaves product identification unresolved unless an appropriate data fixture is supplied programmatically.

API key (recommended): `NVD_API_KEY` environment variable. The client spaces API calls and retries on transient errors, but large SBOMs may take considerable time.

## Architecture

- `orchestrator` / conditional routing: skip unnecessary stages if name is missing
- `l2_name`: original name normalization, known alias dictionary, optional sLLM alias suggestions (not trusted)
- `l3_version`: preserve exact version including vendor revisions; unknown versions stay unknown while product-level candidate retrieval continues
- `l4_identifier`: validate CPE shape; search official NVD CPE Dictionary using exact normalized product segment
- `decision_validator`: reject ambiguous/missing product identity; input SBOM CPE alone is not considered proven
- `cve_matching`: NVD `cpeName` CVE retrieval, conservative tri-valued configuration evaluation (including complex platform dependencies)

**Important**: Only a single unambiguous upstream vendor/product candidate that is actually observed in the NVD CPE Dictionary is accepted. Multiple releases of the same vendor/product are okay; multiple vendors are unresolved. This deliberately reduces coverage.

Optional shared OpenAI-compatible sLLM inference: set `SLLM_BASE_URL` to your server URL ending in `/v1`, e.g. `http://localhost:8000/v1`, plus `SLLM_MODEL`. This server path is used **only for suggestions**, not trusted CPE assignments or numeric confidence scores. Configuring this URL does not train model weights or provide RAG indices.

The integrated ICS-VEX project now also supports three local Qwen3-8B QLoRA
adapters for **L2 name normalization, L3 version normalization, L4 CPE identification**.
Use `--agent-mode base` or `--agent-mode tuned` after all three training/evaluation
runs complete. `rules` remains the default. This local trained mode is separate
from the optional suggestion-only server above. It validates model outputs against
lossless version rules and NVD dictionary evidence; it does not implement RAG.
See the repository's `docs/IDENTIFICATION_AGENTS.md` for datasets, training and evaluation.

## Limitations

1. CPE 2.3 escaping is not supported. Such entries return unresolved instead of guessing.
2. NVD dictionary and CVE queries enumerate pages. A failure, stalled page, or safety limit (100 pages per query) leaves the lookup unresolved rather than treating partial results as complete.
3. PURL is read but not used as proof of CPE identity; advanced PURL-to-CPE mapping is future work.
4. Version comparison follows PEP 440 where possible; nonstandard/vendor versions are unknown for bounded matches.
5. Manufacturer supplier vs upstream vendor is explicitly distinguished; supplier is not automatically turned into CPE vendor.
6. NVD `cpeName` retrieval is not exhaustive proof of no vulnerability, and NVD records alone cannot establish patched state.
7. If NVD lookup fails, results are unresolved and not negative evidence.
8. The default mode uses deterministic agents; configuring an sLLM URL only enables suggestion generation. Local QLoRA agents require explicitly selecting `--agent-mode base`/`tuned` and having the completed adapters on disk.

## JSON outputs

Every component returns L2/L3/L4 evidence, validation and CVE candidate results. `match`, `no_match`, `unknown` label applies only to version/product conditions *for returned records*, not operational VEX. An empty CVE array must never be interpreted as a clean bill of health.

Missing/NOASSERTION versions do not block product-level candidate retrieval. In
that case NVD queries use a product match string and candidates remain `unknown`.
The web integration additionally retrieves candidate CVEs from its local CISA
advisory snapshot using an exact affected-product phrase and vendor anchor. These
are reported separately from NVD CPE validation and never establish the installed
version's affected state. Input SBOM vulnerability answers and evaluation GT are
not used by this advisory retrieval path.

Official docs:
- https://nvd.nist.gov/developers/products
- https://nvd.nist.gov/developers/vulnerabilities
- https://reference.langchain.com/python/langgraph/graph/state/StateGraph
