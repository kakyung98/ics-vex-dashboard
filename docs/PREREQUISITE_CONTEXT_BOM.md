# BOM to operational Context BOM

The dashboard keeps identification and operational review in one workspace:

1. Upload CycloneDX or SPDX JSON and identify CVE candidates.
2. Review the candidate's source passages and prerequisite drafts. Preserve exact quotations and AND/OR/NOT relationships. Unstated requirements remain unknown; explicitly unnecessary requirements remain separate metadata.
3. Compile attack paths, compare candidate K values, and inspect condition consistency, question reuse and exception paths.
4. Inspect common conditions, their path-based Support, domain mappings and question slots. Low-support prerequisites remain individual questions. Attacker credential possession remains unresolved when operator records cannot establish it.
5. Supply observations for an exact asset/component reference, installed build, configuration, operating mode and assessed actor. Evaluate the original CVE-specific formulas.
6. Download the Context BOM envelope, CycloneDX with context/VEX, CSAF, OpenVEX or the assessment record. Resume using the saved review ID.

The Context BOM envelope (`ics-vex-context-bom/1`) is a research-defined format. It preserves the original uploaded BOM, its digest, component/CVE mappings, source reviews, signed paths, templates, observations and decisions. SPDX remains intact in the envelope. The separate CycloneDX export is checked against the locally cached official schema. Unreviewed CVEs and other component/build combinations remain under investigation.

## Model configuration

Semantic embeddings run on CPU from a local model cache; the default is `BAAI/bge-base-en-v1.5`. Override with `ICS_PREREQUISITE_EMBEDDING_MODEL`. Structured predicate/value/polarity vectors remain an explicitly named alternative. Neither mode embeds product/manufacturer identity. These are research designs, not independently validated clustering thresholds.

LLM extraction uses a configured chat-completions-compatible endpoint. Set these server environment variables before starting the app:

```powershell
$env:ICS_PREREQUISITE_LLM_URL = 'http://127.0.0.1:8000/v1/chat/completions'
$env:ICS_PREREQUISITE_LLM_MODEL = 'your-served-model'
# If the endpoint requires authentication:
# $env:ICS_PREREQUISITE_LLM_KEY = 'set through your normal secret management'
python src/api_server.py --host 127.0.0.1 --port 8100
```

The example endpoint is configuration guidance, not a server launched by this feature. No endpoint is enabled by default. LLM output must pass JSON, predicate, formula and exact unique quotation checks, then explicit source review. The review checkbox records an analyst declaration; it is not authenticated independent validation. Unknowns and nonrequirements are never fabricated into positive prerequisites. Existing source-clause inference and manual source-linked review remain usable without an LLM endpoint.

## Deployment

`python tools/build_pages_frontend.py` exports the dashboard UI. GitHub Pages serves static assets; analysis still runs on the connected local FastAPI backend. Public UI deployment does not host the models or the evidence/session database.

## Validation

`tests/test_prerequisite_workflow.py` covers OR paths, signed NOT literals, contradictory formulas, bounded path expansion, exception handling, model evidence rejection, component/build isolation and CycloneDX/SPDX Context BOM round trips. These are implementation checks with synthetic evidence, not real-asset accuracy measurements.
