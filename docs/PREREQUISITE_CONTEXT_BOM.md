# BOM to operational Context BOM

The dashboard keeps identification and operational review in one workspace:

1. Upload CycloneDX or SPDX JSON and identify CVE candidates.
2. Review the candidate's source passages and prerequisite drafts. Preserve exact quotations and AND/OR/NOT relationships. Unstated requirements remain unknown; explicitly unnecessary requirements remain separate metadata.
3. Compile attack paths, compare candidate K values, and inspect condition consistency, question reuse and exception paths.
4. Inspect common conditions, their path-based Support, domain mappings and question slots. Low-support prerequisites remain individual questions. Attacker credential possession remains unresolved when operator records cannot establish it.
5. Supply observations for an exact asset/component reference, installed build, configuration, operating mode and assessed actor. Evaluate the original CVE-specific formulas.
6. Download the Context BOM envelope, CycloneDX with context/VEX, CSAF, OpenVEX or the assessment record. Resume using the saved review ID.

The Context BOM envelope (`ics-vex-context-bom/1`) is a research-defined format. It preserves the original uploaded BOM, its digest, component/CVE mappings, source reviews, signed paths, templates, observations and decisions. SPDX remains intact in the envelope. The separate CycloneDX export is checked against the locally cached official schema. Unreviewed CVEs and other component/build combinations remain under investigation.

## Full 12,418-CVE corpus

The dashboard also has a separate, paginated full-population catalogue. Its SQLite index retains every pinned CVE, including those without conditions, incomplete source reading, identity ambiguity and invalid evidence spans. Search, state/cluster filters, original-source review and streaming NDJSON export cover the entire population. The 500-CVE asset-review basket limit does not limit corpus ingestion or global clustering.

```powershell
python tools/build_operational_corpus.py --mode semantic
```

The corpus builder verifies the source-population digest and every source passage. It clusters the available **unreviewed necessary-condition candidates**, using L2-normalized semantic vectors and spherical k-means with candidate K values. It does not invent AND relationships or path completeness. CVEs without eligible conditions remain explicitly unassigned. Sampled silhouette scores, selected K, exception counts and candidate-level Support are recorded. Corpus cluster drafts cannot grant automatic answer reuse or VEX status; reviewed asset formulas remain a separate execution gate. Per-condition embedding caching avoids re-encoding unchanged conditions on subsequent builds.

The interrupted local source-model run can be resumed from its existing packet cache:

```powershell
python tools/resume_full_corpus.py
```

This requires the existing pinned source/packet manifests, extraction cache and local model weights. The worker respects the GPU lease, uses two-item batches with out-of-memory splitting, and checkpoints each packet. It periodically publishes source-reading snapshots and rebuilds the corpus after a terminal extraction pass. Creating `results/ics_sentence_conditions_v1/STOP` stops the worker after its current batch. A stopped or failed run is never represented as a complete extraction.

The dashboard shows **indexed population**, **snapshot source-reading completion**, **unreviewed condition candidates**, **cluster coverage** and **live extraction packet progress** separately. GitHub Pages includes the complete CVE list and cluster/summary snapshots for browsing without a backend. Source review, rebuild controls and complete source-linked exports require the local backend. Public snapshots contain no asset observations or runtime session data.

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
