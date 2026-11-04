# Public corpus refresh

The live corpus uses CISA's official `cisagov/CSAF` OT ICS/ICSA documents.
Legacy HTML advisories absent from CSAF are retained; ICSMA medical advisories
are outside this corpus. Existing CSAF records are refreshed, including revised
CVE lists, descriptions, product names and scores. Only declared vulnerability
IDs are collected; incidental CVE references in advisory prose are excluded.

NVD yearly JSON 2.0 feeds are downloaded for every corpus CVE year (pre-2002
records use the 2002 feed). This refreshes old CVEs as well as new records.
Records absent from NVD are listed explicitly in the refresh report.

```powershell
gh api repos/cisagov/CSAF/commits/develop --jq .sha
python tools/refresh_public_corpus.py --commit <the-returned-40-character-SHA>
python -m pytest -q tests/test_public_corpus.py tests/test_pages_backend.py
node tests/pages_bridge_test.cjs
python tools/build_pages_frontend.py
python tools/publish_pages_frontend.py
```

Restart the local `src/api_server.py` process after a successful refresh. Its
in-memory store and CPE index are loaded at startup. Publish only after checking
the explicit Pages deployment manifest. Publication updates remote `main` and
triggers the Pages workflow without changing the local branch or staging area.

The corpus refresh also runs `tools/refresh_public_sboms.py` automatically. To
rebuild only the synthetic SBOMs, run that script directly. It regenerates one
document per successfully collected advisory into a versioned directory under
`data/public_sbom/`, applies the pinned CSAF product variants, and verifies all
CVE sets and affected-component references before replacing the live index.
Failed advisory records are listed in `excluded_advisories` and are not invented.
The original `reverse_sbom/` directory and historical findings/devices CSVs remain
frozen inputs for existing evaluation campaigns. Pages exports current documents
in bounded JSON bundles; the same UI resolves individual SBOM requests from them.

`results/public_corpus_refresh.json` records counts, NVD feed timestamps/hashes,
CISA commit, missing IDs and output hashes. Original caches are backed up under
`results/corpus_backups/<UTC timestamp>/`. Public freshness metadata lives in
`data/public_corpus_freshness.json` and the corpus summary shown on both sites.

The runtime projects current advisory/CVE relationships onto the existing
analysis results. Corrected relationships are removed from the current view;
new relationships start under investigation with `analysis_performed: false`.
Collection does not perform source analysis or infer a new VEX verdict.
Training/evaluation datasets and historical batch result files are preserved.
