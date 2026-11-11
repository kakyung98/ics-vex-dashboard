"""Readable explanation of the deployed identification paths."""
from src.method_flows import identification_flow

IDENTIFICATION_METHOD_HTML = '''
<div class="eyebrow">Method / Identification</div>
<h1>SBOM → CVE Method</h1>
<p class="sub">Identify the product. Preserve its version. Retrieve candidate CVEs.</p>
<p class="hint">Implementation updated 2026-11-11 · LangGraph conditionally routes each component to P2, P3 and/or P4. Sufficient structured evidence bypasses agents. Original evidence gates validate every output; rules remain available as a comparison mode.</p>
'''+identification_flow()+'''
<section class="method-notes" aria-label="Identification rules">
<h2>Explore a stage</h2>
<p>Supplied CPEs are checked for format, dictionary product identity and component type. A wildcard release can identify a product without establishing an installed version. Invalid or unverified CPE versions are not installation evidence.</p>
<p>The representative asset is checked separately when metadata.component.cpe is supplied. Its findings enter VEX review, but its CPE is never copied to dependent components. Escaped CPE syntax currently remains unsupported.</p>
<details class="method-topic"><summary>P2 · Find the product<span class="topic-prompt">View details</span></summary><div class="topic-body">
<dl><dt>Input</dt><dd>Component name, manufacturer, PURL and supplied CPE.</dd>
<dt>Processing</dt><dd>Preserve product/model identifiers. Use shared structured lookup, BM25, sparse character TF-IDF vector cosine and reciprocal-rank fusion. When the name is missing, ambiguous or unsupported, P2 ranks supplied candidate IDs and cites input/dictionary evidence. Exact CPE/name/manufacturer evidence disambiguates candidates; ranking scores do not authorize acceptance.</dd>
<dt>Result</dt><dd>Product candidates with their supporting evidence.</dd></dl>
<p class="method-boundary">A device stays a device. Do not replace it with an embedded library.</p>
</div></details>
<details class="method-topic"><summary>P3 · Preserve the version<span class="topic-prompt">View details</span></summary><div class="topic-body">
<dl><dt>Input</dt><dd>Version values from the SBOM, PURL, CPE and component name.</dd>
<dt>Processing</dt><dd>Use declared SBOM versions, including synthetic inventory. For missing, noncanonical or conflicting versions, P3 classifies supplied observations as version facts or verified catalog/model identifiers without generating version strings. Preserve revisions and detect conflicting values. Compare exact versions or declared ranges with CVE conditions. A range fully contained in an affected range matches; a disjoint range does not; partial overlap remains unresolved.</dd>
<dt>Result</dt><dd>Reported exact version, declared range, conflict or unknown. Range comparisons retain their bounds.</dd></dl>
<p class="method-boundary">Declared inventory is compared without claiming independent installation verification. Unsupported vendor-specific ordering remains unknown.</p>
</div></details>
<details class="method-topic"><summary>P4 · Verify the identity<span class="topic-prompt">View details</span></summary><div class="topic-body">
<dl><dt>Input</dt><dd>Product candidates, vendor evidence and supplied identifiers.</dd>
<dt>Processing</dt><dd>After P3, repeat retrieval and routing while retaining all competitors. Missing or inconsistent CPE/PURL evidence routes to P4. If P2 ran, P4 may select only an identity ranked by its accepted response; otherwise selection requires an independently verified unique identity. Independent source/dictionary checks must also pass. Validate the supplied CPE and preserve it verbatim when its release matches the declared version. Without a supplied release CPE, select only a unique compatible dictionary release. Conflicting or platform-ambiguous records remain unresolved.</dd>
<dt>Result</dt><dd>Accepted identity, ambiguity, conflicting evidence, or insufficient evidence.</dd></dl>
<p class="method-boundary">P2 candidate order is not identity proof. P4 cannot discard competing vendors or override conflicts.</p>
</div></details>
<details class="method-topic"><summary>Retrieve CVE candidates<span class="topic-prompt">View details</span></summary><div class="topic-body">
<dl><dt>NVD</dt><dd>Use a verified release CPE when available; otherwise retrieve product candidates and explicitly compare declared versions/ranges. Local product/version checks do not reconstruct missing platform AND/OR predicates.</dd>
<dt>CISA</dt><dd>Keep vendor/product advisory links as a separately attributed source.</dd>
<dt>Handoff</dt><dd>Pass CVE IDs, component links and unresolved evidence into VEX review.</dd></dl>
<p class="method-boundary">A candidate match does not prove applicability. An empty result does not establish safety.</p>
</div></details>
<details class="method-extra"><summary>How do the identification rules work?</summary>
<ul><li><b>P2:</b> source model preservation + dictionary retrieval + LLM candidate-ID ranking.</li>
<li><b>P3:</b> LLM evidence classification + rule-based version preservation + original-value checks.</li>
<li><b>P4:</b> LLM candidate selection + independent CPE, vendor, identity and conflict checks.</li>
<li><b>Insufficient evidence:</b> retain original inputs and conflicts; defer unsupported identities.</li></ul>
<p>The orchestrator records required/skipped agents and reasons per component. The vector index uses sparse character TF-IDF vectors, without a semantic embedding model. Three base-model roles share local Qwen3-8B; old identification adapters are not reused under a different contract. JSON shape, source references, version observations and identity evidence are validated. Model failure or unaccepted output remains visible and unresolved. Question/writer adapters remain separate; the prior rules-only benchmark is not an agent accuracy claim.</p>
</details>
<details class="method-extra"><summary>Evidence and evaluation limits</summary>
<ul><li>Manufacturer and supplier are different fields. Do not infer ownership relationships without evidence.</li>
<li>Version comparisons support plain numeric releases and the configured PEP 440, SemVer, Debian or RPM schemes; unsupported suffix ordering stays unknown.</li>
<li>The flattened local NVD cache cannot prove complete platform applicability.</li>
<li>Synthetic reference agreement is not independently measured real-SBOM accuracy.</li>
<li>Fuzzy acceptance remains disabled pending independent calibration.</li></ul>
</details>
</section>
<section class="method-notes"><h2>Evaluation inputs and gold</h2>
<p>The item-3 corpus includes every unique CVE referenced by the pinned local ICS-CERT advisory snapshot. CVE records, advisory links, product/version conditions and unknown evidence are retained separately. The previous 1,000-case synthetic sample has been retired.</p>
<p>Dataset: <code>data/item3_ics_cert_full_v1</code>. <code>inputs/sboms.jsonl</code> contains answer-free upload inputs; <code>gold/condition_targets.jsonl</code> contains separate condition-level expectations. Counts, source fingerprints, missing-evidence coverage and SQLite lookup are recorded in the manifest. These are source-condition fixtures, not complete platform-applicability or expert-reviewed real-SBOM gold.</p></section>
'''
