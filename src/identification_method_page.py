"""Readable explanation of the deployed identification paths."""
from src.method_flows import identification_flow

IDENTIFICATION_METHOD_HTML = '''
<div class="eyebrow">Method / Identification</div>
<h1>SBOM → CVE Method</h1>
<p class="sub">Identify the product. Preserve its version. Retrieve candidate CVEs.</p>
'''+identification_flow()+'''
<section class="method-notes" aria-label="Identification rules">
<h2>Explore a stage</h2>
<p>Supplied CPEs are checked for format, dictionary product identity and component type. A wildcard release can identify a product without establishing an installed version. Invalid or unverified CPE versions are not installation evidence.</p>
<p>The representative asset is checked separately when metadata.component.cpe is supplied. Its findings enter VEX review, but its CPE is never copied to dependent components. Escaped CPE syntax currently remains unsupported.</p>
<details class="method-topic"><summary>L2 · Find the product<span class="topic-prompt">View details</span></summary><div class="topic-body">
<dl><dt>Input</dt><dd>Component name, manufacturer, PURL and supplied CPE.</dd>
<dt>Processing</dt><dd>Preserve source model observations, retrieve dictionary candidates with BM25 and character matching, and reject unsupported model-letter or digit changes. No LLM is called.</dd>
<dt>Result</dt><dd>Product candidates with their supporting evidence.</dd></dl>
<p class="method-boundary">A device stays a device. Do not replace it with an embedded library.</p>
</div></details>
<details class="method-topic"><summary>L3 · Preserve the version<span class="topic-prompt">View details</span></summary><div class="topic-body">
<dl><dt>Input</dt><dd>Version values from the SBOM, PURL, CPE and component name.</dd>
<dt>Processing</dt><dd>Rules preserve supplied versions and check revisions, source conflicts and synthetic inventory limits.</dd>
<dt>Result</dt><dd>A version observation, a conflict, or an unknown version.</dd></dl>
<p class="method-boundary">An advisory's affected range is not the installed version. Unsupported version ordering stays unknown.</p>
</div></details>
<details class="method-topic"><summary>L4 · Verify the identity<span class="topic-prompt">View details</span></summary><div class="topic-body">
<dl><dt>Input</dt><dd>Product candidates, vendor evidence and supplied identifiers.</dd>
<dt>Processing</dt><dd>Rules accept only a unique dictionary identity supported by original evidence; conflicts remain unresolved.</dd>
<dt>Result</dt><dd>Accepted identity, ambiguity, conflicting evidence, or insufficient evidence.</dd></dl>
<p class="method-boundary">L2 candidate order is not identity proof. L4 cannot discard competing vendors or override conflicts.</p>
</div></details>
<details class="method-topic"><summary>Retrieve CVE candidates<span class="topic-prompt">View details</span></summary><div class="topic-body">
<dl><dt>NVD</dt><dd>Query the product. Assess version and platform conditions separately.</dd>
<dt>CISA</dt><dd>Keep vendor/product advisory links as a separately attributed source.</dd>
<dt>Handoff</dt><dd>Pass CVE IDs, component links and unresolved evidence into VEX review.</dd></dl>
<p class="method-boundary">A candidate match does not prove applicability. An empty result does not establish safety.</p>
</div></details>
<details class="method-extra"><summary>How do the identification rules work?</summary>
<ul><li><b>L2:</b> source model preservation + dictionary retrieval + deterministic ranking.</li>
<li><b>L3:</b> rule-based version preservation + original-value checks.</li>
<li><b>L4:</b> rule-based CPE validation + vendor, identity and conflict checks.</li>
<li><b>Insufficient evidence:</b> retain original inputs and conflicts; defer unsupported identities.</li></ul>
<p>All identification stages use deterministic rules. Qwen3-8B is reserved for the final VEX explanation. The combined pipeline has not been independently evaluated.</p>
</details>
<details class="method-extra"><summary>Evidence and evaluation limits</summary>
<ul><li>Manufacturer and supplier are different fields. Do not infer ownership relationships without evidence.</li>
<li>Use only a supported version scheme: PEP 440, SemVer, Debian or RPM.</li>
<li>The flattened local NVD cache cannot prove complete platform applicability.</li>
<li>Synthetic reference agreement is not independently measured real-SBOM accuracy.</li>
<li>Fuzzy acceptance remains disabled pending independent calibration.</li></ul>
</details>
</section>
'''
