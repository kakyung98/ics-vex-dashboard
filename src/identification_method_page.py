"""Current method overview for identification, operational VEX and datasets."""
from src.method_flows import identification_flow

IDENTIFICATION_METHOD_HTML = '''
<style>
.method-overview{min-width:0;max-width:100%}.method-overview .overview-steps{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin:22px 0}.method-overview .overview-steps article{padding:22px;border:1px solid var(--line);border-radius:20px;background:var(--card);min-width:0}.method-overview .overview-steps small{display:block;color:var(--purple);font-weight:650;letter-spacing:.06em}.method-overview .overview-steps h2{font-size:20px;margin:8px 0}.method-overview .overview-steps p{margin:0;color:var(--ink2);line-height:1.65}.method-overview .method-table{overflow-x:auto;max-width:100%;margin:16px 0}.method-overview table{width:100%;border-collapse:collapse;text-align:left;font-size:14px}.method-overview th,.method-overview td{padding:13px 12px;border-bottom:1px solid var(--line);vertical-align:top;line-height:1.6}.method-overview th{font-weight:650}.method-overview code{overflow-wrap:anywhere;white-space:normal}.method-overview .overview-links{display:flex;gap:12px 22px;flex-wrap:wrap;margin:18px 0}.method-overview .overview-scope{padding:18px 22px;border-left:3px solid var(--purple);border-radius:12px;background:var(--card2);line-height:1.7}.method-overview summary{cursor:pointer}.method-overview .method-topic summary{font-weight:650}.method-overview .method-topic p:last-child{margin-bottom:0}@media(max-width:900px){.method-overview .overview-steps{grid-template-columns:1fr}.method-overview .method-table table{min-width:560px}}
</style>
<div class="method-overview">
<div class="eyebrow">Method / System overview</div>
<h1>Method Overview</h1>
<p class="sub">Identify CVE mappings from an SBOM, then review asset impact using operating context.</p>
<p class="hint">Documentation updated 2026-11-16 · Current implementation, dataset layout and fresh H200 evaluation. Identification and operational impact are separate decisions.</p>
<div class="overview-steps" aria-label="System workflow">
<article><small>01 · SBOM → CVE</small><h2>Identify the component</h2><p>Preserve the supplied name, version and identifiers. Retrieve product candidates and verify CVE mappings against source evidence.</p></article>
<article><small>02 · OPERATIONAL VEX</small><h2>Review the deployment</h2><p>Select the asset and product-specific source scenario. Use configuration, access rules and operating records to answer observable conditions.</p></article>
<article><small>03 · EVIDENCE &amp; EXPORT</small><h2>Keep the decision traceable</h2><p>Validate scope, evidence and scenario coverage. Retain missing or conflicting facts as unknown before exporting a supported VEX result.</p></article>
</div>
<nav class="overview-links" aria-label="Method sections"><a href="#identification-method">Identification</a><a href="#operational-method">Operational VEX</a><a href="#method-datasets">Datasets</a><a href="#method-evaluation">Evaluation</a></nav>
<section id="identification-method" aria-label="Identification method">
'''+identification_flow()+'''
<div class="method-notes">
<h2>Hybrid RAG and conditional agents</h2>
<p>Structured product/CPE lookup, BM25, and sparse character 3-gram TF-IDF cosine search are fused with reciprocal-rank fusion (RRF). Retrieved candidate IDs and source evidence are supplied to the agents. This vector search does not use a semantic embedding model, and similarity scores are not identity probabilities.</p>
<div class="method-table"><table><thead><tr><th>Role</th><th>When it is selected</th><th>Evidence boundary</th></tr></thead><tbody>
<tr><th>P2 · Product name</th><td>The name is empty, unknown, unspecified or NOASSERTION; or dictionary evidence does not support a unique identity.</td><td>Rank supplied candidate IDs. Preserve manufacturer and model identifiers. Fuzzy similarity alone cannot establish identity.</td></tr>
<tr><th>P3 · Version</th><td>No confirmed version or declared range; source versions conflict; a version is extracted from the name; non-exact notation or normalization needs review.</td><td>Classify original observations. Preserve versions and bounds; never invent an installed release.</td></tr>
<tr><th>P4 · Identifier</th><td>CPE/PURL is missing, unverified or inconsistent, or identity still needs review.</td><td>Check candidate eligibility, dictionary evidence, component type, vendor and identifier conflicts.</td></tr>
</tbody></table></div>
<p>The LangGraph orchestrator rechecks remaining conditions after each selected agent. Required roles run sequentially, at most once each. Sufficient structured evidence can bypass a role; a selected role can also resolve a forced structured choice without a GPU call. Every path ends at the decision validator.</p>
<details class="method-topic"><summary>Model and final identity checks</summary><div class="topic-body"><p>P2, P3 and P4 use the Qwen2.5-Coder-14B-Instruct family with a 4-bit NF4 base and a shared QLoRA adapter. Roles have separate prompts and response contracts; they are not three separately trained base models.</p><p>Accepted outputs must cite supported source IDs and agree with independent dictionary checks. Product identity requires unique supported evidence without conflicts. Manufacturer and supplier are different fields. An unaccepted model response remains visible and cannot silently override source evidence.</p></div></details>
<details class="method-topic"><summary>Version handling and current limitations</summary><div class="topic-body"><p>A CPE wildcard does not establish an installed version. Explicit SBOM, PURL and usable CPE versions are retained with provenance. A shorter numeric release line in a name may coexist with a matching longer installed version.</p><p>Conflict detection currently compares normalized strings: explicit <code>1.2</code> and <code>1.2.0</code> can conflict even though numeric version ordering treats them as equal. This differs from the name release-line exception.</p><p><code>&gt;=1.0, &lt;2.0</code> is preserved as a declared range. The general configuration matcher supports contained / disjoint / partial-overlap checks, but the current identification matching path does not pass this range through. A range-only input can therefore remain unresolved for version-constrained CVEs.</p><p>Plain numeric, configured PEP 440, SemVer, Debian and RPM comparisons are supported; unsupported vendor ordering stays unknown. Escaped CPE syntax remains unsupported by the identification parser. Flattened local source atoms do not establish complete platform AND/OR applicability.</p></div></details>
</div></section>
<section id="operational-method" class="method-notes" aria-label="Operational VEX method">
<h2>Operational VEX without source code</h2>
<p>The current workspace browses 18 MITRE ATT&amp;CK ICS asset types and retrieves stored CVE/product-specific source scenarios. Operators provide accessible inventory, configuration, network access and operating records. Asset classification does not establish an exploit prerequisite or VEX status. This scenario lookup is separate from the identification Hybrid RAG path.</p>
<div class="method-table"><table><thead><tr><th>Tool or model</th><th>Role in the review</th></tr></thead><tbody>
<tr><th>NIST Vulntology</th><td>Represent source-bound vulnerability scenarios. Project extensions preserve AND/OR/NOT, unknown facts and operating observations. Native export requires reviewed source-supported fields and schema validation.</td></tr>
<tr><th>MITRE ATT&amp;CK ICS / Asset</th><td>Organize asset types and technique context; membership alone does not prove exposure or impact.</td></tr>
<tr><th>OVAL / OpenSCAP</th><td>Import supported configuration/state observations into reviewed condition mappings. Missing, failed, mismatched or unevaluated observations remain unknown.</td></tr>
<tr><th>MulVAL / XSB</th><td>Derive attack graphs from supported network, service and vulnerability facts. No derived path does not establish non-impact.</td></tr>
</tbody></table></div>
<p>Review scope binds the CVE, asset, product, build, configuration, operating mode, attacker starting point and evaluation time. Source scenarios need scope and sufficiency review; observations must be valid and cover the reviewed conditions. Missing, expired, conflicting or out-of-scope facts keep the decision under investigation. A source extraction is a draft until reviewed; exact quote validation is not independent semantic accuracy validation.</p>
<div class="overview-links"><a href="vex-decision.html">Open Operational VEX →</a><a href="index.html">Open SBOM → CVE →</a></div>
</section>
<section id="method-datasets" class="method-notes" aria-label="Dataset scope">
<h2>Two separate datasets</h2>
<div class="method-table"><table><thead><tr><th>Dataset</th><th>Unit and contents</th><th>Purpose</th></tr></thead><tbody>
<tr><th>ICSA-derived synthetic BOMs</th><td>3,881 advisory JSONs: 3,108 with CPE components and 773 empty records. Includes 10,847 unique CVEs and 13,365 advisory-CVE occurrences.</td><td>The existing Synthetic SBOM menu. Follow ICSA → listed CVE → vulnerable:true source CPE; retain repeated CVEs across advisories.</td></tr>
<tr><th>Recorded identification evaluation</th><td>12,418 input cases; 5,114 unique SBOM JSONs. Separate input, Gold and results files.</td><td>The recorded H200 evaluation. It was not replaced or rerun using the new advisory-derived BOMs.</td></tr>
</tbody></table></div>
<details class="method-topic"><summary>Current files and source provenance</summary><div class="topic-body"><p>Advisory BOMs: <code>benchmark/icsa-cpe-synthetic sbom/sbom/</code>. <code>index.json</code> supports the list; <code>linkage.jsonl</code> retains original CPE matches, version bounds and source paths; <code>excluded.json</code> records exclusions; <code>manifest.json</code> and <code>audit.json</code> record source fingerprints and integrity checks.</p><p>Evaluation package: <code>benchmark/item3_evaluation/input.jsonl</code>, <code>gold.jsonl</code> and <code>results.json</code>. Join input and Gold by <code>id</code>. Input and Gold were consolidated using NTFS hard links; editing their contents changes all paths linked to the same file. The results package contains scores and verification, not the full raw model trace database.</p></div></details>
<p class="overview-scope">Advisory BOMs collect alternative affected products and releases; they do not establish a verified simultaneous installation. Wildcards are not converted to invented installed versions. CVE answer links are included in these exports, so they must not be used unchanged as blind evaluation inputs. The 3,881-document schema/integrity check is not a new Precision evaluation.</p>
<div class="overview-links"><a href="ics-sbom.html">Browse Synthetic SBOM →</a></div>
</section>
<section id="method-evaluation" class="method-notes" aria-label="Recorded H200 evaluation">
<h2>Recorded H200 evaluation · 2026-11-16</h2>
<p>Both evaluation items retain 12,418 target CVEs. Fresh full-population inference completed in about 54 minutes 21 seconds.</p>
<div class="method-table"><table><thead><tr><th>Measurement</th><th>Recorded result</th></tr></thead><tbody>
<tr><th>Identification · unique-input mapping</th><td>TP 683,488; FP 56; unknown emitted mappings 16; FN 2,227.</td></tr>
<tr><th>Identification · conservative Precision</th><td><code>683488 / (683488 + 56 + 16)</code> = <strong>99.9894669%</strong>. Recall on known positives: 99.6752%.</td></tr>
<tr><th>Operational VEX · full population</th><td>24,678 synthetic-context cases. Raw-model Precision: 98.8731% (TP 2,369 / FP 27).</td></tr>
<tr><th>Operational VEX · separate test</th><td>4,012 CVEs / 6,797 cases. Raw-model Precision: 98.8462% (TP 514 / FP 6).</td></tr>
<tr><th>Operational VEX · test with validation</th><td>Precision 100% (TP 508 / FP 0); Recall 30.4010%; abstention 92.5261%.</td></tr>
</tbody></table></div>
<p class="overview-scope">These are public-source-derived synthetic evaluations. Identification includes training-origin cases and is not an independent held-out generalization score. VEX scores depend on the synthetic operating assumptions. High Precision must be read with Recall and abstention. Independent real-asset Precision remains unmeasured. This documentation update does not rerun or change the recorded evaluation.</p>
</section>
</div>
'''
