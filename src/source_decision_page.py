"""Readable source/context decision rules and authoring boundaries."""
from src.method_flows import vex_flow
from src.cwe_policy_page import explorer

SOURCE_DECISION_HTML = '''
<h1>VEX Decision Logic</h1>
'''+vex_flow()+explorer()+'''
<section class="method-notes" aria-label="VEX evidence and decision rules">
<h2>How the decision is made</h2>
<dl><dt>Status</dt><dd>Code applies evidence rules and fixes the status and scope.</dd>
<dt>Explanation</dt><dd>The LLM writes a draft. It cannot change the assigned status.</dd></dl>
<details class="method-topic"><summary>1 · Decide which evidence is required<span class="topic-prompt">View details</span></summary><div class="topic-body">
<dl><dt>Input</dt><dd>The CVE's published CWE, its Pillar ancestry and specific CVE/advisory evidence.</dd>
<dt>Source required</dt><dd>Review source and build evidence. If source is unavailable, immediately retain under_investigation.</dd>
<dt>Operator review</dt><dd>Use only evidence-supported weaknesses with operator-observable configuration or protocol facts.</dd>
<dt>Unresolved</dt><dd>Missing CWE or insufficient routing evidence remains under_investigation.</dd></dl>
<p>Each of the 944 detailed CWEs has a baseline evidence profile. Direct exceptions and nearest detailed ancestors determine the required facts. Explicit CVE configuration/implementation mechanisms can refine eligible profiles. No Pillar-wide source fallback applies. Hardware, design and unspecified mechanisms remain explicit. Reported CWEs are preserved; mapping usage is informational and does not block analysis.</p>
<p class="method-boundary">The CWE hierarchy is official. The analysis-routing policy is a separate project policy awaiting independent validation. Pillar alone does not determine the method.</p>
</div></details>
<details class="method-topic"><summary>2 · Analyze each eligible CVE<span class="topic-prompt">View details</span></summary><div class="topic-body">
<dl><dt>Source branch</dt><dd>Parse C, C++, Python, Java, SQL, JavaScript, Go, R and Ruby source text with Tree-sitter. Record definitions, source locations and name-based call candidates without running the project. Configured C/C++ builds can additionally use Clang/LLVM CFG and direct calls.</dd>
<dt>Operational branch</dt><dd>Rule templates produce common weakness-type and CVE-specific questions that an operator can answer using configuration and operating records.</dd>
<dt>Answers</dt><dd>Collect yes / no / unknown, installed-build facts and supporting records. Unknown operating facts remain unknown.</dd>
<dt>Evidence checks</dt><dd>Validate source references and output format. A valid reference does not establish semantic correctness.</dd></dl>
<p class="method-boundary">Four workflows: source only; source + operating context; required source missing; operating context only. Source-required cases enter an operating questionnaire only after a source result is recorded. Operating-only cases do not escalate to source review from questionnaire answers. Both evidence branches retain one case ID; missing required results or conflicting decisions remain under investigation.</p>
</div></details>
<details class="method-topic"><summary>3 · Decide the status<span class="topic-prompt">View details</span></summary><div class="topic-body">
<dl><dt><code>not_affected</code></dt><dd>Supported targets are absent or unreachable within the required complete scope, with no analysis blockers.</dd>
<dt><code>fixed</code></dt><dd>An explicit vendor-fixed version matches a scoped, operator-attested installation record.</dd>
<dt><code>under_investigation</code></dt><dd>Required version, mapping, path, operating or installation evidence is missing.</dd></dl>
<p class="method-boundary">A reachable function is not automatically affected. A disabled feature is not proof of code absence.</p>
</div></details>
<details class="method-topic"><summary>4 · Write and validate the explanation<span class="topic-prompt">View details</span></summary><div class="topic-body">
<dl><dt>Writer input</dt><dd>The assigned status, product/CVE IDs, evidence references and missing facts.</dd>
<dt>LLM output</dt><dd>Impact and action text for review.</dd>
<dt>Validation</dt><dd>Check complete JSON, locked IDs/status, evidence references and repetition.</dd>
<dt>If writing fails</dt><dd>Reject the generated text. Keep the status, evidence and rule-based rationale.</dd></dl>
<div class="method-example"><b>Example</b><p>If code assigns <code>under_investigation</code>, the writer cannot promote it to <code>not_affected</code>.</p></div>
</div></details>
<details class="method-extra"><summary>What is exported?</summary>
<ul><li><b>CycloneDX:</b> a copy of the original SBOM with component-specific VEX analysis and schema checks.</li>
<li><b>OpenVEX / CSAF:</b> standalone review documents. SPDX input currently uses standalone VEX export.</li>
<li><b>Review log:</b> questions, answers, evidence, model outputs, rejected attempts and validation results.</li></ul>
<p>A rejected LLM explanation does not prevent export of the supported rule-based assessment.</p>
</details>
<details class="method-extra"><summary>Source analysis limits</summary>
<ul><li>Inspect compile_commands.json and build manifests; do not execute uploaded build commands.</li>
<li>Source AST analysis needs no executable or build database. Syntax call candidates are not a verified runtime CFG and cannot authorize absence/unreachability clearance.</li>
<li>Dynamic dispatch, imports, callbacks, cross-language FFI and SQL dialect/quoted-body coverage remain incomplete. Parser errors and unresolved calls are exported.</li>
<li>Compiler errors, missing units and unresolved calls can block negative conclusions.</li>
<li>Patch-hunk similarity does not prove that every fix is present.</li>
<li>Partial source cannot establish whole-product absence or unreachability.</li>
<li>Source completeness and deployed binary identity are not independently attested.</li></ul>
</details>
<details class="method-extra"><summary>Models, CWE and stored records</summary>
<ul><li>Rules extract literal condition/function spans from the source catalog. Only final VEX authoring uses the trained writer adapter.</li>
<li>Operational questions use CWE-specific templates; answer assessment uses deterministic evidence/version rules. Independent validation of rule coverage is pending.</li>
<li>Pinned CWE v5.0 ancestry supports routing. The project policy combines Pillar, specific CWE and advisory evidence; classification is not an exploit prerequisite or clearance rule.</li>
<li>Independent Claude/Gemini verification and expanded vector RAG are not connected.</li>
<li>Local SQLite retains questionnaires/reviews for 24 hours and completed identification jobs for seven days.</li></ul>
</details>
</section>
'''
