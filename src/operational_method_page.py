"""Documentation of the active operational-context VEX path."""
OPERATIONAL_METHOD_HTML = '''<h1>Operational-context VEX</h1>
<p class="sub">SBOM &rarr; CVE identification &rarr; operating-context review &rarr; VEX</p>
<section class="card"><h2>1. Identify the component and CVEs</h2>
<p>Resolve product identity and declared versions from the SBOM. Preserve uncertain matches for review.</p></section>
<section class="card"><h2>2. Collect operating facts</h2>
<p>All CVEs follow this path. Record shared asset context, installed product/version records and CVE-specific answers as yes, no or unknown.</p>
<p>Shared asset facts are collected once. Fixed workflow questions are selected by each CVE’s operational types. Wording, template IDs and question purposes are versioned. No question model is called.</p>
<p>Open the classification panel to see the type definition, selection criterion, literal source match and context. CVSS-only paths and unresolved cases remain distinct. Dependency and recovery checks support outage planning and cannot establish non-impact.</p></section>
<section class="card"><h2>Operational classification criteria</h2><div id="classification-catalog"><p class="hint">Loading the pinned type definitions…</p></div></section>
<section class="card"><h2>3. Assess impact</h2>
<p>Deterministic checks evaluate scope, version records and operating conditions. Advisory estimates describe likely impact; insufficient or conflicting evidence keeps the standard VEX status under investigation.</p>
<p>Network filtering and disabled features are operating mitigations. They do not establish that vulnerable code is absent.</p></section>
<section class="card"><h2>4. Explain and export</h2>
<p>The VEX writer explains the fixed decision using cited evidence. It cannot change the status. Review the draft and export CSAF, OpenVEX or CycloneDX VEX.</p></section>'''
