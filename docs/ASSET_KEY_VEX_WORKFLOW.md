# Asset-key input and VEX workflow

Implemented on 2026-11-20. The active page is `/item4.html`, also served by
`/bom-vex.html` and `/vex-decision.html`.

## Four stages

1. Agent 1 retains ICSA-based component asset classification.
2. Agent 2 retains product-scoped source extraction: positive atoms, exact
   quotations, uncertainties and AND/OR/NOT scenario expressions.
3. Agent 3 displays the selected type's keys and source-specific questions.
   Operators select `o`, `x`, unknown, not applicable or conflicting records.
4. Agent 4 evaluates the saved revision with MulVAL/XSB and supplier version
   rules, then exports OpenVEX or CycloneDX VEX.

`data/operator_asset_keys.csv.gz` preserves the exact UTF-8 BOM CSV catalogue:
505 entries covering all 18 MITRE ICS types, with no per-type quota. This is a
project-authored catalogue, not a MITRE questionnaire. Decoded definitions are
available at `GET /api/item4/analyses/asset-keys`.

## Input semantics

- Inventory-only keys record facts without creating CVE prerequisites.
- Unambiguous positive enabled-feature targets may bind through the explicit
  `ENABLED_TARGETS` vocabulary in `src/item4_asset_inputs.py`. Port qualifiers
  and quantifiers are not stripped to force matches.
- Other admitted conditions receive a `cve_fact_<condition-id>` key containing
  the exact positive statement, source quotation and accessible-record check.
- Source-bound values are isolated by CVE, component and condition target.
  Unclassified components do not inherit another component's type or answers.
- Unknown, not applicable and conflicting values evaluate as unknown. `x`
  makes the positive atom false; source NOT is applied once in the expression.
- Operator attestations retain timestamps and scope identifiers. They are not
  independently verified operating evidence or proof of attacker credentials.
- Changing context clears previous values unless explicitly re-attested in
  the same request. The UI clears values when mode, origin, product or other
  context changes, requiring the operator to confirm the new scope.

## API and persistence

- `POST /api/item4/analyses/start`
- `GET /api/item4/analyses/jobs/{id}`
- `POST /api/item4/analyses/jobs/{id}/retry`
- `POST /api/item4/analyses/jobs/{id}/answers`
- `POST /api/item4/analyses/jobs/{id}/assess`
- `GET /api/item4/analyses/jobs/{id}/assessment`
- `GET /api/item4/analyses/jobs/{id}/export/{analysis|review|openvex|cyclonedx}`

Answers use server-issued question IDs with `answers`, `context_answers`,
`revision` and `plan_sha256`. Assessment accepts only `revision` and
`plan_sha256`. Client verdicts, arbitrary mappings and unregistered choices are
rejected. Revision conflicts return HTTP 409.

Saving changes increments the revision and invalidates assessment and exports.
The browser disables downloads as soon as values change. Export checks the
current revision, plan, answer digest, supplier registry and source evidence.
Catalogue, binding vocabulary, component and extraction changes reset stale
answers. Existing durable job storage is reused. Retired answers are not
migrated; local tab drafts restore only for the same plan and revision.

Explicit source retries accept the current `revision` and `plan_sha256`, retain
successful CVE extractions, and rerun unresolved CVEs and unresolved asset
classification. They use the original hash-checked BOM and the same job ID.
Rebuilding the plan invalidates prior answers and VEX exports. The active page
offers **Retry unresolved analysis** for failed or incomplete source stages.

V4 records `running`, `completed` and `failed` assessment states. Two assessments
may run concurrently; a duplicate request for the same job returns HTTP 429.
Editing inputs during V4 prevents the old result from overwriting the newer
revision. Interrupted assessments retain saved inputs and can be evaluated
again after restart. Missing dependencies or storage return HTTP 503.

JSON requests are limited while streaming to 4 MiB. Duplicate JSON keys,
non-finite constants, malformed component references and malformed SPDX
packages return HTTP 422. BOMs are bounded to 10,000 components, 32 nesting
levels and 2,000 declared CVEs.

The active shell and asset classification use the 505-key catalogue directly;
they do not load the retired 167-field profile editor. The historical
`data/nist_auto_vex/rules.json` registry is optional. Its absence provides no
supplier version claims; current product-scoped ICSA/CSAF evidence still
applies. An existing corrupt registry continues to fail validation. Adding or
changing a registry invalidates exports until the assessment is rerun.

Run the API and website together, rather than using `python -m http.server`:

```powershell
python -B -X utf8 tools/item4/serve_nist_operational_vex.py 8100
```

`ICSVEX_SESSION_DB` can select a separate durable session database for isolated
verification. It defaults to `results/runtime_sessions.sqlite3`; the production
launcher may retain its existing validated runtime-store override.

The local service admits up to three source analyses at once, including jobs
recovered on request after a restart. When all slots are occupied, submission
and recovery return HTTP 429 with `Retry-After`; retry with the same request
or job ID. A completed or failed job releases its slot. Its last SQLite
snapshot remains available for seven days from its last write.

Legacy `/api/item4/questionnaires/*` and retired general questionnaire APIs
remain closed. This methodology uses `/api/item4/analyses`.

## Decision and export boundaries

The result separates product applicability, prerequisite satisfaction,
deployment exploitability and product VEX status. Known paths blocked by `x`
do not establish product `not_affected`. Supplier evidence is required for
fixed/unaffected version decisions. A supplier-confirmed fixed or unaffected
build requires an identified component and confirmation of its current running
version and deployment. Its graph status is `not_required`. CSAF status evidence
records the document hash and pointers to the product and status entry.
Conflicting source claims and unresolved version membership keep the product
under investigation.

An affected decision requires at least one source scenario with a confirmed
product binding and satisfied operating conditions. A source gap concerning a required
condition or product binding adds an unknown operand to each applicable route.
An explicitly contextual note remains in the review. Older unclassified gaps
apply to every route. An independently supported alternative can still satisfy
the decision. Unavailable graph generation leaves this decision under investigation.
Satisfied prerequisites do not prove exploit execution or complete path coverage.

OpenVEX and CycloneDX include the extraction adapter's evaluation result and
any recorded experimental approval when the analysis used a role adapter.
OpenVEX uses the bundled schema validator. The CycloneDX export updates entries
whose target exactly matches the assessed component and preserves the prior
analysis for audit. For a broader or version-qualified target it preserves the
original entry and records the scoped decision separately. Unassessed entries
and existing references remain in the exported inventory. CycloneDX uses the
offline BOM schema validator. SPDX input uses the SPDX-to-CycloneDX inventory
serializer.

Standard VEX exports require a selected BOM component for every CVE; unresolved
product associations can still be exported as assessment reviews. Optional
CycloneDX component refs are assigned in the export copy without changing the
original BOM.

The Operational VEX page preserves the SBOM identification workspace header,
title alignment, upload form styling and footer. The client can restore the
canonical chrome from `/index.html` for an already-running earlier renderer,
so an active analysis does not need to restart for this presentation change.

## Verification

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python -B -m pytest -q -p no:cacheprovider tests/item4/test_operational_backend.py tests/item4/test_item4_asset_key_workflow.py tests/item4/test_item4_questionnaire.py tests/item4/test_item4_vex_assessment.py tests/item4/test_item4_job_recovery.py tests/item4/test_item4_advisory_context.py
node tests/item4/test_item4_questionnaire_ui.cjs
```

Synthetic workflow tests separate source/graph fixtures from actual inference.
They test implementation behavior, not independent real-CVE label accuracy.
A separate synthetic case was run through the configured real MulVAL/XSB
backend to verify true/false/unknown behavior. Browser verification uses a
separate port and durable store; it does not alter existing user assessments.
