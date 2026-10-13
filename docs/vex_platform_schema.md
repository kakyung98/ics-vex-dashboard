# VEX integration schema — unified security management platform

The interface definition for the VEX data ICS-VEXForge hands to the **unified security
management platform**. The platform's UI team uses this document as the contract.

- **Direction**: the document ICS-VEXForge **outputs** is the document the platform takes
  as **input** — the same schema.
- **Standards alignment**: the status and justification vocabularies are compatible with
  **OpenVEX / CISA CSAF-VEX**. On top of that it adds, as a superset, the
  **explainability (evidence), risk and provenance** fields the UI needs in order to
  display anything.
- **Format**: UTF-8 JSON. Times are ISO 8601 UTC (`YYYY-MM-DDThh:mm:ssZ`).
- **Unit of adjudication**: `product x vulnerability` — one CVE can hold a different
  status per product, so one statement = one (product, vulnerability) pair.
- Machine-checkable JSON Schema: [`vex_platform_schema.json`](vex_platform_schema.json) ·
  a real-data example: [`vex_platform_example.json`](vex_platform_example.json).

---

## 1. Output (ICS-VEXForge -> platform): `VexDocument`

### 1.1 Document envelope

| field | type | required | description |
|---|---|---|---|
| `schema_version` | string | ✅ | version of this integration schema (e.g. `"1.0"`) |
| `generator` | object | ✅ | generator information, below |
| `generator.name` | string | ✅ | generator name |
| `generator.version` | string | ✅ | generator version (e.g. `"2026.09"`) |
| `generator.org` | string | ➖ | publishing organisation (e.g. `"Chonnam SSRC"`) |
| `generated_at` | string (ISO8601) | ✅ | document generation time (UTC) |
| `spec` | string | ✅ | vocabulary alignment marker; fixed value `"openvex-compatible"` |
| `asset` | object \| null | ➖ | the asset/device this VEX is about (one per SBOM), below |
| `asset.asset_id` | string | ✅* | platform asset identifier (required when `asset` is present) |
| `asset.product` | string \| null | ➖ | asset (device) product name |
| `asset.vendor` | string \| null | ➖ | asset vendor |
| `asset.sbom_ref` | string \| null | ➖ | reference to the source SBOM (ID/URL) |
| `statement_count` | integer | ✅ | length of `statements` |
| `statements` | array\<VexStatement\> | ✅ | the VEX verdicts (zero or more) |

### 1.2 A VEX verdict (`VexStatement`) — the core record

#### (a) Identity

| field | type | required | description |
|---|---|---|---|
| `statement_id` | string | ✅ | stable unique id; rule: `"<cve>@<product_id>"` |
| `vulnerability` | object | ✅ | the vulnerability, below |
| `vulnerability.cve` | string | ✅ | `CVE-YYYY-N…` (regex `^CVE-\d{4}-\d+$`) |
| `vulnerability.cwe` | array\<string\> | ➖ | CWE list (e.g. `["CWE-787"]`) |
| `vulnerability.title` | string \| null | ➖ | short summary of the vulnerability |
| `vulnerability.aliases` | array\<string\> | ➖ | aliases (GHSA, ICSA, …) |

#### (b) The product in question

| field | type | required | description |
|---|---|---|---|
| `product` | object | ✅ | the affected product/component, below |
| `product.product_id` | string | ✅ | CSAF-style product id (used in statement_id) |
| `product.name` | string | ✅ | component/product name (e.g. `"zlib"`) |
| `product.version` | string | ✅ | version string, or `"NOASSERTION"` when unknown |
| `product.vendor` | string \| null | ➖ | vendor |
| `product.purl` | string \| null | ➖ | Package URL (e.g. `pkg:generic/zlib@1.2.12`) |
| `product.cpe` | string \| null | ➖ | CPE 2.3 string |
| `product.ics_device` | string \| null | ➖ | the ICS device/model this component is embedded in |

#### (c) The VEX verdict (standard vocabulary)

| field | type | required | description |
|---|---|---|---|
| `status` | enum(string) | ✅ | `affected` \| `not_affected` \| `fixed` \| `under_investigation` |
| `justification` | enum(string) \| null | conditional | **required** when `status=not_affected`, otherwise `null` |
| `action_statement` | string \| null | conditional | recommended action when `status=affected` |
| `impact_statement` | string \| null | ➖ | impact description (optional) |

- `justification` enum: `component_not_present` \| `vulnerable_code_not_present` \|
  `vulnerable_code_not_in_execute_path` \| `vulnerable_code_cannot_be_controlled_by_adversary` \|
  `inline_mitigations_already_exist` (CISA's five).

#### (d) Explainability (an ICS-VEXForge extension) — the UI's "why?"

| field | type | required | description |
|---|---|---|---|
| `evidence` | object | ✅ | the grounds for the verdict, below |
| `evidence.tier` | enum(string) | ✅ | strength of the evidence (enum below) |
| `evidence.basis` | string | ✅ | one human-readable line of grounds |
| `evidence.decided_by` | enum(string) | ✅ | the step that settled it: `presence` \| `source-absence` \| `sbom` |
| `evidence.method` | string | ➖ | analysis method (e.g. `"VEX-v2 (CTI + Joern + Z3)"`) |
| `evidence.gates` | object | ✅ | result per gate, below (the hierarchy: **presence decides; Q3/Q4 are optional evidence**) |
| `evidence.gates.presence` | enum \| null | ✅ | Q2: `present` \| `component_only` \| `absent` \| `null` |
| `evidence.gates.reachability` | enum \| null | ➖ | Q3 (Joern): `reachable` \| `not-reachable` \| `unknown` \| `null` |
| `evidence.gates.controllability` | enum \| null | ➖ | Q4 (Z3): `controllable` \| `not-controllable` \| `environment-dependent` \| `unknown` \| `null` |

- `evidence.tier` enum: `verified` (present + reachable + controllable) \|
  `reachable` (present + reachable) \| `present` (present only) \|
  `component` (component only, function not localised) \| `sbom-evidenced` (absent from the
  SBOM) \| `not-present` (function absent from the source) \| `under-investigation`.
- **Display rule for the UI**: `reachability` and `controllability` are **optional
  evidence**. When Q3 is not `reachable`, the `controllability` value plays no part in the
  verdict, so the UI should show it as "not applicable" — respect the gate order.

#### (e) Risk and prioritisation context

| field | type | required | description |
|---|---|---|---|
| `risk` | object | ✅ | below |
| `risk.severity` | enum(string) | ✅ | `critical` \| `high` \| `medium` \| `low` \| `unrated` |
| `risk.cvss` | object | ✅ | below |
| `risk.cvss.score` | number \| null | ➖ | 0.0–10.0 |
| `risk.cvss.vector` | string \| null | ➖ | the CVSS vector string |
| `risk.cvss.version` | string \| null | ➖ | `"3.1"` and so on |
| `risk.kev` | boolean | ✅ | whether it is listed in CISA KEV |
| `risk.epss` | number \| null | ➖ | EPSS probability, 0.0–1.0 |
| `risk.attack_vector` | enum \| null | ➖ | `N` \| `A` \| `L` \| `P` \| `null` (CVSS AV) |
| `risk.ssvc` | object \| null | ➖ | below |
| `risk.ssvc.priority` | enum \| null | ➖ | `act` \| `attend` \| `track*` \| `track` \| `null` |
| `risk.ssvc.vector` | string \| null | ➖ | `SSVCv2/…` vector |

#### (f) Provenance

| field | type | required | description |
|---|---|---|---|
| `provenance` | object | ✅ | below |
| `provenance.advisory` | string \| null | ➖ | the originating ICS advisory id (e.g. `"ICSA-22-…"`) |
| `provenance.source_repo` | string \| null | ➖ | URL of the OSS repository that was analysed |
| `provenance.analyzed_version` | string \| null | ➖ | the source version actually analysed (the snapshot) |
| `provenance.references` | array\<string\> | ➖ | reference URLs (NVD and others) |
| `last_updated` | string (ISO8601) | ✅ | when this statement was last updated |

---

## 2. Input (platform -> ICS-VEXForge): `VexRequest`

What the platform sends when **requesting** a VEX. Two modes.

| field | type | required | description |
|---|---|---|---|
| `request_id` | string | ✅ | request tracking id |
| `mode` | enum(string) | ✅ | `sbom` (analyse an SBOM) \| `query` (look up existing results) |
| `sbom` | object \| null | conditional | a CycloneDX 1.7 SBOM document when `mode=sbom` |
| `sbom_ref` | string \| null | ➖ | for passing the SBOM by reference instead of inline |
| `exposure` | enum \| null | ➖ | deployment exposure for SSVC: `open` \| `controlled` \| `small` \| `null` |
| `filter` | object \| null | conditional | the filter when `mode=query`, below |
| `filter.cve` | array\<string\> \| null | ➖ | CVE allowlist |
| `filter.asset_id` | string \| null | ➖ | a specific asset |
| `filter.status` | array\<enum\> \| null | ➖ | status filter (`affected` and so on) |
| `filter.min_severity` | enum \| null | ➖ | `critical` / `high` / … and above only |

The response is always the **`VexDocument`** of section 1.

---

## 3. Status x required fields (for UI branching)

| status | justification | action_statement | typical evidence.tier |
|---|---|---|---|
| `affected` | `null` | recommended action (optional) | verified / reachable / present / component |
| `not_affected` | **required** (one of the five) | `null` | sbom-evidenced / not-present |
| `fixed` | `null` | patch information (optional) | (grounded in a patch signature) |
| `under_investigation` | `null` | `null` | under-investigation |

---

## 4. Example

A full document example mapped from real data:
[`vex_platform_example.json`](vex_platform_example.json). Below is a single `affected`
statement.

```json
{
  "statement_id": "CVE-2022-37434@zlib",
  "vulnerability": { "cve": "CVE-2022-37434", "cwe": ["CWE-787", "CWE-120"],
    "title": "zlib heap over-read in inflate via a large gzip header" },
  "product": { "product_id": "zlib:1.2.12", "name": "zlib", "version": "1.2.12",
    "vendor": "ABB", "purl": "pkg:generic/zlib@1.2.12", "cpe": null,
    "ics_device": "Lumada Asset Performance Management" },
  "status": "affected",
  "justification": null,
  "action_statement": "Update zlib to a fixed release (>= 1.2.13).",
  "impact_statement": null,
  "evidence": {
    "tier": "present",
    "basis": "vulnerable code present; not refuted (Q3/Q4 optional and not decisive here)",
    "decided_by": "presence",
    "method": "VEX-v2 (CTI + Joern + Z3)",
    "gates": { "presence": "present", "reachability": "not-reachable", "controllability": "controllable" }
  },
  "risk": { "severity": "critical", "cvss": { "score": 9.8, "vector": null, "version": "3.1" },
    "kev": false, "epss": null, "attack_vector": null, "ssvc": { "priority": null, "vector": null } },
  "provenance": { "advisory": null, "source_repo": "https://github.com/madler/zlib",
    "analyzed_version": "zlib-1.2.12", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-37434"] },
  "last_updated": "2026-09-28T00:00:00Z"
}
```

---

## 5. Design notes (to agree with the platform team)

1. **Standard vs extension**: the core vocabularies (`status`, `justification`) are
   OpenVEX/CSAF as-is, so standard tooling interoperates. `evidence`, `risk` and
   `provenance` are this system's extensions, and a standard-only consumer can ignore them.
2. **Required/optional notation**: ✅ = required, ➖ = optional, "conditional" = required
   for certain statuses or modes.
3. **Null rule**: when a value is absent, send `null` rather than omitting the key, so UI
   rendering stays stable. An absent array is `[]`.
4. **Version policy**: a major change to `schema_version` is incompatible; adding fields is
   a minor change and backwards compatible.
5. The transport (REST response, file upload, message queue) is agreed separately — this
   schema specifies the payload shape only.
