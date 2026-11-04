# Clang source review and CWE context

Implemented 2026-11-01. The default uploaded-source endpoint now uses
`src/clang_source.py`; the historical `source_cfg.py` backend is available only
through explicit `engine: "legacy"` requests for comparison.

## Why Clang/LLVM

Clang preprocesses the selected C/C++ translation units, including allowed local
include paths, macros and language-standard flags. It emits LLVM IR at O0 with
debug information and `-femit-all-decls`, so unused static functions are not
mistaken for missing source. llvmlite parses and verifies the actual compiler IR;
basic-block successors produce intraprocedural CFGs and direct call operands
produce interprocedural edges. C++ mangled symbols and per-translation-unit IDs
separate overloads and same-named file-local functions.

Joern's CPG is useful for future data-flow/taint extensions. CodeQL also supports
C/C++ extraction, including build-free extraction, but neither database creation
nor the absence of findings proves a CVE unreachable. This implementation uses
one inspectable compiler-backed path rather than claiming unimplemented tools.

References: [Clang compilation database](https://clang.llvm.org/docs/JSONCompilationDatabase.html),
[LLVM IR](https://llvm.org/docs/LangRef.html),
[llvmlite module inspection](https://llvmlite.readthedocs.io/en/latest/user-guide/binding/modules.html),
[Joern calls](https://docs.joern.io/cpgql/calls/),
[CodeQL extraction](https://docs.github.com/en/code-security/tutorials/customize-code-scanning/prepare-code-for-analysis).

## Setup and request

```powershell
python -m pip install -r requirements.txt
python tools/setup_clang.py
```

Windows setup requires 7-Zip and extracts the official LLVM 18.1.8 archive into
`.tools/llvm18/`; the installer is not executed. Download/compiler hashes are
recorded in `.tools/llvm18/provenance.json`; these are provenance hashes, not an
independent signature verification claim. On another platform install Clang and
set `ICSVEX_CLANG` to its executable path. Compiler builtin headers are included;
the actual target SDK, generated headers and vendor dependencies may still be
missing and then compilation is blocked, never silently assumed successful.

Upload a source ZIP through `/api/source/upload`, then POST `/api/source/judge`:

```json
{
  "session": "<upload session>",
  "engine": "clang",
  "analysis_scope": "product",
  "entry_points": ["main", "protocol_callback"],
  "tree_is_complete": true,
  "cves": [{"cve": "CVE-2099-12345", "functions": ["candidate_target"]}]
}
```

The completeness flag is a caller declaration and is recorded as an assumption,
not independently verified source completeness. Supply every relevant callback,
interrupt, initialization and thread/plugin entry point. Product negatives are
limited to the selected compilation entries and this declared entry set.
Without the declaration, an explicit root set, a compilation database and
unblocked analysis, missing paths do not produce a negative verdict.

`library` roots all compiled externally visible functions, reports API paths and
blocks product-level negatives because consumer integration is absent. `partial`
reports local observations and cannot establish whole-product absence.

Compilation commands are not replayed. The server invokes its own Clang with an
allowlist of declarative frontend flags; uploaded executables, shell commands,
plugins, response files, linking and generated programs are never executed.
Unsupported compiler options/target environments, missing include paths,
compiler errors/timeouts, unresolved external/indirect calls, address escapes and
ambiguous definitions block negative decisions. All selected units are bounded
by file/time/IR-size limits. Resource limits are reported as incomplete analysis.

## What the user sees

Each result explains these separate facts:

1. **Scope and build:** product/library/partial; compiler version; accepted and
   rejected flags; successful versus selected translation units; source/IR hashes
   and diagnostics. Successful IR generation is not a verified linked build.
2. **Target locations:** symbol IDs, source files and definition lines. CVE
   Description names and patch-header names remain candidate mappings; their
   completeness and CVE causality are not independently established.
3. **Paths:** e.g. `main -> wrapper -> candidate_target`, with each caller's source
   line, IR basic block and symbol IDs. A graph path is a possible execution path,
   not a proven exploit or proof of attacker control.
4. **Decision:** targets absent or unreachable can produce scoped `not_affected`
   only with the declared scope and no blockers. A reachable target remains
   `under_investigation` until actual CVE applicability/trigger evidence exists.
5. **Gaps:** failed units, unresolved dispatch, incomplete entry/dependency scope,
   unverified target mapping and deployed-binary identity. Missing evidence is
   displayed; it is not converted to a safe result.

The evidence observations and decision are assembled deterministically. The shared
LLM writer adds a validated explanation draft from that packet without changing
the decision; see [shared runtime](SHARED_VEX_PIPELINE.md). The UI exposes raw
extractions, paths, blockers, writer inputs, model outputs and validation failures.
Attacker-input taint analysis, symbolic path feasibility, patch completeness and
deployed-binary binding are not implemented by this backend. The historical
0/267 pycparser campaign is not a measurement of this new Clang engine.

## CWE for source-unavailable review

Both `/api/oc/judge` and the candidate-job context handoff retain multiple CWE IDs
from cached NVD data, the corpus and/or caller input. Each classification records
its origin and a MITRE definition link. Curated profiles offer weakness-specific
review questions; unsupported IDs stay as supplied classifications without
invented CVE-specific semantics. Missing/placeholder CWEs remain unknown.

Classification and review questions are kept outside the OC prerequisite rows.
They always carry `can_refute: false`: CWE-78 does not establish a network
interface, required privilege or a particular command interpreter; CWE-787 does
not establish which parser/length/configuration triggers a specific CVE. CWE-20
is explicitly marked broad. Adding CWE alone cannot change VEX status or clear
a CVE. The UI and contextual-review JSON retain the classification and questions.

MITRE references: [CWE-78](https://cwe.mitre.org/data/definitions/78.html),
[CWE-787](https://cwe.mitre.org/data/definitions/787.html),
[CWE-20](https://cwe.mitre.org/data/definitions/20.html).

## Validation

Real local Clang runs cover preprocessor/header changes, unused static targets,
C++ overloads, same-named static functions across files, cross-unit path/call-site
evidence, compile failures, rejected plugin options, indirect/external calls,
library scope and the source-upload API. CWE tests check provenance, multiple IDs,
unknown labels and invariance of VEX status when only classification changes.

```powershell
python -m pytest -q tests/test_clang_source.py tests/test_cwe_context.py tests/test_source_evidence.py tests/test_candidate_web.py tests/test_pages_backend.py
```

These are implementation regressions, not corpus-wide CVE/exploitability accuracy
or independently verified exploitability results.
