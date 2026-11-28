# Local storage after the 2026-11-18 cleanup

The active project is `D:\ICS-VEX`. Its current web service no longer imports project modules or opens review databases from the C drive.

| Location | Keep for |
| --- | --- |
| `D:\ICS-VEX\local-service\sbom-vex` | Required service modules, English UI templates, profile definitions and pinned schemas are included through `local-service/runtime_manifest.json` and the explicit `.gitignore` allowlist. Private review/workflow SQLite databases, logs and local run artifacts remain ignored and require local backups. |
| `D:\ICS-VEX\data`, `icsa`, `models`, `benchmark`, `site`, `src`, `tools`, `schemas`, `tests`, `docs` | Source records, compiled catalogues, trained adapters, evaluation inputs, code and website assets. |
| `D:\ICS-VEX\results\nist_population_vex_20261118` | Frozen 12,418-CVE / 37,254-case experiment inputs, references, protocol, decisions, metrics and deployment records. |
| `D:\ICS-VEX-support\cache\huggingface` | Shared model/dataset cache relocated from C. HF snapshot links are now same-volume D hard links to copied blobs. Frozen base-weight hashes and trained-adapter hashes were verified. |
| `D:\ICS-VEX-support\cache` | Retained quantized historical models, conversion receipts/code and other preserved model dependencies. Regenerable BF16 conversion intermediates and disposable caches are cleanup candidates, not unique trained adapters. |
| `D:\ICS-VEX-support\runs` | Historical experiment outputs and source evidence retained for reproducibility. |
| `D:\ICS-VEX-support\archive` | Unique historical files, migration evidence and the intact former C service workspace. After migration-ledger duplicate cleanup, `migration-20261116/source-original/project` is a retained-differences archive, not a standalone complete project backup; consult the deletion manifest for each retained counterpart. |
| `D:\ICS-VEX-support\cleanup-20261118` | Exact SHA-256 duplicate inventory, deletion log, storage relocation checks, original path metadata and protected-model verification. |

`HF_HOME`, `HF_HUB_CACHE` and `HF_DATASETS_CACHE` user settings point to D. The main launcher also sets the D cache location for fresh launches from older desktop processes. Model metadata changed only its storage paths; model parameters and training/evaluation labels were preserved.

Python, Codex and other shared installed programs remain on C. Historical documents can still contain their original C paths as provenance. Those strings do not identify active project data. An old C Desktop junction may remain while another process holds it; its target is the D project and it stores no duplicate project data. Its removal was also rejected by automatic approval review.

Start the site from `D:\ICS-VEX`:

```powershell
python -X utf8 -B tools/serve_nist_operational_vex.py 8100
```

For experiment reproduction, see `docs/NIST_FULL_POPULATION_AUTO_VEX.md`. Frozen experiment inputs/reference files are not cache cleanup targets.
