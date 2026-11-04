"""ICS-VEXForge source evidence analysis. Uploaded programs are never executed.

Patch fingerprints and compilation databases are observations, not proofs of a
deployed binary's contents. This backend has no sound whole-program analyser;
Function absence clears a CVE under the configured uploaded-source policy;
missing mappings, incomplete intake and unresolved references remain open.
"""
from pathlib import Path
import hashlib
import json
import re
import shlex
from collections import Counter

from src import source_intake as SI
from src import source_cfg, clang_source

DATA = Path(__file__).resolve().parents[1] / "data"
CODE = set(SI.LANG_EXT)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def inspect_build(root):
    """Resolve paths against uploaded files; never read host paths from a DB."""
    root = Path(root)
    sources = [p for p in root.rglob("*") if p.is_file() and p.suffix in CODE]
    rels = [p.relative_to(root).as_posix() for p in sources]
    databases, units, unresolved, configurations = [], set(), [], []
    manifests = []
    names = {"CMakeLists.txt", "Makefile", "meson.build", "Cargo.toml",
             "package.json", "pyproject.toml", "requirements.txt", ".config"}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if p.name in names:
            manifests.append({"file": rel, "sha256": digest(p)})
        if p.name != "compile_commands.json":
            continue
        rows = load_json(p, None)
        valid = isinstance(rows, list)
        databases.append({"file": rel, "sha256": digest(p), "valid": valid})
        if not valid:
            unresolved.append({"database": rel, "reason": "invalid_json_array"})
            continue
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("file"), str):
                unresolved.append({"database": rel, "reason": "invalid_entry"})
                continue
            raw = row["file"].replace("\\", "/")
            # A checkout may have moved since compilation. Require a unique
            # suffix match, never assume a same-basename file is the same unit.
            candidates = [r for r in rels if raw == r or raw.endswith("/" + r)
                          or r.endswith("/" + raw)]
            if len(candidates) == 1:
                units.add(candidates[0])
                args = row.get("arguments")
                if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
                    try:
                        args = shlex.split(row.get("command", ""), posix=False)
                    except (ValueError, TypeError):
                        args = []
                configurations.append({"file": candidates[0], "database": rel,
                                       "directory": row.get('directory', ''), "source_file": row['file'],
                                       "arguments": args, "output": row.get("output"),
                                       "configuration_verified": False})
            else:
                unresolved.append({"file": raw, "reason": "unmapped_or_ambiguous"})
    return {"compilation_databases": databases, "translation_units": sorted(units),
            "configurations": configurations,
            "unresolved_entries": unresolved, "manifests": manifests,
            "coverage": "declared_compilation_only" if databases else "missing",
            "binary_verified": False, "commands_executed": False,
            "note": "Compilation entries describe translation units, not linked headers, libraries or deployed binaries. Unlisted files are not proven excluded."}


def parse_patch(text):
    """Keep both sides of each hunk, including context to avoid token matches."""
    hunks, current, file = [], None, None
    for line in text.splitlines():
        if line.startswith("diff --git "):
            current = None
        elif line.startswith("+++ "):
            file = line[4:].split("\t")[0].removeprefix("b/")
            current = None
        elif line.startswith("@@") and file and Path(file).suffix in CODE:
            current = {"file": file, "header": line, "before": [], "after": [], "changed": False}
            hunks.append(current)
        elif current is not None:
            if line.startswith(" "):
                current["before"].append(line[1:]); current["after"].append(line[1:])
            elif line.startswith("-"):
                current["before"].append(line[1:]); current["changed"] = True
            elif line.startswith("+"):
                current["after"].append(line[1:]); current["changed"] = True
            elif not line.startswith("\\"):
                current = None
    return [h for h in hunks if h["changed"]]


def normalized(text):
    return "\n".join(line.strip() for line in text.splitlines() if line.strip())


def patch_evidence(root, cve, data_dir=DATA, files=None, texts=None):
    root, data_dir = Path(root), Path(data_dir)
    if files is None:
        files = [p for p in root.rglob("*") if p.is_file() and p.suffix in CODE]
    if texts is None:
        texts = {}
    refs = load_json(data_dir / "patch_refs.json", {}).get(cve, [])
    # CVE is an identifier, never an arbitrary cache path.
    patches = sorted((data_dir / "patches" / cve).glob("*.diff")) if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve) else []
    results, functions = [], set()
    for patch in patches[:40]:
        observations = []
        for h in parse_patch(patch.read_text(encoding="utf-8", errors="replace")):
            path = h["file"]
            candidates = [p for p in files if p.relative_to(root).as_posix() == path
                          or p.relative_to(root).as_posix().endswith("/" + path)]
            fn = re.search(r"\b([A-Za-z_]\w*)\s*\(", h["header"].split("@@")[-1])
            if fn:
                functions.add(fn.group(1))
            rec = {"patch_file": path, "hunk": h["header"], "status": "file_missing_or_ambiguous"}
            if len(candidates) == 1:
                p = candidates[0]
                if p not in texts:
                    texts[p] = normalized(p.read_text(encoding="utf-8", errors="replace"))
                text = texts[p]
                before, after = normalized("\n".join(h["before"])), normalized("\n".join(h["after"]))
                old, new = bool(before and before in text), bool(after and after in text)
                rec.update(file=p.relative_to(root).as_posix(), sha256=digest(p),
                           status="both_patterns" if old and new else "fixed_pattern" if new else "vulnerable_pattern" if old else "diverged")
            observations.append(rec)
        results.append({"patch": patch.name, "sha256": digest(patch), "hunks": observations})
    return {"references": refs, "patches": results,
            "functions": sorted(functions), "provenance": "local_cve_patch_cache",
            "note": "Whitespace-normalized hunk matches are review evidence; they do not establish patch completeness, applicability or a fixed deployed build."}


def review(root, index, entries, cves, upload=None, data_dir=DATA, *, engine='clang', analysis_scope='partial', complete=False):
    build = inspect_build(root)
    if engine not in {'clang','legacy'}:raise ValueError('Unsupported source engine')
    cfg = (clang_source.build(root,build,entries=entries,scope=analysis_scope,complete=complete)
           if engine=='clang' else source_cfg.build(root))
    source_files = [p for p in Path(root).rglob("*") if p.is_file() and p.suffix in CODE]
    texts = {}
    target_cache = load_json(Path(data_dir) / "vuln_targets.json", {})
    statements = []
    for c in cves:
        cve = c.get("cve")
        if not isinstance(cve, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            continue
        patch = patch_evidence(root, cve, data_dir, source_files, texts)
        cached = target_cache.get(cve, {})
        reference_names=set(patch['functions']+cached.get('targets',[])+c.get('functions',[]))
        names = sorted(reference_names | set(c.get('condition_function_candidates',[])))
        paths, definitions = [], []
        for name in names:
            r = SI.reaches(index, name, entries)
            if r["reachable"]:
                paths.append({"function": name, "path": r["path"]})
            for d in index["functions"].get(name, []):
                definitions.append({"function": name, "file": d["file"], "line": d["line"],
                                    "declared_translation_unit": d["file"] in build["translation_units"]})
        if engine=='clang':
            definitions=[{'function':f['name'],'file':f['file'],'line':f['line'],'symbol_id':key,
                          'declared_translation_unit':True} for key,f in cfg['functions'].items() if f['name'] in names or f['symbol'] in names]
        missing = ["complete_and_correct_vulnerable_artefact_mapping", "sound_whole_program_coverage", "deployed_build_identity"]
        if not names:
            missing.append("vulnerable_artefacts")
        if not patch["patches"]:
            missing.append("local_fixing_patch")
        if not build["compilation_databases"]:
            missing.append("compilation_database")
        if upload and (upload.get("truncated") or any(v for k, v in upload.get("skipped", {}).items() if k != "dir")):
            missing.append("complete_source_intake")
        reason = ("A static path to a candidate vulnerable artefact was found; exploitability requires review." if paths
                  else "No static path was established; this approximate graph cannot prove absence or unreachability.")
        status, justification, rule = "under_investigation", None, "SOURCE_EVIDENCE_REVIEW_REQUIRED"
        references = []
        if names and not definitions:
            tokens = re.compile(r"\b(?:" + "|".join(re.escape(n) for n in names) + r")\b")
            for p in source_files:
                if p not in texts:
                    texts[p] = normalized(p.read_text(encoding="utf-8", errors="replace"))
                if tokens.search(texts[p]):
                    references.append(p.relative_to(Path(root)).as_posix())
            if engine=='legacy' and not references and "complete_source_intake" not in missing:
                status, justification, rule = "not_affected", "vulnerable_code_not_present", "VULNERABLE_FUNCTIONS_ABSENT"
                reason = "All identified vulnerable functions are absent from the uploaded source: " + ", ".join(names) + "."
            elif references:
                reason = "Vulnerable function names occur in source but no definition was indexed; external code or parser coverage requires review."
        elif not names:
            reason = "The vulnerable functions could not be identified; missing mapping is not evidence of function absence."
        flow = (clang_source.assess(cfg,names,'complete_source_intake' not in missing) if engine=='clang'
                else source_cfg.assess(cfg,names,'complete_source_intake' not in missing))
        if engine=='clang' and flow['absence_proven']:
            status,justification,rule='not_affected','vulnerable_code_not_present','CLANG_BUILD_TARGETS_ABSENT'
            reason='The identified targets are absent from the analysed translation units under the supplied build flags and declared complete product/entry scope.'
        if definitions and flow["unreachable"]:
            status, justification, rule = "not_affected", "vulnerable_code_not_in_execute_path", "CFG_VULNERABLE_FUNCTIONS_UNREACHABLE"
            reason = "The identified targets exist, but the analysed CFG/call graph has no path from the declared entry points to them within the selected source/build scope."
        if flow["reachable_paths"]:
            reason = "A compiler/CFG-derived possible call path reaches an identified target; path feasibility, attacker control and CVE applicability require review."
        if engine=='clang':paths=flow['reachable_paths']
        if status=='not_affected' and not reference_names:
            status,justification,rule='under_investigation',None,'UNVERIFIED_LLM_FUNCTION_MAPPING'
            reason='Only description-derived function candidates were available; they cannot authorize source-absence or unreachability clearance.'
        explanation={'engine':cfg['engine'],'scope':cfg['scope'],'conclusion':status,
                     'observations':[str(len(definitions))+' matching compiled/source definitions',
                                     str(len(flow['reachable_paths']))+' entry-to-target paths',
                                     str(len(flow['blockers']))+' analysis blockers'],
                     'paths':flow['reachable_paths'], 'blockers':flow['blockers'],
                     'assumptions':cfg.get('assumptions',{}),
                     'not_established':['attacker-controlled data reaching the vulnerable operation','CVE trigger satisfaction','deployed binary identity','completeness and CVE causality of supplied target names'],
                     'reason':reason}
        evidence = {"artefacts": names, "mapping_source": cached.get("source"),
                    "absence_scope": "uploaded_source_tree", "unresolved_reference_files": references,
                    "definitions": definitions, "reachable_paths": paths, "patch": patch,
                    "cfg": flow,
                    "missing_evidence": missing, "graph_coverage": "compiled_translation_units" if engine=='clang' else "syntactic_approximation",
                    'explanation':explanation}
        statements.append({"cve": cve, "status": status, "justification": justification,
                           "reason": reason, "rule": rule, "arm": "source-evidence",
                           "evidence_basis": "Clang/LLVM CFG and direct call graph, patch hunks and declared build configuration" if engine=='clang' else "Patch hunks, declared build configuration and approximate source paths",
                           "evidence": evidence})
    n = len(statements)
    counts = dict(Counter(s["status"] for s in statements))
    deferred = counts.get("under_investigation", 0)
    inventory = [{"file": p.relative_to(Path(root)).as_posix(), "sha256": digest(p)}
                 for p in sorted(Path(root).rglob("*")) if p.is_file()]
    return {"arm": "source-evidence", "method": "ICS-VEXForge compiler-backed source evidence",
            "statements": statements, "total": n, "by_status": counts,
            "deferred": deferred, "decision_rate": round((n-deferred)/n,4) if n else None, "deferral_rate": round(deferred/n,4) if n else None,
            "build": build, "inventory_sha256": hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest(),
            "cfg": cfg,
            "inventory": inventory,
            "limitations": ["Function absence applies to the uploaded source tree, not independently verified deployed binaries. Unknown mappings and unresolved references do not clear CVEs. Reachability alone does not establish affected status.",
                            "Patch/build inspection is an extension; no uploaded build command is executed."]}
