"""Compatibility API; CFG-only automatic verdicts are retired."""
try:
    from src import source_intake as SI
except ImportError:
    import source_intake as SI


def judge(cve, index, entries, vulnerable_functions, tree_is_complete=False, component=None):
    paths = []
    for name in vulnerable_functions:
        r = SI.reaches(index, name, entries)
        if r["reachable"]:
            paths.append({"function": name, "path": r["path"]})
    absent = bool(vulnerable_functions) and not any(index["functions"].get(name) for name in vulnerable_functions)
    return {"cve": cve, "status": "not_affected" if absent else "under_investigation",
            "justification": "vulnerable_code_not_present" if absent else None,
            "reason": "All identified vulnerable functions are absent from the provided function index." if absent else "Function presence or reachability requires review; unknown mappings cannot establish absence.",
            "arm": "source-evidence", "evidence_basis": "Syntactic call-path hints only",
            "evidence": {"reachable_paths": paths, "tree_completeness_declaration": tree_is_complete,
                         "graph_coverage": "syntactic_approximation"}}


def judge_all(index, entries, targets, tree_is_complete=False):
    out = [judge(cve, index, entries, names, tree_is_complete) for cve, names in targets.items()]
    n = len(out)
    from collections import Counter
    counts = dict(Counter(s["status"] for s in out))
    deferred = counts.get("under_investigation", 0)
    return {"statements": out, "total": n, "by_status": counts,
            "deferred": deferred, "deferral_rate": deferred/n if n else None, "decision_rate": (n-deferred)/n if n else None}
