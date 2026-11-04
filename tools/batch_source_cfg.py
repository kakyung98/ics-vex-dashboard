"""Run the active CFG backend over every locally collected CVE snapshot.

Reports are separate from legacy results/ground truth. Each snapshot is isolated
in a worker process with a timeout; unsupported cases are not silently cleared.
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def read(path):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def worker(cve, out):
    from src.source_cfg import build, assess
    source = ROOT / "data/source_snapshots" / cve
    metadata = read(ROOT / "data/snapshot_index.json").get(cve, {})
    mapping = read(ROOT / "data/vuln_targets.json").get(cve, {})
    locations = read(ROOT / "data/source_locations.json").get(cve, {})
    names = sorted(set(mapping.get("targets", []) + [f["name"] for f in locations.get("functions", []) if f.get("name")]))
    start = time.monotonic()
    g = build(source)
    assessment = assess(g, names)
    status, justification = "under_investigation", None
    if assessment["unreachable"]:
        status, justification = "not_affected", "vulnerable_code_not_in_execute_path"
    elif names and g["negative_decisions_enabled"] and not assessment["present_targets"]:
        status, justification = "not_affected", "vulnerable_code_not_present"
    counts = Counter(b["reason"] for b in g["blockers"])
    result = {"cve": cve, "status": status, "justification": justification,
              "analysis_state": "blocked" if g["blockers"] else "mapping_missing" if not names else "analysed",
              "component": metadata.get("component"), "version": metadata.get("version"),
              "source": str(source.relative_to(ROOT)), "targets": names,
              "mapping_source": mapping.get("source"),
              "parsed_files": len(g["files"]), "functions": len(g["functions"]),
              "entries": g["entries"], "reachable_targets": assessment["reachable_paths"],
              "blocker_counts": dict(counts), "blocker_examples": g["blockers"][:12],
              "duration_seconds": round(time.monotonic()-start, 3),
              "scope": g["scope"], "graph_file": f"graphs/{cve}.json.gz"}
    (out / "graphs").mkdir(parents=True, exist_ok=True)
    with gzip.open(out / result["graph_file"], "wt", encoding="utf-8") as f:
        json.dump(g, f)
    (out / f"{cve}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--worker")
    p.add_argument("--output", default="results/source_cfg_batch")
    p.add_argument("--timeout", type=int, default=60)
    p.add_argument("--workers", type=int, default=3)
    args = p.parse_args()
    out = (ROOT / args.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    if args.worker:
        if not __import__('re').fullmatch(r"CVE-\d{4}-\d{4,}", args.worker): raise ValueError("invalid CVE")
        worker(args.worker, out); return
    snapshots = ROOT / "data/source_snapshots"
    cves = sorted(p.name for p in snapshots.iterdir() if p.is_dir() and p.name.startswith("CVE-"))
    rows = []
    started = datetime.now(timezone.utc).isoformat()
    def execute(cve):
        existing = read(out / f"{cve}.json")
        if existing.get("analysis_state") in {"blocked", "analysed", "mapping_missing"}:
            return existing
        try:
            run = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--worker", cve, "--output", str(out)],
                                 capture_output=True, text=True, timeout=args.timeout)
            if run.returncode: raise RuntimeError(run.stderr[-1500:])
            row = read(out / f"{cve}.json")
        except Exception as exc:
            row = {"cve": cve, "status": "under_investigation", "analysis_state": "timeout" if isinstance(exc, subprocess.TimeoutExpired) else "error", "error": str(exc)[-1500:]}
            (out / f"{cve}.json").write_text(json.dumps(row, indent=2), encoding="utf-8")
        return row
    pool = ThreadPoolExecutor(max_workers=max(1, min(8, args.workers)))
    futures = {pool.submit(execute, cve): cve for cve in cves}
    for i, future in enumerate(as_completed(futures), 1):
        cve = futures[future]
        row = future.result()
        rows.append(row)
        print(f"[{i}/{len(cves)}] {cve}: {row['analysis_state']} / {row['status']}", flush=True)
        summary = {"engine": "c-ast-cfg/1", "started_at": started, "updated_at": datetime.now(timezone.utc).isoformat(),
                   "population_source": "data/source_snapshots directory inventory", "expected": len(cves), "processed": len(rows),
                   "complete": len(rows)==len(cves), "by_status": dict(Counter(r["status"] for r in rows)),
                   "by_analysis_state": dict(Counter(r["analysis_state"] for r in rows)),
                   "blocker_counts": dict(sum((Counter(r.get("blocker_counts", {})) for r in rows), Counter())),
                   "scope_note": "Component snapshots are not complete product firmware. Unsupported analysis is under_investigation, not a completed reachability proof.",
                   "results": sorted(rows, key=lambda r:r["cve"])}
        temporary = out / "summary.tmp"
        temporary.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        temporary.replace(out / "summary.json")
    pool.shutdown()
    print(json.dumps({k:v for k,v in summary.items() if k!='results'}, indent=2), flush=True)


if __name__ == "__main__":
    main()
