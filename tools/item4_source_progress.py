"""Read-only population progress; never reads labels or prediction quality."""
import json,sqlite3,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.item4_source_simulation import DATA
from src.training_io import atomic_json

def progress():
    folder=ROOT/'results/item4_source_context_v1'
    index={r['cve']:len(r['cases']) for r in map(json.loads,(DATA/'cve_index.jsonl').open(encoding='utf-8'))}
    with sqlite3.connect('file:'+(folder/'predictions.sqlite3').as_posix()+'?mode=ro',uri=True) as db:
        done=dict(db.execute('SELECT cve,count(*) FROM predictions GROUP BY cve'))
    completed=sum(n==index[c] for c,n in done.items())
    report=dict(completed_CVEs=completed,started_CVEs=len(done),total_CVEs=12418,
        completed_cases=sum(done.values()),total_cases=sum(index.values()))
    atomic_json(folder/'cve_progress.json',report)
    print(json.dumps(report))

if __name__=='__main__':progress()
