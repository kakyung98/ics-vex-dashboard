"""Monitor a resumable full-population run, recover failed workers and finalize its comparison."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from src.item4.evaluation import evaluation_run_records as ledger
from tools.item4.finalize_item4_population_rerun import finalize


def stamp():
    return datetime.now(timezone.utc).isoformat()


def monitor(run_id, port, manifest=None):
    output=ROOT/'results/item4_scenario_moe'/run_id
    state_path=output/'monitor.json'
    last_accepted=-1
    retries_without_progress=0
    announced=-1
    child=None
    while True:
        row=ledger.get_run(run_id)
        if row.get('user_requested_stop'):
            print(json.dumps(dict(event='user_stopped',run_id=run_id)),flush=True)
            return
        state=dict(run_id=run_id,checked_at=stamp(),status=row['status'],completed=row['completed'],
                   candidate_count=row['candidate_count'],total=row['total'],error=row.get('error'),
                   retries_without_progress=retries_without_progress)
        temp=state_path.with_suffix('.tmp')
        temp.write_text(json.dumps(state,indent=2),encoding='utf-8')
        temp.replace(state_path)
        if row['completed']//1024!=announced or row['status']!='running':
            print(json.dumps(state),flush=True)
            announced=row['completed']//1024
        if row['status']=='completed':
            info=finalize(run_id)
            print(json.dumps(dict(event='finalized',run_id=run_id,
                                  status_changed=info['status_changed'],
                                  reasons_changed=info['reasons_changed'])),flush=True)
            return
        if row['status']!='running':
            if child is not None and child.poll() is None:
                # A completed worker has closed the ledger and is finishing its export.
                time.sleep(5)
                continue
            if row['candidate_count']>last_accepted:
                retries_without_progress=0
                last_accepted=row['candidate_count']
            else:
                retries_without_progress+=1
            if retries_without_progress>=3:
                raise RuntimeError('Repeated identical failures need source-specific recovery: '+str(row.get('error')))
            batch=8 if retries_without_progress else 16
            log=(output/f'recovery-{time.time_ns()}.log').open('wb')
            if manifest:
                args=[sys.executable,'-B','-u','-X','utf8','tools/item4/run_item4_nemotron.py',
                      '--resume',run_id,'--manifest',str(manifest),'--port',str(port),
                      '--chunk-size','128','--batch-size',str(batch)]
            else:
                args=[sys.executable,'-B','-u','-X','utf8','tools/item4/run_item4_scenario_moe.py',
                      '--resume',run_id,'--h200-port',str(port),'--chunk-size','128','--batch-size',str(batch)]
            child=subprocess.Popen(args,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,
                                   creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            log.close()
            print(json.dumps(dict(event='resume',run_id=run_id,pid=child.pid,batch_size=batch)),flush=True)
        time.sleep(60)


if __name__=='__main__':
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('run_id')
    cli.add_argument('--h200-port',type=int,default=18128)
    cli.add_argument('--manifest',type=Path)
    a=cli.parse_args()
    monitor(a.run_id,a.h200_port,a.manifest)
