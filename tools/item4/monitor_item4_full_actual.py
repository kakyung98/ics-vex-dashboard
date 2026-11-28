"""Follow this active evaluation to completion, then verify and package delivery.

This is a job-local controller, not a scheduled automation. It stops on worker
failure rather than converting a missing run into an apparent successful score.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
import json
import subprocess
import sys
import time

from tools.common.ncp_api_transport import execute
from tools.item4.deploy_item4_full_actual import WORK, MIGRATION, CONFIG, LOCAL, fetch


def snapshot():
    script='''from pathlib import Path
import json,sqlite3,os
w=Path(WORK);r=Path(MIGRATION);out=w/'results/item4_full_actual_20261120'
s=json.loads((out/'status.json').read_text())
pid=int((w/'worker.pid').read_text()) if (w/'worker.pid').exists() else None;cmd=Path('/proc')/str(pid)/'cmdline'
s['worker_alive']=bool(pid and cmd.exists() and b'tools.item4.run_item4_full_actual' in cmd.read_bytes())
hp=w/'handoff.pid';hid=int(hp.read_text()) if hp.exists() else None;hc=Path('/proc')/str(hid)/'cmdline'
s['handoff_controller_alive']=bool(hid and hc.exists() and b'tools.item4.await_item4_gpu_handoff' in hc.read_bytes())
p=r/'item3-benchmark-runs/20261119_parser_cisa_v1/results/item3_benchmark_validation_20261119/validation.sqlite3'
if s['stage']=='waiting_for_existing_GPU_job' and p.exists():
 d=sqlite3.connect('file:'+str(p)+'?mode=ro',uri=True);n,a=d.execute('select count(*),sum(agents is not null) from units').fetchone();d.close();s['item3_done']=a;s['item3_total']=n
p=out/'generation_progress.json'
if p.exists():s['generation_progress']=json.loads(p.read_text())
print(json.dumps(s))
'''.replace('Path(WORK)','Path('+repr(WORK)+')').replace('Path(MIGRATION)','Path('+repr(MIGRATION)+')')
    return json.loads(execute(CONFIG,script,timeout=30))


def main():
    previous=None
    failures=0
    while True:
        try:
            state=snapshot()
            failures=0
        except Exception as exc:
            failures+=1
            LOCAL.mkdir(parents=True,exist_ok=True)
            (LOCAL/'monitor_transport_error.json').write_text(json.dumps(dict(
                status='retrying_transport',consecutive_failures=failures,
                error=type(exc).__name__,time=time.time())),encoding='utf-8')
            print(json.dumps(dict(stage='retrying_status_transport',consecutive_failures=failures,
                                  error=type(exc).__name__)),flush=True)
            time.sleep(30)
            continue
        LOCAL.mkdir(parents=True,exist_ok=True)
        (LOCAL/'remote_status.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        concise={k:state[k] for k in ['status','stage','completed_cves','total_cves','llm_requests','item3_done','item3_total','worker_alive'] if k in state}
        progress=state.get('generation_progress')
        if progress:concise['generation']=dict(step=progress['step'],batch_size=progress['batch_size'],requests_completed=progress['requests_completed'])
        if concise!=previous:
            print(json.dumps(concise),flush=True);previous=concise
        if state['status']=='failed' or (state['status']!='complete' and not state['worker_alive'] and not state.get('handoff_controller_alive')):
            raise RuntimeError('Evaluation needs recovery; no score or ZIP will be presented as complete: '+json.dumps(state))
        if state['status']=='complete':break
        time.sleep(30)
    for attempt in range(1,4):
        try:
            fetch()
            break
        except Exception as exc:
            if attempt==3:raise
            print(json.dumps(dict(stage='retrying_result_fetch',attempt=attempt,
                                  error=type(exc).__name__)),flush=True)
            time.sleep(30)
    subprocess.run([sys.executable,'-m','tools.item4.verify_item4_full_actual'],check=True)
    print(json.dumps(dict(stage='evaluation_fetched_and_independently_rescored')),flush=True)
    # All finalization is gated on complete, hash-verified, independently
    # rescored results, regardless of whether the precision target is met.
    subprocess.run([sys.executable,'-m','tools.item4.finalize_item4_full_delivery'],check=True)


if __name__=='__main__':main()
