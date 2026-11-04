"""Adopt active condition training, then write VEX and resume cached item-3 eval."""
import argparse
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tools'))
from src.training_io import atomic_json,read_json
from run_grounded_role_queue import alive


def main():
    p=argparse.ArgumentParser();p.add_argument('--adopt-pid',type=int,required=True);a=p.parse_args()
    report=ROOT/'results/grounded_role_finetune_v1';queue=report/'queue_status.json'
    deadline='2026-11-01T12:15:44+00:00'
    jobs=[{'role':'cve-conditions','phase':'adopting','pid':a.adopt_pid},
          {'role':'vex-writer','phase':'queued','epochs_max':2},
          {'role':'item3-identification','phase':'resume_queued','predictions_cached':True}]
    state={'pid':os.getpid(),'phase':'running','jobs':jobs,'deadline_utc':deadline,'deadline_kst':'2026-11-01 21:15:44 KST',
           'recovery_reason':'Windows progress-file replacement collision; no model/scoring change; cached predictions preserved',
           'started_at':datetime.now(timezone.utc).isoformat()}
    def update(active):
        state.update(active_role=active,updated_at=datetime.now(timezone.utc).isoformat(),seconds_to_target=round(datetime.fromisoformat(deadline).timestamp()-time.time()))
        atomic_json(queue,state)
    source=read_json(ROOT/'results/source_evidence_finetune_v1/status.json')
    assert source.get('phase')=='complete'
    condition=report/'cve-conditions/status.json'
    assert read_json(condition).get('pid')==a.adopt_pid,'Unexpected adopted process'
    while alive(a.adopt_pid):
        c=read_json(condition);jobs[0].update(phase=c.get('phase','running'),step=c.get('global_step'),max_steps=c.get('max_steps'))
        update('cve-conditions');time.sleep(10)
    jobs[0]['phase']='complete' if read_json(condition).get('phase')=='complete' else 'failed'
    def execute(job,command,status_path,logstem):
        with (report/(logstem+'_stdout.log')).open('w',encoding='utf-8') as stdout,(report/(logstem+'_stderr.log')).open('w',encoding='utf-8') as stderr:
            child=subprocess.Popen([sys.executable,'-u',*command],cwd=ROOT,stdout=stdout,stderr=stderr)
            job['pid']=child.pid
            while child.poll() is None:
                c=read_json(status_path);job.update(phase=c.get('phase','starting'),step=c.get('global_step'),max_steps=c.get('max_steps'),done=c.get('done'),total=c.get('total'))
                update(job['role']);time.sleep(10)
            c=read_json(status_path);job.update(returncode=child.returncode,phase='complete' if child.returncode==0 and c.get('phase')=='complete' else 'failed')
            update(job['role'])
    if jobs[0]['phase']!='complete':
        execute(jobs[0],[str(ROOT/'tools/train_grounded_role.py'),'--role','cve-conditions','--resume','--epochs','3'],condition,'cve-conditions_recovery')
    execute(jobs[1],[str(ROOT/'tools/train_grounded_role.py'),'--role','vex-writer','--epochs','2'],report/'vex-writer/status.json','vex-writer')
    execute(jobs[2],[str(ROOT/'tools/eval_item3_agents_batched.py'),'--deadline-utc',deadline],ROOT/'results/item3_identification_v2_run/status.json','item3-identification_recovery')
    complete=all(j['phase']=='complete' for j in jobs)
    state.update(phase='complete' if complete else 'complete_with_errors',deadline_met=complete and time.time()<=datetime.fromisoformat(deadline).timestamp())
    update(None)
    destination=ROOT/'results/four_hour_run_20261101';destination.mkdir(exist_ok=True)
    combined={'queue':state,'source_training':source,'item3':read_json(ROOT/'results/item3_identification_v2_run/summary.json'),
              'item3_string_baseline':read_json(ROOT/'results/item3_string_full_20261101.json'),
              'role_validation':{r:read_json(report/r/'validation_report.json') for r in ['cve-conditions','vex-writer']}}
    atomic_json(destination/'summary.json',combined)
    lines=['# Combined training and item-3 evaluation','','Deadline: '+state['deadline_kst'],
           'Overall state: '+state['phase'],'Completed within target: '+str(state['deadline_met']),'',
           'The first item-3 attempt hit a Windows progress-file lock; the final run reuses its frozen prediction cache.','',
           '| Job | State |','| --- | --- |','| Source facts | complete |']
    lines+=['| '+j['role']+' | '+j['phase']+' |' for j in jobs]
    score=combined['item3'].get('item3',{})
    if score:lines+=['',f"Item-3 components: {score.get('sut_runs')}; TP={score.get('TP')}; FP={score.get('FP')}; precision={score.get('precision')}; labelled share={score.get('labelled_share_pct')}%.",
                     'Local results are CVE candidates with unknown full applicability; they are not VEX conclusions.']
    lines+=['','Source-fact results are synthetic structural validation. Condition references are weak labels; VEX writing includes explicitly simulated decisions. Neither is expert-certified CVE/VEX accuracy.']
    (destination/'REPORT.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')


if __name__=='__main__':main()
