"""Durable local serial GPU queue; wait for the current source-facts run first."""
import ctypes
from datetime import datetime,timezone
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
REPORT=ROOT/'results/grounded_role_finetune_v1'


def read(path):
    try:return json.loads(path.read_text(encoding='utf-8'))
    except (OSError,ValueError):return {}


def alive(pid):
    if not isinstance(pid,int) or pid<=0:return False
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes=[ctypes.c_uint32,ctypes.c_int,ctypes.c_uint32]
    kernel.OpenProcess.restype=ctypes.c_void_p
    kernel.GetExitCodeProcess.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint32)]
    kernel.CloseHandle.argtypes=[ctypes.c_void_p]
    handle=kernel.OpenProcess(0x1000,False,pid)
    if not handle:return False
    code=ctypes.c_uint32()
    try:return bool(kernel.GetExitCodeProcess(handle,ctypes.byref(code))) and code.value==259
    finally:kernel.CloseHandle(handle)


def main():
    REPORT.mkdir(parents=True,exist_ok=True)
    file=REPORT/'queue_status.json'
    prior=read(file)
    if alive(prior.get('pid')):raise RuntimeError('Another grounded-role queue is already running')
    deadline='2026-11-01T12:15:44+00:00'
    specs=[('item3-identification',ROOT/'results/item3_identification_v2_run/status.json',
            [str(ROOT/'tools/eval_item3_agents_batched.py'),'--deadline-utc',deadline]),
           *[(r,REPORT/r/'status.json',[str(ROOT/'tools/train_grounded_role.py'),'--role',r]) for r in ['cve-conditions','vex-writer']]]
    state={'pid':__import__('os').getpid(),'started_at':datetime.now(timezone.utc).isoformat(),
           'deadline_utc':deadline,'deadline_kst':'2026-11-01 21:15:44 KST',
           'jobs':[{'role':r,'phase':'queued'} for r,_,_ in specs]}
    def status(phase,**extra):
        state.update(phase=phase,updated_at=datetime.now(timezone.utc).isoformat(),**extra)
        temporary=file.with_suffix('.tmp');temporary.write_text(json.dumps(state,indent=2),encoding='utf-8');temporary.replace(file)
    for job,(_,status_path,_) in zip(state['jobs'],specs):
        ready=read(status_path)
        if ready.get('phase')!='ready':raise RuntimeError(f'{job["role"]}: preflight not ready')
    predecessor=ROOT/'results/source_evidence_finetune_v1/status.json'
    source=read(predecessor)
    while alive(source.get('pid')):
        status('waiting_for_source_training',predecessor={'pid':source.get('pid'),'phase':source.get('phase'),'step':source.get('global_step'),'max_steps':source.get('max_steps')})
        time.sleep(10);source=read(predecessor)
    status('starting_roles',predecessor={'pid':source.get('pid'),'phase':source.get('phase')})
    for job,(_,status_path,command) in zip(state['jobs'],specs):
        role=job['role'];job['phase']='starting';status('running',active_role=role)
        with (REPORT/f'{role}_stdout.log').open('w',encoding='utf-8') as stdout,(REPORT/f'{role}_stderr.log').open('w',encoding='utf-8') as stderr:
            process=subprocess.Popen([sys.executable,'-u',*command],cwd=ROOT,stdout=stdout,stderr=stderr)
            job['pid']=process.pid
            while process.poll() is None:
                child=read(status_path)
                job.update(phase=child.get('phase','starting'),step=child.get('global_step'),max_steps=child.get('max_steps'))
                status('running',active_role=role);time.sleep(10)
            child=read(status_path)
            job.update(returncode=process.returncode,phase='complete' if process.returncode==0 and child.get('phase')=='complete' else 'failed')
            status('running',active_role=role)
    complete=all(j['phase']=='complete' for j in state['jobs']) and source.get('phase')=='complete'
    status('complete' if complete else 'complete_with_errors',active_role=None,
           deadline_met=complete and datetime.now(timezone.utc).timestamp()<=datetime.fromisoformat(deadline).timestamp())
    # One deliverable links actual outputs; missing reports never become success.
    combined={'queue':state,'source_training':read(ROOT/'results/source_evidence_finetune_v1/status.json'),
              'item3':read(ROOT/'results/item3_identification_v2_run/summary.json'),
              'item3_string_baseline':read(ROOT/'results/item3_string_full_20261101.json'),
              'role_validation':{r:read(REPORT/r/'validation_report.json') for r in ['cve-conditions','vex-writer']}}
    destination=ROOT/'results/four_hour_run_20261101';destination.mkdir(exist_ok=True)
    (destination/'summary.json').write_text(json.dumps(combined,indent=2),encoding='utf-8')
    lines=['# Combined training and item-3 evaluation','','Deadline: '+state['deadline_kst'],
           'Overall status: '+state['phase'], 'Completed within target: '+str(state['deadline_met']),'',
           'Source-fact, condition extraction and VEX writing adapters are separate. Condition references are weak labels; writing includes simulated evidence. Validation is not expert-certified CVE accuracy.','',
           '| Job | State |','| --- | --- |', '| Source evidence | '+source.get('phase','missing')+' |']
    lines += ['| '+j['role']+' | '+j['phase']+' |' for j in state['jobs']]
    score=combined['item3'].get('item3',{})
    if score:lines+=['','## Full item-3 candidate identification',
        f"Components: {score.get('sut_runs')}; TP={score.get('TP')}; FP={score.get('FP')}; precision={score.get('precision')}; labelled share={score.get('labelled_share_pct')}%.",
        'Local snapshot applicability is unknown. Unlabelled and unadjudicable predictions are disclosed, not guessed as false.']
    lines+=['','Detailed reports: ../source_evidence_finetune_v1/validation_report.json; ../item3_identification_v2_run/REPORT.md; ../grounded_role_finetune_v1/{role}/validation_report.json.']
    (destination/'REPORT.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')


if __name__=='__main__':main()
