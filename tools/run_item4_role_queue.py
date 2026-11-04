"""Two serial experimental #4 v3 jobs, with a shared inference admission lease."""
from datetime import datetime, timezone
from pathlib import Path
import os,sys,subprocess,time
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.training_io import atomic_json,read_json
from src.gpu_lease import FILE,alive


def main():
    raise RuntimeError("This analysis-model queue is retired; LLM is reserved for final VEX writing.")
    folder=ROOT/'results/operational_role_finetune_v3';folder.mkdir(exist_ok=True)
    prior=read_json(folder/'queue_status.json');lease=read_json(FILE)
    if alive(prior.get('pid')) or lease.get('active') and (alive(lease.get('pid')) or alive(lease.get('child_pid'))):
        raise RuntimeError('A GPU queue already owns admission.')
    roles=['item4-questions','operation-assessment']
    for role in roles:
        if read_json(folder/role/'status.json').get('phase')!='ready':raise RuntimeError(role+' preflight must pass.')
    state={'pid':os.getpid(),'phase':'starting','started_at':datetime.now(timezone.utc).isoformat(),
           'expert_gold':False,'experimental_curriculum':True,'external_api_calls':0,'deployment_approved':False,
           'jobs':[{'role':r,'phase':'queued'} for r in roles]}
    def save():
        state['updated_at']=datetime.now(timezone.utc).isoformat();atomic_json(folder/'queue_status.json',state)
    atomic_json(FILE,{'pid':os.getpid(),'active':True,'purpose':'#4 v3 experimental operational-role training'})
    save()
    try:
        for job in state['jobs']:
            role=job['role'];state.update(phase='running',active_role=role);save()
            command=[sys.executable,'-u',str(ROOT/'tools/train_grounded_role.py'),'--role',role,
                     '--experimental-curriculum','--item4-curriculum','--epochs','1','--max-length','2048',
                     '--generation-batch-size','4','--eval-heldout-after-training']
            with (folder/(role+'_stdout.log')).open('w',encoding='utf-8') as out,(folder/(role+'_stderr.log')).open('w',encoding='utf-8') as err:
                child=subprocess.Popen(command,cwd=ROOT,stdout=out,stderr=err)
                job['pid']=child.pid
                atomic_json(FILE,{'pid':os.getpid(),'child_pid':child.pid,'active':True,'purpose':'#4 v3 role training/controlled evaluation'})
                while child.poll() is None:
                    info=read_json(folder/role/'status.json')
                    job.update(phase=info.get('phase','starting'),global_step=info.get('global_step'),max_steps=info.get('max_steps'),
                               evaluation=info.get('evaluation'),evaluated=info.get('evaluated'))
                    save();time.sleep(5)
                info=read_json(folder/role/'status.json');job.update(returncode=child.returncode,phase=info.get('phase','failed'));save()
                if child.returncode or job['phase']!='complete':raise RuntimeError(role+' failed; next GPU job was not started.')
        state.update(phase='complete',active_role=None);save()
    except BaseException as e:
        state.update(phase='failed',error=str(e));save();raise
    finally:atomic_json(FILE,{'pid':os.getpid(),'active':False,'phase':state['phase']})


if __name__=='__main__':main()
