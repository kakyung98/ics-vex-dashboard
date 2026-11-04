"""Serialized L2 training and held-out evaluation, never auto-activate weights."""
import sys,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.training_io import read_json,atomic_json
from src.gpu_lease import FILE,alive


def main():
    raise RuntimeError("This analysis-model queue is retired; LLM is reserved for final VEX writing.")
    folder=ROOT/'results/l2_candidate_finetune_v1';lease=read_json(FILE)
    if lease.get('active') and (alive(lease.get('pid')) or alive(lease.get('child_pid'))):raise RuntimeError('Another GPU queue owns admission.')
    if read_json(folder/'status.json').get('phase')!='ready':raise RuntimeError('L2 preflight must pass first.')
    state={'pid':os.getpid(),'active':True,'phase':'starting','purpose':'L2 candidate-ID experimental training/evaluation','deployment_approved':False}
    atomic_json(FILE,state);atomic_json(folder/'queue_status.json',state)
    try:
        import requests
        requests.post('http://127.0.0.1:8100/api/cve-match/models/unload',timeout=60).raise_for_status()
        command=[sys.executable,'-X','faulthandler','-u',str(ROOT/'tools/train_grounded_role.py'),'--role','l2-candidates','--epochs','1','--max-length','1536','--generation-batch-size','4','--eval-heldout-after-training']
        with (folder/'training_stdout.log').open('w',encoding='utf-8') as out,(folder/'training_stderr.log').open('w',encoding='utf-8') as err:
            child=subprocess.Popen(command,cwd=ROOT,stdout=out,stderr=err)
            state.update(child_pid=child.pid,phase='running');atomic_json(FILE,state);atomic_json(folder/'queue_status.json',state)
            code=child.wait()
        state.update(returncode=code,phase='complete' if code==0 and read_json(folder/'status.json').get('phase')=='complete' else 'failed')
    except BaseException as exc:
        state.update(phase='failed',error=str(exc));raise
    finally:
        state['active']=False;atomic_json(FILE,state);atomic_json(folder/'queue_status.json',state)


if __name__=='__main__':main()
