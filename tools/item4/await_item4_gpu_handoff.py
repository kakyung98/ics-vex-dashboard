"""Reserve the replacement evaluation until the existing training releases GPU.

Never stops the separate training/evaluation pipeline. Retires only this task's
superseded v6 worker after that pipeline's documented resume handoff completes.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
import argparse,json,os,signal,subprocess,time


def command(pid):
    p=Path('/proc')/str(pid)/'cmdline'
    return p.read_bytes() if p.exists() else b''


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--migration',type=Path,required=True);parser.add_argument('--work',type=Path,required=True)
    args=parser.parse_args();r=args.migration;w=args.work
    old=r/'item4-full-actual-20261120-v6'
    pipeline=r/'item4-csaf-v2-unsupervised-20261120-r1/pipeline_status.json'
    while True:
        target=int((w/'worker.pid').read_text()) if (w/'worker.pid').exists() else None
        if target and b'tools.item4.run_item4_full_actual' in command(target):return
        state=json.loads(pipeline.read_text()) if pipeline.exists() else {}
        resumed=state.get('v1_resumed_pid')
        if state.get('status') in {'complete','failed'} and resumed:
            previous=int(resumed)
            if b'tools.item4.run_item4_full_actual' in command(previous):
                cwd=Path('/proc')/str(previous)/'cwd'
                if cwd.resolve()!=old.resolve():raise RuntimeError('Superseded worker ownership differs')
                os.kill(previous,signal.SIGTERM)
                for _ in range(50):
                    if b'tools.item4.run_item4_full_actual' not in command(previous):break
                    time.sleep(.2)
                else:raise RuntimeError('Superseded worker did not exit; leave new evaluation reserved')
            active=subprocess.run(['nvidia-smi','--query-compute-apps=pid','--format=csv,noheader,nounits'],capture_output=True,text=True,check=True).stdout
            if not any(line.strip().isdigit() for line in active.splitlines()):
                env=dict(os.environ,ICSVEX_MIGRATION_ROOT=str(r),LOCALAPPDATA=str(w/'runtime'),
                    HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',PYTHONUNBUFFERED='1')
                for key,name in [('CC','item4-cc'),('CXX','item4-cxx')]:
                    compiler=r/'item4-vllm-venv/bin'/name
                    if compiler.is_file():env[key]=str(compiler)
                env.pop('ICS_PREREQUISITE_LLM_URL',None);env.pop('ICS_PREREQUISITE_LLM_MODEL',None)
                out=w/'results/item4_full_actual_20261120';out.mkdir(parents=True,exist_ok=True)
                (out/'runtime_environment.json').write_text(json.dumps({k:env.get(k) for k in ['CC','CXX','HF_HUB_OFFLINE','TRANSFORMERS_OFFLINE','LOCALAPPDATA']},indent=2))
                with (w/'worker.log').open('a') as log:
                    child=subprocess.Popen([str(r/'venv/bin/python'),'-B','-u','-m','tools.item4.run_item4_full_actual',
                        '--engine','hf_xgrammar_compact_cached_rolling','--batch-size','64','--threads','128'],
                        cwd=w,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
                target=child.pid;(w/'worker.pid').write_text(str(target))
                receipt=dict(status='gpu_handed_to_replacement',previous_worker=previous,
                    replacement_worker=target,separate_training_not_interrupted=True,time=time.time())
                (w/'gpu_handoff.json').write_text(json.dumps(receipt,indent=2))
                print(json.dumps(receipt),flush=True);return
        time.sleep(10)


if __name__=='__main__':main()
