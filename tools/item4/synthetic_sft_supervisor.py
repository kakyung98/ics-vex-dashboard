"""Continue DEV tuning only if prompt candidates fail, preserving other services."""
from pathlib import Path
import sys,json,time,subprocess,os,signal,traceback,hashlib,argparse
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from tools.item4.run_metamorphic_synthetic import write


def alive(pid,marker=None):
    p=Path('/proc')/str(pid)/'cmdline'
    if not p.exists():return False
    text=p.read_bytes()
    return bool(text) and (marker is None or marker in text)


def stop_owned(root):
    p=root/'server.pid'
    if not p.exists():return
    pid=int(p.read_text())
    if alive(pid,b'18972'):
        os.killpg(pid,signal.SIGTERM)
        for _ in range(20):
            if not alive(pid):return
            time.sleep(.5)
        if alive(pid,b'18972'):os.killpg(pid,signal.SIGKILL)


def run_checked(args,root,log_name):
    with (root/log_name).open('a') as stream:
        process=subprocess.Popen([str(a) for a in args],cwd=root,stdout=stream,stderr=subprocess.STDOUT)
        code=process.wait()
    if code:raise RuntimeError('Stage failed ('+log_name+'): exit '+str(code))


def start_server(root,adapters,strict_schema=False):
    import requests
    old=root.parent/'item4-goldfree-expanded-20261126'
    args=json.loads((old/'server_command.json').read_text())
    args=args[:args.index('--lora-modules')]
    args[args.index('--port')+1]='18972';args[args.index('--tokenizer')+1]=str(root/'tokenizer')
    args[args.index('--gpu-memory-utilization')+1]='0.12';args[args.index('--max-num-seqs')+1]='8'
    source=root.parent/'operator-vep-real-v2-20261119-r1/trained/vep_extraction'
    args+=['--lora-modules','vep-extraction='+str(source)]+[name+'='+str(path) for name,path in adapters.items()]
    args+=['--max-cpu-loras','4','--enable-prefix-caching','--api-key',(root/'server.auth').read_text().strip()]
    process=subprocess.Popen(args,cwd=root,stdout=(root/'server.log').open('w'),stderr=subprocess.STDOUT,
        start_new_session=True,env=dict(os.environ,TOKENIZERS_PARALLELISM='false',HF_HUB_OFFLINE='1'))
    (root/'server.pid').write_text(str(process.pid))
    session=requests.Session();session.trust_env=False;session.headers['Authorization']='Bearer '+(root/'server.auth').read_text().strip()
    for _ in range(180):
        if process.poll() is not None:raise RuntimeError('Owned SFT inference service failed to start')
        try:
            r=session.get('http://127.0.0.1:18972/v1/models',timeout=5);r.raise_for_status()
            if set(adapters)|{'qwen-base','vep-extraction'} <= {x['id'] for x in r.json()['data']}:
                if strict_schema:
                    probe=session.post('http://127.0.0.1:18972/v1/chat/completions',json=dict(model=next(iter(adapters)),temperature=0,max_tokens=20,
                        messages=[dict(role='user',content='Return the expected field according to the schema.')],
                        response_format=dict(type='json_schema',json_schema=dict(name='boolean_constant',strict=True,schema=dict(type='object',required=['expected'],additionalProperties=False,properties=dict(expected=dict(const=True)))))),timeout=60)
                    probe.raise_for_status();content=probe.json()['choices'][0]['message']['content']
                    if json.loads(content)!={'expected':True}:raise RuntimeError('Native Boolean constant preflight failed')
                return
        except requests.RequestException:pass
        time.sleep(2)
    raise RuntimeError('Owned SFT inference service readiness timed out')


def main(args):
    import fcntl
    root=args.root;out=root/'evaluation';parent=root.parent;python=parent/'venv/bin/python';data=args.data or root/'sft_data'
    lock=(root/'sft_supervisor.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    write(root/'sft_supervisor_status.json',dict(state='watching_dev_candidates',round=args.round))
    # Initial prompt-worker owns the server until it finishes its DEV decision.
    while True:
        status=json.loads((out/'status.json').read_text())
        if status.get('state')=='complete':
            write(root/'sft_supervisor_status.json',dict(state='skipped_prompt_candidate_qualified'));return
        if status.get('state') in ('needs_weight_tuning','sft_below_target'):break
        if status.get('state')=='failed':raise RuntimeError('Repair the earlier evaluation stage before training')
        time.sleep(5)
    old_pid=int((root/'worker.pid').read_text())
    for _ in range(60):
        if not alive(old_pid,str(root/'worker.py').encode()):break
        time.sleep(1)
    else:raise RuntimeError('Original evaluator still owns service lifecycle')
    stop_owned(root)
    training=root/('sft_trained_'+args.round)
    initial=args.initial_adapter or parent/'operator-vep-real-v2-20261119-r1/trained/vep_extraction'
    complete=training/'status.json'
    if not complete.exists() or json.loads(complete.read_text()).get('state')!='complete':
        write(out/'status.json',dict(state='sft_training',round=args.round,epochs=args.epochs))
        write(root/'sft_supervisor_status.json',dict(state='training',round=args.round))
        run_checked([python,root/'tools/item4/train_synthetic_vep_adapter.py','train','--data',data,
            '--base',parent/'base_model','--adapter',initial,'--tokenizer',root/'tokenizer','--output',training,
            '--epochs',str(args.epochs),'--memory-gib','18.5','--learning-rate',str(args.learning_rate)],root,'sft_training_'+args.round+'.log')
    adapters={};identities={}
    for epoch in range(1,args.epochs+1):
        alias='sft-'+args.round+'-e'+str(epoch);folder=training/('epoch-'+str(epoch))/'vep_synthetic'
        marker=json.loads((folder/'training_complete.json').read_text())
        actual=hashlib.sha256((folder/'adapter_model.safetensors').read_bytes()).hexdigest()
        if actual!=marker['adapter_sha256']:raise ValueError('Trained checkpoint hash mismatch')
        adapters[alias]=folder
        identities[alias]=dict(adapter_sha256=actual,path=str(folder),training_manifest_sha256=marker['train_manifest_sha256'],
            epoch=epoch,initial_adapter_sha256=marker['initial_adapter_sha256'],only_lora_trained=True,strict_boolean_constants=args.strict_schema)
    identity=root/('sft_identity_'+args.round+'.json')
    write(identity,dict(adapters=identities,base=json.loads((root/'identity.json').read_text()),round=args.round))
    write(out/'status.json',dict(state='sft_service_loading',round=args.round))
    start_server(root,adapters,args.strict_schema)
    try:
        common=[python,root/'tools/item4/evaluate_synthetic_vep_sft.py']
        options=['--output',out,'--data',data,'--identity',identity,'--token',root/'server.auth','--workers','8']
        aliases=[x for alias in adapters for x in ['--alias',alias]]
        run_checked(common+['validation']+options+aliases,root,'sft_evaluation_'+args.round+'.log')
        selected=json.loads((out/'sft_selection.json').read_text())
        if not selected['above_90']:
            write(root/'sft_supervisor_status.json',dict(state='below_target',round=args.round,selected=selected['selected']));return
        # Selection is frozen before any TEST generation or scoring.
        run_checked(common+['test']+options,root,'sft_evaluation_'+args.round+'.log')
        run_checked([python,root/'tools/item4/run_metamorphic_synthetic.py','run','--output',out,
            '--token-file',root/'server.auth','--identity-file',root/'identity.json','--workers','8','--baseline-test-only'],
            root,'baseline_test.log')
        report=json.loads((out/'baseline_test_report.json').read_text())
        tuned=json.loads((out/'sft_test_report.json').read_text())
        report['scores'].update(tuned['scores']);report.update(sft_selection=selected,
            sft_training=json.loads((training/'status.json').read_text()),
            selected_checkpoint=identities[selected['selected']],production_installed=False)
        write(out/'report.json',report)
        write(out/'status.json',dict(state='complete',selected=selected['selected'],sft=True,
            final_metrics=tuned['scores']['sft_tuned/D_adapter_pipeline/test']))
        write(root/'sft_supervisor_status.json',dict(state='complete',round=args.round,selected=selected['selected']))
    finally:stop_owned(root)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,default=ROOT);p.add_argument('--round',default='r1')
    p.add_argument('--epochs',type=int,default=2);p.add_argument('--initial-adapter',type=Path)
    p.add_argument('--data',type=Path);p.add_argument('--learning-rate',type=float,default=1e-4)
    p.add_argument('--strict-schema',action='store_true');a=p.parse_args()
    try:main(a)
    except Exception:
        write(a.root/'evaluation/status.json',dict(state='failed',stage='sft_supervisor',error=traceback.format_exc()));raise
