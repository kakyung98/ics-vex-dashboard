"""One GPU owner: frozen #3 test, then frozen #4 synthetic test. No tuning."""
from pathlib import Path
import json
import os
import sys
import time

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.training_io import atomic_json,read_json
from src import gpu_lease


def evaluate_item4(runtime):
    from src.operational_assessment import assess,affected_precision
    from tools.build_item4_operational_gold import AT,OUT
    from tools.item3_precision_pipeline import sha
    folder=ROOT/'results/item4_operational_v1'
    manifest=json.loads((OUT/'manifest.json').read_text(encoding='utf-8'))
    for kind in ('inputs','labels'):
        path=OUT/'evaluation'/(kind+'.jsonl')
        assert sha(path)==manifest['artifacts'][str(path.relative_to(OUT))]
    inputs=[json.loads(line) for line in (OUT/'evaluation/inputs.jsonl').open(encoding='utf-8')]
    labels=[json.loads(line) for line in (OUT/'evaluation/labels.jsonl').open(encoding='utf-8')]
    marker=read_json(runtime.folder/'training_complete.json')
    predictions=[];pending=[];started=time.perf_counter()
    for row in inputs:
        result=assess(row['packet'],AT)
        pred=dict(id=row['id'],binding=row['packet']['binding'],status=result['status'],gate_decision=result)
        predictions.append(pred)
        if result['status']=='affected':pending.append((pred,row['packet']))
        else:pred['model_skipped_reason']='source/applicability/operational evidence gate not satisfied'
    for start in range(0,len(pending),16):
        chunk=pending[start:start+16]
        responses=runtime.operational_batch([packet for _,packet in chunk],batch_size=4)
        for (pred,_),response in zip(chunk,responses):
            pred['model_proposal']=response
            if response.get('status')!='affected':pred['status']='under_investigation'
        atomic_json(folder/'trained_status.json',dict(phase='evaluating',model_requests=min(start+len(chunk),len(pending)),
            total_model_requests=len(pending),population=len(inputs)))
        print('item4 trained proposals',min(start+len(chunk),len(pending)),'/',len(pending),flush=True)
    with (folder/'trained_predictions.jsonl').open('w',encoding='utf-8') as f:
        for row in predictions:f.write(json.dumps(row,ensure_ascii=False)+'\n')
    report=affected_precision(predictions,labels)
    report.update(actual_model_requests=len(pending),total_evaluated_inputs=len(inputs),
        adapter_sha256=marker['adapter_sha256'],training_examples=marker['examples'],
        model='Qwen2.5-Coder-14B-Instruct QLoRA + independent evidence gate',
        elapsed_seconds=time.perf_counter()-started,gold_passed_to_inference=False,
        independently_annotated_real_CVEs=0,
        limitation='Fictional simulation test; source extraction and field influence accuracy remain unmeasured.')
    atomic_json(folder/'trained_precision_report.json',report)
    atomic_json(folder/'trained_status.json',dict(phase='complete',cases=len(inputs),actual_model_requests=len(pending)))
    return report


def main():
    from tools.item3_precision_pipeline import evaluate_trained
    from src.precision_role_runtime import PrecisionRoleRuntime
    folder=ROOT/'results/precision_evaluation_v1';folder.mkdir(parents=True,exist_ok=True)
    marker=ROOT/'models/precision_roles_qwen25_14b_v1/training_complete.json'
    while not marker.is_file():
        atomic_json(folder/'status.json',dict(phase='waiting_for_training',pid=os.getpid()))
        time.sleep(5)
    trainer_pid=int(sys.argv[1]) if len(sys.argv)>1 else read_json(marker).get('training_pid')
    while gpu_lease.alive(trainer_pid):time.sleep(1)
    from tools.item3_precision_pipeline import sha
    trained=read_json(marker);base=Path(trained['base'])
    if 'base_files_sha256' not in trained:
        trained['base_files_sha256']={p.name:sha(p) for p in sorted(base.iterdir()) if p.suffix=='.safetensors' or p.name=='config.json'}
        trained['training_pid']=trainer_pid
        trained['memory_policy']='Frozen BF16 embedding lookup on CPU; completion-only projected loss'
        atomic_json(marker,trained)
    gpu_lease.assert_inference_available()
    atomic_json(gpu_lease.FILE,dict(active=True,pid=os.getpid(),stage='frozen_precision_evaluation'))
    try:
        runtime=PrecisionRoleRuntime()
        atomic_json(folder/'status.json',dict(phase='item3_frozen_test',pid=os.getpid()))
        evaluate_trained(runtime)
        atomic_json(folder/'status.json',dict(phase='item4_frozen_simulation_test',pid=os.getpid()))
        report=evaluate_item4(runtime)
        atomic_json(folder/'status.json',dict(phase='complete',pid=os.getpid(),item4=report))
    except BaseException as exc:
        atomic_json(folder/'status.json',dict(phase='failed',pid=os.getpid(),error=type(exc).__name__+': '+str(exc)))
        raise
    finally:
        if read_json(gpu_lease.FILE).get('pid')==os.getpid():atomic_json(gpu_lease.FILE,dict(active=False,pid=os.getpid()))


if __name__=='__main__':main()
