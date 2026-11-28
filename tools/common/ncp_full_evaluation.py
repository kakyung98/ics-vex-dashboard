"""Fresh H200 full-population inference, isolated from all historical predictions."""
from pathlib import Path, PureWindowsPath
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import traceback
import urllib.request

PROJECT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(PROJECT))
from src.common.runtime.training_progress_io import atomic_json


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def normalize_manifest_paths():
    original=Path.__truediv__
    def join(self,key):
        if isinstance(key,str) and '\\' in key and not PureWindowsPath(key).is_absolute():key=key.replace('\\','/')
        return original(self,key)
    Path.__truediv__=join


def item3(root):
    normalize_manifest_paths()
    from tools.item4 import validate_population_precision as evaluator
    from src.research.identification_batch_flow import PacketCache
    from tools.item3.item3_precision_pipeline import digest_json
    evaluator.OUT=root/'item3';evaluator.OUT.mkdir()
    signature=read(PROJECT/'results/item3_precision_v11/trained_evaluation/run_config.json')
    # Existing driver seeds from an old cache unless the destination exists.
    # Create an EMPTY cache so all reusable packets originate in this new run.
    cache=PacketCache(evaluator.OUT/'packet_cache.sqlite3',digest_json(signature))
    initial=cache.statistics();cache.close()
    assert initial==dict(actual_llm_requests=0,generated_tokens=0,cached_packets=0)
    atomic_json(evaluator.OUT/'fresh_inference_protocol.json',dict(initial_cache=initial,
        historical_packet_cache_imported=False,historical_predictions_imported=False,
        exact_duplicate_packet_reuse='Only packets freshly inferred within this run',population=12418))
    evaluator.evaluate()
    atomic_json(evaluator.OUT/'item4_precision_report.json',dict(status='Separate fresh item4 source-conditioned simulation run',
        results_directory=str(root/'item4'),real_asset_precision=None,independent_real_asset_accuracy_verified=False))
    from tools.item4 import report_population_validation as verifier
    verifier.OUT=evaluator.OUT
    verifier.summarize()


def item4(root):
    normalize_manifest_paths()
    from tools.item4 import evaluate_item4_source_context as evaluator
    evaluator.OUT=root/'item4';evaluator.OUT.mkdir()
    atomic_json(evaluator.OUT/'fresh_inference_protocol.json',dict(historical_predictions_imported=False,
        population=12418,cases=24678,source_unknown_CVEs_retained=9966,
        expected_actual_model_requests=14712,labels_passed_to_model=False))
    evaluator.evaluate()
    from tools.item4 import verify_item4_source_context as verifier
    verifier.OUT=evaluator.OUT
    verifier.verify()


def queue(root):
    from src.common import gpu_lease
    gpu_lease.assert_inference_available()
    root.mkdir(parents=True,exist_ok=False)
    state=dict(status='running',started_unix=time.time(),pid=os.getpid(),population_per_item=12418,
        item4_cases=24678,history_reused=False,stages={},real_asset_precision=None)
    atomic_json(root/'status.json',state)
    hardware=subprocess.check_output(['nvidia-smi','--query-gpu=name,uuid,driver_version,memory.total','--format=csv'],text=True)
    assert 'NVIDIA H200' in hardware
    atomic_json(root/'protocol.json',dict(hardware=hardware,driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        historical_predictions_reused=False,historical_packet_cache_imported=False,checkpoints_retrained=False,
        input_and_label_files='Same sealed Gold datasets; no labels sent to model inference',
        item3_scope='Source-derived synthetic inventory, including training-origin cases; full emission scoring and duplicate-input check',
        item4_scope='Source-conditioned synthetic selected-path worlds; held-out results reported separately; actual field precision unmeasured'))
    try:
        # Release only this application's resident model before the evaluation queue.
        request=urllib.request.Request('http://127.0.0.1:18100/api/cve-match/models/unload',data=b'{}',headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(request,timeout=30) as response:response.read()
        for stage in ('item3','item4'):
            atomic_json(gpu_lease.FILE,dict(active=True,pid=os.getpid(),stage='H200_fresh_full_evaluation'))
            state['stage']=stage
            state['stages'][stage]=dict(status='running',started_unix=time.time())
            atomic_json(root/'status.json',state)
            env=dict(os.environ,OMP_NUM_THREADS='2',MKL_NUM_THREADS='2',OPENBLAS_NUM_THREADS='2',TOKENIZERS_PARALLELISM='false',HF_HUB_OFFLINE='1')
            with (root/(stage+'.log')).open('wb') as log:
                child=subprocess.Popen([sys.executable,str(Path(__file__)),stage,'--run-root',str(root)],cwd=PROJECT,env=env,stdout=log,stderr=subprocess.STDOUT)
                atomic_json(gpu_lease.FILE,dict(active=True,pid=os.getpid(),child_pid=child.pid,stage=stage))
                state['child_pid']=child.pid;atomic_json(root/'status.json',state)
                code=child.wait()
            state['stages'][stage].update(status='complete' if code==0 else 'failed',returncode=code,finished_unix=time.time())
            atomic_json(root/'status.json',state)
            if code:raise RuntimeError(stage+' failed; inspect '+str(root/(stage+'.log')))
        third=read(root/'item3/validation_report.json')
        fourth=read(root/'item4/precision_report.json')
        assert third['population']==fourth['population']==12418 and fourth['cases']==24678
        summary=dict(status='complete',population_per_item=12418,item4_cases=24678,
            item3=third['item3'],item4=fourth['results'],item4_source_unknown_CVEs=fourth['CVEs_source_unknown'],
            item3_target_met=third['item3']['precision_criterion_met_by_conservative_bounds'],
            item4_heldout_target_met=fourth['evaluation_fold_target_met'],fresh_GPU_inference=True,
            historical_predictions_reused=False,real_asset_precision=None,
            limitation='Both scores retain their synthetic Gold scopes; full-population aggregates include training-origin cases. No independent field precision claim.')
        atomic_json(root/'summary.json',summary)
        state.update(status='complete',finished_unix=time.time());atomic_json(root/'status.json',state)
        print(json.dumps(summary),flush=True)
    except BaseException as error:
        state.update(status='failed',error=str(error),finished_unix=time.time());atomic_json(root/'status.json',state)
        traceback.print_exc();raise
    finally:
        atomic_json(gpu_lease.FILE,dict(active=False,pid=os.getpid()))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['queue','item3','item4']);parser.add_argument('--run-root',type=Path,required=True)
    args=parser.parse_args()
    {'queue':queue,'item3':item3,'item4':item4}[args.action](args.run_root)
