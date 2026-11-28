"""Manage only this project's isolated, loopback H200 inference service."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from tools.common.ncp_transport import execute

SCRIPT=r'''
from pathlib import Path
import json,os,signal,subprocess,time,urllib.request
root=Path('/home/irteam/data-vol1/ics-vex-migration-20261116')
venv=root/'item4-vllm-venv';state=root/'item4-automatic-runs/vllm_server.json'
manifest=json.loads(state.read_text()) if state.exists() else None
try:
 healthy=urllib.request.urlopen('http://127.0.0.1:18105/health',timeout=3).status==200
except Exception:healthy=False
if ACTION=='status':
 print(json.dumps(dict(healthy=healthy,manifest=manifest)))
elif ACTION=='stop':
 if not manifest:raise ValueError('No project-owned server manifest')
 pid=manifest['pid'];p=Path(f'/proc/{pid}/cmdline')
 if p.exists() and p.read_bytes():
  args=p.read_bytes().split(b'\0')
  assert (b'vllm.entrypoints.openai.api_server' in args and
          str(root/'item4-models/qwen25_7b').encode() in args and
          str(venv/'bin/python').encode() in args and os.getpgid(pid)==pid)
  os.killpg(pid,signal.SIGTERM)
 manifest.update(stopped_at=time.time());state.write_text(json.dumps(manifest,indent=2))
 print(json.dumps(dict(stopped=pid)))
else:
 if healthy:
  if not manifest:raise ValueError('Healthy service exists without this manager provenance')
  print(json.dumps(dict(status='healthy',manifest=manifest)))
 else:
  if manifest and not manifest.get('stopped_at'):
   pid=manifest['pid'];p=Path(f'/proc/{pid}/cmdline')
   if p.exists() and p.read_bytes():raise ValueError('Existing project server unhealthy; inspect before restarting')
  zig=venv/'lib/python3.11/site-packages/ziglang/zig'
  if not zig.exists():raise ValueError('Install ziglang==0.13.0 into isolated vLLM environment first')
  cc=venv/'bin/item4-cc';cc.write_text('#!/bin/sh\nexec "'+str(zig)+'" cc "$@"\n');cc.chmod(0o755)
  cxx=venv/'bin/item4-cxx';cxx.write_text('#!/bin/sh\nexec "'+str(zig)+'" c++ "$@"\n');cxx.chmod(0o755)
  args=[str(venv/'bin/python'),'-m','vllm.entrypoints.openai.api_server','--model',str(root/'item4-models/qwen25_7b'),
   '--host','127.0.0.1','--port','18105','--dtype','bfloat16','--gpu-memory-utilization','0.32',
   '--max-model-len','8192','--max-num-seqs','96','--max-num-batched-tokens','8192',
   '--compilation-config','{"mode":3,"cudagraph_mode":"FULL_DECODE_ONLY","cudagraph_capture_sizes":[1,2,4,8,16,32,48,64,96]}',
   '--enable-prefix-caching','--structured-outputs-config','{"backend":"xgrammar"}',
   '--served-model-name','item4-qwen7b']
  environment=dict(os.environ,CC=str(cc),CXX=str(cxx),TOKENIZERS_PARALLELISM='false')
  versions=json.loads(subprocess.check_output([str(venv/'bin/python'),'-c',
   'import json,torch,vllm; print(json.dumps(dict(torch=torch.__version__,vllm=vllm.__version__,device=torch.cuda.get_device_name(0))))']))
  assert versions['vllm']=='0.12.0' and 'H200' in versions['device']
  log=root/'item4-automatic-runs/vllm_server.log'
  stream=log.open('ab');proc=subprocess.Popen(args,env=environment,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
  manifest=dict(pid=proc.pid,args=args,versions=versions,cc=str(cc),started_at=time.time(),log=str(log),
                isolation='separate venv, loopback 18105, existing service 18100 unchanged')
  state.write_text(json.dumps(manifest,indent=2));print(json.dumps(dict(status='starting',manifest=manifest)))
'''

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',type=Path,required=True)
    p.add_argument('action',choices=['start','status','stop']);a=p.parse_args()
    print(execute(a.config,SCRIPT.replace('ACTION',repr(a.action))))
