"""Read bounded progress and collect the completed #3 70/30 report."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.common.ncp_api_transport import execute


def check(config, run):
    script = '''from pathlib import Path
import json,time,subprocess
r=Path(RUN)
files={}
for name in ['status.json','split_manifest.json','prepare_status.json','training_manifest.json','training_status.json','adapter/training_complete.json','evaluation/status.json','evaluation/precision_report.json']:
 p=r/name
 if name.startswith('evaluation/'):
  current=r/name.replace('evaluation/', 'test/', 1)
  if current.exists():p=current
  name=name.replace('evaluation/', 'test/', 1)
 if p.exists():files[name]=json.loads(p.read_text())
state=files.get('status.json',{})
stage=state.get('phase','starting')
p=r/(stage+'.log')
tail=''
if p.exists():
 with p.open('rb') as f:
  f.seek(max(0,p.stat().st_size-2500));tail=f.read().decode(errors='replace')
if stage=='failed':
 for n in ['prepare.log','train.log','evaluate.log']:
  p=r/n
  if p.exists():
   with p.open('rb') as f:f.seek(max(0,p.stat().st_size-2500));tail+=n+'\\n'+f.read().decode(errors='replace')
print(json.dumps(dict(files=files,log_tail=tail,elapsed_seconds=time.time()-state.get('started_unix',time.time()),gpu=subprocess.check_output(['nvidia-smi','--query-gpu=utilization.gpu,memory.used','--format=csv,noheader'],text=True).strip())))
'''.replace('RUN', repr(run))
    result = json.loads(execute(config, script))
    dest = ROOT/'results'/Path(run).name
    dest.mkdir(parents=True, exist_ok=True)
    for name, data in result['files'].items():
        path = dest/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    (dest/'latest_progress.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',type=Path,default=ROOT/'hysage-kubeconfig.yaml')
    parser.add_argument('--run',default='/home/irteam/data-vol1/ics-vex-migration-20261116/project/results/item3_holdout_7030_20261117_v2')
    args=parser.parse_args()
    print(json.dumps(check(args.config,args.run),ensure_ascii=False,indent=2))
