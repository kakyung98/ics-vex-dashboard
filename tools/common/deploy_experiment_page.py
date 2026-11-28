"""Deploy the requested experiment page to the existing private development API."""
from pathlib import Path
import base64,json,sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.common.ncp_transport import execute
names=['site/experiments.html','site/h200-experiment.json','site/index.html','src/common/web/evaluation_dashboard.html',
       'research_records/h200_full_population_20261116.json','README.md','tools/common/ncp_evaluation_metrics.py',
       'tools/common/publish_experiment_record.py','tools/common/deploy_experiment_page.py']
payload={x:base64.b64encode((ROOT/x).read_bytes()).decode() for x in names}
script='''from pathlib import Path
import json,base64,hashlib,os,signal,subprocess,time,urllib.request
root=Path('/home/irteam/data-vol1/ics-vex-migration-20261116');project=root/'project'
out=project/'results/h200_full_population_20261116_130409/web_publication';out.mkdir(exist_ok=True)
lease=json.loads((project/'results/operational_role_finetune_v2/gpu_lease.json').read_text())
assert not lease.get('active'),'Evaluation/training queue is active'
records=[]
for name,value in json.loads(PAYLOAD).items():
 p=project/name;wire=base64.b64decode(value);before=p.read_bytes() if p.exists() else None
 if before is not None:
  backup=out/'originals'/name
  if not backup.exists():backup.parent.mkdir(parents=True,exist_ok=True);backup.write_bytes(before)
 p.parent.mkdir(parents=True,exist_ok=True);temp=p.with_name(p.name+'.publish-tmp');temp.write_bytes(wire);temp.replace(p)
 records.append(dict(path=name,before_sha256=hashlib.sha256(before).hexdigest() if before is not None else None,after_sha256=hashlib.sha256(wire).hexdigest()))
pid=int((root/'api.pid').read_text())
args=Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\\0')
assert any(Path(os.fsdecode(a)).resolve()==(project/'tools/common/ncp_serve.py').resolve() for a in args if a)
os.kill(pid,signal.SIGTERM)
for _ in range(80):
 proc=Path('/proc')/str(pid)
 if not proc.exists() or (proc/'stat').read_text().rsplit(')',1)[1].split()[0]=='Z':break
 time.sleep(.25)
else:raise RuntimeError('Owned API did not exit; no replacement started')
subprocess.run([str(root/'venv/bin/python'),str(project/'tools/common/ncp_service.py'),'start'],capture_output=True,check=True)
for _ in range(80):
 try:
  with urllib.request.urlopen('http://127.0.0.1:18100/experiments.html',timeout=2) as response:page=response.read().decode()
  assert '683,488' in page and '98.8731%' in page
  with urllib.request.urlopen('http://127.0.0.1:18100/h200-experiment.json') as response:record=json.load(response)
  assert record['population_per_item']==12418 and record['real_asset_precision'] is None
  break
 except Exception:time.sleep(.25)
else:raise RuntimeError('Experiment page did not become healthy')
report=dict(published=True,URL='http://127.0.0.1:18100/experiments.html',record_saved=True,HTTP_checked=True,files=records,
            frozen_prediction_and_Gold_files_modified=False,public_site_pushed=False)
(out/'publication.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report))
'''.replace('PAYLOAD',repr(json.dumps(payload)))
if __name__=='__main__':
 data=json.loads(execute(Path.home()/'Downloads/hysage-kubeconfig.yaml',script))
 (ROOT/'results/h200_full_population_20261116_130409/web_publication.json').write_text(json.dumps(data,indent=2),encoding='utf-8')
 print(json.dumps({k:v for k,v in data.items() if k!='files'}))
