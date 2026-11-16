from pathlib import Path
import base64,json,sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.ncp_transport import execute
job=json.loads((ROOT/'results/cloud_migration/h200_full_evaluation_job.json').read_text(encoding='utf-8'))
payload={x:base64.b64encode((ROOT/x).read_bytes()).decode() for x in ['tools/ncp_serve.py','tools/ncp_evaluation_metrics.py']}
script='''from pathlib import Path
import json,base64,hashlib
r=Path('/home/irteam/data-vol1/ics-vex-migration-20261116/project')
payload=json.loads(PAYLOAD)
records=[]
for name,encoded in payload.items():
 p=r/name;wire=base64.b64decode(encoded)
 if p.exists():
  old=Path(RUN)/'dashboard_originals'/name;old.parent.mkdir(parents=True,exist_ok=True);old.write_bytes(p.read_bytes())
 p.write_bytes(wire);records.append(dict(path=name,sha256=hashlib.sha256(wire).hexdigest()))
(r/'results/h200_latest_evaluation.json').write_text(json.dumps(dict(run_root=RUN)))
(Path(RUN)/'dashboard_integration.json').write_text(json.dumps(records,indent=2))
print(json.dumps(dict(published=True,files=records)))
'''.replace('PAYLOAD',repr(json.dumps(payload))).replace('RUN',repr(job['run_root']))
print(execute(Path.home()/'Downloads/hysage-kubeconfig.yaml',script))
