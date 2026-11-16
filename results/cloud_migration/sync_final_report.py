from pathlib import Path
import json
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.ncp_transport import execute
script='''from pathlib import Path
import json,datetime
out=Path('/home/irteam/data-vol1/ics-vex-migration-20261116/project/results/cloud_migration')
p=out/'migration_report.json';d=json.loads(p.read_text())
d['overlay']=json.loads((out/'overlay.json').read_text())
d['completed_at']=datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))).isoformat()
assert d['jupyter']['actual_kernel_execution']['passed'] and d['acceptance']['passed']
p.write_text(json.dumps(d,indent=2))
print(json.dumps(d))
'''
data=json.loads(execute(Path.home()/'Downloads/hysage-kubeconfig.yaml',script))
(ROOT/'results/cloud_migration/migration_report.json').write_text(json.dumps(data,indent=2),encoding='utf-8')
print(json.dumps(dict(completed=data['completed'],kernel_verified=data['jupyter']['actual_kernel_execution']['passed'],tests_passed=data['pytest']['passed'])))
