from pathlib import Path
import json
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.ncp_transport import execute
SCRIPT='''from pathlib import Path
import subprocess,json,datetime
r=Path('/home/irteam/data-vol1/ics-vex-migration-20261116')
stamp=datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))).strftime('%Y%m%d_%H%M%S')
run=r/'project/results'/('h200_full_population_'+stamp)
log=run.with_suffix('.queue.log').open('wb')
p=subprocess.Popen([str(r/'venv/bin/python'),str(r/'project/tools/ncp_full_evaluation.py'),'queue','--run-root',str(run)],cwd=r/'project',stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
print(json.dumps(dict(run_root=str(run),queue_pid=p.pid,queue_log=str(run.with_suffix('.queue.log')))))
'''
data=json.loads(execute(Path.home()/'Downloads/hysage-kubeconfig.yaml',SCRIPT))
(ROOT/'results/cloud_migration/h200_full_evaluation_job.json').write_text(json.dumps(data,indent=2),encoding='utf-8')
print(json.dumps(data))
