from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import time
ROOT=Path('/home/irteam/data-vol1/ics-vex-migration-20261116')
PROJECT=ROOT/'project'
OUT=PROJECT/'results/cloud_migration';OUT.mkdir(parents=True,exist_ok=True)
py=str(ROOT/'venv/bin/python')
worker='''from pathlib import Path
import json,sys,shutil
root=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(root))
from tools.ncp_operational_runtime import run
from src.operational_assessment import import_oval_results
out=root/'results/cloud_migration/tools';out.mkdir(parents=True,exist_ok=True)
oval=out/'oval';oval.mkdir(exist_ok=True)
for name in ['fixture.conf','definitions.xml']:
 shutil.copyfile(root/'results/operational_tools_v1/oval'/name,oval/name)
for args,label in [(['oscap','oval','validate','/work/definitions.xml'],'schema'),(['oscap','oval','eval','--results','/work/results.xml','/work/definitions.xml'],'oval')]:
 result=run(args,oval,label)
 assert result.returncode==0, result.stderr
observations=import_oval_results((oval/'results.xml').read_text(),{'oval:ics-vex:def:1':'feature'},dict(asset_ref='fictional-container-fixture'),dict(report_asset_ref='fictional-container-fixture'))
assert observations[0]['value']=='true'
mulval=out/'mulval';mulval.mkdir(exist_ok=True)
shutil.copyfile(root.parent/'operational_rootfs/opt/mulval/testcases/3host/input.P',mulval/'input.P')
result=run(['graph_gen.sh','/work/input.P','-l'],mulval,'graph')
assert result.returncode==0,result.stderr
assert (mulval/'VERTICES.CSV').stat().st_size>0
report=dict(passed=True,openscap_oval_real_execution=True,mulval_xsb_real_execution=True,fixtures_only=True,network_policy='Separate network namespace, loopback only; tool helper verifies namespace separation and interface list before execution',aggregate_RSS_limit_bytes=2147483648,real_asset_precision=None)
(out/'verification.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
'''
# Put worker under project/tools so its owning project is explicit.
worker=worker.replace("parents[2]", "parents[1]")
(PROJECT/'tools/ncp_verify_external_tools.py').write_text(worker)
jobs=[]
for name,script in [('legacy_metrics','tools/verify_precision_release.py'),('item4_source_metrics','tools/verify_item4_source_context.py'),('item3_population_metrics','tools/report_population_validation.py')]:
    log=(ROOT/'logs'/f'{name}.log').open('wb')
    p=subprocess.Popen([py,str(PROJECT/'tools/ncp_cloud_setup.py'),'verify-historical',script],cwd=PROJECT,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    jobs.append(dict(name=name,pid=p.pid,log=str(ROOT/'logs'/f'{name}.log')))
log=(ROOT/'logs/external_tools.log').open('wb')
p=subprocess.Popen([py,str(PROJECT/'tools/ncp_verify_external_tools.py')],cwd=PROJECT,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
jobs.append(dict(name='external_tools',pid=p.pid,log=str(ROOT/'logs/external_tools.log')))
(OUT/'verification_jobs.json').write_text(json.dumps(jobs,indent=2))
print(json.dumps(jobs))
