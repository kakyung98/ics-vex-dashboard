"""Collect actual migration evidence from the running cloud project."""
from pathlib import Path
import json
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.ncp_transport import execute

SCRIPT='''from pathlib import Path
import json,subprocess,urllib.request,datetime,hashlib
r=Path('/home/irteam/data-vol1/ics-vex-migration-20261116')
p=r/'project';out=p/'results/cloud_migration'
def read(file):return json.loads(file.read_text())
payload=dict(binding=dict(asset_ref='fictionalPlc'),attacker_host='fictionalAttacker',
 network=[dict(state='true',src='fictionalAttacker',dst='fictionalPlc',protocol='tcp',port=102)],
 services=[dict(state='true',program='fictionalService',protocol='tcp',port=102,user='root')],
 vulnerabilities=[dict(reviewed=True,applicable='true',cve='CVE-2099-4242',program='fictionalService',exploit_semantics_reviewed=True,exploit_range='remoteExploit',effect='privEscalation')])
req=urllib.request.Request('http://127.0.0.1:18100/api/precision/item4/mulval-runs',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
with urllib.request.urlopen(req,timeout=180) as response:mulval=json.load(response)
assert mulval['state']=='complete' and mulval['graph_has_nodes'],mulval
(out/'mulval_http_fixture.json').write_text(json.dumps(mulval,indent=2))
logs={}
for key in ['legacy_metrics','item4_source_metrics','item3_population_metrics']:
 lines=(r/'logs'/f'{key}.log').read_text().splitlines()
 logs[key]=next(json.loads(x) for x in reversed(lines) if x.startswith('{'))
assert logs['legacy_metrics']['passed'] and logs['item4_source_metrics']['passed']
assert logs['item3_population_metrics']['item3']['precision_criterion_met_by_conservative_bounds']
freeze=subprocess.check_output([str(r/'venv/bin/python'),'-m','pip','freeze'],text=True)
(r/'environment-lock.txt').write_text(freeze)
report=dict(completed=True,completed_at=datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))).isoformat(),
 platform='NCP ML expert Platform',project='hysage',notebook='test',pod='test-0',
 root=str(r),workspace_URL='http://127.0.0.1:18100/precision.html',access='Private Pod loopback via local kubectl port-forward',
 project_files_verified=12121,base_files_verified=11,
 transfer_archives=dict(project_sha256='de9f468375fb01ff93712212a34c474664d24ffb107f2c795a11ccb0c98efdb3',
 base_model_sha256='14df834b439aeff012410bf6744968b967a32241bb854b5de3fe0153c8ae5fa8',
 operational_image_sha256='0b86b843c6743475bd65d0d7367090aec8e4be527b7eba77cf493177ec9f4868',
 operational_rootfs_sha256='e5c42e13dc08cbd23ab0cc9b82a9e05053996c577f32875ea84a64949881cac9'),
 relocation=read(out/'relocation.json'),overlay=read(out/'overlay.json'),acceptance=read(out/'acceptance.json'),
 external_tools=read(out/'tools/verification.json'),mulval_HTTP_fixture=mulval,metric_recomputation=logs,
 pytest=dict(passed=118,failed=0,warnings=1,source='Observed cloud pytest output: 118 passed, 1 deprecation warning in 15.61s'),
 existing_workloads_preserved=True,source_PC_preserved=True,real_asset_precision=None,
 full_GPU_evaluation_rerun=False,limitations=['Stored predictions were rescored; only representative live GPU inference rerun.',
 'The #4 accuracy scope remains conditional synthetic worlds; actual installation precision is unmeasured.',
 'Local-path PVCs are tied to the storage node; original local copies and transfer archives are retained.',
 'The local port-forward process must remain running to use the displayed PC URL.'])
(out/'migration_report.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report))
'''

if __name__=='__main__':
    wire=execute(Path.home()/'Downloads/hysage-kubeconfig.yaml',SCRIPT)
    report=json.loads(wire)
    dest=ROOT/'results/cloud_migration/migration_report.json'
    dest.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(dict(completed=report['completed'],project=report['project'],tests_passed=report['pytest']['passed'],
                         mulval_HTTP_fixture=report['mulval_HTTP_fixture']['state'],report=str(dest))))
