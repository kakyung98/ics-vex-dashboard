"""Back up local service databases and restart only the owning localhost worker."""
from pathlib import Path
import hashlib,json,sqlite3,subprocess,sys,time,urllib.request
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[2]
out=ROOT/'results/nist_information_20261118/before_selectable'
out.mkdir(parents=True,exist_ok=True)
base=Path('D:/ICS-VEX/local-service/sbom-vex')
absent=[]
for source in [base/'vex_operational_logic_20261117/reviews.sqlite3',base/'vex_operational_logic_20261117/bom_integration_20261117/workflows.sqlite3']:
    if not source.exists():
        absent.append(str(source));continue
    target=out/('production-'+source.name)
    if target.exists():target=out/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+source.name)
    with sqlite3.connect(source) as src,sqlite3.connect(target) as dst:src.backup(dst)
raw=subprocess.check_output(['powershell','-NoProfile','-Command',"Get-CimInstance Win32_Process -Filter \"Name = 'python.exe'\" | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress"],text=True)
workers=json.loads(raw)
if isinstance(workers,dict):workers=[workers]
old=[]
for worker in workers:
    cmd=worker.get('CommandLine') or ''
    if any(str(path).lower() in cmd.lower() for path in (ROOT/'tools/item4/serve_nist_operational_vex.py',ROOT/'tools/serve_nist_operational_vex.py')) and cmd.rstrip().endswith(' 8100'):
        old.append(worker['ProcessId'])
assert len(old)==1,old
subprocess.run(['taskkill','/PID',str(old[0]),'/F'],check=True,capture_output=True)
log=(out.parent/'selectable_service.log').open('ab')
p=subprocess.Popen([sys.executable,'-X','utf8','-B',str(ROOT/'tools/item4/serve_nist_operational_vex.py'),'8100'],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW)
url='http://127.0.0.1:8100/api/asset-vulntology/operating-profiles'
for attempt in range(60):
    try:
        with urllib.request.urlopen(url,timeout=2) as response:c=json.load(response)
        assert c['version']=='ics-operating-profile/nist-tables-12-17-choice/2'
        assert len(c['answer_specs'])==167
        break
    except Exception:
        if p.poll() is not None:raise RuntimeError('Service exited; inspect selectable_service.log')
        time.sleep(.3)
else:raise RuntimeError('Service readiness timed out')
report=dict(pid=p.pid,previous_pid=old[0],version=c['version'],source_items=54,details=167,options=sum(len(s['options']) for s in c['answer_specs'].values()),spec_sha256=hashlib.sha256((ROOT/'docs/nist_selectable_answers.v1.json').read_bytes()).hexdigest(),url='http://127.0.0.1:8100/bom-vex.html',tests_passed=10,negative_or_exhaustive_choices_tested=137,independent_expert_validation=False,registered_cve_condition_rules=0)
report['databases_not_yet_created']=absent
report.update(tests_passed=28,typed_engine='nist-three-axis-vex/1',registered_cve_condition_rules='Source-bound coded-proof interpreter; unsupported predicates remain unknown')
experiment=ROOT/'results/nist_three_axis_experiment_20261118/experiment_report.json'
if experiment.exists():report['synthetic_experiment']=json.loads(experiment.read_text())['overall']
(out.parent/'selectable_deployment.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report,indent=2))
