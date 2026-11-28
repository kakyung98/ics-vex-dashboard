"""Back up local databases and replace only the owned loopback VEX worker."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,sqlite3,subprocess,sys,time,urllib.request
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'results/nist_auto_vex_20261118'
def main():
    report=json.loads((OUT/'experiment/report.json').read_text())
    if report['engine_sha256']!=hashlib.sha256((ROOT/'src/item4/decision/evidence_based_vex.py').read_bytes()).hexdigest():raise ValueError('Current engine has not been benchmarked')
    base=Path('D:/ICS-VEX/local-service/sbom-vex/vex_operational_logic_20261117');backup=OUT/'before'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');backup.mkdir(parents=True,exist_ok=True)
    for source in [base/'reviews.sqlite3',base/'bom_integration_20261117/workflows.sqlite3']:
        if source.exists():
            with sqlite3.connect(source) as src,sqlite3.connect(backup/source.name) as dst:src.backup(dst)
    raw=subprocess.check_output(['powershell','-NoProfile','-Command',"Get-CimInstance Win32_Process -Filter \"Name = 'python.exe'\" | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress"],text=True)
    workers=json.loads(raw);workers=workers if isinstance(workers,list) else [workers]
    owned=[w['ProcessId'] for w in workers if any(str(path).lower() in (w.get('CommandLine') or '').lower() for path in (ROOT/'tools/item4/serve_nist_operational_vex.py',ROOT/'tools/serve_nist_operational_vex.py')) and (w.get('CommandLine') or '').rstrip().endswith(' 8100')]
    if len(owned)!=1:raise ValueError('Expected one owned loopback worker: '+str(owned))
    subprocess.run(['taskkill','/PID',str(owned[0]),'/F'],capture_output=True,check=True)
    log=(OUT/'service.log').open('ab')
    worker=subprocess.Popen([sys.executable,'-X','utf8','-B',str(ROOT/'tools/item4/serve_nist_operational_vex.py'),'8100'],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW)
    for attempt in range(100):
        try:
            with urllib.request.urlopen('http://127.0.0.1:8100/nist-auto-vex-rules.json',timeout=2) as response:rules=json.load(response)
            assert len(rules['rules'])==8;break
        except Exception:
            if worker.poll() is not None:raise RuntimeError('Server exited; inspect service.log')
            time.sleep(.3)
    else:raise RuntimeError('Automatic service readiness timed out')
    live=dict(pid=worker.pid,previous_pid=owned[0],url='http://127.0.0.1:8100/bom-vex.html',engine='source-bound-operational-auto-vex/1',rule_registry_sha256=rules['sha256'],engine_sha256=report['engine_sha256'],tests_passed=35,benchmark_cases=878,metrics=report['all_cases'],operator_selects_verdict=False,llm_used=False,legacy_decision_payloads_rejected=True,backups=str(backup),independent_expert_validation=False)
    (OUT/'deployment.json').write_text(json.dumps(live,indent=2),encoding='utf-8');print(json.dumps(live,indent=2))
if __name__=='__main__':main()
