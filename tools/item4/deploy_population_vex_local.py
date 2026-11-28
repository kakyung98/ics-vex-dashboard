"""Deploy only the benchmarked full-population engine to the owned loopback app."""
from pathlib import Path
from datetime import datetime,timezone
import argparse,hashlib,json,sqlite3,subprocess,sys,time,urllib.request
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'results/nist_population_vex_20261118'
sys.path.insert(0,str(ROOT))
from src.item4.decision.evidence_based_vex import VERSION as ENGINE_VERSION
from src.common.paths import source_path

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--benchmark-dir',type=Path,default=OUT/'benchmark')
    parser.add_argument('--output',type=Path,default=OUT)
    args=parser.parse_args();out=args.output.resolve();benchmark=args.benchmark_dir.resolve()
    report=json.loads((benchmark/'report.json').read_text())
    if report['target_membership']['evaluated']!=12418 or report['target_membership']['excluded'] or report['overall']['cases']!=37254 or report['overall']['errors']:raise ValueError('Incomplete or failed full-population evaluation')
    for name,expected in report['source_fingerprints'].items():
        if hashlib.sha256((source_path(name, root=ROOT)).read_bytes()).hexdigest()!=expected:raise ValueError('Current source was not evaluated: '+name)
    base=ROOT/'local-service/sbom-vex/vex_operational_logic_20261117';backup=out/'backups'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');backup.mkdir(parents=True,exist_ok=True)
    for source in [base/'reviews.sqlite3',base/'bom_integration_20261117/workflows.sqlite3',base/'bom_integration_20261117/workflows_identification_jobs.sqlite3']:
        if source.exists():
            src=sqlite3.connect(source);dst=sqlite3.connect(backup/source.name)
            try:src.backup(dst)
            finally:src.close();dst.close()
    raw=subprocess.check_output(['powershell','-NoProfile','-Command',"Get-CimInstance Win32_Process -Filter \"Name = 'python.exe'\" | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress"],text=True)
    workers=json.loads(raw);workers=workers if isinstance(workers,list) else [workers]
    owned=[w['ProcessId'] for w in workers if any(str(path).lower() in (w.get('CommandLine') or '').lower() for path in (ROOT/'tools/item4/serve_nist_operational_vex.py',ROOT/'tools/serve_nist_operational_vex.py')) and (w.get('CommandLine') or '').rstrip().endswith(' 8100')]
    if len(owned)!=1:raise ValueError('Expected one owned loopback worker: '+str(owned))
    subprocess.run(['taskkill','/PID',str(owned[0]),'/F'],capture_output=True,check=True)
    log=(out/'service.log').open('ab')
    worker=subprocess.Popen([sys.executable,'-X','utf8','-B',str(ROOT/'tools/item4/serve_nist_operational_vex.py'),'8100'],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW)
    for attempt in range(100):
        try:
            with urllib.request.urlopen('http://127.0.0.1:8100/nist-auto-vex-rules.json',timeout=2) as response:data=json.load(response)
            assert data['population']['population_count']==12418
            assert data['population']['sha256']==report['protocol']['catalogue_sha256']
            assert data['engine_version']==ENGINE_VERSION
            break
        except Exception:
            if worker.poll() is not None:raise RuntimeError('Server exited; inspect service.log')
            time.sleep(.3)
    else:raise RuntimeError('Full-population service readiness timed out')
    live=dict(pid=worker.pid,previous_pid=owned[0],url='http://127.0.0.1:8100/bom-vex.html',engine=data['engine_version'],population_count=12418,excluded_cves=0,benchmark_cases=37254,catalogue_sha256=data['population']['sha256'],source_fingerprints=report['source_fingerprints'],metrics=report['overall'],operator_selects_verdict=False,llm_used=False,backups=str(backup),independent_expert_validation=False)
    live['benchmark_directory']=str(benchmark)
    (out/'deployment.json').write_text(json.dumps(live,indent=2),encoding='utf-8');print(json.dumps(live,indent=2))
if __name__=='__main__':main()
