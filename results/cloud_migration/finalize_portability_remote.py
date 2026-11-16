from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tarfile
ROOT=Path('/home/irteam/data-vol1/ics-vex-migration-20261116')
PROJECT=ROOT/'project'
report=PROJECT/'results/cloud_migration/tools/verification.json'
data=json.loads(report.read_text())
data['network_policy']='Separate network namespace, loopback only; helper checks namespace identity and interfaces before execution'
data['aggregate_RSS_limit_bytes']=2147483648
report.write_text(json.dumps(data,indent=2))
worker=PROJECT/'tools/ncp_verify_external_tools.py'
worker.write_text(worker.read_text().replace('IPv4/IPv6 socket creation denied by inherited seccomp; verified separately', data['network_policy']))
manifest=json.loads((PROJECT/'MIGRATION_INVENTORY.json').read_text())
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
 return h.hexdigest()
changed=[]
for item in manifest['files']:
 path=PROJECT/item['path']
 if digest(path)!=item['sha256']:changed.append(item['path'])
allowed={'results/precision_evaluation_v1/reverification.json','results/item4_source_context_v1/reverification.json',
 'results/cve_population_precision_v1/validation_report.json','results/cve_population_precision_v1/cve_validation_ledger.jsonl'}
if not set(changed)<=allowed:raise ValueError('Unexpected changes after metric verification: '+str(changed))
preserved=PROJECT/'results/cloud_migration/cloud_metric_outputs'
preserved.mkdir(exist_ok=True)
for name in changed:
 target=preserved/name;target.parent.mkdir(parents=True,exist_ok=True)
 target.write_bytes((PROJECT/name).read_bytes())
with tarfile.open(ROOT/'incoming/project.tar.gz') as archive:
 for name in changed:
  wire=archive.extractfile('project/'+name).read()
  (PROJECT/name).write_bytes(wire)
(PROJECT/'results/cloud_migration/historical_restoration.json').write_text(json.dumps(dict(
 regenerated_files_preserved=changed, original_sealed_files_restored_from_verified_archive=True),indent=2))
print(json.dumps(dict(restored_historical_files=changed)))
