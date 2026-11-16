"""Explain the #3 mapping totals with per-input counts and every FP/unknown output."""
from pathlib import Path
import json,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.ncp_transport import execute
SCRIPT='''from pathlib import Path
from collections import Counter
import json,csv,sqlite3
root=Path('/home/irteam/data-vol1/ics-vex-migration-20261116/project')
run=root/'results/h200_full_population_20261116_130409'
unique={}
for line in (run/'item3/cve_validation_ledger.jsonl').open():
 r=json.loads(line)
 if r['input_hash'] not in unique:
  unique[r['input_hash']]=dict(input_hash=r['input_hash'],case_id=r['input_id'],seed_CVE=r['cve'],**r['full_output_score'])
counts=Counter()
for r in unique.values():counts.update({k:r[k] for k in ['TP','FP','FN','unjudged','out_of_scope']})
stored=json.loads((run/'summary.json').read_text())['item3']['deduplicated_full_output_micro']
assert len(unique)==5114 and all(counts[k]==stored[k] for k in counts)
by_id={x['case_id']:x for x in unique.values()}
for line in (root/'benchmark/cve_population_precision_v1/inputs.jsonl').open():
 r=json.loads(line)
 if r['id'] in by_id:
  c=r['sbom']['components'][0];by_id[r['id']].update(name=c.get('name'),version=c.get('version'),manufacturer=c.get('manufacturer',{}).get('name'))
folder=run/'mapping_count_audit';folder.mkdir(exist_ok=True)
fields=['case_id','seed_CVE','input_hash','manufacturer','name','version','TP','FP','FN','unjudged','out_of_scope']
with (folder/'per_SBOM_counts.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(by_id.values())
selected={x['case_id'] for x in by_id.values() if x['FP'] or x['unjudged']}
largest=max(by_id.values(),key=lambda x:x['TP']);selected.add(largest['case_id'])
labels={}
for line in (root/'benchmark/cve_population_precision_v1/labels.jsonl').open():
 r=json.loads(line)
 if r['id'] in selected:labels[r['id']]=r
errors=[];largest_example=None
with sqlite3.connect((run/'item3/item3_predictions.sqlite3').as_uri()+'?mode=ro',uri=True) as db:
 for identity in sorted(selected):
  raw=json.loads(db.execute('select result from predictions where id=?',(identity,)).fetchone()[0])['result']
  predicted={v['cve_id'] for c in raw['components'] for v in c.get('cves',[]) if v.get('match_status')=='match'}
  E=set(labels[identity]['expected_cves']);U=set(labels[identity]['unknown_cves'])
  fp=predicted-E-U;unknown=predicted&U;tp=predicted&E-U
  item=by_id[identity]
  assert (len(fp),len(unknown),len(tp))==(item['FP'],item['unjudged'],item['TP'])
  for kind,values in [('FP',fp),('unjudged',unknown)]:
   errors.extend(dict(case_id=identity,manufacturer=item['manufacturer'],name=item['name'],version=item['version'],CVE=c,classification=kind) for c in sorted(values))
  if identity==largest['case_id']:
   largest_example=dict(**largest,confirmed_count=len(predicted),sample_TP_CVEs=sorted(tp)[:8])
assert sum(x['classification']=='FP' for x in errors)==56
assert sum(x['classification']=='unjudged' for x in errors)==16
with (folder/'FP_and_unjudged_mappings.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=['case_id','manufacturer','name','version','CVE','classification']);w.writeheader();w.writerows(errors)
report=dict(unit='Unique SBOM input + emitted CVE; the same CVE on different SBOM inputs is a different mapping',
 input_rows=12418,unique_SBOM_inputs=5114,duplicate_rows_removed=7304,totals=dict(counts),
 confirmed_mapping_total=counts['TP']+counts['FP']+counts['unjudged']+counts['out_of_scope'],
 all_counts_recomputed_from_per_input_ledger=True,FP_and_unknown_CVE_IDs_rechecked_against_raw_predictions_and_labels=True,
 largest_TP_example=largest_example,average_TP_per_unique_SBOM=counts['TP']/len(unique),
 files=['per_SBOM_counts.csv','FP_and_unjudged_mappings.csv'])
(folder/'summary.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
'''
if __name__=='__main__':
 target=ROOT/'results/h200_full_population_20261116_130409/mapping_count_audit'
 target.mkdir(exist_ok=True)
 if '--download-only' not in sys.argv:
  data=json.loads(execute(Path.home()/'Downloads/hysage-kubeconfig.yaml',SCRIPT))
  (target/'summary.json').write_text(json.dumps(data,indent=2),encoding='utf-8')
  print(json.dumps(data))
 download="from pathlib import Path\nimport json\np=Path('/home/irteam/data-vol1/ics-vex-migration-20261116/project/results/h200_full_population_20261116_130409/mapping_count_audit')\nprint(json.dumps({name:(p/name).read_text() for name in ['per_SBOM_counts.csv','FP_and_unjudged_mappings.csv']}))"
 files=json.loads(execute(Path.home()/'Downloads/hysage-kubeconfig.yaml',download))
 for name,wire in files.items():(target/name).write_text(wire,encoding='utf-8-sig',newline='')
 import csv
 with (target/'per_SBOM_counts.csv').open(encoding='utf-8-sig',newline='') as f:rows=list(csv.DictReader(f))
 assert len(rows)==5114 and sum(int(x['TP']) for x in rows)==683488 and sum(int(x['FP']) for x in rows)==56 and sum(int(x['unjudged']) for x in rows)==16
 print(json.dumps(dict(downloaded=list(files),count_sums_verified=True)))
