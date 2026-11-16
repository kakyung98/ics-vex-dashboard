"""Extract an actual identical-SBOM pair and their shared generation anchor."""
from pathlib import Path
from collections import defaultdict
import json,hashlib,sqlite3
ROOT=Path(__file__).resolve().parents[1]
groups=defaultdict(list);examples={}
for line in (ROOT/'benchmark/cve_population_precision_v1/inputs.jsonl').open(encoding='utf-8'):
 row=json.loads(line)
 text=json.dumps(row['sbom'],ensure_ascii=False,sort_keys=True,separators=(',',':'))
 key=hashlib.sha256(text.encode()).hexdigest()
 groups[key].append(dict(id=row['id'],cve=row['cve']))
 examples.setdefault(key,row['sbom'])
candidates=[k for k,v in groups.items() if len(v)>1 and examples[k].get('metadata',{}).get('component',{}).get('cpe')]
key=max(candidates,key=lambda k:len(groups[k]));pair=groups[key][:2];wanted={x['id'] for x in pair};labels={}
for line in (ROOT/'benchmark/cve_population_precision_v1/labels.jsonl').open(encoding='utf-8'):
 row=json.loads(line)
 if row['id'] in wanted:labels[row['id']]={k:row.get(k) for k in ['source_condition_id','source_input_id','own_cve_truth']}
assert len({v['source_condition_id'] for v in labels.values()})==1
assert len({v['source_input_id'] for v in labels.values()})==1
component=examples[key]['components'][0]
report=dict(identical_SBOM_input_hash=key,number_of_CVE_rows_sharing_this_SBOM=len(groups[key]),
 two_actual_input_rows=[dict(**r,**labels[r['id']]) for r in pair],
 component=component,CPE=examples[key]['metadata']['component']['cpe'],
 source_input_reused=True,SBOM_body_identical=True,full_SBOM=examples[key])
out=ROOT/'results/h200_full_population_20261116_130409/mapping_count_audit/duplicate_SBOM_example.json'
out.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps({k:v for k,v in report.items() if k!='full_SBOM'},ensure_ascii=True))
