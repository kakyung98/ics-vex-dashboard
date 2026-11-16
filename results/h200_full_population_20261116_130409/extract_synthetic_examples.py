from pathlib import Path
import json,sqlite3
root=Path(__file__).resolve().parents[2]
db=sqlite3.connect((root/'data/item3_spelling_noise_v10/dataset.sqlite3').as_uri()+'?mode=ro',uri=True)
examples=[]
for scenario,identity in db.execute("select scenario,min(id) from cases where scenario!='control' group by scenario").fetchall():
    condition,text=db.execute('select condition_id,sbom from cases where id=?',(identity,)).fetchone()
    before=json.loads(db.execute("select sbom from cases where condition_id=? and scenario='control' limit 1",(condition,)).fetchone()[0])
    after=json.loads(text)
    a,b=before['components'][0],after['components'][0]
    examples.append(dict(scenario=scenario,changed_fields={k:[a.get(k),b.get(k)] for k in a.keys()|b.keys() if a.get(k)!=b.get(k)},
        cpe_before=before['metadata']['component'].get('cpe'),cpe_after=after['metadata']['component'].get('cpe')))
db.close()
out=Path(__file__).with_name('synthetic_mutation_examples.json')
out.write_text(json.dumps(examples,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(examples,ensure_ascii=True))
