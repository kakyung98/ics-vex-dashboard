"""Score every frozen test case locally, without changing the frozen oracle."""
from pathlib import Path
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item3.hard_metamorphic import summarize as score3
from src.item4.evaluation.sealed_source_gt import summarize as score4

def main():
    r=ROOT/'results/sealed_recheck_20261127'
    read=lambda p:json.loads(p.read_text(encoding='utf-8'))
    sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    seal=read(r/'freeze.json')
    assert all(sha(ROOT/p)==h for p,h in seal['runtime_files'].items()),'Frozen source changed'
    reports={}
    for task,answer in [('item3','relations.json'),('item4','gold.json')]:
        assert sha(r/task/'inputs.json')==seal['input_sha256'][task]
        assert sha(r/task/answer)==seal['private_answers_sha256'][task]
        inputs=read(r/task/'inputs.json');gold=read(r/task/answer)
        status=read(r/'collected'/task/'status.json')
        assert status['state']=='predictions_complete',status
        rows=[read(p) for p in sorted((r/'collected'/task/'predictions').glob('*.json'))]
        assert {x['id'] for x in rows}=={x['id'] for x in inputs},'Missing or extraneous predictions'
        if task=='item3':report=score3(inputs,rows,gold)
        else:
            byid={g['id']:g for g in gold}
            cases=[dict(c,gold=byid[c['id']]['gold'],challenge=byid[c['id']]['challenge']) for c in inputs]
            report=score4(cases,rows)
        report.update(freeze_sha256=sha(r/'freeze.json'),all_frozen_hashes_verified=True,final_test_tuning=False)
        (r/task/'final_report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
        reports[task]={k:v for k,v in report.items() if k not in ('failures','families')}
    (r/'final_summary.json').write_text(json.dumps(reports,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(reports,ensure_ascii=True))

if __name__=='__main__':main()
