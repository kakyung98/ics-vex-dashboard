"""Seal inputs and score an expanded-corpus run; no tuning on the held-out outputs."""
from pathlib import Path
from collections import Counter
import argparse,hashlib,json,random,sys,tarfile
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item4.evaluation.sealed_source_gt import summarize,judge

DATA=ROOT/'data/item4_synthetic_gt_expanded_v1'
OUT=ROOT/'results/item4_expanded_evaluation_20261127'
SPLITS=('dev','validation','test_candidate','dev_regression')

def read(p):return json.loads(p.read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p,v):
    p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v,ensure_ascii=False,indent=2),encoding='utf-8')

def verify_dataset():
    s=read(DATA/'dataset_freeze.json')
    assert all(sha(DATA/p)==h for p,h in s['file_sha256'].items()),'Dataset changed'
    assert all(sha(ROOT/p)==h for p,h in s['source_sha256'].items()),'Dataset authoring code changed'
    return s

def seal():
    from tools.item4 import extract_source_conditions_for_question_links as S
    verify_dataset()
    if (OUT/'freeze.json').exists():raise FileExistsError('Evaluation already sealed; never overwrite')
    inputs=[];membership={}
    for split in SPLITS:
        for c in read(DATA/split/'inputs.json'):
            assert c['id'] not in membership
            membership[c['id']]=split;inputs.append(c)
    # Fixed interleaving avoids confounding fold with service execution order.
    random.Random(2711202602).shuffle(inputs)
    write(OUT/'item4/inputs.json',inputs);write(OUT/'membership.json',membership)
    files=list((ROOT/'src').rglob('*.py'))+[ROOT/'src/layout.json']
    files += [ROOT/p for p in ['tools/__init__.py','tools/item4/__init__.py','tools/common/run_sealed_recheck.py','tools/item4/extract_source_conditions_for_question_links.py','tools/item4/link_conditions_to_asset_questions.py','tools/item4/compact_json_grammar.py','tools/item4/evaluate_expanded_synthetic_gt.py']]
    files=[p for p in files if p.exists()]
    frozen=dict(protocol='expanded-native-source-evaluation/1',dataset_freeze_sha256=sha(DATA/'dataset_freeze.json'),
        input_sha256={'item4':sha(OUT/'item4/inputs.json')},membership_sha256=sha(OUT/'membership.json'),
        private_gold_sha256={s:sha(DATA/s/'gold.json') for s in SPLITS},
        runtime_files={p.relative_to(ROOT).as_posix():sha(p) for p in files},
        models=dict(item4_model='nvidia/NVIDIA-Nemotron-3.5-Super-VL-120B-A12B-NVFP4',item4_revision='ae1368329b1fc76b71534c5d04b87b35d9cc6e15',item4_prompt_sha256=hashlib.sha256(S.PROMPT.encode()).hexdigest()),
        metrics=['precision','recall','f1','logic_accuracy','evidence_contract_accuracy','requirement_contract_accuracy'],
        gate='Every declared metric strictly greater than 0.90. Headline fold: test_candidate, not pooled dev/validation/regression.',
        policy='No model/prompt/scorer/answer changes after seal. All semantic/schema failures stay in denominator; infrastructure errors are repaired and resumed without answer-based selection.',
        counts=dict(Counter(membership.values())),new_documents=320,total_including_prior_exposed_regression=352,
        limitations=['Strict frozen lexical/evidence oracle may reject semantically valid paraphrases. Scores are contract metrics, not independent expert semantic accuracy.','Ten controlled construction families shared across splits; domain/scenario groups disjoint.','Prior 32 tests are development regression only. New test_candidate is not independently authored or adjudicated.','No absolute claim about real-CVE extraction or pretraining contamination.'],
        excluded_fields=['CVSS axis','self-reported completeness as semantic accuracy'],new_gold_uploaded=False)
    # Write last, exclusively, only after all input preparation has succeeded.
    with (OUT/'freeze.json').open('x',encoding='utf-8') as f:json.dump(frozen,f,ensure_ascii=False,indent=2)
    with tarfile.open(OUT/'inference_bundle.tar.gz','w:gz') as t:
        for p in files:t.add(p,arcname=p.relative_to(ROOT).as_posix())
        t.add(OUT/'freeze.json',arcname='freeze.json');t.add(OUT/'item4/inputs.json',arcname='item4/inputs.json')
    print(json.dumps(dict(counts=frozen['counts'],freeze_sha256=sha(OUT/'freeze.json'),bundle_bytes=(OUT/'inference_bundle.tar.gz').stat().st_size)))

def score():
    verify_dataset();frozen=read(OUT/'freeze.json')
    assert all(sha(ROOT/p)==h for p,h in frozen['runtime_files'].items()),'Frozen evaluation code changed'
    assert sha(OUT/'item4/inputs.json')==frozen['input_sha256']['item4']
    assert sha(OUT/'membership.json')==frozen['membership_sha256']
    assert all(sha(DATA/s/'gold.json')==h for s,h in frozen['private_gold_sha256'].items())
    assert (OUT/'collected/freeze.json').read_bytes()==(OUT/'freeze.json').read_bytes()
    assert read(OUT/'collected/item4/status.json')['state']=='predictions_complete'
    inputs=read(OUT/'item4/inputs.json');membership=read(OUT/'membership.json')
    rows=[read(p) for p in sorted((OUT/'collected/item4/predictions').glob('*.json'))];byid={r['id']:r for r in rows}
    assert len(rows)==len(byid)==len(inputs) and set(byid)=={c['id'] for c in inputs}
    cases=[]
    for s in SPLITS:
        gold={g['id']:g for g in read(DATA/s/'gold.json')}
        for c in inputs:
            if membership[c['id']]==s:cases.append(dict(c,**{k:v for k,v in gold[c['id']].items() if k!='id'},split=s))
    reports={};percase=[]
    for s in [*SPLITS,'new_all']:
        selected=[c for c in cases if c['split']==s or s=='new_all' and c['split']!='dev_regression']
        report=summarize(selected,[byid[c['id']] for c in selected]);reports[s]=report
        write(OUT/'reports'/(s+'.json'),report)
    for c in cases:
        row=byid[c['id']];percase.append(dict(id=c['id'],split=c['split'],challenge=c['challenge'],group_id=c.get('group_id'),domain=c.get('domain'),error=row.get('error'),judgement=judge(c,row.get('prediction'),row.get('valid',False))))
    write(OUT/'per_case_judgements.json',percase)
    raw=[read(p) for p in (OUT/'collected/item4/raw_calls').glob('*.json')];covered=set();keysets=Counter();finishes=Counter()
    for x in raw:
        packet=json.loads(x['request']['messages'][-1]['content'])
        for c in packet['cases'].values():
            covered.add(c['case_id']);keysets[tuple(sorted(c))]+=1
            assert set(c)=={'case_id','cve','passages','cvss_version','scopes'}
        finishes[x['response']['choices'][0]['finish_reason']]+=1
    assert covered==set(byid),'Raw request audit incomplete'
    errors=Counter(r.get('error') for r in rows if r.get('error'))
    write(OUT/'integrity_report.json',dict(all_frozen_hashes_verified=True,freeze_sha256=sha(OUT/'freeze.json'),raw_requests=len(raw),case_ids_covered=len(covered),wire_case_keys=[dict(keys=list(k),count=v) for k,v in keysets.items()],raw_finish_reasons=dict(finishes),errors=dict(errors),new_gold_in_requests=False,new_gold_uploaded=False,final_test_tuning=False))
    summary=dict(model=frozen['models'],freeze_sha256=sha(OUT/'freeze.json'),headline_fold='test_candidate',folds={s:{k:v for k,v in r.items() if k not in ('failures','families')} for s,r in reports.items()},limitations=frozen['limitations'])
    write(OUT/'final_summary.json',summary);print(json.dumps(summary,ensure_ascii=True))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=['seal','score']);a=p.parse_args();globals()[a.action]()
