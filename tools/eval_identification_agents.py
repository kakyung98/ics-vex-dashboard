"""Summarize task reports and optionally compare the complete frozen candidate pipeline."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from evaluation.identification_metrics import score_cve_pairs


def evaluate_tasks(path):
    from src.identification_agents import get_agents
    from evaluation.identification_metrics import score
    rows=[json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]
    ids=[r['id'] for r in rows]
    if len(ids)!=len(set(ids)): raise ValueError('Duplicate evaluation IDs')
    if any(r['task'] not in {'L2','L3','L4'} for r in rows):raise ValueError('Unexpected task')
    result={'dataset_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'tasks':{}}
    for task in ['L2','L3','L4']:
        examples=[r for r in rows if r['task']==task]
        result['tasks'][task]={}
        for mode in ['base','tuned']:
            provider=get_agents(mode)
            outputs=[provider(task,r['input']) for r in examples]
            result['tasks'][task][mode]={'scores':score(task,examples,[o['prediction'] for o in outputs]),
                                        'raw_outputs':outputs}
            print(task,mode,'complete',flush=True)
    return result


def build_pipeline_fixture():
    """Small boundary regression fixture derived from local NVD data; not certification."""
    from ics_agent_matcher_full.ics_agent_matcher.matcher import CPE_API,CVE_API
    index_path=ROOT/'data/cpe_index.json'
    index=json.loads(index_path.read_text(encoding='utf-8'))['by_product']
    cases=[]; fixtures={}; gold={}
    specifications=[('curl','CVE-2011-3389',[('7.10.6',True),('7.23.1',True),('7.23.2',False)]),
                    ('openssh','CVE-2003-0190',[('3.6.0',True),('3.6.1',False)])]
    for product,cve,versions in specifications:
        candidates=[r for r in index[product] if r['cve']==cve]
        row=next(r for r in candidates if not r['version'])
        criteria=f"cpe:2.3:a:{row['vendor']}:{product}:*:*:*:*:*:*:*:*"
        match={'criteria':criteria,'vulnerable':True}
        fields={'startIncl':'versionStartIncluding','startExcl':'versionStartExcluding',
                'endIncl':'versionEndIncluding','endExcl':'versionEndExcluding'}
        for key,field in fields.items():
            if row.get(key): match[field]=row[key]
        # Fail if the underlying authority snapshot changed; the hand-checked labels
        # below must not silently follow a changed SUT comparator.
        expected={'curl':{'versionStartIncluding':'7.10.6','versionEndIncluding':'7.23.1'},
                  'openssh':{'versionEndExcluding':'3.6.1'}}[product]
        if {k:v for k,v in match.items() if k.startswith('version')}!=expected:
            raise ValueError('NVD snapshot changed; review boundary labels')
        fixtures[json.dumps([CPE_API,{'keywordSearch':product,'resultsPerPage':100}],sort_keys=True)]={
            'products':[{'cpe':{'cpeName':criteria}}]}
        for version,label in versions:
            cid=f'{product}-{version}'
            component={'bom-ref':cid,'name':product,'version':version}
            cases.append({'id':cid,'component':component})
            gold[(cid,cve)]=label
            cpe=f"cpe:2.3:a:{row['vendor']}:{product}:{version}:*:*:*:*:*:*:*"
            fixtures[json.dumps([CVE_API,{'cpeName':cpe,'resultsPerPage':2000}],sort_keys=True)]={
                'vulnerabilities':[{'cve':{'id':cve,'configurations':[{'nodes':[{'operator':'OR','cpeMatch':[match]}]}]}}]}
    return cases,fixtures,gold,hashlib.sha256(index_path.read_bytes()).hexdigest()


def compare_pipeline():
    from ics_agent_matcher_full.ics_agent_matcher.matcher import NVD,run,norm,ALIAS
    from src.identification_agents import get_agents
    from src.identification_tasks import identity_gold,version_gold
    cases,fixtures,gold,digest=build_pipeline_fixture()
    cache={}
    def provider(mode):
        actual=get_agents(mode)
        def call(task,payload):
            key=json.dumps([mode,task,payload],sort_keys=True)
            if key not in cache: cache[key]=actual(task,payload)
            return dict(cache[key])
        return call
    tuned=provider('tuned'); base=provider('base')
    def mixed(selected):
        def call(task,payload):
            if task in selected:return tuned(task,payload)
            if task=='L2':
                value=norm(payload.get('name','')); value=ALIAS.get(value,value)
                prediction={'normalized':value or None,'status':'resolved' if value else 'unresolved'}
            elif task=='L3':prediction=version_gold(payload.get('raw_version'))
            else:prediction=identity_gold(payload)
            return {'prediction':prediction,'mode':'rules'}
        return call
    outputs={}
    for name,agents in [('rules',None),('base',base),('L2_only',mixed({'L2'})),
                        ('L3_only',mixed({'L3'})),('L4_only',mixed({'L4'})),('tuned',tuned)]:
        result=run({'bomFormat':'CycloneDX','components':[c['component'] for c in cases]},
                   NVD(offline=True,fixtures=fixtures),agents=agents)
        predictions=set(); resolved=0; errors=0; unknown=0
        for row in result['components']:
            cid=row['component']['id']
            resolved+=row.get('validation',{}).get('status')=='validated'
            errors+='error' in row
            for record in row.get('cves',[]):
                if record['match_status']=='match': predictions.add((cid,record['cve_id']))
                if record['match_status']=='unknown':unknown+=1
        outputs[name]={**score_cve_pairs(gold,predictions),'components':len(cases),
                       'identity_coverage':resolved/len(cases),'errors':errors,
                       'unknown_candidate_records':unknown,'results':result}
        print(name,{k:v for k,v in outputs[name].items() if k!='results'},flush=True)
    return {'scope':'5-case NVD-derived boundary regression only; not production precision',
            'index_sha256':digest,'gold':[{'component':c,'cve':v,'label':label} for (c,v),label in gold.items()],
            'variants':outputs}


def main():
    p=argparse.ArgumentParser(); p.add_argument('--pipeline',action='store_true')
    p.add_argument('--task-data',type=Path,help='Independently run base/tuned agents on an existing labelled JSONL')
    p.add_argument('--reports',type=Path,default=ROOT/'results/identification_agents')
    p.add_argument('--out',type=Path)
    a=p.parse_args(); summary={'tasks':{},'missing':[]}
    if a.out is None:a.out=a.reports/'summary.json'
    for task in ['L2','L3','L4']:
        path=a.reports/f'{task}.json'
        if not path.is_file():summary['missing'].append(task);continue
        report=json.loads(path.read_text(encoding='utf-8'))
        summary['tasks'][task]={k:report[k] for k in ('train_examples','val_examples','test_examples','steps','scope')}
        summary['tasks'][task]['evaluation_split']=report.get('evaluation_split','test')
        for variant in ['baseline','tuned']:
            summary['tasks'][task][variant]={k:v for k,v in report[variant].items() if k!='cases'}
    if a.pipeline:
        if summary['missing']:raise RuntimeError('Training/evaluation incomplete: '+','.join(summary['missing']))
        summary['pipeline']=compare_pipeline()
    if a.task_data:summary['standalone_evaluation']=evaluate_tasks(a.task_data)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(summary,indent=2,ensure_ascii=False),encoding='utf-8')
    def pct(value):return '-' if value is None else f'{100*value:.1f}%'
    lines=['# L2/L3/L4 1차 파인튜닝 평가','',
        'NVD 파생·절차적 데이터의 시험 결과입니다. 실제 SBOM에 대한 공인시험 성능이 아닙니다.','',
        '| 에이전트 | 기본 모델 정답률 | 튜닝 정답률 | 튜닝 판정 Precision | 판정률 | 유보율 | JSON 오류 |',
        '|---|---:|---:|---:|---:|---:|---:|']
    for task,record in summary['tasks'].items():
        base,tuned=record['baseline'],record['tuned']
        lines.append(f"| {task} | {pct(base['exact_accuracy'])} | {pct(tuned['exact_accuracy'])} | {pct(tuned['decision_precision'])} | {pct(tuned['coverage'])} | {pct(tuned['abstention_rate'])} | {tuned['invalid_outputs']} |")
    if summary['missing']:lines+=['','미완료: '+', '.join(summary['missing'])]
    if 'pipeline' in summary:
        lines+=['','## 연결 회귀 평가','',summary['pipeline']['scope'],'',
                '| 구성 | TP | FP | FN | Precision | 라벨 양성 Recall | 식별 판정률 |',
                '|---|---:|---:|---:|---:|---:|---:|']
        for name,record in summary['pipeline']['variants'].items():
            lines.append(f"| {name} | {record['TP']} | {record['FP']} | {record['FN']} | {pct(record['precision'])} | {pct(record['recall_on_labelled_positives'])} | {pct(record['identity_coverage'])} |")
    a.out.with_suffix('.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print('Report:',a.out,'missing:',summary['missing'])


if __name__=='__main__':main()
