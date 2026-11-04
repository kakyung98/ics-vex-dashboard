"""Summarize actual saved results; never infer completion from training steps alone."""
from datetime import datetime,timezone
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.training_io import read_json,atomic_json


def percent(value):return f'{value*100:.2f}%' if isinstance(value,(int,float)) else 'pending'


def main():
    queue=read_json(ROOT/'results/grounded_role_finetune_v1/queue_status.json')
    source=read_json(ROOT/'results/source_evidence_finetune_v1/status.json')
    tests=read_json(ROOT/'results/item3_identification_v2_run/task_test.json')
    pipeline=read_json(ROOT/'results/item3_identification_v2_run/summary.json')
    roles={r:read_json(ROOT/'results/grounded_role_finetune_v1'/r/'validation_report.json') for r in ['cve-conditions','vex-writer']}
    tasks={t:{m:{k:v for k,v in score.items() if k!='cases'} for m,score in modes.items()} for t,modes in tests.get('tasks',{}).items()}
    result={'generated_at':datetime.now(timezone.utc).isoformat(),'queue_phase':queue.get('phase'),
            'all_jobs_complete':queue.get('phase')=='complete', 'deadline_met':queue.get('deadline_met'),
            'source_validation':{'base':source.get('validation_baseline'),'tuned':source.get('validation_tuned')},
            'task_tests':tasks,'pipeline':{k:v for k,v in pipeline.items() if k in ['item3','fingerprints','elapsed_seconds','scope']},
            'role_validation':{r:{k:v for k,v in report.items() if k in ['baseline','tuned','strata','evaluation_split','test_evaluated','best_checkpoint']} for r,report in roles.items()},
            'condition_grounding_audit':{m:v['counts'] for m,v in read_json(ROOT/'results/grounded_role_finetune_v1/cve-conditions/grounding_audit.json').get('models',{}).items()},
            'limitations':['Role tests here are synthetic/procedural, not real-world CVE or VEX accuracy.',
                           'Condition references are weak labels; expert semantic correctness has not been measured.',
                           'VEX authoring copies an assigned decision; it does not establish that decision.',
                           'Source and grounded-role results are validation results; no held-out role test claim.',
                           'Low grounding scores remain failures; scoring was not relaxed.']}
    dest=ROOT/'results/four_hour_run_20261101';dest.mkdir(exist_ok=True)
    atomic_json(dest/'OUTCOME.json',result)
    lines=['# Training and evaluation outcome','', 'As of: '+result['generated_at'],
           'All jobs complete: '+str(result['all_jobs_complete']), 'Original deadline met: '+str(result['deadline_met']),
           '', '| Task | Split | Base exact agreement | Tuned exact agreement | Tuned decision coverage |',
           '| --- | --- | --- | --- | --- |']
    for task,m in tasks.items():
        lines.append(f"| {task} | test, 1024 | {percent(m['base']['exact_accuracy'])} | {percent(m['tuned']['exact_accuracy'])} | {percent(m['tuned']['coverage'])} |")
    lines+=['','## Source structural facts (synthetic validation, 100 examples)','',
            'Base exact agreement: '+percent((source.get('validation_baseline') or {}).get('exact_accuracy')),
            'Tuned exact agreement: '+percent((source.get('validation_tuned') or {}).get('exact_accuracy'))]
    for role,report in roles.items():
        lines+=['','## '+role+' (validation)','']
        for mode in ['baseline','tuned']:
            m=report.get(mode,{})
            lines.append(mode+': '+', '.join(k+'='+percent(v) for k,v in m.items() if isinstance(v,(float,int)) and not isinstance(v,bool) and k!='examples'))
    audit=result['condition_grounding_audit']
    if audit:
        lines+=['','Literal evidence span support (validation audit; not semantic accuracy): '+
                ', '.join(mode+'='+percent(values.get('literal_span_support_rate')) for mode,values in audit.items()),
                'The tuned condition extractor worsened literal quotation fidelity despite better schema compliance.']
    score=pipeline.get('item3',{})
    lines+=['','## Full candidate identification evaluation','']
    if score:
        for k in ['sut_runs','TP','FP','precision','acceptance_criterion','pass','sut_abstained','labelled_share_pct','unlabelled_predictions','unadjudicable_predictions']:
            lines.append(k+': '+str(score.get(k)))
    else:lines.append('Pending. No complete-pipeline precision claimed.')
    lines+=['','## Interpretation','',*['- '+x for x in result['limitations']]]
    (dest/'OUTCOME.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print('Saved',dest/'OUTCOME.md','all_jobs_complete=',result['all_jobs_complete'])


if __name__=='__main__':main()
