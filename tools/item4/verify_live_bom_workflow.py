"""Live local-service integration with a real BOM and explicitly unknown observations.

No operating configuration, installed version or actual exploitability is invented.
"""
import argparse
from collections import Counter
from datetime import datetime,timezone
import json
from pathlib import Path
import time
import uuid
import requests


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--bom',required=True)
    parser.add_argument('--output',required=True);parser.add_argument('--request-id');args=parser.parse_args()
    out=Path(args.output);out.mkdir(parents=True,exist_ok=True)
    bom=json.loads(Path(args.bom).read_text(encoding='utf-8-sig'));session=requests.Session();session.trust_env=False
    root='http://127.0.0.1:8100/api/item4/analyses'
    def call(path,payload=None):
        response=session.get(root+path,timeout=(10,60)) if payload is None else session.post(root+path,json=payload,timeout=(10,240))
        response.raise_for_status();return response.json()
    def save(name,value):(out/name).write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
    job=call('/start',dict(bom=bom,request_id=args.request_id or uuid.uuid4().hex));jid=job['id']
    save('started.json',job);print('Started',jid,flush=True)
    deadline=time.monotonic()+1800;previous=None
    while job['status'] in {'queued','running'}:
        if time.monotonic()>deadline:raise TimeoutError('Live workflow did not finish within 30 minutes; retained the job for recovery')
        time.sleep(2);job=call('/jobs/'+jid)
        state=(job['status'],job.get('cves_done'),job.get('question_state'),job.get('questions_done'))
        if state!=previous:print('Progress',state,flush=True);previous=state
    save('source-analysis.json',job)
    if job['status']!='completed':raise RuntimeError(job.get('error','Source workflow failed'))
    token=lambda value:dict(revision=value['revision'],plan_sha256=value['plan_sha256'])
    answers={q['id']:'unknown' for q in job['asset_questions']}
    contexts={q['id']:'unknown' for q in job['context_questions'] if any(o['code']=='unknown' for o in q['options'])}
    job=call('/jobs/'+jid+'/answers',dict(token(job),answers=answers,context_answers=contexts));save('saved-unknown-observations.json',job)
    print('Saved unknown observations; running V4',flush=True)
    job=call('/jobs/'+jid+'/assess',token(job));save('assessed.json',job)
    exports={}
    for kind in ['analysis','review','openvex','cyclonedx']:
        value=call('/jobs/'+jid+'/export/'+kind);save(kind+'.json',value);exports[kind]=kind+'.json'
    statements=json.loads((out/'openvex.json').read_text(encoding='utf-8'))['statements']
    if any(s['status']!='under_investigation' for s in statements):
        raise AssertionError('Unknown operating evidence must not yield affected/not_affected')
    report=dict(version='item4-live-bom-verification/1',finished_at=datetime.now(timezone.utc).isoformat(),
        job_id=jid,bom=str(Path(args.bom).resolve()),cves=job['cves_total'],processed_cves=job['cves_done'],
        asset_type_id=(job.get('asset_classification') or {}).get('asset_type_id'),
        common_questions=len(job.get('common_questions',[])),special_questions=len(job.get('special_questions',[])),
        question_generation_required=job.get('question_generation_required'),
        source_extraction_failures=sum(r.get('status')!='extracted' for r in job['conditions']),
        assessment_state=job['assessment_state'],vex_statements=len(statements),
        attack_graph_generation_states=dict(Counter(r.get('attack_graph',{}).get('generation_status','none') for r in job['assessment']['decisions'])),
        all_vex_under_investigation=True,exports=exports,operating_values='unknown_only',
        actual_exploitability_verified=False,
        scope='Real BOM and live HTTP workflow. Unknown-only observations validate safe propagation and exports, not field exploitability or semantic extraction accuracy.')
    save('report.json',report);print(json.dumps(report),flush=True)


if __name__=='__main__':main()
