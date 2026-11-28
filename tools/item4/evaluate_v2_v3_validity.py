"""Reproducible source audit, not independent expert-labelled accuracy.

Uses the user's existing authenticated H200 endpoint without changing the web
model. Keep model outputs and errors, including cases that fail validation.
"""
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
import argparse
from copy import deepcopy
from datetime import datetime,timezone
import hashlib
import json
import requests
import time
from src.item4.analysis import exploitation_prerequisites as V2
from src.item4.analysis import asset_operating_question_generation as V3
from src.item4.assets import asset_observations as A
from src.item4.workflow import source_analysis_jobs as Q
from src.item4.models.nemotron_inference_provider import MODEL,REVISION,SERVED_MODEL

REAL=[('CVE-2017-16743','A0015'),('CVE-2020-15782','A0003'),
      ('CVE-2019-10915','A0001'),('CVE-2021-22681','A0003'),
      ('CVE-2016-5743','A0002'),('CVE-2018-13806','A0001'),
      ('CVE-2019-10924','A0001'),('CVE-2015-1798','A0010')]
CONTROLS=[
 ('and','Exploitation requires FTP enabled and the device running in maintenance mode.'),
 ('or','Exploitation requires either FTP enabled or SSH enabled.'),
 ('not','Exploitation is possible only when FTP is disabled.'),
 ('defect','The HTTP server fails to validate input, allowing remote code execution.'),
 ('remediation','The HTTP server has an input validation flaw. Administrators should disable FTP as a mitigation.')]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True)
    p.add_argument('--backend',choices=['nemotron','local','local-base'],default='nemotron')
    p.add_argument('--reference-labels',help='Frozen assistant-reference JSONL; only source records enter model inputs')
    p.add_argument('--include-synthetic-references',action='store_true')
    p.add_argument('--v3-reference-output',help='After evaluation, run isolated V3 in the same local model process')
    p.add_argument('--only',help='Comma-separated case IDs for an explicitly limited regression run')
    p.add_argument('--run-llm',action='store_true');args=p.parse_args()
    out=Path(args.output);out.mkdir(parents=True,exist_ok=True)
    cases=[]
    for cve,aid in REAL:
        packet=Q.description_packet(cve)
        if not packet.get('sources'):raise ValueError('Missing source '+cve)
        cases.append(dict(id=cve,kind='real_description',asset_type_id=aid,record=packet))
    for i,(name,text) in enumerate(CONTROLS):
        cve='CVE-2099-'+str(91000+i)
        cases.append(dict(id=name,kind='synthetic_boundary',asset_type_id='A0003',record=dict(cve=cve,
            products=[],sources=[dict(id='control:'+name,text=text,text_sha256=hashlib.sha256(text.encode()).hexdigest(),
                product_keys=[],scope_binding='unresolved',url='https://example.invalid/control/'+name)])))
    if args.reference_labels:
        references=[json.loads(l) for l in Path(args.reference_labels).read_text(encoding='utf-8').splitlines() if l.strip()]
        cases=[dict(id=r['cve'] if not r['synthetic'] else r['id'],kind='synthetic_boundary' if r['synthetic'] else 'real_description',
            asset_type_id=None,record=r['record'],reference_id=r['id']) for r in references if not r['synthetic'] or args.include_synthetic_references]
    if args.only:
        selected=set(args.only.split(','));cases=[c for c in cases if c['id'] in selected]
        if {c['id'] for c in cases}!=selected:raise ValueError('Unknown case ID')
    manifest=dict(version='item4-v2-v3-validity/1',created_at=datetime.now(timezone.utc).isoformat(),
        operator_policy=V2.OP.POLICY,
        backend=args.backend,review_method='assistant_source_audit_not_independent_human',cases=cases,
        limitations=['Purposive small sample, not population accuracy.','Asset types supplied as evaluation context, not V1 accuracy.',
            'H200 Nemotron base differs from deployed Qwen base / V2 adapter. No deployment-model accuracy claim.',
            'No independently labelled gold or verified field exploitability. Pretraining overlap unknown.'],
        prompts=dict(v2=V2.digest(V2.SYSTEM),v3=V3.digest(V3.SYSTEM)))
    if args.backend.startswith('local'):
        manifest['limitations'][2]='Measured with the deployed Qwen V2 adapter and V3 base; development sample, not independent expert accuracy.'
        from src.item4.models.review_adapter_config import base_model_evaluation
        from contextlib import nullcontext
        with base_model_evaluation() if args.backend=='local-base' else nullcontext():
            manifest['model_identities']={role:V2.L.identity(role) for role in ['exploitation-prerequisites','item4-questions']}
        if args.backend=='local-base':manifest['limitations'][2]='Explicit Qwen base-model ablation. This run does not silently alter deployed adapter selection.'
    previous=out/'manifest.json'
    if previous.exists():
        old=json.loads(previous.read_text(encoding='utf-8'))
        for key in ['prompts','operator_policy','cases','model_identities']:
            if old.get(key)!=manifest.get(key):raise ValueError('Refuse to mix cached runs with changed '+key+'; choose a new output directory')
    (out/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    if not args.run_llm:print('Plan saved; no model calls');return
    if args.backend=='nemotron':
        token=Path('C:/Users/user/AppData/Local/ICS-VEX/runtime/item4_moe_h200.auth').read_text().strip()
        session=requests.Session();session.trust_env=False;session.headers['Authorization']='Bearer '+token
        response=session.get('http://127.0.0.1:18128/v1/models',timeout=10);response.raise_for_status()
        if SERVED_MODEL not in {m['id'] for m in response.json()['data']}:raise ValueError('Unexpected served model')
    def evaluate_case(case):
        file=out/(case['id']+'.json')
        if file.exists():
            return json.loads(file.read_text(encoding='utf-8'))
        trace=[]
        def runner(system,packet,*,role):
            if args.backend.startswith('local'):
                print(case['id'],role,'generating',flush=True)
                started=time.monotonic()
                try:
                    with base_model_evaluation() if args.backend=='local-base' else nullcontext():
                        response=V2.L.generate(system,packet,role=role)
                except Exception as exc:
                    trace.append(dict(role=role,input_sha256=V3.digest([system,packet]),error=str(exc),raw=getattr(exc,'raw_output',None)))
                    raise
                trace.append(dict(role=role,input_sha256=V3.digest([system,packet]),elapsed_seconds=time.monotonic()-started,response=response))
                print(case['id'],role,'completed in',round(time.monotonic()-started,1),'seconds',flush=True)
                return response
            # JSON mode avoids unsupported decoder-schema keywords; the full
            # original schema is supplied and validated after generation.
            body=dict(model=SERVED_MODEL,temperature=0,max_tokens=4096,
                chat_template_kwargs={'enable_thinking':False},
                messages=[dict(role='system',content=system),dict(role='user',content=json.dumps(packet,ensure_ascii=False))],
                response_format=dict(type='json_object'))
            r=session.post('http://127.0.0.1:18128/v1/chat/completions',json=body,timeout=(10,90))
            if not r.ok:raise ValueError('Inference HTTP '+str(r.status_code)+': '+r.text[:350])
            raw=r.json();trace.append(dict(role=role,input_sha256=V3.digest([system,packet]),response=raw))
            choice=raw['choices'][0]
            if choice.get('finish_reason')!='stop':raise ValueError('Incomplete model output')
            return dict(prediction=json.loads(choice['message']['content']),raw=choice['message']['content'],
                model=dict(provider='nemotron_vllm_nvfp4_h200',model=MODEL,revision=REVISION,adapter=None),
                llm_used=True,generation=dict(usage=raw.get('usage'),temperature=0,max_tokens=4096))
        row=dict(id=case['id'],kind=case['kind'],source_sha256=V2.digest(case['record']))
        try:
            artifact=V2.extract(case['record'],runner=runner);row.update(v2_status='validated',v2=artifact)
            bom=dict(bomFormat='CycloneDX',specVersion='1.6',version=1,
                metadata=dict(component={'bom-ref':'asset','type':'device','name':'Evaluation asset'}),
                vulnerabilities=[dict(id=case['record']['cve'],affects=[dict(ref='asset')])])
            components,declared=Q.inventory(bom)
            job=dict(components=[dict(ref='asset',name='Evaluation asset')],representative=dict(ref='asset'),
                declared_cves=declared,asset_classification=dict(status='classified' if case['asset_type_id'] else 'unresolved',asset_type_id=case['asset_type_id'],provisional=True),
                conditions=[dict(cve=case['record']['cve'],status='extracted',source_kind='CVE description',
                    source_policy='cve-description-special/1',sources=case['record']['sources'],prerequisite=artifact,cvss_assessments=[])])
            # Isolate V3 from CVSS availability. All admitted V2 atoms are special
            # here; production retains its deterministic common/special split.
            generated=V3.run_job(job,runner=runner)
            row.update(v3=generated,v3_status='validated' if all(g['status']!='failed' for g in generated.values()) else 'failed')
        except Exception as exc:row.update(v2_status=row.get('v2_status','failed'),error=type(exc).__name__+': '+str(exc))
        row['trace']=trace
        file.write_text(json.dumps(row,ensure_ascii=False,indent=2),encoding='utf-8')
        print(case['id'],row['v2_status'],row.get('v3_status','not_run'),flush=True)
        return row
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=1 if args.backend.startswith('local') else 4) as pool:rows=list(pool.map(evaluate_case,cases))
    summary=dict(version=manifest['version'],manifest_sha256=V3.digest(manifest),
        measured_model=(manifest['model_identities'] if args.backend.startswith('local') else dict(model=MODEL,revision=REVISION,adapter=None)),deployed_model_evaluated=args.backend=='local',
        real_cases=sum(c['kind']=='real_description' for c in cases),synthetic_cases=sum(c['kind']=='synthetic_boundary' for c in cases),llm_calls=sum(len(r['trace']) for r in rows),
        v2_valid=sum(r['v2_status']=='validated' for r in rows),
        v3_valid=sum(r.get('v3_status')=='validated' for r in rows),
        v3_generated_cases=sum(any(g.get('status')=='generated' for g in r.get('v3',{}).values()) for r in rows),
        v3_no_special_cases=sum(bool(r.get('v3')) and all(g.get('status')=='no_special_conditions' for g in r['v3'].values()) for r in rows),
        scope='Structural admission counts only; semantic source audit is separate.',limitations=manifest['limitations'])
    if args.reference_labels:
        from src.item4.evaluation.assistant_reference_scoring import score
        reference_rows=[dict(r,reference_id=c['reference_id']) for r,c in zip(rows,cases)]
        agreement=score(reference_rows,[r for r in references if r['id'] in {c['reference_id'] for c in cases}])
        (out/'reference-agreement.json').write_text(json.dumps(agreement,ensure_ascii=False,indent=2),encoding='utf-8')
        summary['assistant_reference_agreement']=agreement['counts']
    (out/'report.json').write_text(json.dumps(summary,indent=2),encoding='utf-8');print(json.dumps(summary),flush=True)
    if args.v3_reference_output:
        if not args.backend.startswith('local'):raise ValueError('Shared post-run V3 is local only')
        from tools.item4.evaluate_v3_question_presentation import run
        run(args.v3_reference_output,backend='local')


if __name__=='__main__':main()
