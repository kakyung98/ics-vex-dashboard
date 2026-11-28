"""Isolated V3 evaluation with source-audited fixed atoms, not expert gold."""
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
import argparse
import json
from concurrent.futures import ThreadPoolExecutor
import requests
from src.item4.analysis import asset_operating_question_generation as V3
from src.item4.workflow.source_analysis_jobs import description_packet
from src.item4.models.nemotron_inference_provider import MODEL,REVISION,SERVED_MODEL

# References are transparent researcher/assistant-authored presentation inputs.
# They are not independently adjudicated extraction gold and never enter V2.
REFERENCES=[
 ('CVE-2020-15782','A0003',[
  ('Network access to port 102/tcp on the affected device is available','port 102/tcp','network_access','firewall_acl')],'and'),
 ('CVE-2019-10915','A0001',[
  ('Local access to the affected TIA Administrator system is available','TIA Administrator','access_policy','access_control_record')],'and'),
 ('CVE-2018-13806','A0001',[
  ('The assessed attacker has write access to the directory containing the TD project file','TD project directory','access_policy','access_control_record'),
  ('A legitimate user with higher privileges than the attacker opens the TD project','TD project','operating_workflow','operating_procedure')],'and'),
 ('CVE-2019-10924','A0001',[
  ('A valid user opens a manipulated LOGO! Soft Comfort project file','LOGO! Soft Comfort project file','operating_workflow','operating_procedure')],'and'),
 ('and','A0003',[
  ('FTP is enabled','FTP','configuration','configuration_export'),
  ('The device is in maintenance mode','maintenance mode','operating_mode','maintenance_log')],'and'),
 ('or','A0015',[
  ('FTP is enabled','FTP','configuration','configuration_export'),
  ('SSH is enabled','SSH','configuration','configuration_export')],'or'),
 ('not','A0015',[
  ('FTP is enabled','FTP','configuration','configuration_export')],'not')]
TEXT={'and':'Exploitation requires FTP enabled and the device running in maintenance mode.',
      'or':'Exploitation requires either FTP enabled or SSH enabled.',
      'not':'Exploitation is possible only when FTP is disabled.'}


def run(output,backend='nemotron'):
    out=Path(output);out.mkdir(parents=True,exist_ok=True)
    token=Path('C:/Users/user/AppData/Local/ICS-VEX/runtime/item4_moe_h200.auth').read_text().strip() if backend=='nemotron' else None
    def one(reference):
        name,aid,atoms,op=reference
        if name.startswith('CVE-'):sources=description_packet(name)['sources'];cve=name
        else:
            cve='CVE-2099-99999';text=TEXT[name]
            sources=[dict(id='control:'+name,text=text,text_sha256=V3.digest(text),url='https://example.invalid/control/'+name)]
        conditions=[dict(condition='p'+str(i)) for i in range(len(atoms))]
        expression=conditions[0] if len(conditions)==1 else dict(op=op,args=conditions)
        if op=='not':expression=dict(op='not',args=conditions)
        job=dict(conditions=[dict(cve=cve,sources=sources,prerequisite=dict(sha256=V3.digest(atoms),
            draft=dict(scenarios=[dict(id='reference-path',expression=expression)])))],
            representative=dict(ref='asset'),components=[dict(ref='asset',name='Reference asset')],asset_classification=dict(status='classified',asset_type_id=aid,provisional=True))
        case=dict(id='reference:'+name,cve=cve,declared_ref='asset')
        qs=[dict(condition_id='p'+str(i),label=fact,scope_kind=target,
            observation=dict(kind=kind,record_type=record,check='Inspect '+record+' for '+fact),
            source_refs=[dict(source_id=sources[0]['id'],quote=sources[0]['text'])],operational_quote=sources[0]['text'])
            for i,(fact,target,kind,record) in enumerate(atoms)]
        payload=V3.packet(job,case,qs,[])
        trace=[]
        def runner(system,packet,*,role):
            if backend=='local':
                try:response=V3.L.generate(system,packet,role=role)
                except Exception as exc:
                    trace.append(dict(error=str(exc),raw=getattr(exc,'raw_output',None)));raise
                trace.append(response);return response
            r=requests.post('http://127.0.0.1:18128/v1/chat/completions',
                headers={'Authorization':'Bearer '+token},json=dict(model=SERVED_MODEL,temperature=0,max_tokens=1400,
                chat_template_kwargs={'enable_thinking':False},response_format=dict(type='json_object'),
                messages=[dict(role='system',content=system),dict(role='user',content=json.dumps(packet))]),timeout=(10,90))
            r.raise_for_status();raw=r.json();trace.append(raw)
            if raw['choices'][0]['finish_reason']!='stop':raise ValueError('Incomplete output')
            return dict(prediction=json.loads(raw['choices'][0]['message']['content']),raw=raw['choices'][0]['message']['content'],
                llm_used=True,model=dict(model=MODEL,revision=REVISION,adapter=None,provider='nemotron_vllm_nvfp4_h200'),generation=raw.get('usage'))
        row=dict(id=name,kind='real_description_reference' if name.startswith('CVE-') else 'synthetic_boundary',packet=payload,
            review_method='assistant_source_audit_not_independent_human')
        try:row.update(status='validated',artifact=V3.generate(payload,runner))
        except Exception as exc:row.update(status='failed',error=type(exc).__name__+': '+str(exc)[:450])
        row['trace']=trace
        (out/(name+'.json')).write_text(json.dumps(row,ensure_ascii=False,indent=2),encoding='utf-8')
        print(name,row['status'],flush=True);return row
    with ThreadPoolExecutor(max_workers=1 if backend=='local' else 4) as pool:rows=list(pool.map(one,REFERENCES))
    report=dict(version='item4-v3-isolated-validity/1',cases=len(rows),questions=sum(len(r['packet']['atoms']) for r in rows),
        valid_cases=sum(r['status']=='validated' for r in rows),llm_calls=sum(len(r['trace']) for r in rows),
        model=V3.L.identity('item4-questions') if backend=='local' else dict(model=MODEL,revision=REVISION,adapter=None),deployed_model_evaluated=backend=='local',
        review_method='assistant_source_audit_not_independent_human',
        scope='Isolated V3 presentation from fixed source-audited atoms. Does not measure V2 recovery, V1 classification or field exploitability.',
        limitations=['Small purposive sample.','No independent expert gold.','Deployed Qwen V3 base measured.' if backend=='local' else 'Nemotron differs from deployed Qwen models.',
            'Exact fact and Boolean conservation are contract checks; free-text guidance still needs semantic review.'])
    (out/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report),flush=True)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True)
    parser.add_argument('--backend',choices=['nemotron','local'],default='nemotron');args=parser.parse_args()
    run(args.output,args.backend)


if __name__=='__main__':main()
