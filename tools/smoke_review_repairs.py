"""Actual backend regression: source IDs, unknown facts, scoped fixed fixture, merged BOM.
All supplied component/version records below are explicitly simulated, never
claimed to be observations of the user's physical device.
"""

from sbom_paths import public_sbom_file
from pathlib import Path
import argparse,json,time,sys,hashlib
import requests
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.training_io import atomic_json

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',default='results/review_repairs_gpu_bounded');ap.add_argument('--reuse-from')
    args=ap.parse_args();folder=ROOT/args.output;folder.mkdir(parents=True,exist_ok=False)
    state={'phase':'starting','started_at':time.time(),'external_model_api_calls':0,'all_added_facts_are_simulated':True}
    def save():atomic_json(folder/'status.json',state)
    def post(path,payload,timeout=1200):
        r=requests.post('http://127.0.0.1:8100'+path,json=payload,timeout=timeout);r.raise_for_status();return r.json()
    save()
    try:
        original=public_sbom_file('icsa-26-274-04_SBOM-CVE.json');bom=json.loads(original.read_text(encoding='utf-8'))
        state['input_sha256']=hashlib.sha256(original.read_bytes()).hexdigest()
        if args.reuse_from:
            from src.review_store import get
            prior=ROOT/args.reuse_from;previous=json.loads((prior/'status.json').read_text(encoding='utf-8'))
            plan=json.loads((prior/'plan.json').read_text(encoding='utf-8'));stored=get('plan',plan['id'])
            if not stored or stored.get('sbom')!=bom:raise RuntimeError('Reused plan expired or belongs to a different SBOM.')
            jid=previous['job_id'];state.update(job_id=jid,reused_questionnaire=True,questionnaire_origin=str(prior))
        else:
            jid=post('/api/cve-match/jobs',{'sbom':bom,'agent_mode':'evidence','lookup_mode':'local'},30)['id']
            while True:
                r=requests.get('http://127.0.0.1:8100/api/cve-match/jobs/'+jid,timeout=30);r.raise_for_status();job=r.json()
                if job['status'] in {'completed','failed'}:break
                time.sleep(1)
            if job['status']!='completed':raise RuntimeError(job)
            state.update(phase='generating_questions',job_id=jid);save()
            plan=post('/api/oc/questions',{'identification_job':jid})
        atomic_json(folder/'plan.json',plan)
        state.update(phase='assessing_unknown_facts',plan_id=plan['id']);save()
        result=post('/api/oc/answers',{'plan_id':plan['id'],'answers':{},'component_facts':{}})
        atomic_json(folder/'unknown_review.json',result);atomic_json(folder/'unknown_sbom.cdx.json',result['sbom_vex'])
        # One actual component occurrence is declared only for this simulated fixture.
        ref=plan['assets'][0]['ref']
        facts={a['ref']:{'present':'no'} for a in plan['assets']}
        facts[ref]={'present':'yes','product_name':'Johnson Controls EasyIO Neo Series EC Controllers',
            'installed_version':'V3.3b64','evidence':'SIMULATED fixture: device record claims EC V3.3b64. Not an observation of a real asset.','attested':True}
        state.update(phase='assessing_simulated_fixed_version',
            unknown_authoring=[s['authoring']['status'] for s in result['statements']],
            unknown_status=[s['status'] for s in result['statements']],
            unknown_pipeline_complete=result['pipeline']['complete_cases']==len(plan['cases']),
            unknown_schema=result.get('sbom_vex_validation'));save()
        result=post('/api/oc/answers',{'plan_id':plan['id'],'answers':{},'component_facts':facts})
        atomic_json(folder/'simulated_fixed_review.json',result);atomic_json(folder/'simulated_fixed_sbom.cdx.json',result['sbom_vex'])
        state.update(phase='complete',generation=[c['generation']['status'] for c in plan['cases']],
            extraction=[c['extraction']['status'] for c in plan['cases']],authoring=[s['authoring']['status'] for s in result['statements']],
            formal_status=[s['status'] for s in result['statements']],schema=result.get('sbom_vex_validation'),
            all_contract_checks_passed=all(c['generation']['status']=='validated' and c['extraction']['status']=='validated' for c in plan['cases'])
                and all(s['authoring']['status']=='validated_draft' for s in result['statements'])
                and all(s=='validated_draft' for s in state['unknown_authoring'])
                and state['unknown_pipeline_complete'] and result['pipeline']['complete_cases']==len(plan['cases'])
                and all(s['status']=='fixed' for s in result['statements'])
                and state['unknown_status']==['under_investigation']*len(plan['cases'])
                and result['sbom_vex_validation']['status']==state['unknown_schema']['status']=='valid')
    except Exception as e:state.update(phase='failed',error=str(e))
    state['elapsed_seconds']=round(time.time()-state['started_at'],1);save();print(json.dumps(state,indent=2))

if __name__=='__main__':main()
