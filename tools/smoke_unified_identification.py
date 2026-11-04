"""Exercise real saved adapters through the default API; no accuracy claim."""

from sbom_paths import public_sbom_file
from pathlib import Path
import argparse,json,time,sys,hashlib
import requests
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.training_io import atomic_json


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',default='results/unified_identification_smoke');args=ap.parse_args()
    folder=ROOT/args.output;folder.mkdir(exist_ok=True)
    state={'phase':'starting','started_at':time.time(),'external_model_api_calls':0,
           'independent_accuracy_evaluation':False,'all_fixture_facts_are_simulated':True,'jobs':[]}
    def save():atomic_json(folder/'status.json',state)
    original=public_sbom_file('icsa-26-274-04_SBOM-CVE.json')
    fixture={'bomFormat':'CycloneDX','specVersion':'1.7','version':1,
        'properties':[{'name':'dataset:synthetic-inventory','value':'true'}],
        'metadata':{'component':{'name':'Simulated integration fixture, not an observed asset','type':'application'}},
        'components':[
            {'bom-ref':'curl','name':'curl','manufacturer':{'name':'Haxx'},'type':'library','version':'v7.88.1-vendor4'},
            {'bom-ref':'ssl','name':'OpenSSL','manufacturer':{'name':'OpenSSL'},'type':'library','version':'NOASSERTION'},
            {'bom-ref':'unknown','name':'Invented integration product','manufacturer':{'name':'FixtureVendor'},'type':'library','version':'NOASSERTION'}]}
    try:
        save()
        for name,bom in [('fixture',fixture),('user_sbom',json.loads(original.read_text(encoding='utf-8')))]:
            state.update(phase='running_'+name);save()
            r=requests.post('http://127.0.0.1:8100/api/cve-match/jobs',json={'sbom':bom,'lookup_mode':'local'},timeout=30)
            r.raise_for_status();jid=r.json()['id'];state['jobs'].append({'name':name,'id':jid});save()
            for _ in range(900):
                r=requests.get('http://127.0.0.1:8100/api/cve-match/jobs/'+jid,timeout=30);r.raise_for_status();job=r.json()
                if job['status'] in {'completed','failed'}:break
                state['progress']=job.get('progress');save();time.sleep(1)
            if job['status']!='completed':raise RuntimeError(str(job)[:1000])
            atomic_json(folder/(name+'.json'),job)
            result=job['result'];stages=[c[k]['agent'] for c in result['components'] for k in ('l2','l3','l4')]
            checks={'unified_default':job['agent_mode']=='unified' and result['architecture']=='unified-identification-v1',
                'all_model_calls_tuned':all(a.get('mode')=='tuned' for a in stages),
                'all_accepted_identities_require_agreement':all(c['validation'].get('model_confirmation')
                    for c in result['components'] if c['validation']['status']=='validated'),
                'synthetic_versions_remain_unconfirmed':all(c['l3']['normalized'] is None for c in result['components']) if name=='fixture' else None,
                'model_stage_errors':result['summary']['model_stage_errors'],
                'accepted_identities':result['summary']['validated'],
                'unique_cve_candidates':result['summary']['unique_cves'],
                'completed_model_chains':sum(c['pipeline_complete'] for c in result['components']),
                'model_calls':len(stages)}
            if name=='fixture':
                checks['unknown_product_not_accepted']=result['components'][2]['validation']['status']=='unresolved'
                l3=result['components'][0]['l3'];p=l3['agent'].get('prediction') or {}
                checks['revision_preserved_or_explicitly_deferred']=(p=={'normalized':'7.88.1-vendor4','status':'present'}
                    or (p.get('status')=='unresolved' and l3['normalized'] is None)
                    or (not l3['agent']['guard_accepted'] and l3['agent']['status'] in {'rejected','unavailable'}))
            state['jobs'][-1]['checks']=checks;save()
        state.update(phase='complete',input_sha256=hashlib.sha256(original.read_bytes()).hexdigest())
    except Exception as exc:state.update(phase='failed',error=str(exc))
    state['elapsed_seconds']=round(time.time()-state['started_at'],1);save();print(json.dumps(state,indent=2))


if __name__=='__main__':main()
