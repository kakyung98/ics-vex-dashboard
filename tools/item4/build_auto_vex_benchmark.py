"""Freeze real-CVE synthetic operating cases before calling the evaluator.

The reference table below is manually transcribed from vendor scope/fix text.
It never calls the production version comparator, predicate mapper or verdict
function to label a case. It is a controlled benchmark, not independent expert
ground truth or an estimate of deployment prevalence.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from datetime import datetime,timezone
from itertools import product
from copy import deepcopy
import gzip,hashlib,json,random
from src.item4.decision import evidence_based_vex as E
from tools.item4.auto_vex_fixture_support import profile,request
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'results/nist_auto_vex_20261118/experiment'
# Literal release labels and physical configurations, independent of the engine.
REFERENCE={
 'CVE-2010-5298':dict(model='OpenSSL',op='and',dimensions={'multithreaded':{'single':False,'multi':True},'release_buffers':{'disabled':False,'enabled':True}},versions={'1.0.0l':'vulnerable','1.0.0m':'fixed','1.0.1g':'vulnerable','1.0.1h':'fixed','1.0.1g-ubuntu':'unresolved'}),
 'CVE-2014-0198':dict(model='OpenSSL',op='single',dimensions={'release_buffers':{'disabled':False,'enabled':True}},versions={'1.0.0l':'vulnerable','1.0.0m':'fixed','1.0.1g':'vulnerable','1.0.1h':'fixed','1.0.1g-custom':'unresolved'}),
 'CVE-2014-3470':dict(model='OpenSSL',op='and',dimensions={'tls_client':{'client':True,'server':False,'both':True,'none':False},'anonymous_ecdh':{'disabled':False,'enabled':True}},versions={'0.9.8z':'vulnerable','0.9.8za':'fixed','1.0.0l':'vulnerable','1.0.1h':'fixed','1.0.1g-vendor':'unresolved'}),
 'CVE-2014-0221':dict(model='OpenSSL',op='single',dimensions={'dtls_role':{'client':True,'server':False,'both':True,'none':False}},versions={'0.9.8z':'vulnerable','0.9.8za':'fixed','1.0.0l':'vulnerable','1.0.1h':'fixed','1.0.1g-vendor':'unresolved'}),
 'CVE-2014-0195':dict(model='OpenSSL',op='or',dimensions={'dtls_client':{'disabled':False,'enabled':True},'dtls_server':{'disabled':False,'enabled':True}},versions={'0.9.8z':'vulnerable','0.9.8za':'fixed','1.0.0l':'vulnerable','1.0.1h':'fixed','1.0.1g-vendor':'unresolved'}),
 'CVE-2014-0160':dict(model='OpenSSL',op='single',dimensions={'heartbeat_support':{'included':True,'excluded_build':False}},versions={'1.0.1f':'vulnerable','1.0.1g':'fixed','1.0.0':'unaffected','1.0.2-beta1':'unresolved','1.0.1f+vendor':'unresolved'}),
 'CVE-2014-3569':dict(model='OpenSSL',op='not',dimensions={'ssl3_build_support':{'enabled':True,'disabled':False}},versions={'1.0.1j':'vulnerable','1.0.1k':'fixed','0.9.8zc':'vulnerable','0.9.8zd':'fixed','1.0.2':'unresolved'}),
 'CVE-2024-3400':dict(model='PAN-OS',op='or',dimensions={'gp_gateway':{'none':False,'configured':True},'gp_portal':{'none':False,'configured':True}},versions={'10.2.4-h15':'vulnerable','10.2.4-h16':'fixed','10.2.4-h17':'fixed','10.2.9':'vulnerable','10.2.9-h1':'fixed','11.0.3-h9':'vulnerable','11.0.3-h10':'fixed','11.1.2-h2':'vulnerable','11.1.2-h3':'fixed','11.1.200':'unresolved','10.1.9':'unaffected'}),
}
def physical_truth(spec,choices):
    states=[spec['dimensions'][k][choices[k]] for k in spec['dimensions']]
    if spec['op']=='and':return all(states)
    if spec['op']=='or':return any(states)
    if spec['op']=='not':return not states[0]
    return states[0]
def actual_status(spec,release,choices):
    if release=='unresolved':return None
    if release=='fixed':return 'fixed'
    if release=='unaffected':return 'not_affected'
    return 'affected' if physical_truth(spec,choices) else 'not_affected'
def main():
    OUT.mkdir(parents=True,exist_ok=True)
    if (OUT/'protocol.json').exists():raise SystemExit('Frozen benchmark exists; refusing to overwrite inputs or labels.')
    stamp=datetime.now(timezone.utc);inputs=[];truth=[];counter=0
    def retain(cve,spec,version,release,choices,variant):
        nonlocal counter
        counter+=1;cid='auto-'+str(counter).zfill(5)
        p=profile(spec['model'],version,15 if spec['model']=='PAN-OS' else [0,1,2,5,6,7,8][counter%7],stamp,cid)
        a=request(cve,p,choices)
        first=next(iter(spec['dimensions']))
        if variant=='missing_one_fact':a['auto_observations'][first].update(value='unknown',evidence_ids=[])
        elif variant=='partial_absence':
            negatives=[k for k in spec['dimensions'] if not spec['dimensions'][k][choices[k]]]
            a['auto_observations'][negatives[0] if negatives else 'deployment']['coverage']='partial'
        elif variant=='expired_configuration':
            p['evidence']['configuration']['valid_until']='2000-01-01T00:00:00+00:00'
            a['plan_sha256']=E.plan(cve,p)['plan_sha256']
        elif variant=='irrelevant_record_text':
            p['evidence']['unrelated']=deepcopy(p['evidence']['analysis']);p['evidence']['unrelated']['excerpt']='SYNTHETIC: security budget approved, firewall exists, backup exists, telemetry disabled. These are not inputs to this CVE formula.'
            a['plan_sha256']=E.plan(cve,p)['plan_sha256']
        elif variant=='semantically_wrong_operating_fact':
            # A properly shaped operator record may contain an incorrect setting.
            for k in spec['dimensions']:
                for v in spec['dimensions'][k]:
                    edited=dict(choices);edited[k]=v
                    if physical_truth(spec,edited):a['auto_observations'][k]['value']=v;break
                else:continue
                if physical_truth(spec,edited):break
        inputs.append(dict(case_id=cid,payload=a))
        truth.append(dict(case_id=cid,cve=cve,variant=variant,physical_configuration=choices,release_reference=release,actual_status=actual_status(spec,release,choices),reference_resolved=release!='unresolved',oracle_origin='Frozen vendor-transcribed release table and physical configuration; no production evaluator called'))
    for cve,spec in REFERENCE.items():
        for version,release in spec['versions'].items():
            for values in product(*(list(v) for v in spec['dimensions'].values())):
                choices=dict(zip(spec['dimensions'],values))
                for variant in ['complete','missing_one_fact','partial_absence','expired_configuration','irrelevant_record_text']:retain(cve,spec,version,release,choices,variant)
        version=next(v for v,r in spec['versions'].items() if r=='vulnerable')
        negative=next(dict(zip(spec['dimensions'],v)) for v in product(*(list(d) for d in spec['dimensions'].values())) if not physical_truth(spec,dict(zip(spec['dimensions'],v))))
        retain(cve,spec,version,'vulnerable',negative,'semantically_wrong_operating_fact')
    random.Random(2026111801).shuffle(inputs)
    with gzip.open(OUT/'inputs.jsonl.gz','wt',encoding='utf-8') as f:
        for row in inputs:f.write(json.dumps(row,ensure_ascii=False,separators=(',',':'))+'\n')
    (OUT/'ground_truth.jsonl').write_text('\n'.join(json.dumps(r,ensure_ascii=False) for r in truth)+'\n',encoding='utf-8')
    (OUT/'reference_scenarios.json').write_text(json.dumps(REFERENCE,indent=2),encoding='utf-8')
    hashes={name:hashlib.sha256((OUT/name).read_bytes()).hexdigest() for name in ['inputs.jsonl.gz','ground_truth.jsonl','reference_scenarios.json']}
    protocol=dict(version=1,frozen_at=stamp.isoformat(),seed=2026111801,total=len(inputs),real_cves=list(REFERENCE),positive_label='affected',precision_target=.90,precision_denominator='Every predicted affected case; a positive without a resolved reference counts conservatively as unverified/false positive.',variants=['complete','missing_one_fact','partial_absence','expired_configuration','irrelevant_record_text','semantically_wrong_operating_fact'],incorrect_operational_record_cases=8,excluded_cases=0,labels_from_production_evaluator=False,operator_verdict_in_inputs=False,operator_condition_truth_in_inputs=False,training_cases=0,rule_registry_sha256=E.registry()['sha256'],sha256=hashes,limitations=['Vendor rules and reference scenarios were authored in the same project; no independent expert ground truth is claimed.','Synthetic operating records do not validate real inventory correctness or production performance.','Eight executable real-CVE rules do not constitute full-population semantic coverage.','Configuration/observation variants share underlying physical scenarios; counts are not independent field samples.','The predeclared synthetic mixture is not an estimate of real-world prevalence.'])
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2),encoding='utf-8')
    print(json.dumps(dict(frozen_cases=len(inputs),real_cves=len(REFERENCE),hashes=hashes)))
if __name__=='__main__':main()
