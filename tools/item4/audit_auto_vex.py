
if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from collections import Counter
import gzip,json
from src.item4.decision import evidence_based_vex as E
from src.item4.decision import scoped_vex_review as A
from tools.item4.auto_vex_fixture_support import profile
OUT=Path('D:/ICS-VEX/results/nist_auto_vex_20261118')
def main():
    ids=[r['cve'] for r in A.catalogue()['cves']];p=profile();rows=[];counts=Counter()
    for i,cve in enumerate(ids):
        try:
            target=E.registry()['rules'].get(cve)
            scope=profile(target['product'],'10.2.4-h15' if target['product']=='PAN-OS' else '1.0.1g') if target else p
            pl=E.plan(cve,scope);entry=dict(cve=cve,supported=pl['supported'],questions=[q['id'] for q in pl['questions']]);counts['executable_in_population' if pl['supported'] else 'retained_unsupported']+=1
        except (ValueError,KeyError) as error:entry=dict(cve=cve,supported=False,error=str(error));counts['retained_integrity_error']+=1
        rows.append(entry)
        if (i+1)%2000==0:print('CVE records audited:',i+1,flush=True)
    data=dict(total_records=len(ids),counts=dict(counts),executable_registry_cves=sorted(E.registry()['rules']),registry_cves_outside_original_population=sorted(set(E.registry()['rules'])-set(ids)),excluded_records=0,unsupported_policy='No operating-question guesses; under_investigation.',not_accuracy_validation=True,records=rows)
    (OUT/'coverage.json').write_text(json.dumps(data,indent=2),encoding='utf-8')
    truth={r['case_id']:r for r in map(json.loads,(OUT/'experiment/ground_truth.jsonl').read_text(encoding='utf-8').splitlines())};challenges=[]
    with gzip.open(OUT/'experiment/inputs.jsonl.gz','rt',encoding='utf-8') as f:
        for line in f:
            r=json.loads(line);t=truth[r['case_id']]
            if t['variant']!='semantically_wrong_operating_fact':continue
            changed=[k for k,v in t['physical_configuration'].items() if r['payload']['auto_observations'][k]['value']!=v]
            challenges.append(dict(case_id=r['case_id'],changed_parameters=changed,negative_control=not changed))
    audit=dict(challenge_variants=len(challenges),actually_misreported_facts=sum(bool(c['changed_parameters']) for c in challenges),unchanged_negative_controls=sum(c['negative_control'] for c in challenges),all_cases_retained=True,rows=challenges)
    (OUT/'experiment/fixture_audit.json').write_text(json.dumps(audit,indent=2),encoding='utf-8')
    print(json.dumps(dict(coverage={k:v for k,v in data.items() if k!='records'},fixture_audit=audit),indent=2))
if __name__=='__main__':main()
