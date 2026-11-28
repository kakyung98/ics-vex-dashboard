"""Audit the entire fixed population without filtering unsupported records."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from collections import Counter
import json
from tools.item4 import serve_nist_operational_vex as S
from src.item4.decision import scoped_proof_evaluation as T
OUT=Path('D:/ICS-VEX/results/nist_three_axis_experiment_20261118')
def main():
    catalogue=S.V.A.catalogue()['cves'];report=Counter();kinds=Counter();issues=[]
    for item in catalogue:
        report['target_cves']+=1
        try:
            r=S.V.project_record(S.V.current_record(item['cve']))
            report['record_integrity_passed']+=1
            report['with_source_path_candidates' if r['scenarios'] else 'without_source_path_candidates']+=1
            for s in r['scenarios']:
                report['source_path_candidates']+=1
                report['source_path_integrity_passed' if S.V._source_valid(r,s) else 'source_path_integrity_failed']+=1
                for c in s['conditions']:
                    kinds[c['kind']]+=1
                    report['condition_candidates']+=1
                    if not T.ELIGIBLE.get(c['kind']):report['conditions_without_supported_operational_domain']+=1
        except (ValueError,KeyError,TypeError) as e:issues.append(dict(cve=item['cve'],reason=str(e)))
    data=dict(counts=dict(report),condition_kinds=dict(kinds),asset_types=18,logical_cve_type_pairs=18*len(catalogue),excluded_cves=0,issues=issues,unsupported_policy='Retain the CVE and emit unknown/under_investigation until exact source-bound evidence is available.',not_semantic_accuracy_validation=True,asset_type_does_not_supply_truth=True)
    (OUT/'cve_coverage_audit.json').write_text(json.dumps(data,indent=2),encoding='utf-8')
    print(json.dumps(data,indent=2))
if __name__=='__main__':main()
