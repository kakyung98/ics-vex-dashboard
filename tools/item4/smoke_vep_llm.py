"""One real-source extraction and synthetic-record smoke; not accuracy evaluation."""
from pathlib import Path
import json
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from src.item4.decision import evidence_based_vex as E
from src.item4.analysis import exploitation_prerequisites as V
from src.item4.models import operating_record_review_model as O


def main():
    output=V.ROOT/'results/vep_llm_20261119'
    output.mkdir(parents=True,exist_ok=True)
    rule=V.vendor_rule(E.registry()['rules']['CVE-2014-0198'],E.registry())
    report=dict(scope='Real vendor source; synthetic operating evidence; wiring smoke only',
                extraction_error=rule['extraction_error'], prerequisite=rule['prerequisite'],
                questions=rule['questions'], nli_used=False)
    for q in rule['questions'][:1]:
        O.annotate(q,dict(asset_ref='SYNTHETIC-SMOKE',product='OpenSSL',build='1.0.1g',
                         config_baseline='SYNTHETIC',mode='normal',origin='SYNTHETIC-ORIGIN'))
        evidence=[dict(id='synthetic-record',excerpt='Current applied configuration for this assessed OpenSSL component: SSL_MODE_RELEASE_BUFFERS is enabled. This is an observed current setting, not a plan.')]
        report['operating_review']=O.compare(q,evidence,'complete')
    report['nli_module_imported']='src.operational_nli' in sys.modules
    report['passed']=bool(rule['prerequisite']) and not report['nli_module_imported'] and bool(report.get('operating_review',{}).get('executed'))
    path=output/'smoke.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(dict(path=str(path),passed=report['passed'],extraction_error=rule['extraction_error'],
                         prerequisites=len((rule['prerequisite'] or {}).get('draft',{}).get('prerequisites',[])),
                         questions=len(rule['questions']),record_value=report.get('operating_review',{}).get('value'),
                         nli_module_imported=report['nli_module_imported'])))
    if not report['passed']:raise SystemExit(1)


if __name__=='__main__':main()
