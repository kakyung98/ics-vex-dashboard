"""One explicit fictional extraction smoke test; never real-CVE accuracy gold."""
from pathlib import Path
import hashlib
import sys
import time

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.precision_role_runtime import PrecisionRoleRuntime
from src.training_io import atomic_json


def main():
    text='Successful exploitation requires that the maintenance key switch is in the unlocked position.'
    packet=dict(packet_id='fictional-maintenance-switch-smoke',cve='CVE-2099-99999',
        identity_status='fictional_control',
        scopes=[dict(id='fictional-product',member_count=1,product_names=['Fictional maintenance controller'])],
        sources=[dict(id='fictional-source',scope_id='fictional-product',text=text,
            text_sha256=hashlib.sha256(text.encode()).hexdigest(),url='fixture://ics-vex/maintenance-switch',subject_ambiguous=False)])
    started=time.perf_counter();runtime=PrecisionRoleRuntime()
    result=runtime.extract_prerequisites(packet)
    report=dict(packet=packet,result=result,synthetic=True,real_CVE_accuracy=None,
        scope='Single authored fixture; mechanical grounding and API smoke only',
        elapsed_seconds=time.perf_counter()-started)
    out=ROOT/'results/precision_evaluation_v1/extraction_smoke.json'
    atomic_json(out,report)
    print('Mechanical validation:',bool(result.get('validation',{}).get('mechanical_checks_passed')),flush=True)
    if result.get('draft') is None:print('Unresolved extraction:',result.get('error'),flush=True)
    else:
        for scenario in result['draft']['scenarios']:
            for condition in scenario['conditions']:
                print(condition['relation'],condition['statement'],condition.get('question'),flush=True)


if __name__=='__main__':main()
