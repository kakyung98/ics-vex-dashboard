"""Cross-check compiled linkage and captured smoke output against structural labels."""
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/'data/source_training_sw'


def main():
    cases=json.loads((DATA/'oracle/cases.json').read_text())
    text=(DATA/'build/Testing/Temporary/LastTest.log').read_text(encoding='utf-8',errors='replace')
    blocks=re.split(r'(?m)^\d+/\d+ Testing: (\w+)_smoke\s*$',text)
    logs={blocks[i]:blocks[i+1] for i in range(1,len(blocks),2)}
    assert len(logs)==len(cases)==900
    result=[]
    for c in cases:
        log=logs[c['id']]
        assert 'Test Passed.' in log
        output=log.split('Output:',1)[1].split('<end of output>',1)[0]
        witnessed=('library='+c['component']) in output
        assert witnessed==c['api_reachable_from_main'],c['id']
        linkmap=(DATA/'build/maps'/(c['id']+'.map')).read_text(errors='replace')
        symbol=bool(re.search(r'\s'+re.escape(c['application_api'])+r'\s+[0-9a-fA-F]+\s+f\s',linkmap))
        assert symbol==c['dependency_linked'],c['id']
        result.append({'id':c['id'],'api_symbol_linked':symbol,'default_input_api_witness':witnessed})
    report={'checked':len(result),'linked_api_symbols':sum(r['api_symbol_linked'] for r in result),'default_input_api_witnesses':sum(r['default_input_api_witness'] for r in result),'scope':'Application linkage and benign-input API witnesses, not complete path proof or CVE exploitability.','cases':result}
    (ROOT/'results/source_training_sw/runtime_audit.json').write_text(json.dumps(report,indent=2))
    print({k:v for k,v in report.items() if k!='cases'})


if __name__=='__main__':main()
