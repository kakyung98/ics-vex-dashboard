"""Smoke-test actual cloud HTTP inference against sealed representative outputs."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
import json
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'results/cloud_migration';OUT.mkdir(parents=True,exist_ok=True)
BASE='http://127.0.0.1:18100'


def request(path,payload=None):
    wire=None if payload is None else json.dumps(payload).encode()
    req=urllib.request.Request(BASE+path,data=wire,headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=300) as response:
        return json.load(response)


def emitted(result):
    return sorted({v['cve_id'] for row in result['components'] for v in row.get('cves',[]) if v.get('match_status')=='match'})


def main():
    report=dict(health=request('/api/health'),real_asset_precision=None,full_GPU_evaluation_rerun=False,
                scope='Migration acceptance: sealed metrics independently recomputed; representative live HTTP GPU inference')
    assert report['health']['corpus_cves']==12418
    prior=json.loads((ROOT/'results/item4_source_context_v1/http_model_smoke.json').read_text())
    cve=prior['source_packet']['cve']
    rows=request('/api/precision/item4/source-simulation/cves/'+cve)['cases']
    report['item4']=[]
    for row in rows:
        began=time.monotonic()
        # Only input packet goes to inference; sealed predictions stay outside the request.
        actual=request('/api/precision/item4/source-simulation/assess',dict(packet=row['packet']))
        expected=row['sealed_prediction']
        assert actual['raw']['llm_used']
        assert actual['raw']['simulation_status']==expected['raw']['simulation_status'],row['id']
        assert actual['simulation_status']==expected['simulation_status'],row['id']
        assert actual['identification_adapter_restored'] and not actual['export_allowed']
        report['item4'].append(dict(id=row['id'],seconds=time.monotonic()-began,result=actual,matches_sealed=True))
    original=json.loads((ROOT/'results/item4_source_context_v1/item3_after_source_adapter_smoke.json').read_text())
    began=time.monotonic()
    actual=request('/api/cve-match',dict(sbom=original['input_sbom'],agent_mode='unified',lookup_mode='local'))
    (OUT/'item3_live_response.json').write_text(json.dumps(actual,indent=2),encoding='utf-8')
    assert actual['llm_used'] and actual['summary']['model_stage_errors']==0
    assert emitted(actual)==emitted(original['result'])
    report['item3']=dict(seconds=time.monotonic()-began,matches_sealed=True,llm_used=actual['llm_used'],emitted_CVEs=emitted(actual))
    report['passed']=True
    (OUT/'acceptance.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(dict(passed=True,item4_live_cases=len(rows),item3_matches_sealed=True,actual_GPU_inference=True)))


if __name__=='__main__':main()
