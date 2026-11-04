"""Actual local GPU wiring smoke; fictional cases, never model accuracy evidence."""
import io
import json
from pathlib import Path
import sys
import time
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from fastapi.testclient import TestClient
from src.api_server import app
from src.training_io import atomic_json


def main():
    out=ROOT/'results/shared_vex_pipeline_gpu_smoke.json'
    started=time.time();report={'status':'running','synthetic_fixture':True,'real_CVE_accuracy_measured':False,
                               'mocked_models':False,'branches':{}}
    def save(phase):report.update(phase=phase,elapsed_seconds=round(time.time()-started,2));atomic_json(out,report)
    client=TestClient(app)
    cve={'cve':'CVE-2099-12345','description':'The parse_frame function processes malformed frames sent by remote attackers when the service is enabled.',
         'functions':['parse_frame'],'vector':'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H','cwe':'CWE-20'}
    save('context_models_running')
    r=client.post('/api/oc/judge',json={'product':'WIRING-SMOKE-ONLY','simulation':True,'cves':[cve],'asset':{'no_network_interface':True}})
    r.raise_for_status();report['branches']['context']=r.json();save('source_models_running')
    archive=io.BytesIO()
    with zipfile.ZipFile(archive,'w') as z:
        z.writestr('main.c','int parse_frame(int n){return n;}\nint main(void){return parse_frame(3);}\n')
        z.writestr('compile_commands.json',json.dumps([{'file':'main.c','arguments':['cc','-c','main.c']}]))
    up=client.post('/api/source/upload',files={'file':('fixture.zip',archive.getvalue(),'application/zip')});up.raise_for_status()
    r=client.post('/api/source/judge',json={'session':up.json()['session'],'product':'WIRING-SMOKE-ONLY','simulation':True,
         'analysis_scope':'product','entry_points':['main'],'tree_is_complete':True,'cves':[cve]})
    r.raise_for_status();report['branches']['source']=r.json()
    for name,result in report['branches'].items():
        s=result['statements'][0]
        assert s['extraction']['status']!='unavailable',s['extraction']
        assert s['authoring']['status']!='unavailable',s['authoring']
        assert s['authoring'].get('adapter_sha256')
        assert 'tix' not in result
        if s['document_draft']:assert s['document_draft']['status']==s['status']
        print(name,{'status':s['status'],'extraction':s['extraction']['status'],'authoring':s['authoring']['status'],
                    'model_chain_complete':s['pipeline_complete']},flush=True)
    report['status']='complete';save('complete')
    print('Actual GPU model calls and branch wiring verified:',out,flush=True)


if __name__=='__main__':main()
