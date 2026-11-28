"""Isolated preflight workflow with clearly synthetic deployments of real CVEs."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from unittest.mock import patch
import json,uuid,sys
from tools.item4 import serve_nist_operational_vex as S
from tools.item4.auto_vex_fixture_support import profile
OUT=Path('D:/ICS-VEX/results/nist_auto_vex_20261118');HOME=Path('D:/ICS-VEX/results/nist_information_20261118/input_preflight')
def main():
    W=S.service.bom_vex_workflow;REV=S.service.operational_vex_api
    version=sys.argv[1] if len(sys.argv)>1 else '1.0.1g'
    component={'bom-ref':'synthetic-openssl','type':'library','name':'OpenSSL','version':version}
    job=dict(id='SYNTHETIC-AUTO-BROWSER-'+uuid.uuid4().hex,status='completed',input_sbom={'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'components':[component]},result={'components':[{'component':{'id':component['bom-ref'],'name':component['name']},'validation':{'status':'validated'},'cves':[{'cve_id':c,'match_status':'match'} for c in ['CVE-2010-5298','CVE-2014-0198','CVE-1999-1085']]}]})
    with patch.object(W,'DB',HOME/'workflows.sqlite3'),patch.object(REV,'DB',HOME/'reviews.sqlite3'):
        w=W.create(job);p=profile(version=version,asset_ref='SYNTHETIC UI TEST INSTANCE')
        w=W.save_profile(w['id'],dict(revision=w['revision'],bom_sha256=w['bom_sha256'],component_ref=component['bom-ref'],profile=p,component_binding=dict(review_confirmed=True,source='SYNTHETIC preflight inventory',quote='SYNTHETIC OpenSSL '+version+' deployment for UI test only')))
    data=dict(workflow=w['id'],url='http://127.0.0.1:18107/bom-vex.html?workflow='+w['id'],synthetic=True,production_data_written=False)
    (OUT/('browser_fixture_fixed.json' if version!='1.0.1g' else 'browser_fixture.json')).write_text(json.dumps(data,indent=2),encoding='utf-8');print(json.dumps(data))
if __name__=='__main__':main()
