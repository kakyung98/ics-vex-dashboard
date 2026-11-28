"""Synthetic non-specialized CVE workflow in the isolated preflight database."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from unittest.mock import patch
import json,uuid
from tools.item4 import serve_nist_operational_vex as S
from tools.item4.auto_vex_fixture_support import profile
OUT=Path('D:/ICS-VEX/results/nist_population_vex_20261118')
HOME=Path('D:/ICS-VEX/results/nist_information_20261118/input_preflight')
def main():
    W=S.service.bom_vex_workflow;REV=S.service.operational_vex_api
    c=dict(**{'bom-ref':'synthetic-indusoft'},type='application',name='InduSoft Web Studio',version='6.1')
    job=dict(id='SYNTHETIC-FULL-POPULATION-'+uuid.uuid4().hex,status='completed',input_sbom={'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'components':[c]},result={'components':[{'component':{'id':c['bom-ref'],'name':c['name']},'validation':{'status':'validated'},'cves':[{'cve_id':'CVE-2011-4051','match_status':'match'}]}]})
    with patch.object(W,'DB',HOME/'workflows.sqlite3'),patch.object(REV,'DB',HOME/'reviews.sqlite3'):
        w=W.create(job);p=profile(c['name'],c['version'],asset_ref='SYNTHETIC NON-SPECIALIZED UI TEST')
        w=W.save_profile(w['id'],dict(revision=w['revision'],bom_sha256=w['bom_sha256'],component_ref=c['bom-ref'],profile=p,component_binding=dict(review_confirmed=True,source='SYNTHETIC preflight inventory',quote='SYNTHETIC InduSoft Web Studio 6.1 deployment for UI test only')))
    data=dict(workflow=w['id'],url='http://127.0.0.1:18107/bom-vex.html?workflow='+w['id'],synthetic=True,production_data_written=False)
    (OUT/'browser_fixture.json').write_text(json.dumps(data,indent=2),encoding='utf-8');print(json.dumps(data))
if __name__=='__main__':main()
