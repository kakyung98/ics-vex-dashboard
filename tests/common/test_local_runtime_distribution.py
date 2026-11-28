"""The web runtime must ship without local reviews, jobs or execution logs."""
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]


def test_required_runtime_files_are_publishable_and_private_state_stays_ignored():
    manifest=json.loads((ROOT/'local-service/runtime_manifest.json').read_text(encoding='utf-8'))
    files=manifest['files']
    assert files and len(files)==len(set(files))
    assert all((ROOT/p).is_file() for p in files)
    checked=subprocess.run(['git','check-ignore','-z','--stdin'],input=('\0'.join(files)+'\0').encode(),
        cwd=ROOT,capture_output=True)
    assert checked.returncode==1,checked.stdout+checked.stderr
    included=subprocess.check_output(['git','ls-files','-c','-o','--exclude-standard','--','local-service'],cwd=ROOT,text=True)
    assert set(included.splitlines())==set(files)|{'local-service/runtime_manifest.json'}
    private=['local-service/sbom-vex/vex_operational_logic_20261117/reviews.sqlite3',
        'local-service/sbom-vex/vex_operational_logic_20261117/bom_integration_20261117/workflows.sqlite3',
        'local-service/sbom-vex/vex_operational_logic_20261117/english_ui/live_english.jpg',
        'local-service/sbom-vex/operating_profiles_r4_rederived/live.log',
        'results/system_logic_fixes_20261118/backups/example/reviews.sqlite3']
    checked=subprocess.run(['git','check-ignore','-z','--stdin'],input=('\0'.join(private)+'\0').encode(),
        cwd=ROOT,capture_output=True)
    assert set(checked.stdout.decode().rstrip('\0').split('\0'))==set(private)


def test_packaged_runtime_works_in_a_new_location_without_existing_databases(tmp_path):
    manifest=json.loads((ROOT/'local-service/runtime_manifest.json').read_text(encoding='utf-8'))
    for name in manifest['files']:
        target=tmp_path/name;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(ROOT/name,target)
    # Libraries are supplied by the repo; all legacy runtime code/assets/state
    # resolve exclusively under the relocated checkout.
    script='''
import importlib.util,json,sys
from pathlib import Path
root=Path(sys.argv[1]);repo=Path(sys.argv[2])
sys.path.insert(0,str(repo))
home=root/'local-service/sbom-vex/vex_operational_logic_20261117'
sys.path.insert(0,str(home))
import operational_vex as V
import bom_vex_workflow as W
assert V.ROOT==root
assert V.P.ROOT==root
assert len(V.P.catalogue()['profiles'])==18
assert not W.DB.exists()
job=dict(id='distribution-test',status='completed',input_sbom={'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'components':[{'bom-ref':'c','type':'library','name':'OpenSSL','version':'1.0.1g'}]},result={'components':[{'component':{'id':'c','name':'OpenSSL'},'validation':{'status':'validated'},'cves':[{'cve_id':'CVE-2014-0198','match_status':'match'}]}]})
w=W.create(job)
assert W.load(w['id'])['id']==w['id']
assert W.validate_bom(w['bom'])['status']=='valid'
assert W.DB.is_relative_to(root)
print('relocated runtime and fresh SQLite/schema validation passed')
'''
    result=subprocess.run([sys.executable,'-X','utf8','-B','-c',script,str(tmp_path),str(ROOT)],
        cwd=tmp_path,capture_output=True,text=True,encoding='utf-8',timeout=60)
    assert result.returncode==0,result.stdout+result.stderr
