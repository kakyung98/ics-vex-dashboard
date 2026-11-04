import json
from pathlib import Path
import importlib.util
spec=importlib.util.spec_from_file_location('clang_batch_restart',Path(__file__).resolve().parents[1]/'tools/batch_source_clang.py')
B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)


def test_discovery_analysis_never_declares_snapshot_product_complete(tmp_path,monkeypatch):
    cve='CVE-2099-12345';root=tmp_path/'data/source_snapshots'/cve;root.mkdir(parents=True)
    code='int parse_frame(int n){return n;} int main(void){return parse_frame(3);}\n'
    (root/'main.c').write_text(code)
    (tmp_path/'data/source_locations.json').write_text(json.dumps({cve:{'functions':[{'name':'parse_frame','file':None}]}}))
    monkeypatch.setattr(B,'ROOT',tmp_path);out=tmp_path/'results';out.mkdir()
    B.worker(cve,out,20)
    result=json.loads((out/(cve+'.json')).read_text())
    assert result['compiled_project_functions']>0
    assert result['status']=='under_investigation'
    assert result['discovery_configuration_used']
    assert not result['target_mapping_independently_verified']
    assert (root/'main.c').read_text()==code
    assert not (root/'compile_commands.json').exists()
