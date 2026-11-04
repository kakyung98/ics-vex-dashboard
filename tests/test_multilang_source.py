import io
import json
import zipfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from src import multilang_source as MS, source_intake as SI, clang_source as CS
from src.source_evidence import review,inspect_build

SAMPLES={
 'a.c':('c','int bad(){return 1;} int main(){return bad();}'),
 'b.cpp':('cpp','int bad(){return 1;} int main(){return bad();}'),
 'c.py':('python','def bad():\n return 1\ndef main():\n return bad()\nmain()\n'),
 'App.java':('java','class App { static int bad(){return 1;} public static void main(String[] a){bad();}}'),
 'e.js':('javascript','const bad = () => 1; function main(){return bad();} main();'),
 'f.go':('go','package main\nfunc bad() int {return 1}\nfunc main(){bad()}'),
 'g.R':('r','bad <- function() {1}\nmain <- function() {bad()}\nmain()'),
 'h.rb':('ruby','def bad\n 1\nend\ndef main\n bad()\nend\nmain()'),
 'i.sql':('sql',"CREATE FUNCTION bad() RETURNS INTEGER AS 'SELECT 1' LANGUAGE SQL; SELECT bad();"),
}


@pytest.mark.parametrize('filename',list(SAMPLES))
def test_real_parsers_observe_definitions_and_calls_without_build(tmp_path,filename):
    lang,code=SAMPLES[filename];(tmp_path/filename).write_text(code,encoding='utf-8')
    g=MS.auto_build(tmp_path,inspect_build(tmp_path),entries=[],scope='product',complete=True)
    assert g['engine']=='tree-sitter-source/1' and g['languages']=={lang:1}
    assert g['translation_units'][0]['status']=='completed'
    assert any(f['name']=='bad' for f in g['functions'].values())
    assert any(c['symbol']=='bad' for f in g['functions'].values() for c in f['calls'])
    result=MS.assess(g,['bad'])
    assert result['present_targets'] and result['reachable_paths']
    assert not result['absence_proven'] and not result['unreachable']
    assert not g['program_executed'] and not g['uploaded_commands_executed']
    assert MS.assess(g,['missing'])['presence']=='not_observed_not_proven_absent'


def test_comments_strings_and_dynamic_dispatch_do_not_become_proofs(tmp_path):
    (tmp_path/'a.py').write_text('"bad()"\n# bad()\ndef main():\n obj.bad()\n',encoding='utf-8')
    g=MS.build(tmp_path,entries=['main'])
    assert not g['call_edges'] and g['unresolved_calls']
    assert not MS.assess(g,['bad'])['absence_proven']
    assert len([c for f in g['functions'].values() for c in f['calls']])==1


def test_parse_errors_and_ambiguous_names_remain_visible(tmp_path):
    (tmp_path/'a.js').write_text('function bad(){} function bad(){} function main(){bad();}',encoding='utf-8')
    (tmp_path/'b.py').write_text('def broken(:\n',encoding='utf-8')
    g=MS.build(tmp_path,entries=['main'])
    assert g['execution_status']=='partial'
    assert any(b['reason']=='syntax_errors_or_unsupported_dialect' for b in g['blockers'])
    assert g['unresolved_calls'] and not g['call_edges']


def test_sql_query_is_parsed_even_without_routine_definitions(tmp_path):
    (tmp_path/'q.sql').write_text('SELECT bad();',encoding='utf-8')
    g=MS.build(tmp_path)
    assert g['translation_units'][0]['status']=='completed'
    assert any(c['symbol']=='bad' for f in g['functions'].values() for c in f['calls'])
    assert not MS.assess(g,['bad'])['absence_proven']


def test_missing_compiler_falls_back_to_source_without_clearance(tmp_path,monkeypatch):
    (tmp_path/'a.c').write_text('int main(){return 0;}',encoding='utf-8')
    monkeypatch.setattr(CS,'compiler',lambda:None)
    g=MS.auto_build(tmp_path,{'configurations':[{'file':'a.c','arguments':['cc','-c','a.c']}]})
    assert g['engine']=='tree-sitter-source/1'
    assert g['compiler_attempt']['blockers'][0]['reason']=='clang_not_installed'
    assert not MS.assess(g,['bad'])['absence_proven']


def test_source_analysis_never_executes_uploaded_python(tmp_path):
    marker=tmp_path/'EXECUTED'
    (tmp_path/'a.py').write_text('from pathlib import Path\nPath('+repr(str(marker))+').touch()\ndef bad():\n return 1\n',encoding='utf-8')
    g=MS.build(tmp_path)
    assert not marker.exists() and not g['program_executed']


@pytest.mark.skipif(not CS.compiler(),reason='Clang not installed')
def test_auto_retains_clang_for_native_build_but_never_ignores_other_languages(tmp_path):
    (tmp_path/'main.c').write_text('int main(void){return 0;}',encoding='utf-8')
    (tmp_path/'compile_commands.json').write_text(json.dumps([{'file':'main.c','arguments':['cc','-c','main.c']}]),encoding='utf-8')
    assert MS.auto_build(tmp_path,inspect_build(tmp_path),entries=['main'])['engine']=='clang-llvm-ir/1'
    (tmp_path/'extra.py').write_text('def bad():\n return 1\n',encoding='utf-8')
    assert MS.auto_build(tmp_path,inspect_build(tmp_path))['engine']=='tree-sitter-source/1'
    out=review(tmp_path,SI.index_tree(str(tmp_path)),['main'],[{'cve':'CVE-2099-12345','functions':['absent']}],
               engine='clang',analysis_scope='product',complete=True)
    assert out['statements'][0]['status']=='under_investigation'
    assert any(b['reason']=='non_cpp_sources_outside_clang_analysis' for b in out['cfg']['blockers'])


def test_multilingual_upload_and_judge_api(tmp_path):
    from src.api_server import app
    client=TestClient(app);archive=io.BytesIO()
    with zipfile.ZipFile(archive,'w') as z:
        for name,(_,code) in SAMPLES.items():z.writestr(name,code)
    up=client.post('/api/source/upload',files={'file':('source.zip',archive.getvalue(),'application/zip')})
    assert up.status_code==200,up.text
    assert set(up.json()['languages'])=={v[0] for v in SAMPLES.values()}
    assert up.json()['functions']>=1
    out=client.post('/api/source/judge',json={'session':up.json()['session'],'engine':'auto',
        'analysis_scope':'product','tree_is_complete':True,
        'cves':[{'cve':'CVE-2099-12345','functions':['bad'],'description':'The bad function has a vulnerability.'}]})
    assert out.status_code==200,out.text
    result=out.json();s=result['statements'][0]
    assert result['cfg']['engine']=='tree-sitter-source/1'
    assert len(s['evidence']['definitions'])==9 and s['status']=='under_investigation'
    assert s['evidence']['cfg']['graph_kind']=='syntactic_call_graph_not_cfg'
