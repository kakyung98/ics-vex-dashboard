import json
from pathlib import Path
import pytest

from src import clang_source as CS, source_intake as SI
from src.source_evidence import inspect_build,review

pytestmark=pytest.mark.skipif(not CS.compiler(),reason='Clang executable not installed')


def project(tmp_path,files,flags=None):
    for name,text in files.items():
        p=tmp_path/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text,encoding='utf-8')
    rows=[{'file':n,'directory':str(tmp_path),'arguments':['cc',*(flags or []),'-c',n]} for n in files if Path(n).suffix in CS.EXT]
    (tmp_path/'compile_commands.json').write_text(json.dumps(rows),encoding='utf-8')
    return inspect_build(tmp_path)


def graph(root,b,**kw):return CS.build(root,b,scope='product',complete=True,entries=['main'],**kw)


def test_real_compiler_preserves_unused_static_function_and_prunes_dead_call(tmp_path):
    b=project(tmp_path,{'main.c':'static int bad(int n){return n;} int main(void){if(0)return bad(3); return 0;}\n'})
    g=graph(tmp_path,b);a=CS.assess(g,['bad'])
    assert g['engine']=='clang-llvm-ir/1' and g['translation_units'][0]['status']=='completed'
    assert len(a['present_targets'])==1 and a['unreachable'] and not a['absence_proven']
    assert g['program_executed'] is False and g['uploaded_commands_executed'] is False


def test_macro_configuration_and_local_header_change_compiled_presence(tmp_path):
    b=project(tmp_path,{'include/feature.h':'#define ENABLED 0\n',
      'main.c':'#include "feature.h"\n#if ENABLED\nint bad(void){return 1;}\n#endif\nint main(void){return 0;}\n'},['-Iinclude'])
    g=graph(tmp_path,b)
    assert CS.assess(g,['bad'])['absence_proven']
    (tmp_path/'include/feature.h').write_text('#define ENABLED 1\n')
    g=graph(tmp_path,b)
    assert CS.assess(g,['bad'])['present_targets']
    assert g['translation_units'][0]['accepted_flags'][0]=='-I'


def test_cross_translation_unit_path_has_call_site_lines(tmp_path):
    b=project(tmp_path,{'main.c':'int wrapper(int);\nint main(void){return wrapper(5);}\n',
       'lib.c':'int bad(int n){return n;}\nint wrapper(int n){return bad(n);}\n'})
    g=graph(tmp_path,b);a=CS.assess(g,['bad'])
    assert a['reachable_paths'][0]['path']==['main','wrapper','bad']
    assert all(e['line'] for e in a['reachable_paths'][0]['call_sites'])
    assert not a['unreachable']


def test_cpp_overloads_and_file_static_names_are_distinct(tmp_path):
    b=project(tmp_path,{'main.cpp':'int bad(int n){return n;} double bad(double n){return n;} int main(){return bad(1);}\n',
        'other.c':'static int bad(int n){return n+1;}\n'})
    g=graph(tmp_path,b);a=CS.assess(g,['bad'])
    assert len(a['present_targets'])==3 and a['reachable_paths']
    assert not a['unreachable']


@pytest.mark.parametrize('source,reason',[
 ('int bad(void){return 1;} int main(int n,char**v){int(*f)(void)=n?bad:0; return f();}','indirect_call'),
 ('extern int external(void); int bad(void){return 1;} int main(void){return external();}','external_or_ambiguous_call'),
])
def test_unknown_dispatch_blocks_negative_verdicts(tmp_path,source,reason):
    b=project(tmp_path,{'main.c':source});g=graph(tmp_path,b)
    assert any(reason in b['reason'] for b in g['blockers'])
    assert not CS.assess(g,['bad'])['unreachable']


def test_compile_failure_is_not_absent_and_plugins_are_not_forwarded(tmp_path):
    b=project(tmp_path,{'main.c':'#include "missing.h"\nint main(void){return 0;}\n'},['-Xclang','-load','evil.dll'])
    g=graph(tmp_path,b)
    assert g['blockers'] and not CS.assess(g,['bad'])['absence_proven']
    cmd=g['translation_units'][0]['command']
    assert '-load' not in cmd and 'evil.dll' not in cmd


def test_library_analysis_does_not_claim_product_unreachability(tmp_path):
    b=project(tmp_path,{'library.c':'int bad(int n){return n;} int api(void){return bad(4);}\n'})
    g=CS.build(tmp_path,b,scope='library',complete=True)
    assert g['entries'] and CS.assess(g,['bad'])['reachable_paths']
    assert not g['negative_decisions_enabled']


def test_dependency_paths_with_spaces_are_hashed(tmp_path):
    root=tmp_path/'source with spaces';root.mkdir()
    b=project(root,{'main.c':'int main(void){return 0;}\n'})
    g=graph(root,b)
    assert g['negative_decisions_enabled']
    assert g['translation_units'][0]['dependencies'][0]['file']=='main.c'
    assert len(g['translation_units'][0]['dependencies'][0]['sha256'])==64


def test_optimization_preprocessor_changes_are_not_silently_ignored(tmp_path):
    b=project(tmp_path,{'main.c':'int main(void){return 0;}\n'},['-O2','-Wp,-DENABLED=1'])
    g=graph(tmp_path,b)
    assert any('optimization_configuration_not_reproduced' in x['reason'] for x in g['blockers'])
    assert any('unsupported_compiler_option:-Wp' in x['reason'] for x in g['blockers'])
    assert not CS.assess(g,['absent'])['absence_proven']


def test_web_review_explains_compiled_path_and_missing_applicability(tmp_path):
    project(tmp_path,{'main.c':'int bad(void){return 1;} int main(void){return bad();}\n'})
    index=SI.index_tree(str(tmp_path))
    out=review(tmp_path,index,['main'],[{'cve':'CVE-2020-12345','functions':['bad']}],analysis_scope='product',complete=True,data_dir=tmp_path)
    s=out['statements'][0]
    assert s['status']=='under_investigation'
    assert s['evidence']['explanation']['paths'][0]['call_sites']
    assert 'deployed binary identity' in s['evidence']['explanation']['not_established']


def test_upload_api_compiles_selected_build_and_explains_unreachable():
    import io,zipfile
    from fastapi.testclient import TestClient
    from src.api_server import app
    archive=io.BytesIO()
    with zipfile.ZipFile(archive,'w') as z:
        z.writestr('main.c','static int bad(void){return 1;} int main(void){if(0)return bad();return 0;}\n')
        z.writestr('compile_commands.json',json.dumps([{'file':'main.c','arguments':['cc','-c','main.c']}]))
    client=TestClient(app)
    up=client.post('/api/source/upload',files={'file':('source.zip',archive.getvalue(),'application/zip')})
    assert up.status_code==200
    result=client.post('/api/source/judge',json={'session':up.json()['session'],'engine':'clang','analysis_scope':'product',
        'entry_points':['main'],'tree_is_complete':True,'cves':[{'cve':'CVE-2099-12345','functions':['bad']}]})
    assert result.status_code==200,result.text
    out=result.json();statement=out['statements'][0]
    assert statement['status']=='not_affected' and statement['justification']=='vulnerable_code_not_in_execute_path'
    assert statement['evidence']['cfg']['present_targets']
    assert out['cfg']['translation_units'][0]['ir_sha256']
