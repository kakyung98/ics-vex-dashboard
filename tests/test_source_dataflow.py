from src.source_dataflow import analyze_ir

IR='''
define i32 @sink(i32 %value) { entry: ret i32 %value }
define i32 @input(i32 %user) {
entry:
 %slot = alloca i32
 store i32 %user, ptr %slot
 %loaded = load i32, ptr %slot
 %result = call i32 @sink(i32 %loaded)
 ret i32 %result
}
define i32 @constant(i32 %unused) { entry:
 %value = call i32 @sink(i32 7)
 ret i32 %value
}
'''


def test_declared_input_to_sink_has_reproducible_def_use_witness():
    r=analyze_ir(IR,[{'function':'input','parameter':0}],['sink'])
    assert r['status']=='possible_dependency_found'
    assert r['source_to_target_paths'][0]['source']=='input:arg:0'
    assert r['source_to_target_paths'][0]['target_parameter']=='sink:arg:0'
    assert not r['negative_proof_enabled'] and not r['standard_vex_authority']


def test_no_flow_missing_source_or_target_cannot_clear_a_CVE():
    for sources,targets in [([{'function':'constant','parameter':0}],['sink']),([],['sink']),
                            ([{'function':'input','parameter':9}],['sink']),
                            ([{'function':'input','parameter':0}],['missing'])]:
        r=analyze_ir(IR,sources,targets)
        assert r['status']=='unknown' and not r['negative_proof_enabled']


def test_bounded_analysis_fails_open_as_unknown():
    r=analyze_ir(IR,[{'function':'input','parameter':0}],['sink'],max_nodes=1)
    assert r['status']=='unknown' and 'def_use_node_limit' in r['blockers']


def test_llvm_metadata_backslashes_do_not_corrupt_hex_prefixed_filenames():
    from src.clang_source import decode_llvm_string
    assert decode_llvm_string(r'lib\\adler32.c')=='lib\\adler32.c'
    assert decode_llvm_string(r'lib\\deflate.c')=='lib\\deflate.c'
    assert decode_llvm_string(r'lib\5Cadler32.c')=='lib\\adler32.c'
