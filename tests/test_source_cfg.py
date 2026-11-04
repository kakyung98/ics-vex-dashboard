from src import source_cfg
from src import source_intake as SI
from src.source_evidence import review


def graph(tmp_path, code):
    (tmp_path / "main.c").write_text(code)
    return source_cfg.build(tmp_path)


def test_uncalled_vulnerable_function_is_unreachable(tmp_path):
    g = graph(tmp_path, 'int bad() { return 1; } int main() { return 0; }')
    assert source_cfg.assess(g, ["bad"])["unreachable"]
    assert g["functions"]["main"]["nodes"]


def test_dead_branch_and_return_prune_call_edges(tmp_path):
    for code in (
        'int bad() {return 1;} int main() { if (0) { bad(); } return 0; }',
        'int bad() {return 1;} int main() { return 0; bad(); }',
        'int bad() {return 1;} int main() { while(0) { bad(); } return 0; }',
        'int bad() {return 1;} int main() { for (;;) { break; bad(); } return 0; }',
    ):
        g = graph(tmp_path, code)
        assert source_cfg.assess(g, ["bad"])["unreachable"], code


def test_conditional_path_and_do_while_body_stay_reachable(tmp_path):
    for code in (
        'int bad() {return 1;} int main(int n) { if(n) bad(); return 0; }',
        'int bad() {return 1;} int main() { do { bad(); } while(0); return 0; }',
        'int bad() {return 1;} int mid() {return bad();} int main() {return mid();}',
    ):
        g = graph(tmp_path, code)
        out = source_cfg.assess(g, ["bad"])
        assert out["reachable_paths"] and not out["unreachable"], code


def test_unresolved_dispatch_preprocessing_and_library_roots_do_not_clear(tmp_path):
    for code in (
        'int bad() {return 1;} int main() { int (*fp)() = bad; return fp(); }',
        'int bad() {return 1;} int main() { external(); return 0; }',
        '#define X 0\nint bad() {return 1;} int main() {return 0;}',
        'int bad() {return 1;} int entry() {return 0;}',
        'int bad() {return 1;} int main(int n) { switch(n) {case 1:return 0;} return 0;}',
    ):
        g = graph(tmp_path, code)
        assert not source_cfg.assess(g, ["bad"])["unreachable"], code
        assert g["blockers"]


def test_all_targets_must_be_unreachable_and_intake_complete(tmp_path):
    g = graph(tmp_path, 'int bad() {return 1;} int other() {return 2;} int main() {return other();}')
    assert not source_cfg.assess(g, ["bad", "other"])["unreachable"]
    assert not source_cfg.assess(g, ["bad"], intake_complete=False)["unreachable"]


def test_legacy_review_status_and_counts_follow_cfg_without_extra_document(tmp_path):
    graph(tmp_path, 'int bad() {return 1;} int main() {if(0) bad(); return 0;}')
    idx = SI.index_tree(str(tmp_path))
    out = review(tmp_path, idx, ["main"], [{"cve":"CVE-2099-99999", "functions":["bad"]}], data_dir=tmp_path / "empty",engine='legacy')
    assert out["statements"][0]["justification"] == "vulnerable_code_not_in_execute_path"
    assert out["statements"][0]["rule"] == "CFG_VULNERABLE_FUNCTIONS_UNREACHABLE"
    assert 'tix' not in out
    assert out["by_status"] == {"not_affected": 1} and out["decision_rate"] == 1
