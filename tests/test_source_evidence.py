import io
import json
import zipfile

from fastapi.testclient import TestClient
from src import cfg_vex, source_intake as SI
from src.source_evidence import inspect_build, review


def fixture(tmp_path, source):
    root = tmp_path / "upload"
    root.mkdir()
    (root / "main.c").write_text(source)
    data = tmp_path / "cache"
    patch = data / "patches" / "CVE-2020-12345"
    patch.mkdir(parents=True)
    (patch / "fix.diff").write_text('''diff --git a/main.c b/main.c
--- a/main.c
+++ b/main.c
@@ -1,3 +1,4 @@ int bad(int n)
 int bad(int n) {
+    if (n > 8) return -1;
     return n;
 }
''')
    return root, data


def run_review(root, data, **kwargs):
    idx = SI.index_tree(str(root))
    return review(root, idx, SI.entry_points(idx)["entries"],
                  [{"cve": "CVE-2020-12345", **kwargs}], data_dir=data,engine='legacy')


def test_reachable_vulnerable_code_is_review_evidence_not_affected(tmp_path):
    root, data = fixture(tmp_path, 'int bad(int n) {\n    return n;\n}\nint main() { return bad(9); }\n')
    (root / "compile_commands.json").write_text(json.dumps([
        {"file": "main.c", "arguments": ["cc", "-DFEATURE=1", "-c", "main.c"]}]))
    out = run_review(root, data)
    s = out["statements"][0]
    assert s["status"] == "under_investigation"
    assert s["evidence"]["reachable_paths"]
    assert s["evidence"]["patch"]["patches"][0]["hunks"][0]["status"] == "vulnerable_pattern"
    assert out["build"]["translation_units"] == ["main.c"]
    assert "-DFEATURE=1" in out["build"]["configurations"][0]["arguments"]
    assert not out["build"]["commands_executed"]
    assert len(out["inventory_sha256"]) == 64


def test_fixed_pattern_does_not_assert_fixed_deployed_build(tmp_path):
    root, data = fixture(tmp_path, 'int bad(int n) {\n    if (n > 8) return -1;\n    return n;\n}\n')
    out = run_review(root, data)
    s = out["statements"][0]
    assert s["status"] == "under_investigation"
    assert s["evidence"]["patch"]["patches"][0]["hunks"][0]["status"] == "fixed_pattern"
    assert "compilation_database" in s["evidence"]["missing_evidence"]
    assert 'tix' not in out


def test_legacy_absence_clears_but_dead_code_and_unknown_mapping_do_not(tmp_path):
    root, _ = fixture(tmp_path, 'int bad(int n) { if (0) n++; return n; }')
    idx = SI.index_tree(str(root))
    for funcs, expected in ((["missing"], "not_affected"), (["bad"], "under_investigation"), ([], "under_investigation")):
        out = cfg_vex.judge("CVE-2020-12345", idx, ["main"], funcs, tree_is_complete=True)
        assert out["status"] == expected


def test_all_vulnerable_functions_absent_clears_and_updates_counts(tmp_path):
    root, data = fixture(tmp_path, "int unrelated() { return 0; }")
    out = run_review(root, data)
    s = out["statements"][0]
    assert s["status"] == "not_affected"
    assert s["justification"] == "vulnerable_code_not_present"
    assert 'tix' not in out
    assert out["by_status"] == {"not_affected": 1}
    assert out["decision_rate"] == 1 and out["deferred"] == 0


def test_unknown_mapping_and_partial_presence_do_not_clear(tmp_path):
    root, data = fixture(tmp_path, "int bad(int n) { return n; }")
    out = run_review(root, data, functions=["missing"])
    assert out["statements"][0]["status"] == "under_investigation"
    idx = SI.index_tree(str(root))
    out = review(root, idx, [], [{"cve": "CVE-2099-99999"}], data_dir=data)
    assert out["statements"][0]["status"] == "under_investigation"


def test_unindexed_reference_or_truncated_source_does_not_clear(tmp_path):
    root, data = fixture(tmp_path, "#define CALL bad\nint main() { return CALL(1); }")
    out = run_review(root, data)
    assert out["statements"][0]["status"] == "under_investigation"
    assert out["statements"][0]["evidence"]["unresolved_reference_files"]
    (root / "main.c").write_text("int main() { return 0; }")
    idx = SI.index_tree(str(root))
    out = review(root, idx, ["main"], [{"cve": "CVE-2020-12345"}], upload={"truncated": "size limit"}, data_dir=data)
    assert out["statements"][0]["status"] == "under_investigation"


def test_build_database_does_not_read_host_or_prove_exclusion(tmp_path):
    (tmp_path / "a.c").write_text("int main() {}")
    (tmp_path / "compile_commands.json").write_text(json.dumps([
        {"file": "C:/outside/secrets.c", "command": "touch sentinel"}]))
    build = inspect_build(tmp_path)
    assert not build["translation_units"] and build["unresolved_entries"]
    assert not build["binary_verified"]
    assert not (tmp_path / "sentinel").exists()


def test_patch_ambiguous_paths_do_not_select_arbitrary_copy(tmp_path):
    root, data = fixture(tmp_path, "int unrelated() {}")
    for name in ("one", "two"):
        d = root / name
        d.mkdir()
        (d / "main.c").write_text('int bad(int n) {\n    return n;\n}\n')
    out = run_review(root, data)
    hunk = out["statements"][0]["evidence"]["patch"]["patches"][0]["hunks"][0]
    assert hunk["status"] == "file_missing_or_ambiguous"


def test_context_metadata_does_not_change_source_verdict(tmp_path):
    root, data = fixture(tmp_path, 'int bad(int n) {\n return n;\n}\nint main() { return bad(9); }')
    out = run_review(root, data, cvss_score=8, cwe="CWE-20", exploit_references=["https://example.org/advisory"])
    assert 'tix' not in out and 'priority' not in out['statements'][0]
    assert out["statements"][0]["status"] == "under_investigation"


def test_real_cached_heartbleed_patch_is_parsed_with_provenance(tmp_path):
    from src.source_evidence import DATA, patch_evidence
    if not (DATA / "patches" / "CVE-2014-0160").exists():
        return  # Repository snapshots may omit the optional offline cache.
    out = patch_evidence(tmp_path, "CVE-2014-0160")
    assert out["patches"] and all(len(p["sha256"]) == 64 for p in out["patches"])
    assert "dtls1_process_heartbeat" in out["functions"]
    assert all(h["status"] == "file_missing_or_ambiguous" for p in out["patches"] for h in p["hunks"])


def test_upload_api_review_and_input_errors():
    from src.api_server import app
    client = TestClient(app)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("main.c", "int main() { return 0; }")
    up = client.post("/api/source/upload", files={"file": ("src.zip", archive.getvalue(), "application/zip")})
    assert up.status_code == 200
    sid = up.json()["session"]
    assert "build" in up.json()
    result = client.post("/api/source/judge", json={"session": sid,
                         "tree_is_complete": True, "cves": [{"cve": "CVE-2099-99999", "functions": ["absent"]}]})
    assert result.status_code == 200, result.text
    assert result.json()["statements"][0]["status"] == "under_investigation"
    assert result.json()['cfg']['engine']=='clang-llvm-ir/1'
    assert any(b['reason']=='compilation_database_missing' for b in result.json()['cfg']['blockers'])
    assert 'tix' not in result.json()
    assert client.post("/api/source/judge", json={"session": sid, "cves": [42]}).status_code == 400
    assert client.post("/api/source/judge", json={"session": sid, "cves": [{"cve": "CVE-2099-99999", "functions": "bad"}]}).status_code == 400
