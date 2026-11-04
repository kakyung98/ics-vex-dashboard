import gzip
import json

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("batch_source_cfg", Path(__file__).resolve().parents[1] / "tools/batch_source_cfg.py")
batch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(batch)


def setup(tmp_path, monkeypatch, code):
    cve = "CVE-2099-99999"
    data = tmp_path / "data"
    source = data / "source_snapshots" / cve
    source.mkdir(parents=True)
    (source / "main.c").write_text(code)
    (data / "vuln_targets.json").write_text(json.dumps({cve: {"targets": ["bad"], "source": "patch"}}))
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(batch, "ROOT", tmp_path)
    batch.worker(cve, out)
    return json.loads((out / f"{cve}.json").read_text()), out


def test_worker_persists_graph_and_cfg_verdict(tmp_path, monkeypatch):
    result, out = setup(tmp_path, monkeypatch, "int bad(){return 1;} int main(){return 0;}")
    assert result["status"] == "not_affected"
    assert result["justification"] == "vulnerable_code_not_in_execute_path"
    with gzip.open(out / result["graph_file"], "rt") as f:
        g = json.load(f)
    assert "bad" in g["functions"] and g["entries"] == ["main"]


def test_worker_records_preprocessing_blocker_not_successful_clearance(tmp_path, monkeypatch):
    result, _ = setup(tmp_path, monkeypatch, "#define FEATURE 1\nint bad(){return 1;} int main(){return 0;}")
    assert result["analysis_state"] == "blocked"
    assert result["status"] == "under_investigation"
    assert result["blocker_counts"]["preprocessing_required"] == 1
