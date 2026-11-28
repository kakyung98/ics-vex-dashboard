"""Relocation must preserve single module identity and fail closed on source hashes."""
from hashlib import sha256
import importlib
import json
from pathlib import Path

import pytest

from src.common.paths import PROJECT_ROOT, sealed_source_receipt, source_path


def test_maintained_sources_resolve_and_aliases_share_module_identity():
    import src
    for name in ['identity_evidence','item4_scenario_moe','item4_run_ledger','model_paths']:
        path=source_path(name+'.py')
        assert path.is_file()
        canonical='.'.join(path.relative_to(PROJECT_ROOT).with_suffix('').parts)
        assert getattr(src,name) is importlib.import_module(canonical)


def test_paths_reject_escape_and_keep_fixture_root(tmp_path):
    with pytest.raises(ValueError):source_path('../README.md')
    file=tmp_path/'src/item4_scenario_moe.py'
    file.parent.mkdir();file.write_bytes(b'fixture')
    assert source_path(file.name,root=tmp_path)==file


def test_current_and_original_sources_are_distinguished():
    file=source_path('model_paths.py')
    actual=sha256(file.read_bytes()).hexdigest()
    assert sealed_source_receipt('model_paths.py',actual)['kind']=='current'
    migration=json.loads((PROJECT_ROOT/'results/source_layout_20261123/manifest.json').read_bytes())
    original=migration['changed_files']['src/item4_scenario_moe.py']['before_sha256']
    receipt=sealed_source_receipt('item4_scenario_moe.py',original)
    assert receipt['kind']=='historical_snapshot'
    assert receipt['member']=='src/item4_scenario_moe.py'
    with pytest.raises(ValueError):sealed_source_receipt('item4_scenario_moe.py','0'*64)
