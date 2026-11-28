import os
from pathlib import Path
from unittest.mock import patch
import pytest
from src.common.model_paths import pinned_base


def test_relocated_cache_keeps_exact_repository_revision_and_file_pins(tmp_path):
    original=tmp_path/'old/hub/model-a/snapshots/revision-a'
    moved=tmp_path/'new/hub/model-a/snapshots/revision-a'
    moved.mkdir(parents=True);(moved/'config.json').write_text('{}')
    marker=dict(base=str(original),base_files_sha256={'config.json':'a'*64})
    with patch.dict(os.environ,HF_HOME=str(tmp_path/'new'),HF_HUB_CACHE=str(tmp_path/'new/hub')):
        assert pinned_base(marker)==moved
        marker['base']=str(tmp_path/'old/hub/model-a/snapshots/other-revision')
        with pytest.raises(FileNotFoundError):pinned_base(marker)


def test_existing_recorded_base_has_precedence_over_environment(tmp_path):
    base=tmp_path/'recorded';base.mkdir()
    with patch.dict(os.environ,HF_HOME=str(tmp_path/'other')):
        assert pinned_base(dict(base=str(base)))==base
