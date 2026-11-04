import json
import pytest
from src.dataset_paths import public_sbom_directory,public_sbom_file


def test_snapshot_pointer_selects_retained_documents_and_rejects_escape(tmp_path):
    folder=tmp_path/'data/public_sbom/current/documents';folder.mkdir(parents=True)
    (folder/'sample.json').write_text('{}')
    index=tmp_path/'sbom_index.json'
    index.write_text(json.dumps({'source_directory':'data/public_sbom/current/documents'}))
    assert public_sbom_directory(tmp_path)==folder
    assert public_sbom_file('sample.json',tmp_path)==folder/'sample.json'
    for name in ['../sample.json','dir/sample.json',r'dir\sample.json','sample.txt']:
        with pytest.raises(ValueError):public_sbom_file(name,tmp_path)
    index.write_text(json.dumps({'source_directory':'results'}))
    with pytest.raises(ValueError):public_sbom_directory(tmp_path)


def test_missing_pointer_does_not_fall_back_to_retired_data(tmp_path):
    with pytest.raises(FileNotFoundError):public_sbom_directory(tmp_path)
    (tmp_path/'sbom_index.json').write_text('{}')
    with pytest.raises(ValueError):public_sbom_directory(tmp_path)
