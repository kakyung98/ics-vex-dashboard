import hashlib
import zipfile

import pytest
from tools.common import runtime_release as R


def test_release_roundtrip_requires_pinned_manifest_and_empty_destination(tmp_path, monkeypatch):
    payload = b'example'
    checksum = hashlib.sha256(payload).hexdigest()
    monkeypatch.setattr(R, 'release_files', lambda: ({'src/sample.py':payload}, {'src/sample.py':checksum}, {}))
    archive = tmp_path / 'app.zip'
    receipt = R.create(archive)
    with pytest.raises(FileExistsError):
        R.create(archive)
    out = tmp_path / 'restored'
    with pytest.raises(ValueError, match='manifest hash'):
        R.verify_or_restore(archive, '0' * 64, out)
    assert not out.exists()
    R.verify_or_restore(archive, receipt['manifest_sha256'], out)
    assert (out/'src/sample.py').read_bytes() == payload
    with pytest.raises(FileExistsError):
        R.verify_or_restore(archive, receipt['manifest_sha256'], out)


def test_release_creation_rejects_changed_pinned_input(tmp_path, monkeypatch):
    monkeypatch.setattr(R, 'release_files', lambda: ({'ref.json': b'changed'}, {'ref.json': '0' * 64}, {}))
    archive = tmp_path / 'app.zip'
    with pytest.raises(ValueError, match='Pinned input hash'):
        R.create(archive)
    assert not archive.exists()


def test_restore_discards_partial_extraction_after_changed_content(tmp_path):
    names = ['src/first', 'src/second']
    file_meta = {'bytes': 1, 'sha256': hashlib.sha256(b'x').hexdigest()}
    raw = R.encoded({'format': 'ics-vex-runtime/1', 'files': dict.fromkeys(names, file_meta)})
    archive = tmp_path / 'changed.zip'
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr(names[0], b'x')
        z.writestr(names[1], b'y')
        z.writestr(R.MANIFEST, raw)
    out = tmp_path / 'restored'
    out.mkdir()
    with pytest.raises(ValueError, match='Content mismatch'):
        R.verify_or_restore(archive, hashlib.sha256(raw).hexdigest(), out)
    assert list(out.iterdir()) == []


def test_restore_rejects_symlink_metadata(tmp_path):
    archive = tmp_path / 'link.zip'
    entry = zipfile.ZipInfo('link')
    entry.create_system = 3
    entry.external_attr = 0o120777 << 16
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr(entry, '../outside')
    with pytest.raises(ValueError, match='symbolic link'):
        R.verify_or_restore(archive, '0' * 64)


@pytest.mark.parametrize('name', ['../escape', '/absolute', 'sub/../escape', 'C:stream', 'NUL.txt', 'dir\\file'])
def test_restore_rejects_unsafe_paths(tmp_path, name):
    archive = tmp_path/'input.zip'
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr(name,b'bad')
    if '\\' in name:
        # The Windows ZIP writer normalizes backslashes at creation. Test a foreign archive.
        archive.write_bytes(archive.read_bytes().replace(name.replace('\\','/').encode(), name.encode()))
    with pytest.raises(ValueError, match='Invalid release path'):
        R.verify_or_restore(archive, '0'*64, tmp_path/'output')
    assert not (tmp_path/'output').exists()
