"""Project paths and hash-checked historical source receipts after relocation."""
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import zipfile

PROJECT_ROOT=Path(__file__).resolve().parents[2]

@lru_cache(maxsize=1)
def source_layout():
    return json.loads((PROJECT_ROOT/'src/layout.json').read_bytes())

def source_path(name, *, root=None):
    """Locate maintained source; allow isolated fixtures with their original layout."""
    root=Path(root) if root is not None else PROJECT_ROOT
    name=str(name).replace('\\','/')
    if name.startswith('src/'):name=name[4:]
    if Path(name).is_absolute() or '..' in Path(name).parts:
        raise ValueError('Source path must stay within src.')
    original=root/'src'/name
    if root.resolve()!=PROJECT_ROOT and original.is_file():return original
    return root/'src'/source_layout().get(name,name)

def sealed_source_receipt(name, expected_sha256):
    """Verify exact bytes, identifying whether they are live or historical source.

    An archive match establishes the original run's source integrity; it never
    claims that today's refactored implementation has the same fingerprint.
    """
    name=str(name).replace('\\','/')
    key=name if '/' in name else 'src/'+name
    if Path(key).is_absolute() or '..' in Path(key).parts:
        raise ValueError('Invalid sealed source path.')
    if key.startswith('src/'):
        current=source_path(key)
    elif key.startswith('tools/'):
        from tools.common.paths import tool_path
        current=tool_path(key)
    else:
        current=PROJECT_ROOT/key
    if current.is_file() and hashlib.sha256(current.read_bytes()).hexdigest()==expected_sha256:
        return dict(kind='current',path=current.relative_to(PROJECT_ROOT).as_posix(),sha256=expected_sha256)
    for filename in ['source_names_20261123_before.zip','matching_engine_merge_20261123_before.zip','functional_layout_20261123_before.zip','tools_tests_layout_20261123_before.zip','source_layout_20261123_before.zip','source_cleanup_20261123_before.zip']:
        archive=PROJECT_ROOT/'research_records'/filename
        if not archive.is_file():continue
        with zipfile.ZipFile(archive) as stream:
            try:raw=stream.read(key)
            except KeyError:continue
        if hashlib.sha256(raw).hexdigest()==expected_sha256:
            return dict(kind='historical_snapshot',path=archive.relative_to(PROJECT_ROOT).as_posix(),
                        member=key,sha256=expected_sha256)
    raise ValueError('No source with the recorded SHA-256: '+key)
