"""Verify the migrated snapshot and relocate only working-copy model metadata."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import runpy
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(8*1024*1024), b''):
            h.update(b)
    return h.hexdigest()


def verify_tree(root):
    manifest = json.loads((root/'MIGRATION_INVENTORY.json').read_text(encoding='utf-8'))
    for row in manifest['files']:
        path = root/row['path']
        if path.stat().st_size != row['bytes'] or sha(path) != row['sha256']:
            raise ValueError('Migration content mismatch: '+str(path))
    return len(manifest['files'])


def relocate():
    base = ROOT.parent/'base_model'
    report = dict(verified_files=verify_tree(ROOT), verified_base_files=verify_tree(base), changes=[], timestamp=time.time())
    originals = ROOT/'results/cloud_migration/original_metadata'
    for folder in sorted((ROOT/'models').iterdir()):
        if not folder.is_dir():
            continue
        for name, key in [('training_complete.json','base'), ('adapter_config.json','base_model_name_or_path')]:
            path = folder/name
            if not path.exists():
                continue
            content = path.read_bytes()
            data = json.loads(content)
            if key not in data:
                continue
            backup = originals/folder.name/name
            backup.parent.mkdir(parents=True, exist_ok=True)
            backup.write_bytes(content)
            old = data[key]
            data[key] = str(base)
            path.write_text(json.dumps(data, indent=2)+'\n', encoding='utf-8')
            report['changes'].append(dict(path=str(path.relative_to(ROOT)), key=key, old=old, new=str(base), before=hashlib.sha256(content).hexdigest(), after=sha(path)))
    target = ROOT/'results/cloud_migration/relocation.json'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report))


def verify_historical(script):
    # Original Windows manifest keys stay byte-identical; translate only path joins
    # in this isolated verifier process. Do not rewrite sealed manifests or code.
    original = Path.__truediv__
    def join(self, key):
        if isinstance(key, str) and '\\' in key and not PureWindowsPath(key).is_absolute():
            key = key.replace('\\', '/')
        return original(self, key)
    Path.__truediv__ = join
    os.chdir(ROOT)
    sys.path.insert(0, str(ROOT))
    try:
        runpy.run_path(str(ROOT/script), run_name='__main__')
    finally:
        Path.__truediv__ = original


if __name__ == '__main__':
    if len(sys.argv)>1 and sys.argv[1]=='verify-historical':
        verify_historical(sys.argv[2])
    else:
        relocate()
