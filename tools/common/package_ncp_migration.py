"""Create a hashed, secret-excluding migration snapshot without changing source files."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import argparse
from contextlib import closing
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = {'.git', '.pytest_cache', '__pycache__', '.venv', 'venv', 'node_modules', '.ipynb_checkpoints', 'cloud_migration'}
SECRET_NAMES = {'credentials', 'id_rsa', 'id_ed25519', 'kubeconfig', 'kubeconfig.yaml', 'kubeconfig.yml'}


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(8 * 1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def excluded(path, root, allow_cache_links=False):
    rel = path.relative_to(root)
    safe_link = allow_cache_links and path.resolve().is_relative_to(root.parent.parent/'blobs')
    return (any(p in SKIP_DIRS for p in rel.parts) or (path.is_symlink() and not safe_link)
            or path.name.lower() in SECRET_NAMES or path.name.startswith('.env')
            or path.suffix.lower() in {'.pem', '.key', '.pfx', '.p12', '.pyc'}
            or path.name.endswith(('-wal', '-shm')))


def build(root, output, prefix, allow_cache_links=False):
    records, skipped = [], []
    files = sorted(root.rglob('*'))
    partial = output.with_suffix('.partial')
    options = dict(mode='w:gz', compresslevel=1) if output.name.endswith('.gz') else dict(mode='w')
    options['dereference'] = True
    with tarfile.open(partial, **options) as tar, tempfile.TemporaryDirectory(prefix='ics-vex-snapshot-', dir=output.parent) as tmp:
        for path in files:
            if not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if excluded(path, root, allow_cache_links):
                skipped.append(rel)
                continue
            source, mode = path, 'file'
            # WAL-backed databases must be captured through SQLite, including committed WAL pages.
            if path.suffix in {'.sqlite3', '.db'}:
                source = Path(tmp) / 'snapshot.sqlite3'
                if source.exists():
                    source.unlink()
                with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db, closing(sqlite3.connect(source)) as target:
                    db.backup(target)
                mode = 'sqlite-consistent-backup'
            before = source.stat()
            sha = digest(source)
            tar.add(source, arcname=f'{prefix}/{rel}', recursive=False)
            after = source.stat()
            if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
                raise RuntimeError('File changed during snapshot: ' + rel)
            records.append(dict(path=rel, bytes=before.st_size, sha256=sha, snapshot=mode))
            if len(records) % 1000 == 0:
                print(json.dumps(dict(stage=prefix, files=len(records))), flush=True)
        manifest = dict(format=1, created_unix=time.time(), prefix=prefix, files=records, excluded=skipped,
                        sqlite_policy='Consistent SQLite backup; historical logical contents preserved, file bytes may differ')
        wire = json.dumps(manifest, ensure_ascii=False, indent=2).encode()
        info = tarfile.TarInfo(f'{prefix}/MIGRATION_INVENTORY.json')
        info.size = len(wire)
        tar.addfile(info, io.BytesIO(wire))
    partial.replace(output)
    summary = dict(archive=str(output), bytes=output.stat().st_size, sha256=digest(output), files=len(records), excluded=len(skipped))
    output.with_suffix('.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT/'results/cloud_migration')
    parser.add_argument('--base-only', action='store_true')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if not args.base_only:
        build(ROOT, args.output/'project.tar.gz', 'project')
    build(args.base, args.output/'base_model.tar', 'base_model', allow_cache_links=True)
