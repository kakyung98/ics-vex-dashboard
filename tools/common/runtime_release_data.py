"""Restore the separately pinned public advisory SBOM dataset into a verified base release."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import zipfile

try:
    from tools.common import runtime_release as release
except ImportError:
    from tools.common import runtime_release as release


DATASET = 'icsa-cpe-synthetic sbom'
DOWNLOAD = 'icsa-advisory-products-sbom-v2-reviewed.zip'


def package(output):
    output = output.resolve()
    if output.exists():
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    artifacts = [Path(__file__).resolve(), Path(release.__file__).resolve(),
                 release.ROOT / 'benchmark' / DATASET / DOWNLOAD]
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        staged = Path(tmp) / 'supplement.zip'
        members = {}
        with zipfile.ZipFile(staged, 'x') as z:
            for path in artifacts:
                with path.open('rb') as src, z.open(path.name, 'w') as dst:
                    members[path.name] = release.transfer(src, dst)
        with staged.open('rb') as src:
            digest = release.transfer(src)
        os.link(staged, output)
    return dict(archive=str(output), archive_sha256=digest['sha256'], archive_bytes=digest['bytes'], files=members)


def restore(root, base_sha, archive, archive_sha):
    root = root.resolve(strict=True)
    raw = (root / release.MANIFEST).read_bytes()
    if hashlib.sha256(raw).hexdigest() != base_sha:
        raise ValueError('Base manifest SHA-256 differs')
    files = json.loads(raw)['files']
    cache_name = 'site/sbom_index.json'
    cache_raw = (root / cache_name).read_bytes()
    if hashlib.sha256(cache_raw).hexdigest() != files[cache_name]['sha256']:
        raise ValueError('Base dataset cache differs from the release manifest')
    cache = json.loads(cache_raw)
    parent = root / 'benchmark'
    if parent.resolve() != parent:
        raise ValueError('Invalid dataset destination')
    parent.mkdir(exist_ok=True)
    destination = parent / DATASET
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    with archive.open('rb') as src, tempfile.TemporaryDirectory(dir=parent) as tmp:
        stage = Path(tmp)
        # Publish the same archive the download route advertises and verify those exact bytes.
        copy = stage / DOWNLOAD
        with copy.open('xb') as dst:
            actual = release.transfer(src, dst)
        if actual['sha256'] != archive_sha:
            raise ValueError('Dataset archive SHA-256 differs')
        with zipfile.ZipFile(copy) as z:
            entries = z.infolist()
            names = [release.safe_name(i.orig_filename) for i in entries]
            if (len(set(n.casefold() for n in names)) != len(names)
                    or any(stat.S_ISLNK(i.external_attr >> 16) for i in entries)):
                raise ValueError('Ambiguous or linked dataset members')
            index_raw = z.read('index.json')
            index_sha = hashlib.sha256(index_raw).hexdigest()
            if cache['source_index_sha256'] != index_sha:
                raise ValueError('Dataset index differs from the serving cache')
            index = json.loads(index_raw)
            rows = index['advisories']
            pins = {release.safe_name(r['file']): r['sha256'] for r in rows}
            if len(pins) != len(rows) or {n for n in names if n.startswith('sbom/')} != set(pins):
                raise ValueError('Incomplete or duplicate dataset SBOM set')
            for info in entries:
                path = stage / info.filename
                path.parent.mkdir(parents=True, exist_ok=True)
                with z.open(info) as source, path.open('xb') as target:
                    meta = release.transfer(source, target)
                if info.filename in pins and meta['sha256'] != pins[info.filename]:
                    raise ValueError('Dataset SBOM fingerprint mismatch: ' + info.filename)
        release.publish_tree(stage, destination)
    return dict(dataset=str(destination), public_archive_sha256=archive_sha,
                base_manifest_sha256=base_sha, index_sha256=index_sha,
                sboms_verified=len(pins), archive_contents_verified=len(names))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest='action', required=True)
    commands.add_parser('create').add_argument('output', type=Path)
    r = commands.add_parser('restore')
    r.add_argument('base_directory', type=Path)
    r.add_argument('base_manifest_sha256')
    r.add_argument('dataset_zip', type=Path)
    r.add_argument('dataset_sha256')
    args = p.parse_args()
    result = package(args.output) if args.action == 'create' else restore(
        args.base_directory, args.base_manifest_sha256, args.dataset_zip, args.dataset_sha256)
    print(json.dumps(result, ensure_ascii=False))
