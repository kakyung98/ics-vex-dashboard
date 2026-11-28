"""Snapshot, verify and restore the current ICS-VEX web runtime (Python 3.10+)."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PureWindowsPath
import platform
import re
import stat
import sys
import tempfile
import time
import zipfile


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = 'RELEASE_MANIFEST.json'
BLOCK = 8 * 1024 * 1024


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def safe_name(name):
    if not isinstance(name, str) or not name or '\\' in name or ':' in name:
        raise ValueError('Invalid release path')
    parts = name.split('/')
    if any(p in {'', '.', '..'} or p.rstrip('. ') != p or PureWindowsPath(p).is_reserved()
           or re.search(r'[\x00-\x1f<>|"?*]', p) for p in parts):
        raise ValueError('Invalid release path: ' + name)
    return name


def transfer(src, dst=None):
    h = hashlib.sha256()
    size = 0
    while block := src.read(BLOCK):
        h.update(block)
        size += len(block)
        if dst is not None:
            dst.write(block)
    return {'bytes': size, 'sha256': h.hexdigest()}


def environment_lock():
    from importlib import metadata
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name
    names = ['torch', 'torchvision', 'requests', 'kubernetes']
    for p in ('requirements-precision.txt', 'requirements-ncp.txt', 'requirements-ncp-transport.txt'):
        for line in (ROOT / p).read_text().splitlines():
            if line.strip() and not line.startswith(('#', '-')):
                name = Requirement(line).name
                if name != 'ipykernel':  # Optional training notebooks, outside the web runtime.
                    names.append(name)
    locked = {}
    while names:
        name = canonicalize_name(names.pop())
        if name in locked:
            continue
        package = metadata.distribution(name)
        locked[name] = package.version
        for raw in package.requires or []:
            req = Requirement(raw)
            if not req.marker or req.marker.evaluate({'extra': ''}):
                names.append(req.name)
    return {name: locked[name] for name in sorted(locked)}


def release_files():
    """Explicit source/public-data boundaries. Never traverse job stores or model caches."""
    files = {}
    pins = {}
    extensions = {'.py', '.js', '.cjs', '.json', '.jsonl', '.html', '.css', '.md', '.txt', '.svg',
                  '.gz', '.npy', '.npz', '.woff2', '.png', '.ico', '.xml', '.map'}
    for directory in ['src', 'tests', 'tools', 'site', 'schemas', 'icsa/csaf', 'data/cisa_identification_csaf',
                      'data/standards', 'data/nist_auto_vex', 'data/cwe_taxonomy', 'data/item3_identification_sources_v11',
                      'data/icsa_sbom_source_html', 'data/runtime/icsa_fixed18_improvement_v2',
                      'data/runtime/icsa_fixed18_reclassification']:
        for path in (ROOT / directory).rglob('*'):
            if (path.is_file() and path.suffix.lower() in extensions
                    and not {'__pycache__', '.pytest_cache', 'node_modules'}.intersection(path.parts)):
                files[path.relative_to(ROOT).as_posix()] = path
    for p in (ROOT / 'docs').iterdir():
        if p.is_file() and p.suffix in {'.md', '.json'}:
            files[p.relative_to(ROOT).as_posix()] = p
    local_manifest = 'local-service/runtime_manifest.json'
    required = [local_manifest, 'README.md', '.gitignore', 'data/identification_runtime.json',
                'data/cpe_dictionary.jsonl', 'data/cisa_advisories.json', 'data/cisa_reference_manifest.json',
                'data/operator_asset_keys.csv.gz', 'data/identity_aliases_v3.json']
    required.extend(p.name for p in ROOT.glob('requirements*.txt'))
    required.extend(json.loads((ROOT / local_manifest).read_bytes())['files'])
    files.update({safe_name(n): ROOT / n for n in required})
    reference = json.loads(files['data/cisa_reference_manifest.json'].read_bytes())
    pins['data/cisa_advisories.json'] = reference['index_sha256']
    advisories = json.loads(files['data/cisa_advisories.json'].read_bytes())
    for advisory_id, row in advisories.items():
        if row['source'] == 'CISA CSAF':
            names = [f'{folder}/{advisory_id}.json' for folder in ('icsa/csaf', 'data/cisa_identification_csaf')]
        elif row['source'] == 'CISA HTML':
            names = [f'data/icsa_sbom_source_html/{advisory_id}.html']
        else:
            raise ValueError('Unrecognized advisory source: ' + advisory_id)
        for name in names:
            pins[safe_name(name)] = row['source_raw_sha256']
    atom_root = 'data/item3_identification_sources_v11/'
    pins[atom_root + 'cves.jsonl'] = json.loads(files[atom_root + 'manifest.json'].read_bytes())['sha256']
    for n in ('data/nist_population_vex_v3/catalog.sqlite3', 'data/nist_population_vex_v3/manifest.json'):
        if (ROOT / n).is_file():
            files[n] = ROOT / n

    roles_path = 'data/prerequisite_adapter_roles.json'
    roles = json.loads((ROOT / roles_path).read_bytes())
    roles.pop('storage_roots', None)
    identity_path = 'models/precision_roles_qwen25_14b_v1'
    adapters = {identity_path: ROOT / identity_path}
    for role in roles['roles'].values():
        path = ROOT / role['path']
        if role['enabled']:
            relative = 'models/' + path.name
            adapters[relative] = path
            role['path'] = relative
        for key in ('dataset', 'training_run', 'evaluation_report'):
            role.pop(key, None)
    files[roles_path] = encoded(roles)
    base_pin = json.loads((ROOT / identity_path / 'training_complete.json').read_bytes())
    sys.path.insert(0, str(ROOT))
    from src.common.model_paths import pinned_base
    base = pinned_base(base_pin)
    for p in base.iterdir():
        if p.is_file() and p.suffix in {'.json', '.txt', '.safetensors', '.jinja', '.model'}:
            files['models/base_model/' + p.name] = p
    for key, sha in base_pin['base_files_sha256'].items():
        pins['models/base_model/'+safe_name(key)] = sha
    for relative, directory in adapters.items():
        marker = json.loads((directory / 'training_complete.json').read_bytes())
        cfg = json.loads((directory / 'adapter_config.json').read_bytes())
        model_pins = marker.get('base_files_sha256', {})
        for key, sha in model_pins.items():
            name = 'models/base_model/' + safe_name(key)
            if name in pins and pins[name] != sha:
                raise ValueError('Adapter does not match the pinned base: ' + relative)
            pins[name] = sha
        weight_name = relative + '/adapter_model.safetensors'
        files[weight_name] = directory / 'adapter_model.safetensors'
        pins[weight_name] = marker['adapter_sha256']
        marker['base'] = cfg['base_model_name_or_path'] = 'models/base_model'
        for key in ('base_path','training_base','base_relocation','evaluation_report'):
            marker.pop(key, None)
        files[relative+'/training_complete.json'] = encoded(marker)
        files[relative+'/adapter_config.json'] = encoded(cfg)
        for name in ('tokenizer.json','tokenizer_config.json','chat_template.jinja','special_tokens_map.json',
                     'added_tokens.json','vocab.json','merges.txt','evaluation.json','import_receipt.json'):
            p = directory / name
            if p.is_file():
                if name == 'import_receipt.json':
                    receipt = json.loads(p.read_bytes())
                    receipt.pop('source', None)
                    files[relative+'/'+name] = encoded(receipt)
                else:
                    files[relative+'/'+name] = p
    if missing := pins.keys() - files.keys():
        raise ValueError(f'Missing pinned files: {sorted(missing)}')
    lock = environment_lock()
    files['requirements-runtime.lock'] = ''.join(f'{k}=={v}\n' for k,v in lock.items()).encode()
    info = dict(python=platform.python_version(), platform=platform.platform(), dependencies=lock,
                entry_point='python -X utf8 -B tools/item4/serve_nist_operational_vex.py 8100',
                working_directory='restored project root', external_runtime='MulVAL/XSB with native, Docker, or user-configured NCP backend')
    return files, pins, info


def create(archive):
    archive = archive.resolve()
    if archive.exists():
        raise FileExistsError(archive)
    files, pins, info = release_files()
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=archive.parent) as tmp:
        stage = Path(tmp) / 'snapshot.zip'
        manifest = dict(format='ics-vex-runtime/1', environment=info, files={})
        with zipfile.ZipFile(stage, 'x', allowZip64=True) as output:
            for name, source in sorted(files.items()):
                safe_name(name)
                if isinstance(source, Path):
                    stream = source.open('rb')
                else:
                    stream = io.BytesIO(source)
                with stream, output.open(name,'w',force_zip64=True) as target:
                    meta = transfer(stream, target)
                if name in pins and meta['sha256'] != pins[name]:
                    raise ValueError('Pinned input hash mismatch: ' + name)
                manifest['files'][name] = meta
            raw = encoded(manifest)
            output.writestr(MANIFEST, raw)
        # Create the final name atomically without replacing an existing release.
        os.link(stage, archive)
    return summary(archive, manifest, raw)


def summary(archive, manifest, raw):
    return dict(archive=str(archive), manifest_sha256=hashlib.sha256(raw).hexdigest(),
                files=len(manifest['files']), bytes=sum(x['bytes'] for x in manifest['files'].values()))


def publish_tree(stage, destination):
    if destination.exists():
        destination.rmdir()  # Fails if another process populated it.
    deadline = time.monotonic() + 90
    while True:
        try:
            stage.rename(destination)
            return
        except PermissionError as exc:
            # Windows scanners briefly hold child files after a large extraction.
            if os.name != 'nt' or exc.winerror not in (5, 32, 33) or time.monotonic() >= deadline:
                raise
            time.sleep(1)


def verify_or_restore(archive, expected, destination=None):
    archive = archive.resolve(strict=True)
    if destination is not None:
        destination = destination.absolute()
        if destination.is_symlink() or destination.resolve() != destination:
            raise ValueError('Restore destination must be a direct filesystem path')
        if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
            raise FileExistsError('Restore destination must be empty or new')
        destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as z:
        entries = z.infolist()
        if any(stat.S_ISLNK(i.external_attr >> 16) for i in entries):
            raise ValueError('Release archive contains a symbolic link')
        members = [safe_name(i.orig_filename) for i in entries]
        if len({n.casefold() for n in members}) != len(members) or MANIFEST not in members:
            raise ValueError('Duplicate members or missing release manifest')
        raw = z.read(MANIFEST)
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Release manifest hash mismatch')
        manifest = json.loads(raw)
        files = manifest['files']
        if set(members) != set(files) | {MANIFEST} or MANIFEST in files or manifest['format'] != 'ics-vex-runtime/1':
            raise ValueError('Manifest/member mismatch')
        with tempfile.TemporaryDirectory(dir=destination.parent if destination is not None else None) as tmp:
            stage = Path(tmp)
            for name, expected_file in files.items():
                if z.getinfo(name).file_size != expected_file['bytes']:
                    raise ValueError('Size mismatch: ' + name)
                with z.open(name) as src:
                    if destination is None:
                        observed = transfer(src)
                    else:
                        p = stage / name
                        p.parent.mkdir(parents=True, exist_ok=True)
                        with p.open('xb') as dst:
                            observed = transfer(src, dst)
                if observed != expected_file:
                    raise ValueError('Content mismatch: ' + name)
            if destination is not None:
                (stage / MANIFEST).write_bytes(raw)
                publish_tree(stage, destination)
        return summary(archive, manifest, raw)


def preflight():
    """Start the application in process with isolated user state and no live network."""
    from importlib import metadata
    manifest = json.loads((ROOT / MANIFEST).read_bytes())
    mismatches = {k:v for k,v in manifest['environment']['dependencies'].items() if metadata.version(k) != v}
    if platform.python_version() != manifest['environment']['python'] or mismatches:
        raise ValueError('Restored environment differs from recorded dependency pins: ' + str(mismatches))
    sys.path.insert(0, str(ROOT))
    os.chdir(ROOT)
    with tempfile.TemporaryDirectory() as tmp:
        os.environ['LOCALAPPDATA'] = tmp
        for key in list(os.environ):
            if key.startswith(('ICSVEX_','ICS_PREREQUISITE_')) or key in {'HF_HUB_CACHE','HF_HOME'}:
                os.environ.pop(key)
        os.environ['HF_HOME'] = str(Path(tmp) / 'hf')
        os.environ['HF_HUB_OFFLINE'] = '1'
        from fastapi.testclient import TestClient
        from tools.item4.serve_nist_operational_vex import app
        from src.common.model_paths import pinned_base
        marker = json.loads((ROOT/'models/precision_roles_qwen25_14b_v1/training_complete.json').read_bytes())
        if pinned_base(marker).resolve() != (ROOT/'models/base_model').resolve():
            raise ValueError('Restored base resolves outside release')
        with TestClient(app) as client:
            routes = {}
            for url in ('/index.html','/item4.html','/api/item4/analyses/asset-keys',
                        '/api/operational-vex/llm-status'):
                response = client.get(url)
                response.raise_for_status()
                routes[url] = response.status_code
            status = response.json()
            if not status['enabled'] or not status['policy']['provider']['weights_available']:
                raise ValueError('Restored inference runtime configuration is unavailable')
            roles = {r['role']:r for r in status['role_adapters']}
            active = roles['exploitation-prerequisites']
            configured = json.loads((ROOT/'data/prerequisite_adapter_roles.json').read_bytes())['roles']['exploitation-prerequisites']
            if active['enabled'] != configured['enabled'] or active['evaluation_passed'] != configured.get('evaluation_passed'):
                raise ValueError('Restored extraction adapter does not match configuration')
            return dict(routes=routes, dependency_pins=len(manifest['environment']['dependencies']),
                        extracted_adapter_enabled=active['enabled'], evaluation_passed=active['evaluation_passed'],
                        base='models/base_model', gpu_inference_exercised=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='action', required=True)
    for name in ('create','verify','restore'):
        p = subs.add_parser(name)
        p.add_argument('archive', type=Path)
        if name != 'create':
            p.add_argument('manifest_sha256')
        if name == 'restore':
            p.add_argument('destination', type=Path)
    subs.add_parser('preflight')
    a = parser.parse_args()
    if a.action == 'preflight':
        result = preflight()
    elif a.action == 'create':
        result = create(a.archive)
    else:
        result = verify_or_restore(a.archive, a.manifest_sha256, getattr(a, 'destination', None))
    print(json.dumps(result, ensure_ascii=False))
