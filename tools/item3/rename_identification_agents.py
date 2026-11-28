"""Migrate identification roles to I1/name, I2/version and I3/identifiers.

Source products, benchmark inputs, binary model weights and archived evidence
are not agent labels. Keep those records intact and normalize old role fields
when reading historical analysis results.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
import hashlib
import json
import re
import shutil

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'outputs/identification_role_rename_20261125'
TOKEN = re.compile(r'(?<![A-Za-z0-9])([Pp])([234])(?=[^A-Za-z0-9]|$)(?!-\d)')
COMBINED = re.compile(r'(?<![A-Za-z0-9])([Pp])234(?=[^A-Za-z0-9]|$)')
HTML_DATA = re.compile(r'(<div\b[^>]*(?:\bhidden\b|\bid=[\"\'][^\"\']*-data[\"\'])[^>]*>)(\s*(?:\{|\[).*?)(</div>)', re.S | re.I)
HML_DATA = re.compile(r'(<BINDATA\b[^>]*>)(.*?)(</BINDATA>)', re.S)
EXCLUDED_PARTS = {'archive', 'backups', 'source_before', '__pycache__', 'node_modules', '.git', '.pytest_cache'}
RENAMES = {'src/p2_candidates.py': 'src/item3/matching/product_candidate_ranking.py',
           'tools/benchmark_item3_p234.py': 'tools/item3/benchmark_item3_i123.py',
           'tools/build_item3_precision_p234.py': 'tools/item3/build_item3_precision_i123.py'}


def rename_text(text):
    # This literal is a reproducibility seed, not a displayed agent role.
    seed = 'p3-stratum-v1'
    text = text.replace(seed, '__UNCHANGED_VERSION_STRATUM_SEED__')
    text = COMBINED.sub(lambda m: ('I' if m[1] == 'P' else 'i') + '123', text)
    text = TOKEN.sub(lambda m: ('I' if m[1] == 'P' else 'i') + str(int(m[2]) - 1), text)
    text = re.sub(r'(?<![A-Za-z0-9])([Cc])([123])(?=[^A-Za-z0-9]|$)(?!-\d)',
                  lambda m: ('I' if m[1].isupper() else 'i') + m[2], text)
    return text.replace('__UNCHANGED_VERSION_STRATUM_SEED__', seed)


def update(path):
    original = path.read_bytes()
    try:
        text = original.decode('utf-8-sig')
    except UnicodeDecodeError:
        return None
    saved = []
    if path.suffix in {'.html', '.hml'}:
        def hold(match):
            saved.append(match[2])
            return match[1] + f'__SOURCE_JSON_{len(saved)-1}__' + match[3]
        text = (HTML_DATA if path.suffix == '.html' else HML_DATA).sub(hold, text)
    updated = rename_text(text)
    for i, value in enumerate(saved):
        updated = updated.replace(f'__SOURCE_JSON_{i}__', value)
    data = (b'\xef\xbb\xbf' if original.startswith(b'\xef\xbb\xbf') else b'') + updated.encode('utf-8')
    if data == original:
        return None
    relative = path.relative_to(ROOT)
    backup = OUT / 'before' / relative
    backup.parent.mkdir(parents=True, exist_ok=True)
    if backup.exists():
        raise FileExistsError('Refusing to overwrite migration backup: ' + str(backup))
    shutil.copy2(path, backup)
    path.write_bytes(data)
    return dict(path=relative.as_posix(), before_sha256=hashlib.sha256(original).hexdigest(),
                after_sha256=hashlib.sha256(data).hexdigest())


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    files = [ROOT / 'README.md']
    for folder in ['src', 'tools', 'tests', 'docs', 'site', 'local-service', 'outputs']:
        for path in (ROOT / folder).rglob('*'):
            if not path.is_file() or path.suffix not in {'.py', '.js', '.cjs', '.html', '.md', '.txt', '.hml'}:
                continue
            parts = set(path.relative_to(ROOT).parts)
            if parts & EXCLUDED_PARTS or path == Path(__file__) or OUT in path.parents:
                continue
            if any('before' in p.lower() or 'original' in p.lower() for p in path.relative_to(ROOT).parts):
                continue
            # These are source-expression atom IDs, unrelated to identification agents.
            if path.name in {'test_item4_ox_benchmark.py', 'test_vep_llm.py'}:
                continue
            files.append(path)
    changed = []
    for path in files:
        if path.exists():
            entry = update(path)
            if entry:
                changed.append(entry)
    for old, new in RENAMES.items():
        source, target = ROOT / old, ROOT / new
        if source.exists():
            if target.exists():
                raise FileExistsError(str(target))
            source.rename(target)
    (OUT / 'source_manifest.json').write_text(json.dumps(dict(
        roles={'I1': 'Component name', 'I2': 'Version', 'I3': 'CPE and purl identifiers'},
        changed=changed, renames=RENAMES, source_evidence_and_model_weights_preserved=True),
        ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(dict(changed_files=len(changed), renamed_files=len(RENAMES))))


if __name__ == '__main__':
    main()
