"""NVD-derived pilot data for L2 names, L3 versions, L4 CPE; not VEX tasks."""
import argparse
import hashlib
import json
import random
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.identification_tasks import identity_gold, version_gold


def build(out, train=512, val=64, test=64, seed=20261101, extend_from=None, replace=False):
    canonical=lambda value: re.sub('[^a-z0-9]','',str(value).lower())
    rng = random.Random(seed)
    source = ROOT / 'data/cpe_dictionary.jsonl'
    entries = {}; versions = set()
    for line in source.open(encoding='utf-8'):
        row = json.loads(line)
        cpe = row.get('cpe', ''); parts = cpe.split(':')
        if len(parts) != 13 or '\\' in cpe or parts[2] not in {'a', 'o', 'h'}: continue
        if row.get('vendor') in {'', '*', '-'}: continue
        entries.setdefault((row['vendor'], row['product']), row)
        v = row.get('version', '')
        if v and v not in {'*', '-'}: versions.add(v)
    identities = sorted(entries); rng.shuffle(identities)
    version_keys = sorted(versions); rng.shuffle(version_keys)
    sizes = {'train': train, 'val': val, 'test': test}
    if min(len(identities), len(version_keys)) < sum(sizes.values()):
        raise ValueError('Not enough disjoint product/version groups')
    out = Path(out)
    if (out/'manifest.json').exists() and not replace:
        raise FileExistsError('Dataset already exists; select a new --out to preserve earlier results')
    preserved={split:[] for split in sizes}
    chosen_ids={}; chosen_versions={}
    if extend_from:
        previous=Path(extend_from)
        for split in sizes:
            preserved[split]=[json.loads(l) for l in (previous/f'{split}.jsonl').read_text(encoding='utf-8').splitlines()]
        old_products={r['group'][1] for rows in preserved.values() for r in rows if r['task']=='L2'}
        old_versions={r['group'] for rows in preserved.values() for r in rows if r['task']=='L3'}
        # Preserve all earlier holdouts, including their original row contents.
        old_names={canonical(r['input']['name']) for rows in preserved.values() for r in rows if r['task']=='L2' and r['input']['name']}
        seen_products={canonical(p) for p in old_products}
        available_ids=[]
        for key in identities:
            product=canonical(key[1])
            if product in seen_products or product in old_names:continue
            seen_products.add(product); available_ids.append(key)
        def version_key(value):return re.sub(r'^[vV](?=\d)','',str(value).strip()).lower()
        seen_versions={version_key(v) for v in old_versions}
        available_versions=[]
        for key in version_keys:
            group=version_key(key)
            if group in seen_versions:continue
            seen_versions.add(group); available_versions.append(key)
        id_offset=version_offset=0
        for split,size in sizes.items():
            old_ids=[tuple(r['group']) for r in preserved[split] if r['task']=='L2']
            old_v=[r['group'] for r in preserved[split] if r['task']=='L3']
            if len(old_ids)!=len(old_v) or len(old_ids)>size:
                raise ValueError('Cannot shrink or misalign preserved groups')
            need=size-len(old_ids)
            chosen_ids[split]=old_ids+available_ids[id_offset:id_offset+need]
            chosen_versions[split]=old_v+available_versions[version_offset:version_offset+need]
            id_offset+=need; version_offset+=need
            if len(chosen_ids[split])!=size or len(chosen_versions[split])!=size:
                raise ValueError('Not enough additional groups')
    else:
        cursor=0
        for split,size in sizes.items():
            chosen_ids[split]=identities[cursor:cursor+size]
            chosen_versions[split]=version_keys[cursor:cursor+size]
            cursor+=size
    out.mkdir(parents=True, exist_ok=True)
    reserved_names={canonical(key[1]):key for keys in chosen_ids.values() for key in keys}
    observed_names={canonical(r['input']['name']):tuple(r['group']) for rows in preserved.values() for r in rows
                    if r['task']=='L2' and r['input']['name']}
    manifest = {'seed': seed, 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                'scope': 'pilot: NVD-derived and procedurally augmented; not independently reviewed real SBOM benchmark',
                'split_rule': 'L2/L4 by vendor-product identity; L3 by original version string', 'splits': {}}
    manifest['additional_separation']='new rows have canonical product/version group separation and nonempty L2 name separation; v1 rows are preserved'
    if extend_from:
        manifest['extends']={'path':str(Path(extend_from).resolve()),
                             'manifest_sha256':hashlib.sha256((Path(extend_from)/'manifest.json').read_bytes()).hexdigest(),
                             'earlier_rows_preserved':True}
    manifest['size_rationale']={'status':'planned experimental budget, not empirically optimal',
        'training_grid':[512,1024,2048,4096],
        'train':'geometric scaling to compare validation quality and compute cost',
        'val':'fixed model-selection holdout', 'test':'fixed final holdout; not for hyperparameter selection',
        'limitations':'synthetic distribution and repeated abstention inputs limit generalization claims'}
    for split, size in sizes.items():
        rows = []
        old_count=sum(r['task']=='L2' for r in preserved[split])
        old_by_id={r['id']:r for r in preserved[split]}
        for i, key in enumerate(chosen_ids[split]):
            if i<old_count:
                rows.extend(old_by_id[f'{split}-{task}-{i}'] for task in ('L2','L3','L4'))
                continue
            r = entries[key]; raw_title = r.get('title') or r['product'].replace('_', ' ')
            if r.get('version') and raw_title.endswith(' ' + r['version']):
                raw_title = raw_title[:-len(r['version'])].strip()
            # Multiple realistic inputs per group; the complete group stays in one split.
            text = raw_title if i % 2 else r['product'].replace('_', ' ')
            text_key=canonical(text)
            if (text_key in reserved_names and reserved_names[text_key]!=key) or (text_key in observed_names and observed_names[text_key]!=key):
                text=r['product'].replace('_',' ')
            missing_name=(i % 8 == 0 and not extend_from)
            if not missing_name:
                observed_names[canonical(text)]=key
            l2 = {'name': text, 'supplier': ''}
            gold = {'normalized': r['product'], 'status': 'resolved'}
            if missing_name:
                l2['name'] = ''; gold = {'normalized': None, 'status': 'unresolved'}
            rows.append({'id': f'{split}-L2-{i}', 'task': 'L2', 'group': list(key), 'input': l2, 'gold': gold})
            raw = chosen_versions[split][i]
            raw = [raw, 'v'+raw, ' '+raw+' ', raw+'-vendor3', raw+' HF2', 'V'+raw, raw+':rev2', raw if extend_from else 'NOASSERTION'][i % 8]
            rows.append({'id': f'{split}-L3-{i}', 'task': 'L3', 'group': chosen_versions[split][i],
                         'input': {'raw_version': raw}, 'gold': version_gold(raw)})
            candidate = {'cpe': r['cpe'], 'origin': 'nvd_dictionary'}
            candidates = [candidate]
            mode = i % 6
            if mode == 1: candidates = []
            elif mode == 2: candidates = [{'cpe': r['cpe'], 'origin': 'sbom_unverified'}]
            elif mode == 3:
                # Explicitly synthetic competing vendor: teaches rejection, not NVD truth.
                fields = r['cpe'].split(':'); fields[3] = 'synthetic_competing_vendor'
                candidates.append({'cpe': ':'.join(fields), 'origin': 'nvd_dictionary'})
            elif mode == 4: candidates.append(candidate.copy())
            payload = {'normalized_name': r['product'], 'candidates': candidates,
                       'lookup_error': 'timeout' if mode == 5 else None}
            rows.append({'id': f'{split}-L4-{i}', 'task': 'L4', 'group': list(key),
                         'input': payload, 'gold': identity_gold(payload)})
        path = out / f'{split}.jsonl'
        path.write_text(''.join(json.dumps(r, ensure_ascii=False)+'\n' for r in rows), encoding='utf-8')
        manifest['splits'][split] = {'per_task': size, 'total': len(rows), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    (out/'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    return manifest


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('--out', default=str(ROOT/'data/identification_agents'))
    p.add_argument('--train', type=int, default=512); p.add_argument('--val', type=int, default=64)
    p.add_argument('--test', type=int, default=64)
    p.add_argument('--extend-from',type=Path)
    p.add_argument('--replace',action='store_true',help='Explicitly replace generated data; never use on data of an active run')
    a = p.parse_args(); print(json.dumps(build(a.out, a.train, a.val, a.test, extend_from=a.extend_from,replace=a.replace), indent=2))
