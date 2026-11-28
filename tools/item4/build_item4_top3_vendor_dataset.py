"""Build the #4 top-3 vendor precision dataset from explicit CSAF product statuses.

Ground truth comes only from explicit supplier ``product_status`` rows
(known_affected / fixed / known_not_affected) in the local CISA CSAF mirror.
The concrete running version of each asset is chosen by an independent parser
in this file, not by the system's version parser, so the evaluation also tests
the system's version membership logic.

Selection is fixed before any system output is seen: deduplicate assets,
then draw a seeded uniform random sample per vendor. No case is kept or dropped
based on the system's result.

    python -B -X utf8 tools/item4/build_item4_top3_vendor_dataset.py
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import random
import uuid
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CSAF_DIR = ROOT / 'data/cisa_identification_csaf'
OUT = ROOT / 'benchmark/item4_evaluation/top3_vendor_precision_v1'
VERSION = 'item4-top3-vendor-precision-dataset/1'
VENDORS = ('Siemens', 'Rockwell Automation', 'Schneider Electric')
STATUSES = ('known_affected', 'fixed', 'known_not_affected')
SEED = 20261126
ASSETS_PER_VENDOR = 250
MAX_CVES_PER_ASSET = 20

NUM = r'V?\d+(?:\.\d+)*'
RE_ANY = re.compile(r'^\*$|^all versions$', re.I)
RE_LT = re.compile(rf'^<\s*({NUM})$')
RE_LE = re.compile(rf'^<=\s*({NUM})$')
RE_GE = re.compile(rf'^>=\s*({NUM})$')
RE_EQ = re.compile(rf'^=?\s*({NUM})$')
RE_RANGE = re.compile(rf'^>=\s*({NUM})\s*(?:\||_and_|,)?\s*(<=?)\s*({NUM})$')


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(value) -> str:
    return sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode())


# ---------------------------------------------------------------- versions --
def parts(token: str) -> tuple[str, list[str]]:
    prefix = 'V' if token[:1] in 'vV' else ''
    return prefix, token.lstrip('vV').split('.')


def key(token: str) -> tuple[int, ...]:
    values = [int(p) for p in parts(token)[1]]
    while len(values) > 1 and values[-1] == 0:
        values.pop()
    return tuple(values)


def compare(a: str, b: str) -> int:
    ka, kb = key(a), key(b)
    width = max(len(ka), len(kb))
    ka, kb = ka + (0,) * (width - len(ka)), kb + (0,) * (width - len(kb))
    return (ka > kb) - (ka < kb)


def below(token: str) -> str | None:
    """Largest-looking release under ``token`` by decrementing the last nonzero part."""
    prefix, fields = parts(token)
    for i in range(len(fields) - 1, -1, -1):
        if int(fields[i]) > 0:
            fields[i] = str(int(fields[i]) - 1).zfill(len(fields[i]))
            return prefix + '.'.join(fields)
    return None


def predicate(expression: str):
    """Independent grammar. Returns None for anything outside it."""
    text = re.sub(r'^vers:[a-z]+/', '', expression.strip(), flags=re.I).strip()
    if RE_ANY.match(text):
        return ('any',)
    for pattern, kind in ((RE_RANGE, 'range'), (RE_LT, 'lt'), (RE_LE, 'le'), (RE_GE, 'ge'), (RE_EQ, 'eq')):
        m = pattern.match(text)
        if m:
            return (kind, *m.groups())
    return None


def member(pred, version: str) -> bool:
    kind = pred[0]
    if kind == 'any':
        return True
    if kind == 'lt':
        return compare(version, pred[1]) < 0
    if kind == 'le':
        return compare(version, pred[1]) <= 0
    if kind == 'ge':
        return compare(version, pred[1]) >= 0
    if kind == 'eq':
        return compare(version, pred[1]) == 0
    low, op, high = pred[1:]
    return compare(version, low) >= 0 and (compare(version, high) < 0 if op == '<' else compare(version, high) <= 0)


def choose_version(pred) -> str | None:
    kind = pred[0]
    if kind == 'any':
        return 'V1.0'
    if kind == 'lt':
        return below(pred[1])
    if kind in ('le', 'ge', 'eq'):
        return pred[1]
    low, op, high = pred[1:]
    return low if member(pred, low) else None


# -------------------------------------------------------------------- CSAF --
def products(document):
    """vendor / product_name / version per product_id; ids listed twice are dropped."""
    out, duplicates = {}, set()

    def walk(branches, vendor='', name='', version='', family=''):
        for branch in branches or []:
            category, label = branch.get('category'), branch.get('name', '')
            ve = label if category == 'vendor' else vendor
            na = label if category == 'product_name' else name
            ver = label if category in ('product_version', 'product_version_range') else version
            fam = label if category == 'product_family' else family
            product = branch.get('product')
            if product:
                pid = product['product_id']
                if pid in out:
                    duplicates.add(pid)
                out[pid] = dict(vendor=ve, name=na, version=ver, family=fam,
                                standard=category in ('product_version', 'product_version_range'))
            walk(branch.get('branches'), ve, na, ver, fam)

    walk(document.get('product_tree', {}).get('branches'))
    for pid in duplicates:
        out.pop(pid)
    return out


def norm(name: str) -> str:
    return ' '.join(re.findall(r'[a-z0-9]+', name.casefold()))


def load_rows():
    """Every explicit status row of the three vendors, plus files read."""
    rows, files = [], {}
    for path in sorted(CSAF_DIR.glob('icsa-*.json')):
        raw = path.read_bytes()
        document = json.loads(raw)
        tree = products(document)
        aid = path.stem
        for vuln in document.get('vulnerabilities', []):
            cve = vuln.get('cve')
            if not cve or not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve):
                continue
            for status in STATUSES:
                for pid in (vuln.get('product_status') or {}).get(status, []):
                    product = tree.get(pid)
                    if not product or product['vendor'] not in VENDORS or not product['name']:
                        continue
                    files[aid] = sha256(raw)
                    rows.append(dict(advisory_id=aid, cve=cve, product_id=pid, status=status, **product))
    return rows, files


def build_pool(rows):
    """Assets with a concrete version and per-CVE labels that no other row contradicts."""
    by_product_cve = collections.defaultdict(list)
    for row in rows:
        by_product_cve[(row['vendor'], norm(row['name']), row['cve'])].append(row)
    assets = {}  # (advisory, product_id) -> entry, or None when the asset is excluded
    excluded = collections.Counter()
    for row in rows:
        asset_id = (row['advisory_id'], row['product_id'])
        if asset_id not in assets:
            pred = predicate(row['version']) if row['standard'] else None
            version = choose_version(pred) if pred else None
            if not row['standard']:
                reason = 'non_standard_product_branch'
            elif pred is None:
                reason = 'unsupported_version_expression'
            elif not version or not member(pred, version):
                reason = 'no_concrete_version_in_range'
            else:
                reason = None
            if reason:
                excluded[reason] += 1
                assets[asset_id] = None
                continue
            assets[asset_id] = dict(advisory_id=row['advisory_id'], product_id=row['product_id'],
                                    vendor=row['vendor'], name=row['name'], family=row['family'],
                                    source_version=row['version'], version=version, labels={})
        entry = assets[asset_id]
        if entry is None:
            continue
        # Every explicit row for the same vendor/product/CVE must agree at this version.
        statuses = set()
        ambiguous = False
        for other in by_product_cve[(row['vendor'], norm(row['name']), row['cve'])]:
            other_pred = predicate(other['version']) if other['standard'] else None
            if other_pred is None:
                ambiguous = True
                break
            if member(other_pred, entry['version']):
                statuses.add(other['status'])
        if ambiguous or statuses != {row['status']}:
            excluded['ambiguous_or_contradicted_label'] += 1
            continue
        entry['labels'][row['cve']] = row['status']
    pool = [a for a in assets.values() if a and a['labels']]
    return pool, excluded


def deduplicate(pool):
    seen, out = set(), []
    for asset in pool:
        signature = (asset['vendor'], norm(asset['name']), asset['version'], tuple(sorted(asset['labels'].items())))
        if signature not in seen:
            seen.add(signature)
            out.append(asset)
    return out


# ------------------------------------------------------------------ output --
def sbom(case_id, asset, cves):
    ref = 'asset-component'
    return {
        '$schema': 'https://cyclonedx.org/schema/bom-1.6.schema.json',
        'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
        'serialNumber': 'urn:uuid:' + str(uuid.UUID(digest([VERSION, case_id])[:32])),
        'metadata': {'properties': [
            {'name': 'dataset:id', 'value': VERSION},
            {'name': 'dataset:case-id', 'value': case_id},
            {'name': 'dataset:synthetic-inventory', 'value': 'true'},
            {'name': 'dataset:source-advisory', 'value': asset['advisory_id']},
        ]},
        'components': [{'bom-ref': ref, 'type': 'device', 'name': asset['name'],
                        'version': asset['version'], 'manufacturer': {'name': asset['vendor']}}],
        'vulnerabilities': [{'id': cve, 'affects': [{'ref': ref}]} for cve in cves],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--output', type=Path, default=OUT)
    parser.add_argument('--seed', type=int, default=SEED)
    parser.add_argument('--assets-per-vendor', type=int, default=ASSETS_PER_VENDOR)
    parser.add_argument('--max-cves-per-asset', type=int, default=MAX_CVES_PER_ASSET)
    args = parser.parse_args(argv)

    rows, files = load_rows()
    pool, excluded = build_pool(rows)
    pool = deduplicate(pool)
    rng = random.Random(args.seed)
    selected = []
    for vendor in VENDORS:
        candidates = [a for a in pool if a['vendor'] == vendor]
        selected += rng.sample(candidates, min(args.assets_per_vendor, len(candidates)))

    out = args.output
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f'Refusing to overwrite existing dataset: {out}')
    (out / 'sboms').mkdir(parents=True, exist_ok=True)
    gold, index = [], []
    for n, asset in enumerate(selected, 1):
        case_id = f'top3_{n:05d}'
        cves = sorted(asset['labels'])
        if len(cves) > args.max_cves_per_asset:
            cves = sorted(rng.sample(cves, args.max_cves_per_asset))
        document = sbom(case_id, asset, cves)
        raw = (json.dumps(document, ensure_ascii=False, indent=2) + '\n').encode()
        (out / 'sboms' / f'{case_id}.json').write_bytes(raw)
        index.append(dict(id=case_id, sbom_file=f'sboms/{case_id}.json', sbom_sha256=sha256(raw),
                          vendor=asset['vendor'], cve_count=len(cves)))
        for cve in cves:
            status = asset['labels'][cve]
            gold.append(dict(case_id=case_id, component_ref='asset-component', cve=cve,
                             vendor=asset['vendor'], product=asset['name'], version=asset['version'],
                             truth='affected' if status == 'known_affected' else 'not_affected',
                             csaf_status=status, advisory_id=asset['advisory_id'],
                             product_id=asset['product_id'], source_version=asset['source_version'],
                             source_sha256=files[asset['advisory_id']]))
    gold_raw = ''.join(json.dumps(g, ensure_ascii=False) + '\n' for g in gold).encode()
    (out / 'gold.jsonl').write_bytes(gold_raw)
    # One operator context for every case: the asset is the single current
    # configuration, the component is running, and the running version equals
    # the BOM version. Only the product/version claim is under test.
    context = dict(scope='current_single', mode='normal', deployment='running', runtime='bom')
    (out / 'operator_context.json').write_text(json.dumps(context, indent=2) + '\n', encoding='utf-8')

    counts = collections.Counter((g['vendor'], g['truth']) for g in gold)
    manifest = dict(
        version=VERSION, created_at=datetime.now(timezone.utc).isoformat(), seed=args.seed,
        vendors=list(VENDORS), assets_per_vendor=args.assets_per_vendor,
        max_cves_per_asset=args.max_cves_per_asset,
        ground_truth='explicit CSAF product_status at the chosen concrete version; known_affected -> affected, fixed/known_not_affected -> not_affected',
        selection='deduplicated assets, seeded uniform sample per vendor; chosen before any system output',
        version_choice='independent parser in tools/item4/build_item4_top3_vendor_dataset.py, not the system parser',
        not_covered=['versions outside every explicit product_status row (e.g. post-fix releases named only in remediations)',
                     'exploit-path conditions and operator observations beyond deployment/runtime confirmation'],
        source_rows=len(rows), pool_assets=len(pool), excluded=dict(excluded),
        sboms=len(selected), cases=len(gold),
        cases_by_vendor={v: {t: counts[(v, t)] for t in ('affected', 'not_affected')} for v in VENDORS},
        affected_share=round(sum(g['truth'] == 'affected' for g in gold) / len(gold), 4) if gold else None,
        files=dict(gold_sha256=sha256(gold_raw), index=index),
        csaf_sources={aid: files[aid] for aid in sorted({a['advisory_id'] for a in selected})})
    (out / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: manifest[k] for k in ('sboms', 'cases', 'cases_by_vendor', 'affected_share', 'excluded', 'pool_assets')},
                     ensure_ascii=False, indent=2))


if __name__ == '__main__':
    sys.exit(main())
