"""Copy the top-3 vendor ICSA synthetic SBOMs and attach CSAF gold for #4.

Source: benchmark/icsa-cpe-synthetic sbom/sbom (CPE-enriched v3, 3,881 files).
A file is selected when its advisory's CSAF product tree names Siemens,
Rockwell Automation or Schneider Electric. Files are copied byte for byte.

Gold covers each declared (CVE, component) link whose component is a CSAF
product: the supplier's explicit product_status for that CVE decides the truth.
Links to NVD CPE-condition components have no supplier statement and are
listed as unjudged.

    python -B -X utf8 tools/item4/build_item4_top3_icsa_sbom_dataset.py
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'benchmark/icsa-cpe-synthetic sbom/sbom'
CSAF_DIR = ROOT / 'data/cisa_identification_csaf'
OUT = ROOT / 'benchmark/item4_evaluation/top3_vendor_icsa_sbom'
VERSION = 'item4-top3-vendor-icsa-sbom-dataset/1'
VENDORS = ('Siemens', 'Rockwell Automation', 'Schneider Electric')
STATUSES = ('known_affected', 'fixed', 'known_not_affected', 'under_investigation')


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def csaf(aid: str):
    """Vendors in the product tree and {(cve, product_id): status}."""
    path = CSAF_DIR / f'{aid}.json'
    if not path.is_file():
        return None
    raw = path.read_bytes()
    document = json.loads(raw)
    vendors = set()

    def walk(branches):
        for branch in branches or []:
            if branch.get('category') == 'vendor':
                vendors.add(branch.get('name', ''))
            walk(branch.get('branches'))

    walk(document.get('product_tree', {}).get('branches'))
    status = {}
    for vuln in document.get('vulnerabilities', []):
        for kind in STATUSES:
            for pid in (vuln.get('product_status') or {}).get(kind, []):
                status[(vuln.get('cve'), pid)] = kind
    return dict(vendors=vendors, status=status, sha256=sha256(raw))


def props(item):
    return {p.get('name'): p.get('value') for p in item.get('properties', []) if isinstance(p, dict)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--output', type=Path, default=OUT)
    args = parser.parse_args(argv)
    out = args.output
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f'Refusing to overwrite existing dataset: {out}')
    (out / 'sboms').mkdir(parents=True, exist_ok=True)

    index, gold, unjudged, sources = [], [], collections.Counter(), {}
    missing_csaf = 0
    embedded_mismatch = 0
    for path in sorted(SOURCE.glob('icsa-*.json')):
        record = csaf(path.stem)
        if record is None:
            missing_csaf += 1
            continue
        vendors = sorted(record['vendors'] & set(VENDORS))
        if not vendors:
            continue
        raw = path.read_bytes()
        shutil.copyfile(path, out / 'sboms' / path.name)
        sources[path.stem] = record['sha256']
        document = json.loads(raw)
        components = {c.get('bom-ref'): c for c in document.get('components', [])}
        declared = 0
        for vuln in document.get('vulnerabilities', []):
            cve = str(vuln.get('id', ''))
            if not cve.startswith('CVE-'):
                continue
            embedded = json.loads(props(vuln).get('dataset:source-product-status') or '{}')
            embedded = {pid: kind for kind, ids in embedded.items() for pid in ids}
            for affect in vuln.get('affects', []):
                ref = affect.get('ref')
                component = components.get(ref)
                declared += 1
                pid = props(component).get('dataset:source-product-id') if component else None
                if not pid:
                    unjudged['nvd_cpe_condition_component' if component else 'dangling_reference'] += 1
                    continue
                status = record['status'].get((cve, pid))
                if status is None or status == 'under_investigation':
                    unjudged['no_explicit_supplier_status'] += 1
                    continue
                if embedded.get(pid) != status:
                    embedded_mismatch += 1
                gold.append(dict(case_id=path.stem, component_ref=ref, cve=cve,
                                 vendor=(component.get('manufacturer') or {}).get('name'),
                                 product=component.get('name'), version=component.get('version'),
                                 truth='affected' if status == 'known_affected' else 'not_affected',
                                 csaf_status=status, advisory_id=path.stem, product_id=pid,
                                 source_sha256=record['sha256']))
        index.append(dict(id=path.stem, sbom_file=f'sboms/{path.name}', sbom_sha256=sha256(raw),
                          vendors=vendors, declared_links=declared))

    gold_raw = ''.join(json.dumps(g, ensure_ascii=False) + '\n' for g in gold).encode()
    (out / 'gold.jsonl').write_bytes(gold_raw)
    context = dict(scope='current_single', mode='normal', deployment='running', runtime='bom')
    (out / 'operator_context.json').write_text(json.dumps(context, indent=2) + '\n', encoding='utf-8')
    truth = collections.Counter(g['truth'] for g in gold)
    by_vendor = collections.Counter((g['vendor'], g['truth']) for g in gold)
    manifest = dict(
        version=VERSION, created_at=datetime.now(timezone.utc).isoformat(),
        source=str(SOURCE.relative_to(ROOT)), vendors=list(VENDORS),
        selection="advisory CSAF product tree names one of the vendors; files copied byte for byte",
        ground_truth='explicit CSAF product_status for the (CVE, product_id) of each declared CSAF-product link',
        sboms=len(index), gold_links=len(gold), truth=dict(truth),
        gold_by_vendor={f'{v} / {t}': n for (v, t), n in sorted(by_vendor.items(), key=lambda x: (str(x[0][0]), x[0][1]))},
        unjudged_links=dict(unjudged), embedded_answer_mismatches=embedded_mismatch,
        skipped_without_local_csaf=missing_csaf,
        blinding='evaluation.py removes dataset:* properties and vulnerability properties (embedded answers) before judging',
        files=dict(gold_sha256=sha256(gold_raw), index=index), csaf_sources=sources)
    (out / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: manifest[k] for k in ('sboms', 'gold_links', 'truth', 'unjudged_links',
                                                'embedded_answer_mismatches', 'skipped_without_local_csaf')}, indent=2))


if __name__ == '__main__':
    sys.exit(main())
