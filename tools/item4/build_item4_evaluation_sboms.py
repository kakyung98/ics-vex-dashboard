"""Historical 1,164-case split builder; cannot overwrite the unified package."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from collections import Counter, defaultdict
from datetime import datetime, timezone
import argparse
import hashlib
import json
from pathlib import Path
import re
import random
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SEED = 20261119


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, value):
    raw = (json.dumps(value, ensure_ascii=False, indent=2)+'\n').encode('utf-8')
    temporary = path.with_suffix(path.suffix+'.tmp')
    temporary.write_bytes(raw)
    temporary.replace(path)


def family(aid):
    match = re.fullmatch(r'(icsa-\d{2}-\d{3}-\d{2})[a-z]*', aid)
    if not match:
        raise ValueError('Unrecognized advisory identity: '+aid)
    return match[1]


def split(ids, count):
    """Simple random sample without replacement from all existing SBOMs."""
    evaluation = sorted(random.Random(SEED).sample(sorted(ids), count))
    remaining = sorted(set(ids)-set(evaluation))
    return evaluation, remaining


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT/'benchmark/item4_evaluation')
    args = parser.parse_args()
    if (args.output / 'summary.json').exists():
        raise SystemExit('Unified item4_evaluation is frozen. Do not recreate the retired 7:3 split. See its README.txt.')
    source = ROOT/'benchmark/icsa-cpe-synthetic sbom'
    index_raw = (source/'index.json').read_bytes()
    index = json.loads(index_raw)
    rows = {r['advisory_id']: r for r in index['advisories']}
    if len(rows) != 3881 or len(index['advisories']) != 3881:
        raise ValueError('Expected the fixed 3,881-advisory population')
    evaluation, remaining = split(rows, 1164)
    assert len(evaluation)==1164 and len(remaining)==2717
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    metadata = out/'_metadata'
    metadata.mkdir(exist_ok=True)
    existing = {p.stem for p in out.glob('*.json')}
    # Replace only this task's interrupted grouped selection, after checking
    # every existing byte against the source index. Preserve foreign edits.
    for aid in existing:
        path=out/(aid+'.json')
        if aid not in rows or sha(path.read_bytes()) != rows[aid]['sha256']:
            raise ValueError('Output contains a foreign or modified file: '+str(path))
    for aid in existing-set(evaluation):
        (out/(aid+'.json')).unlink()
    entries = []
    counts = Counter()
    eval_cves = set()
    archive = source/'icsa-advisory-products-sbom-v2-reviewed.zip'
    with zipfile.ZipFile(archive) as z:
        if set(r['file'] for r in rows.values()) != {n for n in z.namelist() if n.startswith('sbom/') and n.endswith('.json')}:
            raise ValueError('Reviewed archive does not contain exactly the indexed population')
        if z.read('index.json') != index_raw:
            raise ValueError('Reviewed archive and current source index differ')
        for number, aid in enumerate(evaluation, 1):
            row = rows[aid]
            raw = z.read(row['file'])
            if sha(raw) != row['sha256']:
                raise ValueError('Reviewed SBOM hash mismatch: '+aid)
            doc = json.loads(raw)
            properties = {p['name']: p['value'] for p in doc.get('properties', [])}
            if properties.get('dataset:advisory-id') != aid:
                raise ValueError('SBOM advisory identity mismatch: '+aid)
            if properties.get('dataset:synthetic-inventory') != 'true':
                raise ValueError('Expected explicitly synthetic advisory inventory')
            target = out/(aid+'.json')
            if target.exists() and target.read_bytes() != raw:
                raise ValueError('Existing evaluation SBOM differs: '+aid)
            if not target.exists():
                temporary = target.with_suffix('.json.tmp')
                temporary.write_bytes(raw)
                temporary.replace(target)
            if sha(target.read_bytes()) != row['sha256']:
                raise ValueError('Saved SBOM hash mismatch: '+aid)
            cves = sorted({v['id'] for v in doc.get('vulnerabilities', [])})
            eval_cves.update(cves)
            counts['components'] += len(doc.get('components', []))
            counts['empty_sboms'] += not bool(doc.get('components'))
            counts['sboms_without_cves'] += not bool(cves)
            counts['cve_occurrences'] += len(cves)
            entries.append(dict(advisory_id=aid, update_family=family(aid), file=target.name,
                                sha256=row['sha256'], source_archive_member=row['file'],
                                title=row.get('title'), url=row['url'],
                                component_count=len(doc.get('components', [])),
                                declared_cves=cves, source_status=row['status']))
            if number % 200 == 0:
                print(f'Copied and hash-verified {number}/1164', flush=True)
    remaining_cves = {cve for aid in remaining for cve in rows[aid]['declared_cves']}
    shared_cves = sorted(eval_cves & remaining_cves)
    counts['unique_cves'] = len(eval_cves)
    write(metadata/'split.json', dict(seed=SEED,
        method='Simple random sample without replacement; Python random.Random(seed).sample over sorted advisory IDs',
        population_count=3881, evaluation_count=1164, remaining_count=2717,
        evaluation_advisory_ids=evaluation, remaining_advisory_ids=remaining,
        advisory_overlap=0, update_family_overlap=len({family(a) for a in evaluation} & {family(a) for a in remaining}),
        year_counts={part:dict(sorted(Counter(a[5:7] for a in ids).items()))
                     for part, ids in [('population',sorted(rows)),('evaluation',evaluation),('remaining',remaining)]}))
    write(metadata/'index.json', dict(advisories=entries))
    write(metadata/'cve_overlap.json', dict(evaluation_unique_cves=len(eval_cves),
        remaining_unique_cves=len(remaining_cves), shared_cve_count=len(shared_cves),
        shared_cves=shared_cves,
        interpretation='Simple random advisory-level sample; not an update-family-disjoint, CVE-disjoint or model-training-disjoint test.'))
    manifest = dict(dataset='item4-evaluation-icsa-synthetic-sbom-v1',
        created_at=datetime.now(timezone.utc).isoformat(), source_population=3881,
        evaluation_sboms=1164, remaining_advisories=2717,
        schema='CycloneDX 1.7', integrity_verified_documents=1164,
        schema_validation='Already validated in the reviewed source dataset; files copied without regeneration',
        byte_identical_to_reviewed_source=True, **dict(counts),
        source_archive=str(archive.relative_to(ROOT)), source_archive_sha256=sha(archive.read_bytes()),
        source_index_sha256=sha(index_raw), source_dataset=index['summary']['dataset_id'],
        seed=SEED, selection='simple random without replacement', advisory_update_families_kept_together=False,
        operating_records_included=False, vex_ground_truth_included=False,
        versions='Original source version expressions, including ranges and unknown; no invented installed releases',
        empty_or_source_poor_advisories='Preserved when selected; not filtered by difficulty or CVE availability',
        independent_semantic_accuracy_verified=False,
        prior_model_training_exposure_verified=False)
    assert len(list(out.glob('*.json'))) == 1164
    write(metadata/'manifest.json', manifest)
    (metadata/'README.txt').write_text(
        'Item #4 evaluation input: 1,164 ICSA-based synthetic CycloneDX 1.7 SBOMs.\n'
        'One root JSON per advisory, byte-identical to the source-reviewed archive.\n'
        'The full 3,881 population is split into 1,164 evaluation and 2,717 remaining advisory IDs.\n'
        'Simple random sample without replacement, seed 20261119. No grouping or filtering.\n'
        'Updates and CVEs can overlap across partitions; see split.json and cve_overlap.json.\n'
        'Existing model training exposure has not been audited. This is not an independently unseen model test.\n'
        'Source expressions and unknowns are preserved; these are product collections, not verified installations.\n'
        'Operating records and VEX evaluation ground truth are not included.\n', encoding='utf-8')
    print(json.dumps(manifest, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
