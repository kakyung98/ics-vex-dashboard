"""Verify supplier product/version evidence for the frozen V1 refusal cohort."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.analysis import product_advisory_evidence as source
from src.item4.workflow.source_analysis_jobs import inventory


def sha_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(4*1024*1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def audit(delivery, output):
    prior = ROOT / 'results/item4_fixed_world_replay_20261121'
    prior_summary = json.loads((prior/'report.json').read_bytes())
    cohort = prior/'cve_audit.jsonl'
    cohort_sha = sha_file(cohort)
    if cohort_sha != prior_summary['ledgers'][cohort.name]:
        raise ValueError('The pinned cohort ledger changed')
    with cohort.open(encoding='utf-8') as rows:
        selected = {r['cve'] for r in map(json.loads, rows) if r['prior_v1']}
    if len(selected) != 3640:
        raise ValueError('The historical V1 cohort must contain 3,640 CVEs')
    archive = delivery/'delivery.tar.gz'
    archive_sha = sha_file(archive)
    baseline = json.loads((ROOT/'results/item4_extracted_ox_v3_20261120/verification.json').read_bytes())
    if archive_sha != baseline['archive']['sha256']:
        raise ValueError('The source delivery differs from the verified original')
    manifest = delivery/'delivery_manifest.json'
    if sha_file(manifest) != prior_summary['source_manifest_sha256']:
        raise ValueError('The source delivery manifest changed')
    pins = json.loads(manifest.read_bytes())
    packet_files = {f'benchmark/item4_evaluation/extracted_ox_v3/cves/{cve}.json': cve for cve in selected}
    rows = {}
    with tarfile.open(archive, mode='r|gz', bufsize=1024*1024) as bundle:
        for member in bundle:
            cve = packet_files.get(member.name)
            if not cve:
                continue
            raw = bundle.extractfile(member).read()
            packet_sha = hashlib.sha256(raw).hexdigest()
            if packet_sha != pins[member.name] or cve in rows:
                raise ValueError('Duplicate or divergent source packet: ' + cve)
            job = json.loads(raw)['job']
            previous, = job['conditions']
            if previous['cve'] != cve or 'V1 claim does not match the original product status' not in previous['reason']:
                raise ValueError('Archived job is outside the V1 cohort: ' + cve)
            components, declaration = inventory(job['input_bom'])
            target, = declaration
            if declaration != job['declared_cves'] or target['cve'] != cve:
                raise ValueError('BOM or declaration drift: ' + cve)
            bound, = [c for c in components if c['ref'] in target['component_refs']]
            binding = source.verified_version_evidence(cve, bound)
            record, _ = source.packet(cve, [bound])
            claim_ids = sorted(source.verified_product_claims(record))
            evidence = [{k: row[k] for k in ('evidence_id','document_sha256','source_file','status',
                        'product_key','status_pointer','product_pointer','source_version','version_membership')}
                        for row in binding['evidence']]
            rows[cve] = dict(cve=cve, frozen_packet_sha256=packet_sha, component_ref=bound['ref'],
                component_version=binding['version'], state=binding['state'], reasons=binding['reasons'],
                source_issues=binding['source_issues'], evidence=evidence, selectable_v1_source_ids=claim_ids)
    if set(rows) != selected:
        raise ValueError('One or more selected source packets are missing')
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise FileExistsError('Provide an empty output directory')
    statuses = Counter(row['state'] for row in rows.values())
    reasons = Counter(reason for row in rows.values() for reason in row['reasons'])
    ledger = output/'product_evidence.jsonl'
    with ledger.open('x', encoding='utf-8', newline='\n') as stream:
        for cve in sorted(rows):
            stream.write(json.dumps(rows[cve], ensure_ascii=False, separators=(',', ':')) + '\n')
    report = dict(cves=len(rows), original_v1_rejections=len(rows), code_verified_version_statuses=statuses,
                  cves_with_selectable_source_claim=sum(bool(r['selectable_v1_source_ids']) for r in rows.values()),
                  cves_with_product_match=sum(bool(r['evidence']) for r in rows.values()), reason_cves=reasons,
                  original_cohort_sha256=cohort_sha, frozen_delivery_sha256=archive_sha,
                  output_ledger_sha256=sha_file(ledger), code_sha256={path:sha_file(ROOT/path) for path in (
                      'src/item4/analysis/product_advisory_evidence.py','src/common/data/source_version_parser.py',
                      'src/item4/analysis/exploitation_prerequisites.py','tools/item4/audit_item4_v1_product_evidence.py')},
                  model_inference=False, historical_responses_rewritten=False, independent_gold=False,
                  interpretation='Structured source claim availability and product/build scope, independently of model selection or final scenario outcome.')
    (output/'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('delivery', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    audit(args.delivery, args.output)
