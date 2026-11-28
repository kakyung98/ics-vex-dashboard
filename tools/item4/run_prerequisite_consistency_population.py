"""Resumable full-population auxiliary mapping of existing VEP extractions.

Uses the existing pinned H200 model; empty/unresolved extractions are retained,
not filled from references. All original identities and checkpoints are kept.
"""
if __package__ in (None, ''):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import threading
import time

from src.item4.evaluation import prerequisite_consistency as E

ROOT = Path(__file__).resolve().parents[2]
LOCK = threading.Lock()


def write(path, value):
    temp = path.with_name(path.name+'.'+str(os.getpid())+'.'+str(threading.get_ident())+'.tmp')
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    # Windows readers/antivirus may hold a short-lived non-delete-sharing handle.
    # Keep the atomic checkpoint and retry, rather than lose a completed run.
    for attempt in range(20):
        try:
            temp.replace(path)
            return
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(min(.05*(attempt+1), .5))


def prepare(output, population, corpus, csaf):
    ids = [r['cve'] for r in json.loads(population.read_bytes())]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate population IDs')
    references = {cve: dict(cve=cve, vectors=[], cwes=[]) for cve in ids}
    for folder in csaf:
        for path in folder.glob('*.json'):
            document = json.loads(path.read_bytes())
            for vuln in document.get('vulnerabilities', []):
                cve = vuln.get('cve')
                if cve not in references:
                    continue
                ref = references[cve]
                cwe = vuln.get('cwe', {}).get('id')
                if cwe and cwe not in ref['cwes']:
                    ref['cwes'].append(cwe)
                for score in vuln.get('scores', []):
                    for key, data in score.items():
                        if isinstance(data, dict) and data.get('vectorString'):
                            row = dict(vector=data['vectorString'], source=str(path.relative_to(ROOT)),
                                       score_key=key, products=score.get('products', []))
                            if row not in ref['vectors']:
                                ref['vectors'].append(row)
    write(output/'references.json', list(references.values()))
    counts = Counter()
    with (output/'extractions.jsonl').open('w', encoding='utf-8') as stream:
        for i, cve in enumerate(ids):
            path = corpus/(cve+'.json')
            record = dict(cve=cve)
            if path.is_file():
                raw = path.read_bytes()
                original = json.loads(raw)
                candidates = [r for r in original.get('job', {}).get('conditions', []) if r.get('cve') == cve]
                if len(candidates) != 1:
                    record.update(extraction_status='missing_or_ambiguous_saved_extraction', prerequisites=[])
                else:
                    selected = candidates[0]
                    record.update(prerequisite=selected.get('prerequisite', {}),
                                  extraction_status=selected.get('status', 'unknown'))
                    counts['source_contains_cvss'] += any('CVSS' in s.get('text', '') for s in selected.get('sources', []))
                record['saved_checkpoint_sha256'] = hashlib.sha256(raw).hexdigest()
            else:
                record.update(extraction_status='checkpoint_missing', prerequisites=[])
            counts['records'] += 1
            view = E.extraction_view(record)
            counts['with_assertions' if view['conditions'] else 'without_assertions'] += 1
            counts['assertions'] += len(view['conditions'])
            counts['with_cvss_reference'] += bool(references[cve]['vectors'])
            stream.write(json.dumps(record, ensure_ascii=False)+'\n')
            if (i+1) % 250 == 0:
                stream.flush()
                write(output/'progress.json', dict(phase='preparing', completed=i+1, population=len(ids), counts=dict(counts)))
    manifest = dict(population=len(ids), population_sha256=hashlib.sha256(population.read_bytes()).hexdigest(),
                    counts=dict(counts), source=str(corpus),
                    extraction_input_sha256=hashlib.sha256((output/'extractions.jsonl').read_bytes()).hexdigest(),
                    references_sha256=hashlib.sha256((output/'references.json').read_bytes()).hexdigest(),
                    original_extraction_blinding='not_established; source CVSS visibility counted',
                    purpose='auxiliary_metadata_characterization_not_semantic_accuracy_or_cluster_validation')
    write(output/'preparation.json', manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT/'results/prerequisite_auxiliary_population_20261124')
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--port', type=int, default=18128)
    parser.add_argument('--limit', type=int, help='Pilot only; omit for full population')
    parser.add_argument('--retry-errors', action='store_true')
    args = parser.parse_args()
    if not 1 <= args.workers <= 16:
        parser.error('workers must be 1..16')
    output = args.output; output.mkdir(parents=True, exist_ok=True)
    (output/'checkpoints').mkdir(exist_ok=True)
    (output/'mapping_responses').mkdir(exist_ok=True)
    (output/'checkpoint_history').mkdir(exist_ok=True)
    population = ROOT/'benchmark/item4_evaluation/extracted_ox_v3/population_index.json'
    if not (output/'preparation.json').is_file():
        prepare(output, population, ROOT/'benchmark/item4_evaluation/extracted_ox_v3/cves',
                [ROOT/'data/cisa_identification_csaf'])
    preparation = json.loads((output/'preparation.json').read_bytes())
    rows = [json.loads(line) for line in (output/'extractions.jsonl').read_text(encoding='utf-8').splitlines()]
    if args.limit:
        # Choose nonempty extraction pilot first, without claiming population coverage.
        rows = sorted(rows, key=lambda r: not bool(E.extraction_view(r)['conditions']))[:args.limit]
    refs = {r['cve']: r for r in json.loads((output/'references.json').read_bytes())}
    taxonomy = json.loads((ROOT/'data/cwe_taxonomy/v5.0/catalog.json').read_bytes())
    identity = json.loads((ROOT/'results/item4_scenario_moe/nemotron-20261122T121210Z-534c666308/setup.json').read_bytes())['backend_identity']
    write(output/'model_identity.json', identity)
    from src.item4.models.nemotron_inference_provider import NemotronBatch
    from src.item4.models.remote_gpu_expert_client import token_path
    if not token_path().is_file():
        os.environ['ICSVEX_MOE_H200_TOKEN_FILE'] = 'C:/Users/user/AppData/Local/ICS-VEX/runtime/item4_moe_h200.auth'
    provider = NemotronBatch(args.port, output/'model_identity.json', concurrency=args.workers)
    def runner(system, packet, *, role):
        result = provider._one(dict(system=system, packet=packet))
        return result
    checkpoint = output/'checkpoints'; checkpoint.mkdir(exist_ok=True)
    write(output/'run_config.json', dict(version=E.VERSION, population=preparation['population'],
        selected=len(rows), workers=args.workers, pilot=bool(args.limit), model=identity['model'],
        reference_labels_hidden_from_mapper=True, empty_extractions_not_invented=True,
        mapper_system_sha256=hashlib.sha256(E.PROJECTION_SYSTEM.encode()).hexdigest(),
        sources=E.SOURCES, clusters_computed=False, started_at=datetime.now(timezone.utc).isoformat()))
    def one(record):
        path = checkpoint/(record['cve']+'.json')
        sha = E.digest(record)
        if path.is_file():
            previous = json.loads(path.read_bytes())
            if previous['input_sha256'] != sha:
                raise ValueError('Checkpoint input changed')
            if previous['state'] != 'error' or not args.retry_errors:
                return previous
            write(output/'checkpoint_history'/(record['cve']+'-'+str(time.time_ns())+'.json'), previous)
        result = dict(cve=record['cve'], input_sha256=sha, llm_used=False)
        try:
            if E.extraction_view(record)['conditions']:
                result['llm_attempted'] = True
                def audited_runner(system, packet, *, role):
                    response = runner(system, packet, role=role)
                    receipt = output/'mapping_responses'/(record['cve']+'-'+str(time.time_ns())+'.json')
                    write(receipt, dict(cve=record['cve'], input_sha256=E.digest(packet),
                                        system_sha256=hashlib.sha256(system.encode()).hexdigest(),
                                        reference_labels_used=False, response=response))
                    result['model_response_file'] = str(receipt.relative_to(output))
                    return response
                mapped, audit = E.model_projection(record, audited_runner)
                result.update(state='mapped', llm_used=True, mapping=audit,
                              comparison=E.evaluate(mapped, refs[record['cve']], taxonomy))
            else:
                result.update(state='no_extracted_assertions', llm_attempted=False,
                              comparison=E.evaluate(record, refs[record['cve']], taxonomy))
        except Exception as exc:
            result.update(state='error', error=type(exc).__name__+': '+str(exc)[:400])
        write(path, result)
        return result
    results = []
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(one, row) for row in rows]
        for future in as_completed(futures):
            results.append(future.result())
            if len(results) % 50 == 0 or len(results) == len(rows):
                counts = Counter(r['state'] for r in results)
                progress = dict(phase='mapping', completed=len(results), population=len(rows),
                                counts=dict(counts), elapsed_seconds=round(time.monotonic()-start, 1))
                write(output/'progress.json', progress)
                print(json.dumps(progress), flush=True)
    results.sort(key=lambda r:r['cve'])
    summary = E.summarize([r['comparison'] for r in results if 'comparison' in r])
    summary.update(population=preparation['population'], accounted_records=len(results), pilot=bool(args.limit),
                   counts=dict(Counter(r['state'] for r in results)),
                   llm_completed=sum(r['llm_used'] for r in results),
                   errors=[dict(cve=r['cve'], error=r['error']) for r in results if r['state']=='error'],
                   full_population_accounted=not args.limit and len(results)==preparation['population'],
                   all_llm_mapping_complete=all(r['state']!='error' for r in results),
                   original_extraction_source_cvss_visible=preparation['counts'].get('source_contains_cvss', 0),
                   interpretation='Auxiliary characterization. Not semantic extraction accuracy, independent validation, clustering quality or new clustering.',
                   clusters_computed=False)
    write(output/'report.json', summary)
    with (output/'comparisons.jsonl').open('w', encoding='utf-8') as stream:
        for r in results:
            stream.write(json.dumps(r, ensure_ascii=False)+'\n')
    write(output/'progress.json', dict(phase='finished', completed=len(results), population=len(rows), counts=summary['counts']))
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    return 2 if summary['errors'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
