"""Evaluate saved condition extractions against published CVSS/CWE metadata."""
if __package__ in (None, ''):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import argparse
import json
from pathlib import Path
from src.item4.evaluation import prerequisite_consistency as E

ROOT = Path(__file__).resolve().parents[2]


def read_records(path):
    path = Path(path)
    if path.suffix.lower() == '.jsonl':
        return [json.loads(line) for line in path.read_text(encoding='utf-8-sig').splitlines() if line.strip()]
    data = json.loads(path.read_text(encoding='utf-8-sig'))
    if isinstance(data, list):
        return data
    if 'vulnerabilities' in data:
        return [row['cve'] for row in data['vulnerabilities']]
    if 'records' in data and isinstance(data['records'], list):
        return data['records']
    if 'cve' not in data and E.extracted(data).get('cve'):
        data['cve'] = E.extracted(data)['cve']
    return [data]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--extractions', type=Path, required=True, help='VEP JSON, JSON list or JSONL')
    parser.add_argument('--references', type=Path, required=True, help='NVD JSON or normalized reference JSON/JSONL')
    parser.add_argument('--projection-model', action='store_true',
                        help='Use configured LLM to project extracted assertions, with reference labels withheld')
    parser.add_argument('--taxonomy', type=Path, default=ROOT/'data/cwe_taxonomy/v5.0/catalog.json')
    parser.add_argument('--output', type=Path, default=ROOT/'results/prerequisite_consistency_v1')
    args = parser.parse_args(argv)
    extraction_rows = read_records(args.extractions)
    references = {}
    for row in read_records(args.references):
        cve = row.get('cve') if isinstance(row.get('cve'), str) else row.get('id')
        if not cve:
            raise ValueError('Reference requires cve or id')
        # Keep providers and versions from duplicate reference rows.
        merged = references.setdefault(cve, dict(cve=cve, vectors=[], cwes=[]))
        merged['vectors'].extend(E.reference_vectors(row))
        merged['cwes'] = sorted(set(merged['cwes']) | set(E.reference_cwes(row)))
    taxonomy = json.loads(args.taxonomy.read_bytes()) if args.taxonomy.is_file() else None
    reports, errors, seen, projections = [], [], set(), []
    if args.projection_model:
        from src.item4.models.json_inference_client import generate as runner
    for record in extraction_rows:
        cve = record.get('cve')
        try:
            if not cve:
                raise ValueError('Extraction requires a top-level cve ID')
            if cve in seen:
                raise ValueError('Duplicate extraction CVE; split runs or scopes into separate input files')
            seen.add(cve)
            if args.projection_model:
                original_sha = E.digest(record)
                record, projection = E.model_projection(record, runner)
                projections.append(dict(cve=cve, original_extraction_sha256=original_sha, **projection))
            reports.append(E.evaluate(record, references.get(cve), taxonomy))
        except Exception as exc:
            errors.append(dict(cve=cve, error=str(exc)))
    summary = E.summarize(reports)
    summary.update(input_records=len(extraction_rows), errors=errors,
                   reference_cves_without_extraction=sorted(set(references)-seen),
                   input_sha256=E.digest(extraction_rows), references_sha256=E.digest(references),
                   projection_method='blinded_llm' if args.projection_model else 'conservative_explicit_phrase_rules',
                   evaluation_scope='all supplied records, including missing/unmapped/error cases')
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output/'report.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    with (args.output/'comparisons.jsonl').open('w', encoding='utf-8') as stream:
        for row in reports:
            stream.write(json.dumps(row, ensure_ascii=False)+'\n')
    with (args.output/'projections.jsonl').open('w', encoding='utf-8') as stream:
        for row in projections:
            stream.write(json.dumps(row, ensure_ascii=False)+'\n')
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 2 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
