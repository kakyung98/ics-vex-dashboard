"""Stratify the completed auxiliary run; no clusters or semantic gold are inferred."""
if __package__ in (None, ''):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
from src.item4.evaluation import prerequisite_consistency as E


def characterize(folder):
    folder = Path(folder)
    records = [json.loads(s) for s in (folder/'extractions.jsonl').read_text(encoding='utf-8').splitlines()]
    refs = {r['cve']: r for r in json.loads((folder/'references.json').read_bytes())}
    states, statuses = Counter(), Counter()
    composition = Counter()
    by_cwe = defaultdict(Counter)
    by_cvss = defaultdict(Counter)
    comparison_counts = defaultdict(Counter)
    identity = {}
    errors, unmapped, missing_checkpoints = [], [], []
    for record in records:
        cve = record['cve']
        statuses[record.get('extraction_status', 'unknown')] += 1
        checkpoint = folder/'checkpoints'/(cve+'.json')
        if not checkpoint.is_file():
            states['checkpoint_missing'] += 1
            missing_checkpoints.append(cve)
            continue
        result = json.loads(checkpoint.read_bytes())
        if result['input_sha256'] != E.digest(record):
            raise ValueError('Input/checkpoint digest mismatch: '+cve)
        state = result['state']; states[state] += 1
        assertions = len(E.extraction_view(record)['conditions'])
        raw = E.extracted(record)
        positive = len(raw.get('prerequisites', []))
        negative = len(raw.get('nonrequirements', []))
        composition['positive_prerequisite_atoms'] += positive
        composition['explicit_nonrequirements'] += negative
        composition['records_with_positive_prerequisites'] += bool(positive)
        composition['records_with_nonrequirements'] += bool(negative)
        identity[cve] = dict(state=state, extraction_status=record.get('extraction_status'), assertions=assertions)
        for cwe in refs[cve]['cwes'] or ['unknown']:
            by_cwe[cwe]['records'] += 1
            by_cwe[cwe][state] += 1
            by_cwe[cwe]['assertions'] += assertions
        signatures = set()
        for vector in refs[cve]['vectors']:
            try:
                version, values = E.parse_vector(vector['vector'])
                signatures.update((version, key, value) for key, value in values.items())
            except ValueError:
                continue
        for version, key, value in signatures:
            label = version+'/'+key+':'+value
            by_cvss[label]['records'] += 1
            by_cvss[label][state] += 1
        if state == 'error':
            errors.append(dict(cve=cve, error=result['error']))
        comparison = result.get('comparison', {})
        if comparison.get('projection', {}).get('unmapped_condition_ids'):
            unmapped.append(dict(cve=cve, condition_ids=comparison['projection']['unmapped_condition_ids']))
        for vector in comparison.get('cvss', []):
            for m in vector.get('metrics', []):
                label = vector['version']+'/'+m['metric']
                comparison_counts[label][m['status']] += 1
    report = dict(purpose='auxiliary_metadata_stratification', population=len(records),
        accounted_records=sum(states.values()), state_counts=dict(states),
        original_extraction_status_counts=dict(statuses),
        assertion_composition=dict(composition),
        by_reference_cwe={k:dict(v) for k,v in sorted(by_cwe.items())},
        by_reference_cvss={k:dict(v) for k,v in sorted(by_cvss.items())},
        comparison_counts_by_version_metric={k:dict(v) for k,v in sorted(comparison_counts.items())},
        errors=errors, unmapped_assertions=unmapped, missing_checkpoints=missing_checkpoints,
        original_identities_retained=True, new_clusters_computed=False,
        cluster_purity_measured=False, semantic_accuracy_measured=False,
        interpretation='CWE and CVSS label strata overlap. Counts do not define a clustering partition or establish cluster validity. Same CVE can appear in multiple CWE/version/metric strata.')
    (folder/'characterization.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    with (folder/'population_ledger.jsonl').open('w',encoding='utf-8') as stream:
        for cve,row in sorted(identity.items()):
            stream.write(json.dumps(dict(cve=cve,**row))+'\n')
    return report


if __name__ == '__main__':
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('folder',type=Path)
    result=characterize(cli.parse_args().folder)
    print(json.dumps({k:result[k] for k in ('population','accounted_records','state_counts','original_extraction_status_counts')},indent=2))
