"""Independently reconcile raw configuration-tree CPE occurrences with scheduled cases."""
from collections import Counter
import json
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.training_io import atomic_json


def audit(dataset, output):
    db = sqlite3.connect(f'file:{(Path(dataset) / "corpus.sqlite3").resolve().as_posix()}?mode=ro', uri=True)
    # SQLite JSON traversal is independent of the preprocessor's Python traversal.
    raw = dict(db.execute('''SELECT c.cve,SUM(json_array_length(j.value))
        FROM cves AS c,json_tree(c.payload,'$.configurations') AS j
        WHERE j.key='cpeMatch' AND j.type='array' GROUP BY c.cve'''))
    scheduled = dict(db.execute("SELECT json_extract(target,'$.target_cve'),COUNT(*) FROM cases GROUP BY json_extract(target,'$.target_cve')"))
    assert {k: v for k, v in raw.items() if v} == scheduled, 'Per-CVE CPE occurrence counts differ'
    records = {cid: json.loads(payload) for cid, payload in db.execute('SELECT cve,payload FROM cves')}
    seen = set(); flags = Counter(); input_ids = set()
    for _, sbom_text, target_text in db.execute('SELECT id,sbom,target FROM cases'):
        target = json.loads(target_text);cid = target['target_cve'];path = target['source_path']
        assert (cid, path) not in seen, 'Duplicate source path scheduled'
        seen.add((cid, path))
        value = records[cid]
        for key in path.strip('/').split('/'):
            value = value[int(key)] if isinstance(value, list) else value[key]
        assert value == target['raw_match'], 'Original CPE match changed'
        flags[str(value.get('vulnerable')) if isinstance(value, dict) else 'malformed'] += 1
        sbom = json.loads(sbom_text)
        assert 'cpe' not in sbom['components'][0], 'CPE answer leaked into inventory input'
        input_ids.add(sbom_text)
    assert len(seen) == sum(raw.values()), 'Not every original occurrence was covered'
    result = {'passed': True, 'population_cves': len(records), 'raw_cpe_occurrences': sum(raw.values()),
              'scheduled_cases': len(seen), 'unique_sbom_inputs': len(input_ids),
              'per_cve_count_mismatches': 0, 'duplicate_source_paths': 0,
              'changed_raw_match_records': 0, 'dictionary_based_exclusions': 0,
              'vulnerable_flags': dict(flags), 'verification': 'SQLite JSON traversal + exact source-path match equality'}
    atomic_json(output, result);db.close()
    return result


if __name__ == '__main__':
    print(json.dumps(audit(ROOT / 'data/item3_all_assigned_cpes_v1',
                           ROOT / 'results/item3_all_assigned_cpes_agents_v1/coverage_audit.json'), indent=2))
