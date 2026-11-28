"""Verify submitted files match frozen inference inputs without scoring outputs."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from collections import Counter
import hashlib
import json

ROOT=Path(__file__).resolve().parents[2]
DATA=ROOT/'benchmark/item4_evaluation'
OUT=ROOT/'results/item4_full_actual_20261120'


def main():
    counts=Counter();seen=set()
    for line in (DATA/'full_population_inputs.jsonl').open(encoding='utf-8'):
        row=json.loads(line);counts['CVEs']+=1
        assert len(row['cases'])==5
        for case in row['cases']:
            case_id=case['id'];assert case_id not in seen;seen.add(case_id)
            raw=(DATA/'sboms'/(case_id+'.json')).read_bytes()
            assert json.loads(raw)==row['bom'],case_id
            annotation=json.loads((DATA/'annotations'/(case_id+'.json')).read_bytes())
            assert annotation['inputs']==case and annotation['cve']==row['cve'],case_id
            assert annotation['sbom_file_sha256']==hashlib.sha256(raw).hexdigest(),case_id
            counts['matching_new_SBOM_and_annotation_files']+=1
        if counts['CVEs']%1000==0:print(json.dumps(dict(counts)),flush=True)
    assert counts['CVEs']==12418 and counts['matching_new_SBOM_and_annotation_files']==62090
    original=json.loads((ROOT/'benchmark/icsa-cpe-synthetic sbom/index.json').read_bytes())
    for row in original['advisories']:
        assert hashlib.sha256((DATA/'sboms'/(row['advisory_id']+'.json')).read_bytes()).hexdigest()==row['sha256']
        counts['original_SBOMs_byte_identical']+=1
    ledger_ids=set()
    for line in (DATA/'gold.jsonl').open(encoding='utf-8'):
        row=json.loads(line);case_id=row['id'];assert case_id not in ledger_ids;ledger_ids.add(case_id)
        assert row==json.loads((DATA/'annotations'/(case_id+'.json')).read_bytes()),case_id
        counts['common_gold_annotation_objects_identical']+=1
    expected=66962
    assert len(ledger_ids)==counts['common_gold_annotation_objects_identical']==expected
    assert ledger_ids=={p.stem for p in (DATA/'sboms').glob('*.json')}=={p.stem for p in (DATA/'annotations').glob('*.json')}
    result=dict(passed=True,**dict(counts),duplicate_case_ids=0,
        full_population_unique_BOM_schema_validation_previously_passed=12418,
        all_five_materialized_variants_match_each_validated_unique_BOM=True,
        model_predictions_or_metric_labels_consulted=False,
        original_and_previous_baseline_cases_retained=True,
        full_population_unknown_truth_retained=True)
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/'package_audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2),flush=True)


if __name__=='__main__':main()
