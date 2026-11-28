"""Freeze full-population, source-conditioned operational worlds before inference.

Every CVE receives all five variants. A missing source path never becomes a
fabricated positive/negative reference; the complete-inventory absence variant
has an independent negative label even for source-poor CVEs.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from collections import Counter
from copy import deepcopy
from functools import lru_cache
import hashlib
import itertools
import json
from pathlib import Path
import re

from src.item4.decision import scoped_vex_review as A
from src.item4.analysis.product_advisory_evidence import source_products
from src.common.source_version_parser import version_predicate, membership
from src.item4.decision.population_condition_rules import witness
from src.research.item4_source_recovery import recover

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / 'benchmark/item4_evaluation'
VARIANTS = ('present_true', 'present_false', 'missing_records', 'conflicting_records', 'component_absent')


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    if path.exists() and path.parent.name in {'sboms','annotations'}:
        if json.loads(path.read_bytes()) != value:
            raise ValueError('Existing synthetic input/reference changed: ' + str(path))
        return
    path.write_bytes(raw)


def dnf(expr, negate=False):
    """Independent Boolean reference; never calls production graph evaluation."""
    if 'condition' in expr:
        return [{expr['condition']: not negate}]
    op = expr['op']
    if op == 'not':
        return dnf(expr['args'][0], not negate)
    if negate:
        op = {'and': 'or', 'or': 'and'}[op]
    children = [dnf(a, negate) for a in expr['args']]
    if op == 'or':
        return [term for child in children for term in child]
    result = [{}]
    for child in children:
        result = [{**a, **b} for a in result for b in child
                  if all(k not in a or a[k] == v for k, v in b.items())]
        if len(result) > 1024:
            raise ValueError('Reference formula budget exceeded')
    return result


def truth(terms, values):
    return any(all(values[k] == v for k, v in term.items()) for term in terms)


def states(scenario):
    ids = sorted({c['id'] for c in scenario['conditions']})
    if len(ids) > 14 or len(ids) != len(scenario['conditions']):
        raise ValueError('Unbounded or colliding source condition identifiers')
    terms = dnf(scenario['expression'])
    positive = negative = None
    for values in itertools.product((False, True), repeat=len(ids)):
        state = dict(zip(ids, values))
        if truth(terms, state):
            if positive is None:
                positive = state
        elif negative is None:
            negative = state
        if positive is not None and negative is not None:
            return positive, negative
    raise ValueError('No positive/negative discriminating reference state')


@lru_cache(maxsize=4096)
def csaf(aid):
    path = ROOT / 'icsa/csaf' / (aid + '.json')
    if not path.is_file():
        return {}, None
    raw = path.read_bytes()
    try:
        return source_products(json.loads(raw.decode('utf-8-sig'))), hashlib.sha256(raw).hexdigest()
    except (UnicodeError, ValueError):
        return {}, hashlib.sha256(raw).hexdigest()  # Malformed source is unresolved, never excluded.


def selected(record):
    """Choose from sources only, before predictions; do not discard any CVE."""
    by_key = {}
    for aid in sorted(record['advisory_ids']):
        products, sha = csaf(aid)
        for pid, p in products.items():
            by_key[aid + ':' + pid] = dict(p, key=aid + ':' + pid, document_sha256=sha)
    source_ids = {s['id']: s for s in record['sources']}
    candidates = sorted(record['scenarios'], key=lambda s: s['id'])
    failures = []
    for scenario in candidates:
        if scenario.get('scope_ambiguous'):
            failures.append('ambiguous_source_scope')
            continue
        try:
            for c in scenario['conditions']:
                ref = c['source_ref']; s = source_ids[ref['source_id']]
                a, b = ref['span']
                if s.get('subject_ambiguous') or s['text'][a:b] != ref['quote']:
                    raise ValueError('Source quote mismatch or ambiguity')
            positive, negative = states(scenario)
        except (KeyError, ValueError) as exc:
            failures.append(str(exc)); continue
        for key in sorted(scenario.get('product_keys', [])):
            product = by_key.get(key)
            if not product:
                continue
            version = witness(version_predicate(product['version']))
            if version and membership(version_predicate(product['version']), version) == 'true':
                return product, version, scenario, positive, negative, failures
    # Keep actual product identity and unknown release when no path can be bound.
    product = next((by_key[k] for p in record['products'] if (k := p['key']) in by_key), None)
    version = witness(version_predicate(product['version'])) if product else None
    return product, version, None, None, None, failures


def build(resume=False):
    marker = DATA / 'full_population_manifest.json'
    if marker.exists():
        raise FileExistsError('Full-population reference already frozen')
    counts = Counter(); reasons = Counter(); index = []
    job_file = DATA / 'full_population_inputs.jsonl'
    gold_file = DATA / 'full_population_gold.jsonl'
    if not resume and (job_file.exists() or gold_file.exists()):
        raise FileExistsError('Partial full-population files exist; inspect before resuming')
    with job_file.open('w', encoding='utf-8', newline='\n') as jobs, gold_file.open('w', encoding='utf-8', newline='\n') as gold:
        for cat in sorted(A.catalogue()['cves'], key=lambda r: r['cve']):
            original = A.detail(cat['cve']); record = recover(original)
            product, version, spec, positive, negative, failures = selected(record)
            cve = record['cve']
            component_ref = 'component-' + digest(cve)[:24]
            if product:
                name, vendor = product['name'], product['vendor']
            else:
                name = record['products'][0]['name'] if record['products'] else 'unresolved-source-product'
                vendor = ''
            bom = dict(bomFormat='CycloneDX', specVersion='1.7', version=1,
                metadata=dict(component=dict(type='device', name='hypothetical-asset-' + digest(cve)[:16], **{'bom-ref': 'hypothetical-asset'})),
                components=[dict(type='application', name=name, version=version or 'unknown',
                                 manufacturer=dict(name=vendor or 'unknown'), **{'bom-ref': component_ref})],
                vulnerabilities=[dict(id=cve, affects=[dict(ref=component_ref)])],
                properties=[dict(name='dataset:synthetic-inventory', value='true'),
                            dict(name='dataset:deployment-verified', value='false')])
            case_inputs = []
            ids = []
            for variant in VARIANTS:
                case_id = 'FULL-' + digest([cve, variant, original['record_digest']])[:28]
                ids.append(case_id)
                latent = negative if variant == 'present_false' else positive
                observed = []
                if spec and variant not in ('missing_records', 'component_absent'):
                    for c in spec['conditions']:
                        if not c.get('operator_observable'):
                            continue
                        observed.append(dict(source_ref=deepcopy(c['source_ref']),
                            statement=c['proposition'], value=latent[c['id']],
                            record_kind='hypothetical_operator_record', scope='same_product_build_configuration',
                            evidence_basis='synthetic_assignment_not_real_observation'))
                if variant == 'conflicting_records':
                    observed += [dict(o, value=not o['value']) for o in deepcopy(observed)]
                actual = False if variant == 'component_absent' else (
                    variant != 'present_false' if spec else None)
                case = dict(id=case_id, cve=cve, synthetic=True, component_ref=component_ref,
                    context=dict(scope='current_single', mode='normal', origin='same_zone',
                                 deployment='not_deployed' if variant == 'component_absent' else 'running',
                                 runtime='bom' if version else 'unknown'),
                    operating_records=observed)
                label = dict(id=case_id, cve=cve, synthetic=True, actual_affected=actual,
                    variant=variant, latent_state=latent,
                    label_method='complete_inventory_absence' if variant == 'component_absent' else
                                 'source_conditioned_closed_world_DNF_oracle' if spec else 'unknown_source_scope',
                    source_record_digest=original['record_digest'], selected_path=deepcopy(spec),
                    assumptions=['Named source product/build applies in this hypothetical world only.',
                                 'Selected source-described path is complete in this hypothetical world; other paths are excluded.',
                                 'Latent state may include unobservable conditions; they are withheld from operator inputs.'] if spec else [],
                    source_semantics_independently_verified=False, real_asset_impact_verified=False)
                write(DATA / 'sboms' / (case_id + '.json'), bom)
                annotation = dict(id=case_id, fold='evaluation', sbom_file='sboms/' + case_id + '.json',
                    case_kind='full_population_source_conditioned_world', synthetic=True,
                    cve=cve, declared_cves=[cve], inputs=case, gold=label,
                    source_product=product, source_record_digest=original['record_digest'],
                    sbom_file_sha256=hashlib.sha256((DATA / 'sboms' / (case_id + '.json')).read_bytes()).hexdigest())
                write(DATA / 'annotations' / (case_id + '.json'), annotation)
                gold.write(json.dumps(label, ensure_ascii=False) + '\n')
                case_inputs.append(case)
                counts['cases'] += 1; counts['variant:' + variant] += 1
                counts['gold:true' if actual is True else 'gold:false' if actual is False else 'gold:unknown'] += 1
            jobs.write(json.dumps(dict(cve=cve, bom=bom, cases=case_inputs), ensure_ascii=False) + '\n')
            counts['CVEs'] += 1; counts['CVEs_with_source_world'] += bool(spec)
            if not spec:
                reasons.update(set(failures) or ['no_bound_discriminating_source_path_and_exact_version'])
            index.append(dict(cve=cve, case_ids=ids, source_world_available=bool(spec),
                              selected_product=product, version=version, unresolved_reasons=sorted(set(failures))))
            if counts['CVEs'] % 250 == 0:
                print(json.dumps(dict(stage='building_frozen_worlds', **dict(counts))), flush=True)
    assert counts['CVEs'] == 12418 and counts['cases'] == 62090
    write(DATA / 'full_population_index.json', index)
    # The requested common ledger remains a complete, identical annotation export.
    with (DATA / 'gold.jsonl').open('w', encoding='utf-8', newline='\n') as f:
        for p in sorted((DATA / 'annotations').glob('*.json')):
            f.write(json.dumps(json.loads(p.read_bytes()), ensure_ascii=False) + '\n')
    manifest = dict(schema='full-population-actual-item4-evaluation/1', population=12418,
        counts=dict(counts), unresolved_reasons=dict(reasons), variants=list(VARIANTS),
        frozen_before_model_inference=True, labels_from_model_predictions=False,
        reference_semantics='Conditional synthetic source/path truth, not expert gold or actual deployment impact',
        originals_and_previous_991_scenarios_retained=True, baseline_991_excluded_from_new_score=True,
        unknown_labels_retained=True, inferred_internal_states_not_supplied_to_operators=True,
        target_percent=85, strict_comparison=True,
        required_runtime='Current item4_questionnaire extraction and classification, asset-key questions, item4_vex_assessment with real MulVAL/XSB',
        artifacts={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in
                   [job_file, gold_file, DATA / 'full_population_index.json']})
    write(marker, manifest)
    summary = json.loads((DATA / 'summary.json').read_bytes())
    summary['gold_jsonl_sha256'] = hashlib.sha256((DATA / 'gold.jsonl').read_bytes()).hexdigest()
    summary['case_count'] = len(list((DATA / 'sboms').glob('*.json')))
    summary['full_population_evaluation'] = manifest
    summary['prior_evaluation'] = summary.pop('evaluation', None)
    write(DATA / 'summary.json', summary)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--resume',action='store_true')
    build(parser.parse_args().resume)
