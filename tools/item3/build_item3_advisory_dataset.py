"""Derive blinded, paired #3 inputs from the explicitly selected advisory SBOMs."""
from collections import Counter, defaultdict
from copy import deepcopy
from pathlib import Path
import argparse
import hashlib
import json
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SCHEMA = 'item3-advisory-paired/1'
SEED = 'item3-advisory-20261125-v1'
SCENARIOS = ('component_mask', 'component_noise', 'version_mask', 'version_noise', 'CPE_mask', 'CPE_noise')


def compact(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def digest(value):
    return hashlib.sha256(compact(value).encode()).hexdigest()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')


def properties(obj):
    value = obj.get('properties', [])
    return value if isinstance(value, dict) else {p['name']:p['value'] for p in value}


def blind_document(original, identity):
    """Retain product fields and component refs, remove answers and duplicate hints."""
    document = {k:deepcopy(original[k]) for k in ('$schema','bomFormat','specVersion','serialNumber','version','dependencies') if k in original}
    document['metadata'] = {'component': {'type':'data', 'bom-ref':'collection-'+identity,
        'name':'Synthetic product collection', 'version':'unknown'}}
    document['properties'] = [{'name':'dataset:synthetic-inventory','value':'true'}]
    keep = ('type','bom-ref','name','version','cpe','purl','manufacturer','supplier','publisher',
            'scope','hashes','licenses','copyright')
    document['components'] = [{k:deepcopy(c[k]) for k in keep if k in c} for c in original.get('components', [])]
    # Some source version fields include prose with the answer CVE IDs. Redact
    # identifiers only; never extract or invent a different installed release.
    def redact(value):
        if isinstance(value,str):
            return re.sub(r'(?i)CVE-\d{4}-\d+','[redacted-cve]',value)
        if isinstance(value,list):
            return [redact(v) for v in value]
        if isinstance(value,dict):
            return {k:redact(v) for k,v in value.items()}
        return value
    document=redact(document)
    if re.search(r'(?i)CVE-\d{4}-\d+', compact(document)):
        raise ValueError('CVE answer remains in blinded input')
    return document


def source_gold(document, universe, rejected=()):
    """CSAF source-explicit relations, not model-derived or document co-occurrence."""
    components = {c['bom-ref']:c for c in document.get('components', [])}
    if len(components) != len(document.get('components', [])):
        raise ValueError('Duplicate component reference')
    truth = {ref:dict(component_ref=ref, expected_cves=[], negative_cves=[], source_refs={},
                     unknown_scope='all_unlisted_in_universe') for ref in components}
    declared = set()
    for index, vulnerability in enumerate(document.get('vulnerabilities', [])):
        cid = vulnerability.get('id')
        if cid not in universe:
            continue
        declared.add(cid)
        status = properties(vulnerability)
        statuses = json.loads(status.get('dataset:source-product-status', '{}'))
        refs = [a['ref'] for a in vulnerability.get('affects', [])]
        if any(ref not in components for ref in refs):
            raise ValueError('Dangling source CVE-component reference')
        conflict = status.get('dataset:product-link-status') == 'source-conflict-review'
        if cid in rejected or conflict:
            continue
        if status.get('dataset:product-link-status') == 'source-explicit':
            for ref in refs:
                truth[ref]['expected_cves'].append(cid)
                truth[ref]['source_refs'][cid] = f'/vulnerabilities/{index}/affects'
        nvd_refs=set(json.loads(status.get('dataset:nvd-cpe-component-refs','[]')))
        for ref in nvd_refs:
            if ref not in refs or ref not in components:
                raise ValueError('Invalid explicit NVD component relation')
            truth[ref]['expected_cves'].append(cid)
            truth[ref]['source_refs'][cid]=f'/vulnerabilities/{index}/properties/dataset:nvd-cpe-component-refs'
        negative_ids = set(statuses.get('known_not_affected', []))
        for ref, component in components.items():
            if properties(component).get('dataset:source-product-id') in negative_ids:
                truth[ref]['negative_cves'].append(cid)
    for item in truth.values():
        overlap = set(item['expected_cves']) & set(item['negative_cves'])
        item['expected_cves'] = sorted(set(item['expected_cves'])-overlap)
        item['negative_cves'] = sorted(set(item['negative_cves'])-overlap)
        item['source_refs'] = {k:v for k,v in item['source_refs'].items() if k not in overlap}
        item['conflicting_cves'] = sorted(overlap)
    return dict(components=list(truth.values()), declared_scope_cves=sorted(declared),
        expected_cves=sorted({cid for c in truth.values() for cid in c['expected_cves']}),
        label_policy='Source-explicit affected product/version expressions; unlisted pairs remain unknown, not negative.',
        provenance='preserved_advisory_product_status_and_affects', independent_real_asset_gold=False)


def partition(records):
    """Keep whole documents sharing a target CVE or identical product inputs together."""
    parent = list(range(len(records)))
    def find(a):
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a
    def union(a,b):
        parent[find(a)] = find(b)
    owners = {}
    for i, record in enumerate(records):
        keys = [('cve',c) for c in record['gold']['declared_scope_cves']]
        keys.extend([('input',record['semantic_sha256']),('input',record['variant_semantic_sha256'])])
        keys.extend(('input',value) for value in record.get('additional_semantic_sha256',[]))
        for key in keys:
            if key in owners:
                union(i,owners[key])
            owners[key] = i
    groups = defaultdict(list)
    for i in range(len(records)):
        groups[find(i)].append(i)
    groups = sorted(groups.values(), key=lambda g:digest([SEED,[records[i]['source_id'] for i in g]]))
    cves = [{cid for i in group for cid in records[i]['gold']['declared_scope_cves']} for group in groups]
    total = len(set().union(*cves)) if cves else 0
    target = round(total*0.3)
    mandatory = {j for j,group in enumerate(groups) if any(records[i].get('requires_cpe_test') for i in group)}
    mandatory_weight=sum(len(cves[j]) for j in mandatory)
    optional_target=max(0,target-mandatory_weight)
    reachable = {0:None}
    for j, values in enumerate(cves):
        if j in mandatory:
            continue
        weight = len(values)
        if not weight:
            continue
        for previous in sorted(list(reachable), reverse=True):
            value = previous+weight
            if value <= optional_target and value not in reachable:
                reachable[value] = (previous,j)
    selected = set(mandatory)
    value = max(reachable)
    actual = mandatory_weight+value
    while value:
        value, j = reachable[value]
        selected.add(j)
    # Distribute source documents without target CVEs independently, rather
    # than filling the test with unscorable documents to meet a document ratio.
    desired_docs = round(sum(len(group) for j,group in enumerate(groups) if not cves[j])*0.3)
    test_docs = sum(len(groups[j]) for j in selected if not cves[j])
    for j, group in enumerate(groups):
        if not cves[j] and abs(test_docs+len(group)-desired_docs) < abs(test_docs-desired_docs):
            selected.add(j)
            test_docs += len(group)
    folds = {}
    split_cves = {'train':set(), 'test':set()}
    for j, group in enumerate(groups):
        fold = 'test' if j in selected else 'train'
        for i in group:
            folds[records[i]['source_id']] = fold
        split_cves[fold].update(cves[j])
    if split_cves['train'] & split_cves['test']:
        raise ValueError('Target CVE split leakage')
    return folds, dict(seed=SEED, split_unit='whole SBOM groups connected by target CVEs or identical control/perturbed product inputs',
        requested_test_cves=target, actual_test_cves=actual, target_cve_overlap=0,
        mandatory_test_sources=sorted(r['source_id'] for r in records if r.get('requires_cpe_test')),
        mandatory_test_group_cves=mandatory_weight,
        ratio_relaxed_for_CPE_coverage=mandatory_weight>target,
        actual_test_cve_fraction=actual/total if total else None,
        coverage_selection_uses_predictions=False,
        counts={k:len(v) for k,v in split_cves.items()},
        cves={k:sorted(v) for k,v in split_cves.items()},
        semantic_input_overlap=0, product_identity_disjointness_guaranteed=False,
        largest_target_cve_group=max(map(len,cves),default=0))


def usable(value):
    return isinstance(value,str) and value.strip().lower() not in ('','unknown','noassertion','*','none','n/a')


def perturb(document, scenario, source_id, product_names, allowed_refs=None):
    output = deepcopy(document)
    field = 'name' if scenario.startswith('component_') else 'version' if scenario.startswith('version_') else 'cpe'
    candidates = [c for c in output['components'] if usable(c.get(field))]
    if field == 'cpe':
        candidates = [c for c in candidates if c[field].startswith('cpe:2.3:')]
    if allowed_refs is not None:
        candidates=[c for c in candidates if c['bom-ref'] in allowed_refs]
    record = dict(field=field, scenario=scenario, applied=False, operator=None,
                  component_ref=None, before=None, after=None, reason=None)
    if not candidates:
        record['reason'] = 'source_field_missing_or_unknown'
        return output, record
    target = min(candidates, key=lambda c:digest([SEED,source_id,scenario,c['bom-ref']]))
    before = target[field]
    options = []
    if scenario.endswith('_mask'):
        options = [('mask','NOASSERTION')]
    elif field == 'name':
        options = [('outer_whitespace',' '+before+' '), ('letter_case',before.swapcase()),
                   ('space_to_underscore',before.replace(' ','_'))]
        for match in re.finditer(r'[A-Za-z]{2}',before):
            i = match.start()
            value = before[:i]+before[i+1]+before[i]+before[i+2:]
            if value.casefold() not in product_names:
                options.append(('adjacent_letter_transposition',value))
                break
    elif field == 'version':
        options = [('Version_prefix','Version '+before), ('version_prefix','version '+before)]
        if re.match(r'^\d',before):
            options.append(('v_prefix','v'+before))
    else:
        options = [('prefix_case','CPE:2.3:'+before[8:]),
                   ('prefix_transposition','cep:2.3:'+before[8:]),
                   ('prefix_whitespace','cpe: 2.3:'+before[8:])]
    options = [(op,value) for op,value in options if value != before]
    if not options:
        record['reason'] = 'no_semantics_preserving_operator'
        return output, record
    operator, after = options[int(digest([source_id,scenario])[:8],16)%len(options)]
    target[field] = after
    record.update(applied=True, operator=operator, component_ref=target['bom-ref'], before=before, after=after)
    return output, record


def cpe_test_refs(record):
    """Use existing CPE fields whose own component has an in-scope judged label."""
    judged={c['component_ref'] for c in record['gold']['components']
            if c['expected_cves'] or c['negative_cves']}
    return sorted(c['bom-ref'] for c in record['blind']['components']
                  if c['bom-ref'] in judged and usable(c.get('cpe')) and c['cpe'].startswith('cpe:2.3:'))


def build(source, output, cve_source):
    source, output, cve_source = Path(source).resolve(), Path(output).resolve(), Path(cve_source).resolve()
    if output == source or source in output.parents:
        raise ValueError('Keep derived data outside the source corpus')
    if output.exists():
        raise FileExistsError(output)
    cve_records = [json.loads(s) for s in cve_source.read_text(encoding='utf-8').splitlines() if s.strip()]
    universe = {r['id'] for r in cve_records}
    rejected = {r['id'] for r in cve_records if r.get('vulnStatus') == 'Rejected'}
    paths = sorted(source.glob('*.json'))
    if not paths:
        raise ValueError('No source SBOM files')
    records, all_cves, product_names = [], set(), set()
    for path in paths:
        original = json.loads(path.read_bytes())
        identity = digest(['source',path.stem])[:24]
        blind = blind_document(original,identity)
        gold = source_gold(original, universe, rejected)
        semantic = [{k:v for k,v in c.items() if k!='bom-ref'} for c in blind['components']]
        semantic = sorted(semantic,key=compact)
        redactions=[dict(component_ref=b['bom-ref'],field=k,before=a.get(k),after=b.get(k))
                    for a,b in zip(original.get('components',[]),blind['components'])
                    for k in b if a.get(k)!=b.get(k)]
        records.append(dict(source_id=path.stem, source_file=path.name, source_sha256=sha(path),
                            blinding_redactions=redactions,
                            blind=blind, gold=gold, semantic_sha256=digest(semantic)))
        product_names.update(c.get('name','').casefold() for c in original.get('components',[]))
        all_cves.update(v['id'] for v in original.get('vulnerabilities',[]) if v.get('id'))
    ordered = sorted(records,key=lambda r:digest([SEED,'scenario',r['source_id']]))
    scenarios = {r['source_id']:SCENARIOS[i%len(SCENARIOS)] for i,r in enumerate(ordered)}
    for record in records:
        refs=cpe_test_refs(record)
        record['requires_cpe_test']=bool(refs)
        record['cpe_test_component_refs']=refs
        record['original_assigned_scenario']=scenarios[record['source_id']]
        if refs:
            scenarios[record['source_id']]='CPE_noise'
        variant,change=perturb(record['blind'],scenarios[record['source_id']],record['source_id'],product_names,
                               allowed_refs=set(refs) if refs else None)
        if refs and not change['applied']:
            raise ValueError('Required CPE test perturbation was not applied')
        record['variant']=variant
        record['perturbation']=change
        semantic=sorted([{k:v for k,v in c.items() if k!='bom-ref'} for c in variant['components']],key=compact)
        record['variant_semantic_sha256']=digest(semantic)
    folds, split = partition(records)
    output.mkdir(parents=True)
    for fold in ('train','test'):
        for name in ('sboms','annotations'):
            (output/fold/name).mkdir(parents=True)
    write(output/'universe.json', dict(scored_cves=sorted(universe), source_population_cves=len(all_cves),
        out_of_scope_cves=sorted(all_cves-universe), cve_source_sha256=sha(cve_source)))
    write(output/'CVE_split.json',split['cves'])
    write(output/'split_manifest.json', {k:v for k,v in split.items() if k!='cves'})
    counts, fold_counts, noise_counts = Counter(), defaultdict(Counter), Counter()
    source_ledger = []
    handles = {fold:(output/fold/'gold.jsonl').open('x',encoding='utf-8') for fold in ('train','test')}
    try:
        for record in records:
            source_id = record['source_id']
            fold = folds[source_id]
            pair_id = 'advisory-'+digest(source_id)[:24]
            control_id = pair_id+'-control'
            scenario = scenarios[source_id]
            variant,change=record['variant'],record['perturbation']
            source_ledger.append({k:record[k] for k in ('source_id','source_file','source_sha256','semantic_sha256','variant_semantic_sha256','requires_cpe_test','cpe_test_component_refs')} | dict(fold=fold))
            for kind, document, perturbation in [('control',record['blind'],None),(scenario,variant,change)]:
                identity = control_id if kind=='control' else pair_id+'-variant'
                path = output/fold/'sboms'/(identity+'.json')
                write(path,document)
                annotation = dict(schema=SCHEMA,id=identity,fold=fold,sbom_file='sboms/'+path.name,
                    condition_id=pair_id, pair_id=pair_id, source_id=source_id,
                    source_file=record['source_file'],source_sha256=record['source_sha256'],
                    blinding_redactions=record['blinding_redactions'],
                    required_CPE_test_coverage=record['requires_cpe_test'],
                    original_assigned_scenario=record['original_assigned_scenario'],
                    scenario=kind,axis='control' if kind=='control' else {'name':'I1','version':'I2','cpe':'I3'}[change['field']],
                    control_sbom_id=control_id,noise_applied=bool(perturbation and perturbation['applied']),
                    perturbation=perturbation, gold=record['gold'],
                    export_format=dict(sbom_file_sha256=sha(path)))
                write(output/fold/'annotations'/(identity+'.json'),annotation)
                handles[fold].write(compact(annotation)+'\n')
                counts['cases']+=1
                fold_counts[fold]['cases']+=1
            for counter in (counts,fold_counts[fold]):
                counter.update(source_sboms=1,components=len(record['blind']['components']),
                    empty_source_sboms=not bool(record['blind']['components']),
                    with_scope_cves=bool(record['gold']['declared_scope_cves']),
                    with_positive_gold=bool(record['gold']['expected_cves']),
                    positive_component_cve_edges=sum(len(c['expected_cves']) for c in record['gold']['components']),
                    explicit_negative_edges=sum(len(c['negative_cves']) for c in record['gold']['components']),
                    applied_variants=change['applied'],unavailable_variants=not change['applied'])
            noise_counts[scenario+(':applied' if change['applied'] else ':unavailable')]+=1
    finally:
        for stream in handles.values():
            stream.close()
    with (output/'source_ledger.jsonl').open('x',encoding='utf-8') as stream:
        for row in source_ledger:
            stream.write(compact(row)+'\n')
    if any(sha(source/r['source_file']) != r['source_sha256'] for r in records):
        raise ValueError('Source changed during build')
    manifest = dict(schema=SCHEMA, source_directory=str(source), source_documents=len(records),
        source_dataset_id='icsa-advisory-products-sbom-v2', source_files_modified=False,
        counts=dict(counts), by_fold={k:dict(v) for k,v in fold_counts.items()}, noise=dict(noise_counts),
        input_component_occurrences=2*counts['components'],
        answer_token_redacted_fields=sum(len(r['blinding_redactions']) for r in records),
        scored_cves=len(universe), source_unique_cves=len(all_cves),
        target_cves_present=len({cid for r in records for cid in r['gold']['declared_scope_cves']}),
        source_ledger_sha256=sha(output/'source_ledger.jsonl'),
        cve_source_sha256=sha(cve_source), builder_sha256=sha(Path(__file__)),
        blind_policy='Remove vulnerabilities, descriptions, source properties/references and identifying advisory metadata. Preserve product/version/CPE values except explicit CVE answer tokens, recorded in blinding_redactions. Never invent a release.',
        noise_policy='One original field family on one component per variant; missing CPE is not invented. Unavailable variants remain recorded and are excluded from robustness denominators.',
        gold_policy='Explicit source affected/known-not-affected product relations. Missing relations remain open-world unknown. CPE selects CVE scope only.',
        split_manifest='split_manifest.json', new_model_training_performed=False,
        CPE_test_policy='Prioritize an existing CPE on a component with source-supported in-scope gold. Keep its entire connected group in test; relax 7:3 before breaking grouping.',
        required_CPE_test_sources=split['mandatory_test_sources'],
        product_identity_disjointness_guaranteed=False,
        artifacts={f'{fold}/gold.jsonl':sha(output/fold/'gold.jsonl') for fold in ('train','test')})
    write(output/'manifest.json',manifest)
    for fold in ('train','test'):
        write(output/fold/'manifest.json',dict(schema=SCHEMA,fold=fold,parent_manifest_sha256=sha(output/'manifest.json'),
            gold_sha256=sha(output/fold/'gold.jsonl'), universe_sha256=sha(output/'universe.json')))
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=ROOT/'benchmark/icsa-cpe-synthetic sbom/sbom')
    parser.add_argument('--output',type=Path,default=ROOT/'benchmark/item3_advisory_inputs_v3')
    parser.add_argument('--cve-source',type=Path,default=ROOT/'data/item3_identification_sources_v11/cves.jsonl')
    args = parser.parse_args()
    print(json.dumps(build(args.source,args.output,args.cve_source),ensure_ascii=False,indent=2))
