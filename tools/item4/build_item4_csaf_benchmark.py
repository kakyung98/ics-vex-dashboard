"""Build a versioned full-population benchmark without changing historical gold."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from collections import Counter, defaultdict
from copy import deepcopy
import argparse
import hashlib
import json
from pathlib import Path
import random

from src.item4.evaluation.synthetic_vex_benchmark import VERSION; from src.item4.evaluation.synthetic_vex_benchmark import JUSTIFICATIONS; from src.item4.evaluation.synthetic_vex_benchmark import VARIANTS; from src.item4.evaluation.synthetic_vex_benchmark import FACTS; from src.item4.evaluation.synthetic_vex_benchmark import digest; from src.item4.evaluation.synthetic_vex_benchmark import scenario; from src.item4.evaluation.synthetic_vex_benchmark import csaf_vex

ROOT = Path(__file__).resolve().parents[2]
DEFAULT = ROOT / 'benchmark/item4_evaluation/csaf_vex_v2'
SEED = 20261120
FACT_TEXT = {
    'component_present': ('The identified CVE-relevant component is present in the assessed product.',
        'A complete build and deployment inventory establishes that the identified CVE-relevant component is absent, including bundled and transitive components.'),
    'vulnerable_code_present': ('The component includes the code underlying this CVE.',
        'A build-specific exclusion certificate establishes that the code underlying this CVE is absent; the component itself remains present.'),
    'execution_path_exists': ('The vulnerable code has an executable path in the assessed product.',
        'A product-specific path analysis establishes that the vulnerable code is unreachable in every assessed product state, including non-anticipated states; this is not merely network filtering.'),
    'adversary_control_possible': ('An adversary can control the input or state required by the source-described vulnerability.',
        'A product-specific data and trust-boundary analysis establishes that an adversary cannot control the input or state required to exploit this CVE, across the assessed attack vectors.'),
    'inline_protection_effective': ('A built-in inline protection prevents exploitation of this CVE across the assessed vectors; it is effective in the specified build and cannot be bypassed in this hypothetical world. External firewalls and operational procedures are not this protection.',
        'No effective built-in inline protection blocks exploitation in this hypothetical product.'),
}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')


def line(handle, value):
    handle.write(json.dumps(value, ensure_ascii=False, separators=(',', ':'))+'\n')


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def advisory_split(rows):
    """Exact 1,164 evaluation advisories, stratified by year and CVE availability."""
    groups = defaultdict(list)
    for aid, row in rows.items():
        groups[(aid[5:7], bool(row.get('declared_cves')))].append(aid)
    target = 1164
    quotas = {k:len(v)*target/len(rows) for k,v in groups.items()}
    allocations = {k:int(q) for k,q in quotas.items()}
    order = sorted(groups, key=lambda k:(-(quotas[k]-allocations[k]), k))
    for key in order[:target-sum(allocations.values())]:
        allocations[key] += 1
    evaluation = set()
    for key in sorted(groups):
        rng = random.Random(str(SEED)+repr(key))
        evaluation.update(rng.sample(sorted(groups[key]), allocations[key]))
    return sorted(set(rows)-evaluation), sorted(evaluation)


def review_blank(case_id, cve, aid):
    return dict(id=case_id, cve=cve, advisory_id=aid, reviewer_id=None,
        status=None, actual_affected=None, justifications=None,
        reason_component_not_present=None, reason_vulnerable_code_not_present=None,
        reason_vulnerable_code_not_in_execute_path=None,
        reason_vulnerable_code_cannot_be_controlled_by_adversary=None,
        reason_inline_mitigations_already_exist=None,
        source_binding_valid=None, scenario_logic_valid=None, evidence_sufficient=None,
        evidence_refs=[], rationale=None, reviewed_at=None)


def training_text(row, root=ROOT):
    path = root/'icsa/csaf'/(row['advisory_id']+'.json')
    if not path.is_file():
        return row['title'], None
    raw = path.read_bytes()
    try:
        doc = json.loads(raw)
    except ValueError:
        return row['title'], hashlib.sha256(raw).hexdigest()
    parts = [row['title']]
    for owner in [doc.get('document', {}), *doc.get('vulnerabilities', [])]:
        for note in owner.get('notes', []):
            if note.get('category') in {'description', 'details', 'summary', 'general'} and note.get('text'):
                parts.append(note['text'])
    # No generated labels, status tables, flags, candidates or expert decisions.
    return '\n\n'.join(dict.fromkeys(parts)), hashlib.sha256(raw).hexdigest()


def build(out=DEFAULT):
    out = out.resolve()
    if out.exists():
        raise FileExistsError('Versioned output exists; preserve it and choose a new --output')
    legacy = ROOT/'benchmark/item4_evaluation'
    frozen = json.loads((legacy/'full_population_manifest.json').read_bytes())
    for name, expected in frozen['artifacts'].items():
        if sha(legacy/name) != expected:
            raise ValueError('Historical frozen reference changed: '+name)
    index_raw = (ROOT/'benchmark/icsa-cpe-synthetic sbom/index.json').read_bytes()
    rows = {r['advisory_id']:r for r in json.loads(index_raw)['advisories']}
    if len(rows) != 3881:
        raise ValueError('Expected 3,881 original ICSA')
    train, evaluation = advisory_split(rows)
    train_set, eval_set = set(train), set(evaluation)
    source_index = {r['cve']:r for r in json.loads((legacy/'full_population_index.json').read_bytes())}
    references = {}
    with (legacy/'full_population_gold.jsonl').open(encoding='utf-8') as f:
        for r in map(json.loads, f):
            if r['variant'] == 'present_true':
                references[r['cve']] = r
    from src.item4.decision.scoped_vex_review import catalogue; from src.item4.decision.scoped_vex_review import detail
    cves = sorted(r['cve'] for r in catalogue()['cves'])
    if len(cves) != 12418 or set(cves) != set(source_index):
        raise ValueError('Fixed CVE population mismatch')
    for folder in ['sboms', 'review', 'training', 'sources']:
        (out/folder).mkdir(parents=True, exist_ok=True)
    write(out/'advisory_split.json', dict(seed=SEED, unit='ICSA', train=train, evaluation=evaluation,
        stratification=['advisory_year', 'has_declared_cves'],
        split_before_scenarios=True, learning='self_supervised_causal_language_modeling_only',
        no_generated_training_labels=True, index_sha256=hashlib.sha256(index_raw).hexdigest()))
    counts = Counter(); overlap = []; population = []; review_advisories = defaultdict(list)
    training_text_hashes = Counter()
    handles = {name:(out/name).open('w', encoding='utf-8', newline='\n') for name in
        ['inputs.jsonl','candidate_labels.jsonl','gold.jsonl','candidate_csaf_vex.jsonl',
         'sources/cve_evidence.jsonl','review/packets.jsonl','review/rater_a.jsonl','review/rater_b.jsonl',
         'review/adjudication.jsonl','training/corpus.jsonl']}
    try:
        for aid in train:
            text, source_sha = training_text(rows[aid])
            training_text_hashes[digest(text)] += 1
            line(handles['training/corpus.jsonl'], dict(id=aid, text=text, source_sha256=source_sha,
                source_url=rows[aid]['url'], label_supervision=False))
        for cve in cves:
            record = detail(cve)
            aids = sorted(set(record['advisory_ids']) & set(rows))
            evaluation_aids = sorted(set(aids) & eval_set)
            training_aids = sorted(set(aids) & train_set)
            owner = (evaluation_aids or aids or ['unresolved-advisory'])[0]
            fold = 'evaluation' if evaluation_aids else 'train_context'
            if evaluation_aids and training_aids:
                overlap.append(dict(cve=cve, train_advisories=training_aids, evaluation_advisories=evaluation_aids))
            src = source_index[cve]; ref = references[cve]
            bound = bool(src['source_world_available'])
            product = src.get('selected_product')
            name = product['name'] if product else 'unresolved-source-product'
            version = src.get('version') or 'unknown'
            target = dict(name=name, version=version, cve=cve, asset_ref='hypothetical-'+digest(cve)[:20],
                          configuration='synthetic-fixed-configuration', evaluated_at='2026-11-20T00:00:00Z')
            line(handles['sources/cve_evidence.jsonl'], dict(cve=cve, original=record,
                selected_path=ref.get('selected_path'), source_binding_verified_by_expert=False))
            ids = []
            for variant in VARIANTS:
                case_id = 'V2-'+digest([VERSION,cve,variant,ref['source_record_digest']])[:28]
                ids.append(case_id)
                s = scenario(variant,bound)
                documents = []
                for key in FACTS:
                    value = s['facts'][key]
                    if value is None:
                        continue
                    documents.append(dict(id='EV-'+digest([case_id,key])[:18],
                        kind='synthetic_product_attestation', target=target,
                        statement=FACT_TEXT[key][0 if value else 1],
                        synthetic=True, actual_supplier_statement=False))
                if variant == 'insufficient_evidence':
                    documents = [dict(id='EV-'+digest(case_id)[:18], kind='incomplete_inventory_note',
                        target=target, statement='This inventory is incomplete. No build-specific code, path, adversary-control or inline-protection evidence is available.',
                        synthetic=True, actual_supplier_statement=False)]
                assumptions = [
                    'All supplied attestations are fictional facts for this hypothetical product/build only.',
                    'The identified component is the only CVE-relevant component in this hypothetical product.',
                    'When a source path is available, it completely describes exploitation in this hypothetical world; other paths are excluded by assumption, not by a real supplier finding.',
                    'Source binding and completeness require independent expert review before expert-gold export.']
                packet = dict(id=case_id,cve=cve,synthetic=True,target=target,
                    sbom_file='sboms/'+cve+'.json', source_evidence_ref='sources/cve_evidence.jsonl#'+cve,
                    documents=documents, assumptions=assumptions)
                line(handles['inputs.jsonl'],packet)
                candidate = dict(id=case_id,cve=cve,advisory_id=owner,advisory_ids=aids,fold=fold,
                    variant=variant,**s, intended_justification=variant if variant in JUSTIFICATIONS else None,
                    label_method='conditional_synthetic_product_facts_v2',
                    expert_validated=False, real_asset_impact_verified=False)
                line(handles['candidate_labels.jsonl'],candidate)
                # Authoritative scoring ledger is blank until human adjudication.
                line(handles['gold.jsonl'],dict(id=case_id,cve=cve,advisory_id=owner,fold=fold,
                    actual_affected=None,status=None,justifications=None,expert_validated=False))
                statement = ('Conditional synthetic reference only. These are fictional product attestations, '
                    'not real supplier findings or verified installed-asset impact. Source-unresolved scenarios remain under investigation. '
                    + ' '.join(d['statement'] for d in documents))
                line(handles['candidate_csaf_vex.jsonl'],dict(id=case_id,document=csaf_vex(case_id,cve,
                    'Hypothetical assessed product / '+name+' / '+version,s['candidate_status'],s['candidate_justifications'],statement)))
                if fold == 'evaluation':
                    line(handles['review/packets.jsonl'],dict(**packet,advisory_id=owner,
                        source_advisory_ids=evaluation_aids))
                    blank = review_blank(case_id,cve,owner)
                    for rater in ['a','b']:
                        line(handles['review/rater_'+rater+'.jsonl'],blank)
                    line(handles['review/adjudication.jsonl'],dict(**blank,adjudicator_id=None,
                        independent_ratings_locked=False,resolution=None))
                    for aid in evaluation_aids:
                        review_advisories[aid].append(case_id)
                counts['cases'] += 1; counts['variant:'+variant] += 1; counts['fold:'+fold] += 1
                counts['candidate:'+str(s['candidate_actual_affected']).lower()] += 1
            # Absence assertions refer to assessed product, while target identity
            # remains in evidence; per-case inventory facts are in documents.
            bom = dict(bomFormat='CycloneDX',specVersion='1.7',version=1,
                metadata=dict(component=dict(type='device',name=target['asset_ref'],**{'bom-ref':target['asset_ref']})),
                components=[dict(type='application',name=name,version=version,**{'bom-ref':'target-component'})],
                vulnerabilities=[dict(id=cve,affects=[dict(ref=target['asset_ref'])])],
                properties=[dict(name='dataset:synthetic-inventory',value='true'),
                            dict(name='dataset:inventory-role',value='target-reference-not-confirmed-deployment')])
            write(out/'sboms'/(cve+'.json'),bom)
            population.append(dict(cve=cve,advisory_ids=aids,owner_advisory=owner,fold=fold,
                source_world_available=bound,case_ids=ids,selected_product=product,
                expert_status='pending' if fold=='evaluation' else 'not_in_30pct_expert_sample'))
            counts['cves'] += 1; counts['source_bound_cves'] += bound
            if counts['cves'] % 1000 == 0:
                print(json.dumps(dict(stage='build_v2',**dict(counts))),flush=True)
    finally:
        for handle in handles.values():
            handle.close()
    assert counts['cves']==12418 and counts['cases']==12418*7
    write(out/'population_index.json',population)
    write(out/'review/advisory_index.json',[dict(advisory_id=aid,
        case_ids=sorted(set(review_advisories[aid])),
        status='pending_case_review' if review_advisories[aid] else 'no_linked_target_cve',
        advisory_scope_valid=None,reviewer_a=None,reviewer_b=None) for aid in evaluation])
    write(out/'split_overlap_audit.json',dict(overlapping_cves=len(overlap),rows=overlap,
        interpretation='ICSA-disjoint split; not a CVE-disjoint or pretraining-unseen holdout',
        exact_training_text_overlap_evaluation_advisories=sum(
            digest(training_text(rows[aid])[0]) in training_text_hashes for aid in evaluation)))
    manifest = dict(schema=VERSION,population_cves=12418,population_icsa=3881,
        train_icsa=2717,evaluation_icsa=1164,seed=SEED,counts=dict(counts),variants=list(VARIANTS),
        candidate_reference_only=True,expert_review_complete=False,training_executed=False,
        all_population_assigned=True,expert_scope='Cases with at least one of the 1,164 evaluation advisories; canonical evaluation owner prevents double counting.',
        source_unresolved_retained=True,full_population_expert_precision_available=False,
        metric=dict(formula='TP/(TP+FP)',positive_status='affected',threshold=.85,comparison='strictly_greater',
            unknown_predicted_affected='blocks_full_precision_and_pass',zero_positive='undefined'),
        standards=dict(csaf='https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html',
            cohen='https://doi.org/10.1177/001316446002000104'),
        source_manifest_sha256=sha(legacy/'full_population_manifest.json'),
        generator_sha256=sha(Path(__file__)),
        reference_code_sha256=sha(ROOT/'src/item4/evaluation/synthetic_vex_benchmark.py'))
    # Hash every generated input, source, blank form and candidate artifact.
    manifest['artifacts']={p.relative_to(out).as_posix():sha(p) for p in sorted(out.rglob('*')) if p.is_file()}
    write(out/'manifest.json',manifest)
    (out/'README.txt').write_text('''#4 CSAF 비영향 사유 및 전문가 검증 벤치마크 v2
12,418개 CVE 전체 × 7개 = 86,926개 사례. 원본 3,881개 ICSA와 과거 벤치마크를 보존합니다.
ICSA 기준 학습 2,717 / 전문가 평가 1,164. 분할은 seed 20261120, 연도·CVE 유무 층화입니다.
training/corpus.jsonl은 text 필드만 자기지도 학습에 사용합니다. 정답·후보·전문가 판정으로 학습하지 않습니다.
공급사 제품 증명은 합성 가정이며 실제 공급사의 주장이 아닙니다. 다섯 사유의 조건부 논리 검증용입니다.
inputs.jsonl과 sboms/ 및 sources/는 입력, candidate_labels.jsonl은 후보 정답입니다.
candidate_csaf_vex.jsonl은 synthetic DRAFT이며 전문가 확정 문서가 아닙니다.
gold.jsonl은 실제 전문가 확정 전까지 전건 미확정입니다. 후보 정답을 전문가 골든으로 복사하지 마십시오.
review/packets.jsonl은 의도 라벨을 숨긴 평가 입력입니다. 대응 rater_a/rater_b 양식을 독립 작성합니다.
review/advisory_index.json에는 CVE가 없는 ICSA도 포함됩니다. 없는 CVE를 생성하지 않습니다.
중복 CVE는 평가 ICSA가 하나라도 있으면 평가에 배정하고, 대표 평가 ICSA 하나로 집계합니다.
split_overlap_audit.json을 함께 보고합니다. ICSA 분할은 미학습 CVE 일반화의 증거가 아닙니다.
평가: python -m tools.item4.item4_expert_review --help
기존 지표 TP/(TP+FP), affected 양성, 85% 초과를 유지합니다. unknown 양성은 전체 통과를 보류합니다.
70% 문맥 측은 전문가 정답이 없으므로 전체 모집단 전문가 정확도를 확정할 수 없습니다.
정밀도는 전문가 표본과 전체 조건부 합성 기준선을 구분하며, 전자는 조정 완료 후에만 산출합니다.
전문가 검증·모델 재학습·실제 모델 전수 평가 완료를 이 데이터 생성으로 주장하지 않습니다.
상세 설계: docs/ITEM4_CSAF_EXPERT_DESIGN.md, 실행: docs/ITEM4_CSAF_EXPERT_MANUAL.md
''',encoding='utf-8')
    print(json.dumps(manifest,ensure_ascii=False,indent=2)[:5000])


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=DEFAULT)
    build(parser.parse_args().output)
