"""Build blinded review exhibits from frozen operator inputs and primary supplier records."""
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re

from src.item4.decision import scoped_vex_review as asset_vulntology; from src.item4.analysis import product_advisory_evidence as advisory
from src.item4.workflow import source_analysis_jobs as item4_questionnaire; from src.item4.evaluation import scenario_evaluation_runner as item4_scenario_run
from src.item3.evidence.cisa_advisory_lookup import source_records
from src.item4.evaluation.operator_observation_benchmark import source_bindings


def require(test, message):
    if not test:
        raise ValueError(message)


def pointer_value(document, pointer):
    if not isinstance(pointer, str) or not pointer.startswith('/'):
        raise ValueError('Invalid JSON pointer')
    value = document
    for token in pointer[1:].split('/'):
        key = token.replace('~1', '/').replace('~0', '~')
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def exhibit(identifier, kind, title, facts, source):
    return dict(evidence_id=identifier, kind=kind, title=title, facts=facts, source=source)


@lru_cache(maxsize=100)
def source_material(cve):
    detail = asset_vulntology.detail(cve)
    materials = {}
    for aid in detail['advisory_ids']:
        require(re.fullmatch(r'icsa-\d{2}-\d{3}-\d+[a-z]?', aid), 'Invalid advisory index ID')
        entry = source_records().get(aid, {})
        pinned = advisory._document(aid, detail)
        url = entry.get('url') or 'https://www.cisa.gov/news-events/ics-advisories/' + aid
        if pinned:
            path, sha, doc, sources = pinned
            materials[aid] = (dict(file=path.relative_to(asset_vulntology.ROOT).as_posix(),
                                    document_sha256=sha, url=url), doc, sources)
            continue
        html = Path('data/icsa_sbom_source_html') / (aid + '.html')
        if entry.get('source') == 'CISA HTML' and (asset_vulntology.ROOT / html).is_file():
            digest = hashlib.sha256((asset_vulntology.ROOT / html).read_bytes()).hexdigest()
            if digest == entry.get('source_raw_sha256'):
                materials[aid] = (dict(file=html.as_posix(), document_sha256=digest, url=url), None, [])
                continue
        # An index entry may survive without a hash-verifiable source file.
        materials[aid] = (dict(url=url, indexed_sha256=entry.get('source_raw_sha256')), None, [])
    return detail, materials


def document_exhibits(cve, materials, matches):
    exhibits = []
    for ordinal, (aid, (location, doc, _)) in enumerate(sorted(materials.items()), 1):
        facts = dict(advisory_id=aid, cve=cve)
        if doc is None:
            facts['record_format'] = 'archived_html' if 'file' in location else 'index_only'
        else:
            tree = advisory.source_products(doc)
            rows = list(advisory.status_rows(doc, cve))
            facts.update(record_format='CSAF', publisher=doc['document']['publisher'].get('name'),
                         title=doc['document']['title'], cve_status_row_count=len(rows),
                         product_ids_without_unique_tree_entry=[
                             dict(product_id=pid, status_category=status, pointer=pointer)
                             for pid, status, pointer in rows if pid not in tree])
        exhibits.append(exhibit(f'D{ordinal:02}', 'advisory_reference', '권고문 원본과 제품 목록',
                                facts, location))
    for ordinal, row in enumerate(matches, 1):
        location, doc, _ = materials[row['advisory_id']]
        require(doc is not None and location['document_sha256'] == row['document_sha256'],
                'Pinned supplier row has no corresponding document')
        status_ptr, product_ptr = row['status_pointer'], row['product_pointer']
        pid = pointer_value(doc, status_ptr)
        product = pointer_value(doc, product_ptr)
        status = status_ptr.split('/')[-2]
        vulnerability_ptr = status_ptr.split('/product_status/')[0]
        branch_ptr = product_ptr.rsplit('/', 1)[0]
        branch = pointer_value(doc, branch_ptr)
        chain = []
        cursor = branch_ptr
        while cursor.startswith('/product_tree/branches/'):
            node = pointer_value(doc, cursor)
            chain.append(dict(pointer=cursor, category=node['category'], name=node['name']))
            cursor = cursor.rsplit('/branches/', 1)[0]
        chain.reverse()
        version_names = [node['name'] for node in chain
                         if node['category'] in ('product_version', 'product_version_range')]
        require((version_names[-1] if version_names else '') == row['source_version'],
                'The source product-tree version differs from the scoped record')
        require(pid == row['source_product_id'] == product['product_id'] and status == row['status']
                and pointer_value(doc, vulnerability_ptr + '/cve') == cve, 'Supplier pointer scope differs')
        # Include only original product/status fields; the reader judges applicability.
        facts = dict(advisory_id=row['advisory_id'], cve=cve, product_id=pid,
                     product_name=product['name'], branch_category=branch.get('category'),
                     branch_name=branch.get('name'), source_version=row['source_version'],
                     source_status=status, product_tree_branches=chain)
        exhibits.append(exhibit(f'S{ordinal:02}', 'published_product_status', '공급사 제품·버전 상태 원문',
                                facts, dict(location, product_pointer=product_ptr, status_pointer=status_ptr)))
    return exhibits


def condition_exhibits(detail, materials, questions, matches):
    """Expose a source expression only if every quoted leaf is scoped and maps to a recorded question."""
    eligible = {r['product_key'] for r in matches
                if r['status'] == 'known_affected' and r['version_membership'] == 'true'}
    records = []
    for rule in detail['scenarios']:
        scope = sorted(eligible & set(rule.get('product_keys', [])))
        if not scope or rule.get('scope_ambiguous') or not rule.get('conditions'):
            continue
        bindings, _ = source_bindings(questions, {'selected_path': rule})
        atoms = []
        for atom in rule['conditions']:
            if atom['id'] not in bindings or not atom.get('operator_observable'):
                break
            ref = atom['source_ref']
            aid = ref['source_id'].split(':')[0]
            if aid not in materials:
                break
            location, doc, sources = materials[aid]
            source = next((s for s in sources if s['id'] == ref['source_id']), None)
            if not doc or not source or source.get('subject_ambiguous'):
                break
            scoped_products = sorted(set(scope) & set(source.get('product_keys', [])))
            if not scoped_products:
                break
            ptr = source['pointer']
            raw_text = pointer_value(doc, ptr)
            a, b = ref['span']
            require(isinstance(raw_text, str) and raw_text == source['text'] and
                    hashlib.sha256(raw_text.encode()).hexdigest() == source['text_sha256'] and
                    0 <= a < b <= len(raw_text) and raw_text[a:b] == ref['quote'],
                    'A quoted operator condition differs from the primary source')
            # Additional version ceilings in the same note can qualify an embedded
            # product independently of the version in the CSAF product tree.
            version_phrases = re.finditer(
                r'\b(?:(?:vulnerability|issue) in (?:the )?(?:[a-zA-Z0-9_.+-]+ ){1,10})?'
                r'(?:before|prior to|earlier than|up to and including) v?\d+(?:\.\d+){1,6}\b',
                raw_text, flags=re.IGNORECASE)
            atoms.append(dict(condition_id=atom['id'], question_id=bindings[atom['id']],
                              scope_product_keys=scoped_products, source_product_set=source['product_keys'],
                              scope_binding=source.get('scope_binding'), quote=raw_text[a:b],
                              note_version_excerpts=[dict(quote=m.group(), character_span=list(m.span()))
                                                     for m in version_phrases],
                              source=dict(location, pointer=ptr, text_sha256=source['text_sha256'],
                                          character_span=[a, b])))
        if len(atoms) != len(rule['conditions']):
            continue
        facts = dict(source_expression=rule['expression'], operator_condition_excerpts=atoms,
                     product_scope=scope, derivation=rule.get('derivation'))
        records.append(exhibit(f'R{len(records)+1:02}', 'source_condition_mapping', '자산 운영 정보 질문과 권고문 조건 대조',
                               facts, dict(file=f'site/asset_vulntology/records_{detail["cve"][4:8]}.json',
                                           record_digest=detail['record_digest'], source_rule_id=rule['id'])))
    return records


def make_evidence(candidate, packet, case, *, source_input_sha256, packet_sha256):
    """Return only public supplier and frozen synthetic material, with no candidate or model decision."""
    cve = case['cve']
    require(cve == packet['cve'] == candidate['cve'] and candidate['id'] == case['id'] and
            candidate['packet_sha256'] == packet_sha256 and case['synthetic'] is True and
            candidate['synthetic'] is True, 'Case, packet, or reviewed product scopes differ')
    case_positions = [i for i, item in enumerate(packet['cases']) if item['id'] == case['id']]
    require(len(case_positions) == 1 and packet['cases'][case_positions[0]] == case,
            'Operator input is missing or differs in its frozen packet')
    require(source_input_sha256 == candidate['inventory_review']['source_input_sha256'] and
            hashlib.sha256(json.dumps(case, ensure_ascii=False).encode()).hexdigest() == source_input_sha256,
            'The operator input fingerprint differs')
    job = packet['job']
    bom = job['input_bom']
    require(item4_questionnaire.digest(bom) == job['bom_sha256'], 'Frozen BOM fingerprint differs')
    components, declarations = item4_questionnaire.inventory(bom)
    decl, = [item for item in declarations if item['cve'] == cve]
    ref, = decl['component_refs']
    component, = [item for item in components if item['ref'] == ref]
    identity = advisory.component_identity(component)
    product = advisory.verified_version_evidence(cve, component)
    require(product == candidate['verified_product'], 'Re-read supplier facts differ from the sealed source scope')
    packet_file = f'{item4_scenario_run.PREFIX}/cves/{cve}.json'
    location = dict(file=packet_file, packet_sha256=packet_sha256)
    properties = {p['name']:p['value'] for p in bom.get('properties', []) if p['name'] in
                  ('dataset:synthetic-inventory','dataset:deployment-verified')}
    require(properties == {'dataset:synthetic-inventory': 'true', 'dataset:deployment-verified': 'false'},
            'Unexpected inventory provenance in frozen sample')
    evidence = [exhibit('B01', 'synthetic_bom_component', '동결된 합성 BOM 구성요소',
                        dict(component=identity, bom_properties=properties),
                        dict(location, pointer='/job/input_bom'+component['pointer'], bom_sha256=job['bom_sha256']))]
    questions = {q['id']:(i,q) for i,q in enumerate(job['questions'])
                 if q.get('component_ref') == ref and q['cve'] == cve}
    answers = []
    for qid,value in sorted(case['answers'].items()):
        require(qid in questions, 'The frozen answer has no matching component-scoped question')
        idx, q = questions[qid]
        options = {option['code']:option['label'] for option in q['options']}
        require(value in options, 'The frozen answer is outside its question options')
        answers.append(dict(question_id=qid, label=q['label'], value=value,
                            value_label=options[value],
                            record_type=(q.get('observation') or {}).get('record_type'),
                            question_pointer=f'/job/questions/{idx}'))
    evidence.append(exhibit('O01', 'synthetic_operator_input', '동결된 합성 운영 관측과 응답',
                            dict(context=case['context'], answers=answers),
                            dict(location, pointer=f'/cases/{case_positions[0]}',
                                 aggregate_file=f'{item4_scenario_run.PREFIX}/inputs.jsonl',
                                 original_line_sha256=source_input_sha256)))
    detail, materials = source_material(cve)
    evidence.extend(document_exhibits(cve, materials, product['evidence']))
    evidence.extend(condition_exhibits(detail, materials, [q for _,q in questions.values()],
                                       product['evidence']))
    return dict(cve=cve, component=identity, evidence=evidence)
