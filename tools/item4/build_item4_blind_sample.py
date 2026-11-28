"""Prepare a stratified, blinded defensive applicability review of the frozen #4 population."""
import argparse
from collections import Counter, defaultdict
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.evaluation import evaluation_run_records as ledger
from src.item4.evaluation import scenario_evaluation_runner as runs


VERSION = 'item4-blind-sample/1'
SEED = 'ics-vex-item4-independent-review-20261122-v1'
CAP = 20
POSITIVE = 'affected'
STRATA = {
    POSITIVE: '영향 후보',
    'deployment_or_running_version_unresolved': '배포 상태 또는 실행 버전 미확정',
    'sufficient_source_rule_unavailable': '판정에 충분한 출처 규칙 없음',
    'inventory_completeness_not_evidenced': '배포 재고의 완전성 근거 없음',
    'supplier_evidence_conflicting_or_unresolved': '공급사 근거 충돌 또는 미확정',
    'source_rule_unsatisfied_or_unresolved': '출처 규칙 미충족 또는 충족 여부 미확정',
    'crosscheck_did_not_corroborate': '교차검토에서 근거 미확인',
}
EVIDENCE_NAMES = {
    'synthetic_bom_component': '동결 합성 BOM 구성요소',
    'synthetic_operator_input': '동결 합성 운영 관측·응답',
    'advisory_reference': '공개 권고문과 대상 제품 목록',
    'published_product_status': '권고문 원문에서 대조한 제품·버전 상태 행',
    'source_condition_mapping': '원문 조건과 자산 운영 정보 질문의 대응',
}
DEFAULT_OUTPUT = ROOT / 'results/item4_independent_review_20261122'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return sha256(raw).hexdigest()


def rank(domain, identifier):
    return digest('\0'.join([SEED, domain, identifier]).encode())


def review_id(identifier):
    return 'R-' + rank('blind-id', identifier)[:14].upper()


def classify(row):
    require(row['generation_status'] == 'completed' and row['synthetic'] is True, 'Unexpected input cohort.')
    if row['candidate_status'] == POSITIVE:
        return POSITIVE
    require(row['candidate_status'] == 'under_investigation' and len(row['reasons']) == 1
            and row['reasons'][0] in STRATA and row['reasons'][0] != POSITIVE, 'Unexpected or overlapping stratum.')
    return row['reasons'][0]


def sample(source_dir):
    snapshot = ledger.get_run(source_dir.name)
    require(snapshot['status'] == 'completed' and snapshot['generation_method'] == 'scenario_moe_explicit_inventory_review',
            'Review requires a completed explicit inventory review.')
    report = runs.sealed_json(source_dir/'report.json', snapshot['data_hashes']['report.json'])
    audit = runs.sealed_json(source_dir/'independent_verification.json', snapshot['data_hashes']['independent_verification.json'])
    ranked = defaultdict(list)
    seen = set()
    source_sha = sha256()
    candidates = source_dir/'candidates.jsonl'
    with candidates.open('rb') as stream:
        for raw in stream:
            source_sha.update(raw)
            row = json.loads(raw)
            key = row['id']
            require(key not in seen and row['run_id'] == source_dir.name, 'Duplicate ID or wrong candidate run.')
            seen.add(key)
            ranked[classify(row)].append((rank('select', key), key))
    require(source_sha.hexdigest() == audit['candidates_sha256'] == report['candidates_sha256'] == snapshot['result']['candidates_sha256']
            and len(seen) == audit['unique_scenarios'] == report['unique_scenarios']
            and not any(audit[k] for k in ('missing_ids','duplicate_ids','extra_ids','order_mismatches')),
            'Population differs from the signed-off ledger.')
    counts = {s:len(ranked[s]) for s in STRATA}
    require(counts == dict(report['hold_reasons'], affected=1) and set(ranked) == set(STRATA),
            'The source no longer has the expected single positive and six hold strata.')
    chosen = {key for group in ranked.values() for _,key in sorted(group)[:CAP]}
    selected = []
    with candidates.open('rb') as stream:
        for raw in stream:
            row = json.loads(raw)
            if row['id'] in chosen:
                selected.append((row, digest(raw.rstrip(b'\r\n'))))
    selected.sort(key=lambda entry: rank('display', entry[0]['id']))
    require(len(selected) == len(chosen) == len({review_id(row['id']) for row,_ in selected}),
            'Sample identities do not reconcile.')
    return report, counts, selected


def json_bytes(item):
    return json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def put_json(path, item):
    path.write_bytes(json.dumps(item, ensure_ascii=False, indent=2, allow_nan=False).encode('utf-8') + b'\n')


def put_rows(path, rows):
    with path.open('xb') as stream:
        for row in rows:
            stream.write(json_bytes(row) + b'\n')


def source_cases(report, selected):
    delivery = Path(json.loads(runs.BASELINE.read_bytes())['artifact_directory'])
    manifest = runs.sealed_json(delivery/'delivery_manifest.json', report['source_manifest_sha256'])
    needed = {row['id'] for row,_ in selected}
    inputs = {}
    input_key = runs.PREFIX + '/inputs.jsonl'
    raw_sha = sha256()
    with (delivery/input_key).open('rb') as stream:
        for raw in stream:
            raw_sha.update(raw)
            case = json.loads(raw)
            if case['id'] in needed:
                require(case['id'] not in inputs, 'A selected input occurs twice.')
                inputs[case['id']] = (case, digest(raw.rstrip(b'\r\n')))
    require(raw_sha.hexdigest() == manifest[input_key] == report['inputs_sha256'] and set(inputs) == needed,
            'Selected frozen operator inputs or file hash differ.')
    return delivery, manifest, inputs


def assemble(report, counts, selected):
    from tools.item4.item4_review_sample_evidence import make_evidence

    delivery, manifest, inputs = source_cases(report, selected)
    packets = {}
    neutral, key = [], []
    for candidate, source_line_sha in selected:
        identifier, cve = candidate['id'], candidate['cve']
        rid = review_id(identifier)
        case, input_sha = inputs[identifier]
        packet_name = f'{runs.PREFIX}/cves/{cve}.json'
        packet_sha = manifest[packet_name]
        if cve not in packets:
            packets[cve] = runs.input_packet(delivery, manifest, cve)
        packet = packets[cve]
        matches = [item for item in packet['cases'] if item['id'] == identifier]
        require(matches == [case] and case['cve'] == cve and case['synthetic'] is True
                and candidate['packet_sha256'] == packet_sha
                and candidate['inventory_review']['source_input_sha256'] == input_sha,
                'Source packet, operator input and candidate do not bind to the same observation.')
        item = make_evidence(candidate, packet, case, source_input_sha256=input_sha, packet_sha256=packet_sha)
        require(item['cve'] == cve, 'Evidence cites a different CVE.')
        case_card = dict(review_id=rid, **item)
        neutral.append(case_card)
        stratum = classify(candidate)
        key.append(dict(review_id=rid, source_scenario_id=identifier, cve=cve, stratum=stratum,
                        candidate_status=candidate['candidate_status'], previous_reasons=candidate['reasons'],
                        selection_hash=rank('select', identifier), sample_n=min(CAP,counts[stratum]), population_n=counts[stratum],
                        candidate_row_sha256=source_line_sha, input_row_sha256=input_sha,
                        packet_path=packet_name, packet_sha256=packet_sha, neutral_case_sha256=digest(json_bytes(case_card))))
    check_blinding(neutral, key)
    return neutral, key


def check_blinding(cases, key):
    require(len(cases) == len(key), 'Different numbers of review cards and key entries.')
    hidden = {'candidate_status','stratum','source_scenario_id','expert_validated','ground_truth','expected_status',
              'source_decision','run_id','routed_experts','model_verdict','selection_hash','product_vex_status'}
    def field_names(item):
        if isinstance(item, list):
            for child in item:
                yield from field_names(child)
        if isinstance(item, dict):
            for name, value in item.items():
                yield name
                yield from field_names(value)
    for card, origin in zip(cases, key):
        ids = [e['evidence_id'] for e in card['evidence']]
        raw = json_bytes(card)
        require(ids and len(ids) == len(set(ids)) and card['review_id'] == origin['review_id']
                and len(set(field_names(card)) & hidden) == 0
                and origin['source_scenario_id'].encode() not in raw
                and all(s.encode() not in raw for s in STRATA if s != POSITIVE),
                'Review material includes an internal identifier, prior decision or repeated evidence ID.')


def field_requests(cases, key):
    specific = {
        POSITIVE: ['배포·실행 버전 및 해당 운영 조건을 각각 입증하는 시점 일치 원기록'],
        'deployment_or_running_version_unresolved': ['실제 설치·실행 버전 또는 빌드와 배포 단위를 특정하는 인벤토리·변경 기록'],
        'sufficient_source_rule_unavailable': ['해당 제품 버전과 운영 조건의 관계를 명시한 공급사 권고문 원문 또는 공식 확인서'],
        'inventory_completeness_not_evidenced': ['해당 시점의 재고 수집 범위·예외·누락과 구성요소 조회 결과를 함께 기록한 자산 인벤토리'],
        'supplier_evidence_conflicting_or_unresolved': ['제품 식별자·에디션·빌드와 적용 범위를 확인할 수 있는 최신 공급사 개정 이력 및 동일 시점 자산 기록'],
        'source_rule_unsatisfied_or_unresolved': ['원문에 연결된 운영 조건별 설정·변경 기록과 해당 시점의 적용 범위'],
        'crosscheck_did_not_corroborate': ['동일 구성요소·시점을 가리키는 별도 운영 기록과 공급사 원문 내 근거 위치'],
    }
    for card, mapping in zip(cases, key):
        yield dict(review_id=card['review_id'], cve=card['cve'], reference_component=card['component'],
                   record_status='awaiting_new_field_evidence', requested_records=specific[mapping['stratum']],
                   # Synthetic inventories do not identify a physical site or prove a real deployment.
                   supplied_record=dict(field_case_ref=None, pseudonymous_asset_ref=None, configuration_scope=None,
                       product_component_ref=None, deployment_state=None, running_build=None,
                       observation_time_with_timezone=None, inventory_coverage=None, explicit_coverage_basis=None,
                       source_record_ref=None, source_record_sha256=None, source_locator_or_excerpt=None,
                       recorded_by_or_role=None, scope_and_time_match_basis=None))


def provenance_check(source_dir, report):
    p = json.loads((runs.OUTPUT/'current_full_population.json').read_bytes())
    require(source_dir == runs.OUTPUT/p['run_id'] and report['candidates_sha256'] == p['candidates_sha256'],
            'Sampling must start from the current full-population pointer.')


def field_scope_ok(audit, report):
    require(audit['status'] == 'complete' and audit['verified_field_record_links'] == 0
            and audit['manual_review_records'] == 0 and report['inputs_sha256'] == audit['frozen_source']['inputs_sha256']
            and report['source_manifest_sha256'] == audit['frozen_source']['delivery_manifest_sha256'],
            'Local field evidence requires manual reconciliation before preparing this no-field-evidence package.')


def prepare(directory):
    from tools.item4.audit_item4_field_record_links import audit
    from tools.item4.render_item4_blind_sample import render_review_forms

    destination = directory.resolve()
    if destination.exists():
        raise FileExistsError('Select a new destination. Existing reviews are preserved.')
    pointer = json.loads((runs.OUTPUT/'current_full_population.json').read_bytes())
    source_dir = runs.OUTPUT/pointer['run_id']
    report, counts, selected = sample(source_dir)
    provenance_check(source_dir, report)
    cards, key = assemble(report, counts, selected)
    field_audit = audit()
    field_scope_ok(field_audit, report)
    counts_by_kind = Counter(e['kind'] for card in cards for e in card['evidence'])
    cases_by_kind = Counter(kind for card in cards for kind in {e['kind'] for e in card['evidence']})
    packet_id = 'B-' + digest(json_bytes(cards))[:24]
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.blind-review-', dir=destination.parent) as staging:
        directory = Path(staging)/destination.name
        private = directory/'coordinator'
        private.mkdir(parents=True)
        put_rows(private/'neutral_evidence.jsonl', cards)
        put_rows(private/'selection_key.jsonl', key)
        put_rows(private/'field_record_requests.jsonl', field_requests(cards, key))
        put_json(private/'field_record_audit.json', field_audit)
        render_review_forms(directory, cards, packet_id=packet_id)
        summary = dict(version=VERSION, packet_id=packet_id, source_run_id=source_dir.name,
            source_candidates_sha256=report['candidates_sha256'], frozen_inputs_sha256=report['inputs_sha256'],
            frozen_manifest_sha256=report['source_manifest_sha256'], seed=SEED,
            selection='Order each original scenario ID within its single stratum by SHA256(seed + NUL + select + NUL + id); take min(20,N). Separate domains assign blind IDs and display order.',
            per_stratum_cap=CAP, population_scenarios=report['unique_scenarios'], population_cves=report['unique_cves'],
            sample_scenarios=len(cards), sample_cves=len({c['cve'] for c in cards}), population_counts=counts,
            selected_counts=dict(Counter(row['stratum'] for row in key)), evidence_items_by_kind=dict(counts_by_kind),
            cases_with_evidence_kind=dict(cases_by_kind), verified_field_records_attached=0,
            completed_human_reviews_at_preparation=0)
        write_guide(directory, destination, summary, field_audit)
        summary['files'] = {p.relative_to(directory).as_posix():runs.file_sha(p)
                            for p in sorted(directory.rglob('*')) if p.is_file()}
        put_json(private/'manifest.json', summary)
        verify(directory, expected=summary, rerun=False)
        directory.rename(destination)
    return destination


def write_guide(directory, destination, summary, audit):
    n = summary['sample_scenarios']
    table = '\n'.join(f"| {title} | {summary['population_counts'][s]:,} | {summary['selected_counts'][s]:,} |"
                      for s,title in STRATA.items())
    kinds = '\n'.join(f'| {EVIDENCE_NAMES.get(k,k)} | {v:,} | {summary["evidence_items_by_kind"][k]:,} |'
                      for k,v in sorted(summary['cases_with_evidence_kind'].items()))
    location = destination.relative_to(ROOT).as_posix() if destination.is_relative_to(ROOT) else destination.as_posix()
    guide = f"""# #4 독립 검토 표본 · 진행자용

검토 대상은 {summary['sample_cves']:,}개 CVE의 동결 합성 시나리오 {n}건입니다. 검토자는 각 시나리오의 가정과 문서 근거로 네 가지 VEX 상태 중 하나를 판단합니다. 실제 현장에 설치됐는지, 해당 시간에 어떤 설정이 적용됐는지는 별도 운영 기록으로 확인해야 합니다. 준비 시점에 완료된 사람 검토는 0건입니다.

## 검토자에게 줄 파일

서로 다른 두 사람에게 각자 담당하는 HTML 파일 하나만 전달합니다. 파일을 내려받아 브라우저에서 열면 각 사례의 구성요소, 동결 운영 응답 및 출처 발췌를 볼 수 있습니다. 원래 후보 판정과 표본 추출 기준은 진행자가 보관합니다.

- [검토자 A 양식](reviewer_a/index.html)
- [검토자 B 양식](reviewer_b/index.html)

각자 사례별로 상태와 근거 ID, 판단 사유를 입력합니다. 보류할 때는 어떤 자료가 더 필요한지 기록합니다. 검토 파일을 내보내면 다른 장치에서 이어 볼 수 있습니다. 두 검토자의 최초 판정을 별도로 보관한 뒤 일치 여부를 확인하고, 불일치는 제3자가 근거와 함께 조정합니다. 보류와 미검토를 구분하고 완료 전에는 정확도나 전문가 확정 건수를 산출하지 않습니다.

## 표본 구성

| 추출 집단 | 전수 시나리오 | 표본 |
| --- | ---: | ---: |
{table}
| **합계** | **{summary['population_scenarios']:,}** | **{n}** |

단위는 시나리오입니다. 사유당 최대 {CAP}건을 고정 시드로 비복원 추출했습니다. {CAP}건 이하인 세 집단은 전부 포함했습니다. 추출 전에 결과 파일의 SHA-256, 집단별 건수, 상태 완료 여부, ID 고유성을 원장과 대조했습니다. 추출 및 표시 순서에 서로 다른 해시를 사용했습니다. 사유별 추출 비율이 달라 표본의 단순 비율은 전수 성능 추정에 부적절합니다. 같은 CVE의 서로 다른 시나리오도 개별 표본이 될 수 있습니다.

## 동봉한 근거와 추가 수집

| 근거 종류 | 해당 사례 | 근거 항목 |
| --- | ---: | ---: |
{kinds}

동결 입력과 호출 패킷의 지문을 맞춘 뒤 운영 응답을 옮겼습니다. 공급사 근거에는 원문에서 확인한 제품·버전의 적용 범위와 출처 위치를 실었습니다. 누락·충돌은 판정자가 확인할 수 있게 남겼습니다. 공개 권고문이 제품 버전에 대해 밝힌 내용과 현장 배포의 증명은 별개로 기록합니다.

8100 운영 저장소 3개의 기록 {audit['records_examined']:,}개를 대조한 결과 표본에 연결 가능한 현장 원기록은 0건입니다. 참조가 일치한 {audit['synthetic_bom_only_records']}건은 동결 합성 BOM을 사용한 설문으로 추가 운영 응답이 비어 있었습니다. 이 수치는 확인한 저장소와 연결 기준에 한정됩니다. [운영 기록 대조 범위 및 건수](coordinator/field_record_audit.json) · [사례별 추가 수집 양식](coordinator/field_record_requests.jsonl)

수집 양식의 빈 항목에 실제 자산의 별칭, 구성요소·빌드, 설정 범위와 관측시점, 원기록 식별자·지문·근거 위치를 기록합니다. 재고 완전성은 운영 기록이 보장하는 수집 범위와 예외를 함께 확인합니다. 새 현장 자료에는 별도 현장 사례 ID를 부여하고 제품·범위·시점이 일치하는 이유를 남깁니다. CVE나 제품명이 같은 자료만으로 기존 합성 관측을 현장 사실로 바꾸지 않습니다.

## 추적과 재검증

패킷 ID는 `{summary['packet_id']}`이며 모본 실행은 `{summary['source_run_id']}`입니다. 진행자 대조표에는 원래 시나리오 ID, 후보 상태, 사유, 선택 해시, 시나리오별 추출 확률의 분자·분모, 입력·후보 행의 지문이 있습니다. [진행자 대조표](coordinator/selection_key.jsonl) · [중립 근거 원본 JSONL](coordinator/neutral_evidence.jsonl) · [파일 지문 및 집계](coordinator/manifest.json)

프로젝트 루트에서 아래 명령을 실행하면 원본 전수본과 동결 입력으로 표본과 근거를 다시 만들어 저장된 파일과 대조합니다.

```powershell
python -B -X utf8 tools/item4/build_item4_blind_sample.py verify "{location}"
```
"""
    (directory/'README.md').write_text(guide, encoding='utf-8')


def read_rows(path):
    with path.open('rb') as stream:
        return [json.loads(line) for line in stream]


def verify(directory, expected=None, *, rerun=True):
    private = directory/'coordinator'
    manifest = json.loads((private/'manifest.json').read_bytes())
    require(manifest['version'] == VERSION and manifest['seed'] == SEED and manifest['per_stratum_cap'] == CAP
            and (expected is None or manifest == expected), 'Sample manifest differs.')
    known = {'README.md','reviewer_a/index.html','reviewer_b/index.html','coordinator/neutral_evidence.jsonl',
             'coordinator/selection_key.jsonl','coordinator/field_record_requests.jsonl','coordinator/field_record_audit.json'}
    require(set(manifest['files']) == known and all(runs.file_sha(directory/name) == fp for name,fp in manifest['files'].items()),
            'A review document or published file checksum differs.')
    key = read_rows(private/'selection_key.jsonl')
    cases = read_rows(private/'neutral_evidence.jsonl')
    requests = read_rows(private/'field_record_requests.jsonl')
    ids = [row['review_id'] for row in key]
    require(ids == [row['review_id'] for row in cases] == [row['review_id'] for row in requests]
            and ids == list(dict.fromkeys(ids)) and len(ids) == manifest['sample_scenarios']
            and len({row['cve'] for row in cases}) == manifest['sample_cves']
            and manifest['packet_id'] == 'B-' + digest(json_bytes(cases))[:24]
            and Counter(r['stratum'] for r in key) == manifest['selected_counts']
            and list(field_requests(cases,key)) == requests, 'Sample case coverage differs.')
    check_blinding(cases, key)
    for slot in ('reviewer_a','reviewer_b'):
        html = (directory/slot/'index.html').read_text(encoding='utf-8')
        embedded = re.findall(r'<script\b[^>]*\btype="application/json"[^>]*>(.*?)</script>', html, re.DOTALL)
        require(len(embedded)==1 and json.loads(embedded[0]) ==
                dict(packet_id=manifest['packet_id'], reviewer_slot=slot, cases=cases),
                'The browser form differs from the blinded evidence.')
    if rerun:
        source_dir = runs.OUTPUT/manifest['source_run_id']
        report, counts, selected = sample(source_dir)
        reproduced, repeated_key = assemble(report, counts, selected)
        require(report['candidates_sha256'] == manifest['source_candidates_sha256']
                and report['inputs_sha256'] == manifest['frozen_inputs_sha256']
                and report['source_manifest_sha256'] == manifest['frozen_manifest_sha256']
                and counts == manifest['population_counts'] and (reproduced, repeated_key) == (cases,key),
                'Selection or source evidence could not be reproduced.')
        field_scope_ok(json.loads((private/'field_record_audit.json').read_bytes()), report)
    return dict(packet_id=manifest['packet_id'], sample_scenarios=len(cases), unique_cves=manifest['sample_cves'],
                source_cases_reproduced=rerun, verified_files=len(known))


if __name__ == '__main__':
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('action', choices=('build','verify'))
    cli.add_argument('directory', type=Path, nargs='?', default=DEFAULT_OUTPUT)
    args = cli.parse_args()
    if args.action == 'build':
        print(prepare(args.directory))
    else:
        print(json.dumps(verify(args.directory.resolve()), ensure_ascii=False, indent=2))
