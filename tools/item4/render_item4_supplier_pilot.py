"""Render the closed supplier evidence pilot with its source and independent verification receipts."""
import argparse
from collections import Counter
from contextlib import closing
from hashlib import sha256
from html import escape
import json
from pathlib import Path
import sqlite3
import sys
import zlib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.evaluation.evaluation_run_records import ProgressCounts
from src.item4.evaluation import scenario_evaluation_runner as runs
from tools.item4.render_item4_scenario_run_ko import CSS, STATUS, WHY, labeled, table
from tools.item4.verify_item4_supplier_pilot import PARENT, require, verify


GROUPS = ('failure', 'control')
NAMES = ('기존 후보 미생성 사례', '회귀 대조군')
DIFF = {'candidate_status': '후보 상태', 'reasons': '판정 사유', 'product_reasons': '제품 근거 세부 사유',
        'supplier_verdict': '공급사 자료 판정', 'supplier_evidence_ids': '공급사 전문가의 인용',
        'evidence_ids': '후보 전체의 인용'}


def summary(rows):
    counts = ProgressCounts()
    for row in rows:
        counts.add(row)
    return counts.snapshot()


def changed_controls(parent, rows):
    changes = []
    with closing(sqlite3.connect((parent / 'records.sqlite3').as_uri() + '?mode=ro', uri=True)) as db:
        for row in rows:
            if row['cohort'] != 'control':
                continue
            prior = db.execute('SELECT payload FROM candidates WHERE id=?', (row['id'],)).fetchone()
            data = zlib.decompress(prior[0])
            require(sha256(data).hexdigest() == row['parent_row_sha256'], 'Control row fingerprint differs.')
            old = json.loads(data)
            fields = [k for k in ('candidate_status', 'reasons', 'product_reasons', 'evidence_ids') if row[k] != old[k]]
            new_expert, old_expert = [next(e for e in v['experts'] if e['expert'] == 'supplier') for v in (row, old)]
            fields.extend('supplier_' + k for k in ('verdict', 'evidence_ids') if new_expert[k] != old_expert[k])
            if fields:
                changes.append((row['id'], row['cve'], fields))
    return changes


def mixed_verification_section(directory, coverage, pilot):
    path = directory / 'mixed_verification.json'
    if not path.is_file():
        return ''
    audit = json.loads(path.read_bytes())
    shared = ('parent_run_id', 'pilot_run_id', 'parent_candidates_sha256', 'pilot_candidates_sha256',
              'combined_candidates_sha256', 'preserved_parent_rows_sha256', 'unique_scenarios', 'unique_cves')
    require(audit['kind'] == 'independent_mixed_candidate_file_verification' and
            all(audit[k] == coverage[k] for k in shared) and
            all(Counter(audit[k]) == Counter(coverage[k]) for k in
                ('candidate_statuses','generation_statuses','hold_reasons','product_hold_reasons')) and
            audit['coverage_sha256'] == sha256((directory / 'coverage.json').read_bytes()).hexdigest() and
            audit['byte_identical_parent_rows'] == coverage['parent_rows_preserved'] and
            audit['byte_identical_pilot_replacement_rows'] == coverage['pilot_rows_used'] and
            audit['preserved_historical_controls'] == pilot['cohorts']['control']['scenarios'] and
            audit['combined_bytes'] == (directory / 'all_candidates.jsonl').stat().st_size ==
            audit['byte_identical_parent_bytes'] + audit['byte_identical_pilot_replacement_bytes'] and
            all(audit[k] == 0 for k in ('duplicate_ids', 'missing_ids', 'extra_ids', 'order_mismatches',
                                        'independent_expert_reviews')),
            'Independent row comparison does not match the verified combined export.')
    return (f'<p>전체 {audit["unique_scenarios"]:,}개 행을 독립 대조해 원본과의 바이트 일치, '
            'ID 중복·누락·추가 0건, 순서 차이 0건을 확인했습니다. '
            '<a href="mixed_verification.json">전수 행 비교 검증 기록</a></p>')


DEPLOYMENT_CAUSES = {
    'scope_mixed': ('여러 자산 또는 시점의 관측이 혼재', '대상 자산과 관측 시점을 지정한 재고 기록'),
    'scope_unknown': ('관측 대상 범위 미확인', '자산 식별자와 관측 시점'),
    'missing_component_ref': ('BOM 부품 식별자 미연결', '대상 자산과 BOM 부품을 연결한 목록'),
    'deployment_mixed': ('인스턴스별 배포 상태가 다름', '인스턴스별 설치·배포 기록'),
    'deployment_unknown': ('설치·배포 여부 미확인', '대상 자산의 설치 목록 또는 배포 기록'),
    'absence_coverage_incomplete': ('미배포 관측의 재고 범위가 불완전', '대상 자산과 시점을 포함한 재고 조사 범위'),
    'absence_model_not_confirmed': ('미배포 관측을 전문가가 확인하지 못함', '미배포 응답과 재고 원문 대조'),
    'runtime_different': ('가동 버전과 BOM 버전이 다름', '해당 장치에서 확인한 실제 버전과 BOM 기록'),
    'runtime_bom_range': ('가동 버전이 범위로 기록됨', '대상 장치에서 확인한 정확한 버전 또는 빌드 번호'),
    'runtime_mixed': ('인스턴스별 가동 버전이 다름', '인스턴스별 실제 버전 또는 빌드 번호'),
    'runtime_unknown': ('현재 가동 버전 미확인', '대상 장치의 실제 가동 버전 기록'),
    'installed_model_not_confirmed': ('설치·가동 버전을 전문가가 확인하지 못함', '설치 관측 및 버전 원문 대조'),
}


def deployment_review_section(directory, coverage, parent, pilot_absent):
    path = directory / 'deployment_hold_review.json'
    if not path.is_file():
        return ''
    review = json.loads(path.read_bytes())
    folder = Path(json.loads(runs.BASELINE.read_bytes())['artifact_directory'])
    manifest = runs.sealed_json(folder / 'delivery_manifest.json', parent['ledger']['data_hashes']['v3 delivery manifest'])
    counts = review['first_cause_counts']
    verdicts = review['raw_field_counts']['inventory_verdict']
    held = coverage['hold_reasons']['deployment_or_running_version_unresolved']
    absence = review['complete_absence_input_coverage_sources']
    eligible = review['eligible_inventory_checks']['all_scenarios']['complete_absence']
    parent_audit = json.loads((runs.OUTPUT / coverage['parent_run_id'] / 'independent_verification.json').read_bytes())
    parent_absent = parent_audit['not_affected_by_deployment'].get('not_deployed', 0)
    require(review['kind'] == 'frozen_deployment_hold_diagnostic' and
            all(review[k] == coverage[k] for k in ('parent_run_id', 'pilot_run_id', 'combined_candidates_sha256')) and
            review['inputs_sha256'] == manifest[runs.PREFIX + '/inputs.jsonl'] and
            review['source_manifest_sha256'] == parent['ledger']['data_hashes']['v3 delivery manifest'] and
            review['inventory_gate_sha256'] == parent['ledger']['code_hashes']['item4_scenario_moe.py'] and
            review['unique_scenarios'] == coverage['unique_scenarios'] and review['unique_cves'] == coverage['unique_cves']
            and 0 < review['held_cves'] <= review['unique_cves'] and review['held_scenarios'] == held
            and review['matched_inventory_input_receipts'] == review['unique_scenarios']
            and all(review[k] == 0 for k in ('additional_model_calls', 'changed_candidate_rows', 'duplicate_ids', 'missing_ids'))
            and set(counts) <= DEPLOYMENT_CAUSES.keys()
            and all(type(n) is int and n >= 0 for n in (*counts.values(), *verdicts.values()))
            and sum(counts.values()) == sum(verdicts.values()) == held,
            'The deployment review does not match the frozen inputs, output scope or held count.')
    require(eligible['input_eligible'] == sum(absence.values()) and
            set(absence) == {'explicit_complete', 'synthetic_not_deployed_default'} and
            all(type(n) is int and n >= 0 for n in absence.values()) and
            parent_absent == parent['candidate_statuses'].get('not_affected', 0) and
            parent_absent + pilot_absent == coverage['candidate_statuses'].get('not_affected', 0),
            'The verified scope of synthetic absence decisions differs.')
    entries = []
    for key, n in sorted(counts.items(), key=lambda item: -item[1]):
        if n:
            label, evidence = DEPLOYMENT_CAUSES[key]
            entries.append((escape(label), f'{n:,}', escape(evidence)))
    return ('<section class="deployment"><h2>전수본의 배포·가동 버전 보류 원인</h2>'
            f'<p>배포 상태 또는 가동 버전이 확인되지 않은 {review["held_cves"]:,}개 CVE의 '
            f'{held:,}개 시나리오를 분류했습니다. 각 시나리오는 v2의 판정 순서에서 처음 충족하지 못한 '
            '조건 한 곳에만 집계했습니다. 마지막 열은 실제 자산을 평가할 때 확인할 운영 자료입니다.</p>' +
            table(['첫 미충족 조건', '시나리오 수', '확인할 운영 자료'], entries) +
            f'<p>이 보류 사례 중 재고 전문가가 BOM 버전의 설치를 확인했다고 응답한 경우는 '
            f'{verdicts.get("installed_exact", 0):,}건입니다. 최종 판정은 운영 입력의 필수 조건을 검증해 보류를 유지했습니다. '
            '추가 모델 호출은 0회입니다. '
            '<a href="deployment_hold_review.json">원인별 집계와 원본 입력 분포</a></p>'
            '<h3>합성 미배포 사례의 재고 범위</h3>'
            f'<p>미배포 입력에서 v2의 재고 완전성 조건을 충족한 {eligible["input_eligible"]:,}건 중 '
            f'원본 운영 입력이 재고 범위를 완전하다고 명시한 경우는 {absence["explicit_complete"]:,}건입니다. '
            f'{absence["synthetic_not_deployed_default"]:,}건은 합성 시나리오에서 미배포를 선택하고 재고 범위를 생략해 '
            '벤치마크 규칙에 따라 재고를 완전하다고 간주했습니다. '
            f'결합 전수본의 미영향 후보 {parent_absent + pilot_absent:,}건은 모두 합성 미배포 사례이며, '
            f'이번 검증에서 보완한 {pilot_absent:,}건이 여기에 포함됩니다.</p></section>')


def coverage_section(directory, parent, pilot, pilot_absent):
    receipt = directory / 'coverage.json'
    if not receipt.is_file():
        return ''
    coverage = json.loads(receipt.read_bytes())
    added = pilot['cohorts']['failure']
    states = Counter(parent['candidate_statuses']) + Counter(added['candidate_statuses'])
    holds = Counter(parent['hold_reasons']) + Counter(added['hold_reasons'])
    digest = sha256()
    with (directory / 'all_candidates.jsonl').open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            digest.update(block)
    require(coverage['kind'] == 'mixed_version_candidate_export' and
            coverage['parent_run_id'] == pilot['parent_run_id'] and coverage['pilot_run_id'] == pilot['run_id'] and
            coverage['parent_candidates_sha256'] == pilot['parent_candidates_sha256'] and
            coverage['pilot_candidates_sha256'] == pilot['candidates_sha256'] and
            coverage['combined_candidates_sha256'] == digest.hexdigest() and
            coverage['parent_rows_preserved'] == parent['ledger']['candidate_count'] and
            coverage['pilot_rows_used'] == added['scenarios'] == sum(added['candidate_statuses'].values()) and
            coverage['unique_scenarios'] == pilot['parent_total'] == sum(states.values()) and
            coverage['unique_cves'] == parent['represented_cve_count'] and
            coverage['controls_replaced'] == coverage['independent_expert_reviews'] == 0 and
            Counter(coverage['candidate_statuses']) == states and Counter(coverage['hold_reasons']) == holds,
            'The combined export differs from its source runs or sealed file.')
    return ('<h2>두 버전을 결합한 전수 후보 파일</h2>'
            f'<p>기존 v2에서 완성한 {coverage["parent_rows_preserved"]:,}개 행을 원본 바이트 그대로 보존하고, '
            f'이번 검증에서 채운 {coverage["pilot_rows_used"]:,}개 행을 더했습니다. 결합 파일은 '
            f'{coverage["unique_cves"]:,}개 CVE의 시나리오 {coverage["unique_scenarios"]:,}건을 수록합니다. '
            '회귀 대조군의 행은 기존 v2 결과를 사용합니다.</p>' +
            table(['결합 파일의 후보 상태', '시나리오 수'], [(STATUS[k], f'{states[k]:,}') for k in STATUS]) +
            '<p><a class="file" href="all_candidates.jsonl">결합 전수 후보 JSONL</a>'
            '<a class="file" href="coverage.json">결합 범위와 파일 지문</a></p>' +
            mixed_verification_section(directory, coverage, pilot) +
            deployment_review_section(directory, coverage, parent, pilot_absent))


def render(directory):
    directory = directory.resolve()
    report = json.loads((directory / 'report.json').read_bytes())
    audit = json.loads((directory / 'independent_verification.json').read_bytes())
    parent = ROOT / 'results/item4_scenario_moe' / PARENT
    candidate = directory / 'pilot_candidates.jsonl'
    require(verify(parent, candidate) == audit, 'Independent verification does not reproduce from the supplied files.')
    for key in ('run_id', 'parent_run_id', 'parent_candidates_sha256', 'requests_sha256',
                'responses_sha256', 'candidates_sha256'):
        require(report[key] == audit[key], 'Report and verified file fingerprints differ for ' + key)
    rows = [json.loads(line) for line in candidate.read_bytes().splitlines()]
    parent_report = json.loads((parent / 'report.json').read_bytes())
    require(report['parent_total'] == parent_report['ledger']['total'] and report['expert_validated'] is False
            and audit['independent_expert_reviews'] == 0, 'The parent scope or expert review total differs.')
    groups = report['cohorts']
    for name in GROUPS:
        part = [r for r in rows if r['cohort'] == name]
        expected = dict(scenarios=len(part), cves=len({r['cve'] for r in part}), **summary(part))
        require(groups[name] == expected, 'Report cohort totals differ for ' + name)
    require(all(report[k] == v for k,v in summary(rows).items()), 'Report totals differ from candidate rows.')
    changes = changed_controls(parent, rows)
    diffs = Counter(k for _, _, keys in changes for k in keys)
    require(report['control_differences'] == {k: diffs[k] for k in DIFF}, 'Control differences do not reproduce.')

    requests = json.loads((directory / 'requests.json').read_bytes())['requests']
    receipt = json.loads((directory / 'responses.json').read_bytes())
    calls = receipt['actual_model_calls']
    answers = receipt['responses']
    forced = {r['wire_sha256'] for r in requests
              if r['packet']['schema']['properties']['assessment']['enum'] == ['unresolved']}
    abstained = {wire for wire, record in answers.items() if record['prediction'] == {'assessment':'unresolved'}}
    selection = dict(single_choice_wires=len(forced), multi_choice_wires=len(requests)-len(forced),
                     model_abstained_wires=len(abstained))
    require(report['selection_counts'] == selection and forced <= abstained and
            calls == report['actual_model_calls'] == audit['actual_supplier_model_calls'] and
            report['model_identity'] == receipt['model_identity'] and
            report['parent_expert_receipts_reused'] == audit['reused_non_supplier_receipts'],
            'Supplier decisions, model identity or expert execution totals differ.')
    single_scenarios = sum(e['expert'] == 'supplier' and e['wire_sha256'] in forced for r in rows for e in r['experts'])
    multi_abstained_scenarios = sum(e['expert'] == 'supplier' and e['wire_sha256'] in abstained-forced
                                   for r in rows for e in r['experts'])
    roles = Counter(e['expert'] for r in rows for e in r['experts'] if e['response_source'] == 'parent_v2_model_cache')

    sections = []
    add = sections.append
    failure = groups['failure']
    controls = groups['control']
    resolved = sum(failure['candidate_statuses'].values())
    add('<h1>공급사 근거 검증 결과</h1>')
    add(f'<p>기존 v2에서 공급사 근거 검증을 통과하지 못한 {failure["scenarios"]:,}건 중 '
        f'<strong>{resolved:,}건</strong>에서 후보가 생성됐습니다. '
        f'회귀 대조군 {controls["scenarios"]:,}건 중 최종 후보 상태가 달라진 사례는 {diffs["candidate_status"]:,}건입니다.</p>')
    add(f'<p>기존 전수 실행의 범위는 CVE {parent_report["represented_cve_count"]:,}개, '
        f'시나리오 {report["parent_total"]:,}건입니다. 이번 검증의 범위는 두 집단을 합한 '
        f'{len(rows):,}건이며, 공급사 전문가 입력과 응답 근거 연결 방식을 변경했습니다. '
        '운영 관측은 합성 자료이며 독립 전문가가 정답으로 확정한 사례는 0건입니다.</p>')

    add('<h2>후보 상태</h2>')
    headers = ['결과', *NAMES]
    def count_row(label, pair):
        return (label, *(f'{n:,}' for n in pair))
    state_rows = [count_row(STATUS[s], [groups[g]['candidate_statuses'].get(s, 0) for g in GROUPS]) for s in STATUS]
    state_rows.append(count_row('후보 미생성', [groups[g]['scenarios']-sum(groups[g]['candidate_statuses'].values()) for g in GROUPS]))
    state_rows.append(count_row('전체 시나리오', [groups[g]['scenarios'] for g in GROUPS]))
    state_rows.append(count_row('포함된 CVE', [groups[g]['cves'] for g in GROUPS]))
    add(table(headers, state_rows))
    absent = 0
    for row in rows:
        if row['cohort'] == 'failure' and row['candidate_status'] == 'not_affected':
            verdicts = {e['expert']: e['verdict'] for e in row['experts']}
            if verdicts.get('inventory') == 'absent_complete' and verdicts.get('crosscheck') == 'corroborated':
                absent += 1
    add(f'<p>기존 후보 미생성 집단에서 미영향으로 판정한 {failure["candidate_statuses"].get("not_affected", 0):,}건 중 '
        f'{absent:,}건은 합성 시나리오의 미배포 관측과 교차검토에 따른 결과입니다. '
        'v2는 합성 미배포 입력에서 재고 범위가 생략되면 재고를 완전하다고 간주합니다.</p>')
    add(coverage_section(directory, parent_report, report, absent))
    for key, title in [('hold_reasons','조사 보류 사유'), ('product_hold_reasons','공급사 근거의 세부 보류 사유'),
                       ('generation_failure_reasons','후보 미생성 사유')]:
        add('<h2>' + title + '</h2>')
        totals = Counter(groups['failure'][key]) + Counter(groups['control'][key])
        if not totals:
            add('<p>두 집단 모두 해당 사례가 0건입니다.</p>')
            continue
        add(table(['사유', *NAMES], [count_row(labeled(WHY.get(k, '기록 사유'), k),
                   [groups[g][key].get(k, 0) for g in GROUPS]) for k,_ in totals.most_common()]))
        add('<p class="note">각 칸의 단위는 시나리오입니다. 같은 사례의 서로 다른 사유는 각각 한 번씩 셉니다.</p>')

    add('<h2>모델 호출과 판정 보류</h2>')
    model = report['model_identity']
    add(f'<p>{escape(model["device"])}에서 {escape(model["model"])}가 서로 다른 공급사 입력 '
        f'{calls:,}개에 대해 각각 한 번씩 직렬 추론했습니다. 동일 입력의 공급사 응답을 추가 '
        f'{audit["cached_supplier_receipts"]:,}건에 적용했습니다.</p>')
    add(table(['공급사 입력에 허용된 선택', '고유 입력 수', '판정 보류 응답', '보류 응답 적용 시나리오'],
              [count_row('근거 선택 또는 판정 보류', [calls-len(forced),len(abstained-forced),multi_abstained_scenarios]),
               count_row('판정 보류만 허용', [len(forced),len(forced),single_scenarios])]))
    role_names = {'inventory': '설치·가동 관측', 'conditions': '출처 조건', 'crosscheck': '독립 교차검토'}
    add('<p>운영 관측과 출처 조건에 대한 다른 전문가의 응답은 기존 v2 실행 기록에서 입력과 인용 근거를 확인해 재사용했습니다.</p>')
    add(table(['기존 응답을 재사용한 전문가', '적용 횟수'],
              [count_row(name,[roles[role]]) for role,name in role_names.items()] +
              [count_row('합계',[audit['reused_non_supplier_receipts']])]))
    add('<p class="note">위 보류 응답은 공급사 전문가가 내린 개별 응답입니다. 최종 후보의 조사 보류는 운영 관측과 교차검토까지 종합한 결과입니다.</p>')

    add('<h2>회귀 대조군 변화</h2>')
    add(f'<p>대조군 {controls["scenarios"]:,}건을 기존 판정과 비교했습니다. '
        f'한 항목 이상 달라진 시나리오는 {len(changes):,}건입니다.</p>')
    add(table(['비교 항목', '달라진 시나리오 수'], [count_row(label,[diffs[k]]) for k,label in DIFF.items()]))
    if changes:
        add('<details><summary>달라진 시나리오와 근거 항목</summary><ul>')
        for identifier, cve, fields in changes:
            add(f'<li><code>{escape(identifier)}</code> · {escape(cve)} · ' + ', '.join(DIFF[k] for k in fields) + '</li>')
        add('</ul></details>')
    add('<h2>검증 기록</h2>')
    add(f'<p>실행 ID <code>{escape(report["run_id"])}</code></p>')
    add('<p>' + ' '.join(f'<a class="file" href="{name}">{label}</a>' for name,label in (
        ('report.json','집계 원문'),('pilot_candidates.jsonl','시나리오별 후보 기록'),
        ('independent_verification.json','독립 재계산 기록'),('requests.json','공급사 모델 입력'),('responses.json','모델 응답'))) + '</p>')
    output = directory / 'report.ko.html'
    temp = output.with_suffix('.html.tmp')
    temp.write_text('<!doctype html><html lang="ko"><head><meta charset="utf-8">'
                    '<meta name="viewport" content="width=device-width,initial-scale=1">'
                    '<title>공급사 근거 검증 결과</title><style>' + CSS +
                    'details li{overflow-wrap:anywhere}.file{display:inline-block}'
                    '.deployment th:last-child,.deployment td:last-child{text-align:left;white-space:normal}'
                    '@media(max-width:640px){thead th.num{white-space:normal}}</style></head><body><main>' +
                    '\n'.join(sections) + '</main></body></html>', encoding='utf-8')
    temp.replace(output)
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path, help='Pilot directory containing the verification and report.')
    print(render(parser.parse_args().directory))
