"""Render the verified Item 4 inventory review as a Korean HTML report."""
import argparse
from collections import Counter
from html import escape
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.evaluation.scenario_evaluation_runner import file_sha
from tools.item4.render_item4_scenario_run_ko import CSS, WHY, reason_table, table


STATUSES = {'affected': '영향 있음', 'not_affected': '미영향', 'fixed': '수정됨',
            'under_investigation': '조사 보류'}
HOLD = 'inventory_completeness_not_evidenced'


def check(condition, message):
    if not condition:
        raise ValueError(message)


def verify_totals(data, audit, directory):
    total = data['unique_scenarios']
    old, new = (Counter(data[key]) for key in ('previous_candidate_statuses', 'candidate_statuses'))
    cases = data['prior_not_affected_review']
    absence = data['absence_evidence_review']
    transitions = data['transitions']
    check(data['generation_method'] == 'scenario_moe_explicit_inventory_review' and
          data['version'] == 'item4-scenario-explicit-inventory/1', 'Unexpected inventory review method.')
    check(audit['run_id'] == data['run_id'] == directory.name and
          audit['candidates_sha256'] == data['candidates_sha256'] == file_sha(directory / 'candidates.jsonl') and
          audit['prior_candidates_sha256'] == data['source_candidates_sha256'] and
          audit['inputs_sha256'] == data['inputs_sha256'] and audit['source_manifest_sha256'] == data['source_manifest_sha256'] and
          audit['prior_not_affected_review_sha256'] == data['prior_not_affected_review_sha256'] ==
          file_sha(directory / 'prior_not_affected_review.jsonl'),
          'The candidate fingerprints differ from the independently verified files.')
    check(total == audit['unique_scenarios'] == audit['matched_packet_cases'] == sum(old.values()) == sum(new.values()) and
          data['unique_cves'] == audit['unique_cves'] and set(old) | set(new) <= STATUSES.keys(),
          'Full population totals do not reconcile.')
    check(Counter({key: sum(n.values()) for key, n in transitions.items()}) == old and
          sum((Counter(n) for n in transitions.values()), Counter()) == new,
          'Candidate transition totals differ from the before or after counts.')
    for key in ('generation_statuses', 'candidate_statuses', 'hold_reasons', 'product_hold_reasons'):
        check(Counter(data[key]) == Counter(audit[key]), 'The independent count differs for ' + key)
    check(cases['reviewed'] == old['not_affected'] == audit['previous_not_affected_reviewed'] and
          cases['retained'] == audit['previous_not_affected_retained'] and
          cases['changed_to_under_investigation'] == transitions.get('not_affected', {}).get('under_investigation', 0) and
          cases['reviewed'] == cases['retained'] + cases['changed_to_under_investigation'] == sum(cases['coverage_values'].values()),
          'The prior not-affected cohort does not reconcile.')
    check(absence['reviewed'] == sum(absence[key] for key in ('explicit_complete', 'missing', 'partial', 'other')) and
          absence['prior_crosscheck_holds_replaced'] == audit['previously_held_reason_reclassified'] and
          data['hold_reasons'].get(HOLD, 0) == audit['gated_rows'] and
          audit['gated_rows'] + audit['unchanged_decisions_and_reasons'] == total,
          'Inventory evidence and hold transitions do not reconcile.')
    check(data['additional_model_calls'] == audit['new_model_calls'] == data['independent_expert_reviews'] ==
          audit['independent_expert_reviews'] == 0 and all(
              audit[k] == 0 for k in ('duplicate_ids', 'missing_ids', 'extra_ids', 'order_mismatches')),
          'Review provenance or population integrity differs from the independent receipt.')


def render(directory):
    directory = directory.resolve()
    data = json.loads((directory / 'report.json').read_bytes())
    audit = json.loads((directory / 'independent_verification.json').read_bytes())
    verify_totals(data, audit, directory)
    old, new = (Counter(data[key]) for key in ('previous_candidate_statuses', 'candidate_statuses'))
    cases, absence = data['prior_not_affected_review'], data['absence_evidence_review']
    sections = []
    add = sections.append
    add('<h1>재고 완전성 근거로 다시 검증한 미영향 후보</h1>')
    add(f'<p>전체 {data["unique_cves"]:,}개 CVE의 합성 시나리오 {data["unique_scenarios"]:,}건 중 '
        f'기존 미영향 후보 <strong>{cases["reviewed"]:,}건</strong>을 모두 다시 검증했습니다. '
        f'그 결과 <strong>{cases["changed_to_under_investigation"]:,}건이 조사 보류</strong>로 바뀌었고, '
        f'미영향을 유지한 사례는 {cases["retained"]:,}건입니다.</p>')
    add('<h2>전수본의 후보 상태</h2>')
    add(table(['상태', '기존 시나리오 수', '재검증 후', '증감'], [
        (label, f'{old[key]:,}', f'{new[key]:,}', f'{new[key] - old[key]:+,}' if old[key] != new[key] else '0')
        for key, label in STATUSES.items()] + [
        ('합계', f'{sum(old.values()):,}', f'{sum(new.values()):,}', '0')]))
    add('<h2>미배포 관측과 재고 완전성</h2>')
    add('<p>미배포를 근거로 미영향 후보를 만들려면 해당 시나리오의 원본 운영 입력에서 재고 범위를 '
        '<code>inventory_coverage = complete</code>로 명시해야 합니다. 미배포 관측은 현재의 단일 대상과 '
        '식별된 구성요소에 적용되어야 하며, 재고 전문가의 판정과 교차검토가 이를 뒷받침해야 합니다. '
        '재고 범위를 생략하면 미배포 응답이 있어도 조사 보류로 처리합니다.</p>')
    add(table(['미배포 시나리오의 원본 재고 범위', '시나리오 수'], [
        (label, f'{absence[key]:,}') for key, label in (
            ('explicit_complete', '완전하다고 명시'), ('partial', '부분 재고로 명시'),
            ('missing', '재고 범위 누락'), ('other', '기타 값'), ('reviewed', '전체 미배포 시나리오'))]))
    add(f'<p>미배포 시나리오 중 기존에도 조사 보류였던 사례는 {absence["already_under_investigation"]:,}건입니다. '
        f'그중 {absence["prior_crosscheck_holds_replaced"]:,}건은 교차검토에서 보류되었고, '
        '이번 재검증에서 재고 완전성 근거 부족을 보류 사유로 기록했습니다.</p>')
    add('<h2>전수본의 조사 보류 사유</h2>')
    prior, holds = Counter(data['previous_hold_reasons']), Counter(data['hold_reasons'])
    names = dict(WHY, inventory_completeness_not_evidenced='재고가 완전하다는 명시적 근거가 없음')
    add(table(['사유', '기존 시나리오 수', '재검증 후'], [
        (escape(names.get(reason, reason)), f'{prior[reason]:,}', f'{holds[reason]:,}')
        for reason in sorted(set(prior) | set(holds), key=lambda key: (-holds[key], key))]))
    add('<p class="note">사유별로 해당 시나리오를 한 번씩 셉니다. 여러 사유가 적용되면 각각의 행에 포함합니다.</p>')
    if data['product_hold_reasons']:
        add('<h3>공급사 근거를 확인할 수 없었던 세부 사유</h3>')
        add(reason_table(data['product_hold_reasons'], holds['supplier_evidence_conflicting_or_unresolved']))
        add('<p class="note">비율의 분모는 공급사 근거가 충돌하거나 제품·버전 상태를 확인할 수 없어 보류된 시나리오입니다.</p>')
    add('<h2>검증 범위와 원본 기록</h2>')
    add(f'<p>독립 검증에서 시나리오 {audit["matched_packet_cases"]:,}건을 원본 입력과 대조했습니다. '
        'ID의 중복·누락·추가와 행 순서 차이는 각각 0건입니다. '
        f'후보 상태와 판정 사유가 모두 유지된 시나리오는 {audit["unchanged_decisions_and_reasons"]:,}건입니다.</p>')
    add(f'<p>이 검증은 기존 모델 응답과 동결된 합성 운영 입력으로 판정 규칙을 다시 적용했습니다. '
        f'추가 모델 호출은 {data["additional_model_calls"]:,}회, '
        f'독립 전문가가 정답으로 확정한 사례는 {data["independent_expert_reviews"]:,}건입니다.</p>')
    add('<dl class="meta">' + ''.join(f'<dt>{label}</dt><dd><code>{escape(value)}</code></dd>' for label, value in (
        ('재검증 실행 ID', data['run_id']), ('기존 전수본 SHA-256', data['source_candidates_sha256']),
        ('재검증 전수본 SHA-256', data['candidates_sha256']))) + '</dl>')
    add('<p>' + ' '.join(f'<a class="file" href="{path}">{label}</a>' for path, label in (
        ('candidates.jsonl', '시나리오별 전수 후보'), ('prior_not_affected_review.jsonl', '기존 미영향 건별 재검증 기록'),
        ('report.json', '집계 보고서 JSON'),
        ('independent_verification.json', '독립 검증 기록 JSON'))) + '</p>')
    out = directory / 'report.ko.html'
    temp = out.with_suffix('.html.tmp')
    temp.write_text('<!doctype html><html lang="ko"><head><meta charset="utf-8">'
                    '<meta name="viewport" content="width=device-width,initial-scale=1">'
                    '<title>항목 4 · 재고 완전성 재검증</title><style>' + CSS +
                    '.file{display:inline-block}@media(max-width:640px){thead th.num{white-space:normal}}'
                    '</style></head><body><main>' + '\n'.join(sections) + '</main></body></html>', encoding='utf-8')
    temp.replace(out)
    return out


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    print(render(parser.parse_args().directory))
