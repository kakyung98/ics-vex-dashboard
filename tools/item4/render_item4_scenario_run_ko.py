"""Render a closed Item 4 MoE run as a standalone Korean HTML report."""
import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from html import escape
import json
import os
from pathlib import Path
import sys
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.evaluation.evaluation_run_records import ProgressCounts


STATUS = {'affected': '영향 있음', 'not_affected': '영향 없음', 'fixed': '수정됨',
          'under_investigation': '조사 보류'}
EXPERT = {'model': '모델 직접 호출 · 유효 응답', 'cached': '동일 입력의 유효 응답 재사용',
          'error': '전문가 실행 오류'}
WHY = {
    'deployment_or_running_version_unresolved': '배포 여부 또는 가동 버전을 확인할 수 없음',
    'supplier_evidence_conflicting_or_unresolved': '공급사 근거가 충돌하거나 제품·버전에 대한 상태를 확인할 수 없음',
    'invalid_condition_binding': '운영 관측을 출처의 조건과 연결할 수 없음',
    'source_rule_unsatisfied_or_unresolved': '출처의 조건을 충족하지 않거나 충족 여부를 확인할 수 없음',
    'sufficient_source_rule_unavailable': '판정에 충분한 출처 기반 조건을 확보할 수 없음',
    'crosscheck_did_not_corroborate': '교차 검토가 후보를 뒷받침할 근거를 확인하지 못함',
    'missing_or_unverified_source': '공급사 출처가 없거나 출처 무결성을 확인할 수 없음',
    'unresolved_supplier_product_id': '공급사 제품 식별자를 확인할 수 없음',
    'missing_or_nonconcrete_build': '구체적인 버전 또는 빌드가 없음',
    'conflicting_supplier_statuses': '동일 제품·버전에 적용되는 공급사 상태가 서로 충돌함',
    'unresolved_version_or_product_qualifier': '버전 범위 또는 제품 세부 조건을 해소할 수 없음',
    'no_in_scope_supplier_status': '평가 범위와 일치하는 공급사 상태가 없음',
    'scenario_component_scope_unresolved': '시나리오의 대상 구성요소를 특정할 수 없음',
    'provider_exception': '모델 제공자 호출 중 예외 발생',
    'missing_generation_receipt': '모델 생성 기록 누락',
    'invalid_finding_fields': '모델 응답의 필드 구성이 요구 형식과 다름',
    'invalid_conflict_choice': '공급사 상태 충돌에 대한 응답값 오류',
    'invalid_finding': '허용된 판정값 범위를 벗어남',
    'unknown_citation': '제공하지 않은 근거를 인용함',
    'uncited_finding': '판정에 필요한 인용 근거가 없음',
    'no_verified_conflict_pair': '서로 충돌하는 검증 근거 쌍이 없음',
    'reason_not_recorded': '구체 사유가 기록되지 않음',
}


def load_report(source):
    data = json.loads(source.read_bytes())
    run = data['ledger']
    if run['status'] not in {'completed', 'partial', 'failed'}:
        raise ValueError('A terminal report is required.')
    if data['candidates_sha256'] != run['result']['candidates_sha256']:
        raise ValueError('The candidate fingerprint differs from the ledger.')
    # Older V1 sample reports lack reason counts. Recover them from the sealed rows.
    required = {'hold_reasons', 'product_hold_reasons', 'generation_failure_reasons', 'represented_cve_count'}
    if not required.issubset(data):
        counts, represented, digest = ProgressCounts(), set(), sha256()
        with (source.parent / 'candidates.jsonl').open('rb') as stream:
            for raw in stream:
                digest.update(raw)
                row = json.loads(raw)
                counts.add(row)
                represented.add(row['cve'])
        if digest.hexdigest() != data['candidates_sha256']:
            raise ValueError('The candidate file fingerprint differs from the ledger.')
        data['represented_cve_count'] = len(represented)
        for key, distribution in counts.snapshot().items():
            if data.setdefault(key, distribution) != distribution:
                raise ValueError(f'The legacy report differs from its candidate rows: {key}')
    for key in ('candidate_statuses','generation_statuses','hold_reasons','product_hold_reasons','generation_failure_reasons'):
        values = data[key]
        if any(type(n) is not int or n < 0 for n in values.values()) or run['result'].get(key, values) != values:
            raise ValueError(f'Invalid counts or inconsistent ledger: {key}')
    generation = data['generation_statuses']
    if (set(data['candidate_statuses']) - STATUS.keys()
            or set(generation) - {'completed','partial','failed'}
            or not 0 <= run['completed'] <= run['total']
            or sum(generation.values()) != run['completed']
            or generation.get('completed', 0) != run['candidate_count']
            or sum(data['candidate_statuses'].values()) != run['candidate_count']
            or not 0 <= data['represented_cve_count'] <= len(data['selected_cves'])):
        raise ValueError('The scenario counts do not reconcile.')
    return data


CSS = """
*{box-sizing:border-box}html{color:#152f3e;background:#eef2f3;font-family:Inter,"Malgun Gothic","Apple SD Gothic Neo",sans-serif}
body{margin:0;line-height:1.55}main{max-width:930px;margin:32px auto;padding:48px 54px;background:white}
h1,h2,h3,p{margin:0}h1{font-size:clamp(26px,4vw,41px);line-height:1.25;letter-spacing:-.045em;margin:9px 0 13px}
h2{font-size:23px;letter-spacing:-.035em;margin-top:38px}h3{font-size:17px;margin-top:24px}p{margin:5px 0 12px}
.eyebrow{font-weight:700;color:#126452;letter-spacing:.025em}.note,small{color:#4b626c;font-size:14px}
.summary{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-top:22px}
.stat{margin:0;padding:16px 0;border-top:3px solid #17665b}.stat dt{font-size:14px}.stat dd{margin:0;font-size:28px;font-weight:700}
table{width:100%;border-collapse:collapse;margin:10px 0 16px;font-size:15px}th,td{padding:9px 10px;vertical-align:top;text-align:left;border-bottom:1px solid #dce3e5}
thead th{background:#eaf1f1;color:#294a54;font-size:13px}td.num,th.num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
tbody th{font-weight:500}code{font-family:"IBM Plex Mono",Consolas,monospace;overflow-wrap:anywhere;font-size:12px;color:#485d65}
tbody th code{display:block}a{color:#096054;text-underline-offset:3px}.file{margin-right:20px}.meta{display:grid;grid-template-columns:max-content 1fr;gap:5px 20px;font-size:14px}
.meta dd{margin:0;overflow-wrap:anywhere}.meta dt{color:#4b626c}.error{border-left:3px solid #b16726;padding-left:12px}
@media(max-width:640px){main{margin:0;padding:24px 16px}.summary{gap:8px}.stat dd{font-size:22px}.stat dt,.note{font-size:13px}th,td{padding:7px 5px}.meta{grid-template-columns:1fr;gap:2px}.meta dd{margin-bottom:8px}}
@media print{html{background:white}main{max-width:none;margin:0;padding:0}h2,h3,thead{break-after:avoid}tr,.stat{break-inside:avoid}a{color:inherit}}
"""


def pct(n, total):
    return f'{100 * n / total:,.2f}%' if total else '—'


def table(headers, rows):
    def cell(tag, value, numeric):
        style = ' class="num"' if numeric else ''
        return f'<{tag}{style}>{value}</{tag}>'
    cols = ''.join(cell('th', escape(name), i > 0) for i,name in enumerate(headers))
    body = ''.join('<tr>' + ''.join(cell('td' if i else 'th', value, i > 0)
                                    for i,value in enumerate(row)) + '</tr>' for row in rows)
    return f'<table><thead><tr>{cols}</tr></thead><tbody>{body}</tbody></table>'


def labeled(label, code):
    return f'{escape(label)}<code lang="en">{escape(code)}</code>'


def reason_table(counts, denominator):
    if not counts:
        return '<p class="note">기록된 사유 0건</p>'
    rows = [(labeled(WHY.get(key,'원장 사유 코드'), key), f'{n:,}', pct(n, denominator))
            for key,n in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]
    return table(['사유', '시나리오 수', '비율'], rows)


def failed_replay_summary(path, data):
    from tools.item4.replay_item4_failed_experts import REASON, snapshot

    receipt = json.loads(path.read_bytes())
    run, summary = data['ledger'], receipt['summary']
    pins, n, expected = snapshot(path.parent.resolve())
    incomplete = run['completed'] - run['candidate_count']
    if (receipt['kind'] != 'independent_failed_expert_serial_replay'
            or not receipt['official_run_id'] == pins['run_id'] == run['run_id']
            or pins['code_hashes'] != run['code_hashes']
            or receipt['runtime_sha256'] != run['code_hashes']['GPU runtime identity']
            or not summary['snapshot_cases'] == summary['target_cases'] == n == run['completed'] == run['total']
            or receipt['official_attempts_added'] != 0):
        raise ValueError('The serial replay does not match the full checkpoint, run or runtime.')
    remaining = dict(expected)
    cases, cves = set(), set()
    classifications = Counter()
    fresh = 0
    for result in receipt['results']:
        key = (result['expert'], result['wire_sha256'])
        members = remaining.pop(key, [])
        rows = result['official_rows']
        if not members or result['scenario_count'] != len(rows) or sorted(rows, key=lambda r: r['id']) != sorted(members, key=lambda r: r['id']):
            raise ValueError('A failed scenario or its current row fingerprint differs from the serial replay.')
        cases.update(row['id'] for row in rows)
        cves.update(row['cve'] for row in rows)
        status = result['status']
        if status == 'same_evidence_rejection':
            scopes = {row['scope_sha'] for row in rows}
            output, checks = result['serial_output'], result['scoped_checks']
            if (result['expert'] != 'supplier' or output.get('llm_used') is not True or not output.get('model')
                    or result['official_reason_counts'] != {REASON:len(rows)}
                    or {r['reason'] for r in rows} != {REASON} or checks.keys() != scopes
                    or any(c['reason_code'] != REASON or c['error_kind'] != 'evidence' for c in checks.values())):
                raise ValueError('The serial rejection does not agree with the verified scope and evidence receipts.')
        classifications[status] += 1
        fresh += result.get('source') == 'independent_h200_serial'
    if (remaining or not len(cases) == incomplete == summary['affected_scenarios']
            or not len(expected) == summary['distinct_failed_wires'] == sum(classifications.values())
            or summary['wire_classifications'] != classifications or summary['independent_serial_requests'] != fresh):
        raise ValueError('The serial replay coverage does not reconcile with the final failures.')
    repeated = classifications['same_evidence_rejection']
    return (f'<h3>잔여 생성 실패 전수 재생</h3><p>최종 생성 실패 {incomplete:,}건 전체(CVE {len(cves):,}개)의 '
            f'고유 전문가 입력 {len(expected):,}개를 대조했습니다. 동일 v2 모델을 단건으로 새로 호출한 횟수는 {fresh:,}회입니다. '
            f'{repeated:,}개 입력에서 공급사 전문가가 충돌을 보고했으나 이를 뒷받침하는 근거 쌍을 확인할 수 없어 '
            '같은 사유로 판정이 거절됐습니다. 독립 재생을 공식 판정 시도에 추가한 횟수는 0회입니다.</p>')


def v1_summary(path, data):
    cohort = json.loads(path.read_bytes())
    run = data['ledger']
    if (cohort['mode'] != 'original_v1_rejections' or cohort['selection_field'] != 'prior_v1'
            or cohort['run_id'] != run['run_id'] or cohort['candidates_sha256'] != data['candidates_sha256']
            or cohort['source_manifest_sha256'] != run['data_hashes']['v3 delivery manifest']
            or cohort['full_population_cves'] != len(data['selected_cves'])
            or not cohort['full_scenarios'] == run['total'] == run['completed']):
        raise ValueError('The V1 cohort verification belongs to a different run or source.')
    for key in ('candidate_statuses', 'generation_statuses', 'hold_reasons',
                'product_hold_reasons', 'generation_failure_reasons'):
        if any(type(n) is not int or not 0 <= n <= data[key].get(code, 0) for code,n in cohort[key].items()):
            raise ValueError('The V1 cohort counts exceed the full run or contain invalid values.')
    cases, cves = cohort['unique_scenarios'], cohort['unique_cves']
    candidates, incomplete = cohort['candidate_count'], cohort['incomplete_generation_count']
    statuses, generations = cohort['candidate_statuses'], cohort['generation_statuses']
    if (set(statuses) != set(STATUS) or set(generations) != {'completed','partial','failed'}
            or cohort['missing_scenarios'] or cohort['missing_cves'] or cohort['duplicate_ids']
            or not 0 < cases == cohort['expected_scenarios'] <= run['completed']
            or not 0 < cves == cohort['expected_cves'] <= data['represented_cve_count']
            or not sum(statuses.values()) == candidates == generations['completed']
            or not sum(generations.values()) == cases == candidates + incomplete):
        raise ValueError('The V1 cohort coverage and outcomes do not reconcile.')
    rows = [(labeled(label, key), f'{statuses[key]:,}', pct(statuses[key], candidates))
            for key, label in STATUS.items()]
    supplier = cohort['hold_reasons'].get('supplier_evidence_conflicting_or_unresolved', 0)
    return ''.join([
        '<h2>기존 V1 거절 사례</h2>',
        f'<p>최초 V1 감사표에서 거절로 표시한 CVE {cves:,}개의 모의 시나리오 {cases:,}건이 모두 이번 실행에 포함됐습니다. '
        f'이 가운데 {candidates:,}건에서 후보 판정을 생성했습니다.</p>',
        table(['후보 상태', '시나리오 수', '이 집단의 생성 후보 중 비율'], rows),
        f'<h3>V1 집단의 보류 사유</h3><p class="note">조사 보류 {statuses["under_investigation"]:,}건 중 각 사유가 기록된 시나리오를 셌습니다.</p>',
        reason_table(cohort['hold_reasons'], statuses['under_investigation']),
        f'<h3>공급사 근거 세부 사유</h3><p class="note">공급사 근거의 충돌 또는 미확인으로 보류한 {supplier:,}건을 기준으로 집계했습니다.</p>',
        reason_table(cohort['product_hold_reasons'], supplier),
        f'<h3>V1 집단의 생성 실패</h3><p>후보를 생성하지 못한 {incomplete:,}건 중 일부 전문가 실행이 실패한 시나리오는 '
        f'{generations["partial"]:,}건, 모든 전문가 실행이 실패한 시나리오는 {generations["failed"]:,}건입니다.</p>',
        reason_table(cohort['generation_failure_reasons'], incomplete),
    ])


def parity_summary(source, run):
    parity = json.loads(source.read_bytes())
    if any(run['model_hashes'].get(k) != v for k,v in parity['runtime']['base_files_sha256'].items()):
        raise ValueError('The parity comparison used different model weights.')
    archived = parity['comparisons']['archived_vs_h200_batch']
    serial = parity['comparisons']['h200_serial_vs_batch']
    req = parity['expert_requests']
    different = {row['case'] for row in serial['mismatches']}
    details = {k for row in serial['mismatches'] if 'expert' in row for k in row['fields']}
    names = {row['expert'] for row in serial['mismatches'] if 'expert' in row}
    state_fields = {'candidate_status','reasons','product_reasons'}
    result = '전체 일치' if parity['passed'] else '차이 확인'
    archived_result = '일치했습니다' if archived['passed'] else '차이가 있었습니다'
    text = [f'<h2>H200 사전 표본 대조</h2><p>전체 대조 결과는 <strong>{result}</strong>입니다. '
            f'과거 실행 원장과 H200 배치의 후보 {archived["cases"]:,}건을 대조해 {archived_result}. '
            f'판정과 인용이 일치한 전문가 기록은 {archived["matched_expert_receipts"]:,}건입니다.</p>']
    text.append(f'<p>H200 단건 실행과 배치 실행을 비교한 고유 전문가 입력 {req["distinct"]:,}개 중 '
                f'{len(req["mismatches"]):,}개에서 응답 차이가 발생했습니다. '
                f'차이가 있는 시나리오는 {len(different):,}건입니다.')
    if names == {'crosscheck'} and {'verdict','evidence_ids'} <= details:
        text.append(' 교차 검토 전문가의 판정과 인용 근거가 달랐습니다.')
    if not (set(serial['mismatched_case_field_counts']) & state_fields):
        text.append(f' 비교한 {serial["cases"]:,}건 모두 최종 상태와 보류 사유가 일치했습니다.')
    text.append('</p>')
    return ''.join(text)


def population_replay_summary(path, data):
    replay = json.loads(path.read_bytes())
    run = data['ledger']
    cases = replay['cases']
    if (replay['run_id'] != run['run_id'] or replay['generation_status'] != run['status']
            or replay['population_candidates_sha256'] != data['candidates_sha256'] or cases != 33):
        raise ValueError('The frozen sample replay belongs to a different run or candidate export.')
    differences = replay['mismatches']
    case_rows = [row for row in differences if 'expert' not in row]
    expert_rows = [row for row in differences if 'expert' in row]
    field_counts = Counter(field for row in case_rows for field in row['fields'])
    different_experts = {(row['case'], row['expert']) for row in expert_rows}
    different_cases = {row['case'] for row in differences}
    matched_experts = replay['matched_expert_receipts']
    if (field_counts != replay['mismatched_case_field_counts'] or replay['passed'] is not (not differences)
            or len(different_cases) > cases or len(different_experts) != len(expert_rows)
            or type(matched_experts) is not int or matched_experts < 0):
        raise ValueError('The frozen sample replay does not reconcile with its field differences.')
    rows = []
    for label, fields in [('후보 판정 상태', {'candidate_status'}), ('보류 사유와 공급사 세부 사유', {'reasons','product_reasons'}),
                          ('시나리오의 인용 근거', {'evidence_ids','cited_evidence'})]:
        n = len({row['case'] for row in case_rows if fields.intersection(row['fields'])})
        rows.append((label, f'{cases-n:,}', f'{n:,}'))
    return (f'<h2>전수 실행에서 추출한 {cases:,}건과 과거 후보 대조</h2>'
            f'<p>최종 후보 파일에서 과거 표본과 같은 ID의 시나리오 {cases:,}건을 추출했습니다. '
            f'후보와 전문가 기록의 모든 비교 항목이 일치한 시나리오는 {cases-len(different_cases):,}건입니다.</p>'
            + table(['시나리오별 비교 항목','일치','차이 확인'], rows)
            + f'<p>전문가 기록은 {matched_experts+len(different_experts):,}건 중 {matched_experts:,}건에서 '
              '판정·인용·사유 코드 등 비교 항목이 모두 일치했습니다.</p>')


def render(source, output, verification=None, parity=None):
    data = load_report(source)
    run = data['ledger']
    attempted, candidates, total = (run[k] for k in ('completed','candidate_count','total'))
    selected, represented = len(data['selected_cves']), data['represented_cve_count']
    partial = data['generation_statuses'].get('partial', 0)
    failed = data['generation_statuses'].get('failed', 0)
    held = data['candidate_statuses'].get('under_investigation', 0)
    supplier_held = data['hold_reasons'].get('supplier_evidence_conflicting_or_unresolved', 0)
    run_state = {'completed':'완료','partial':'부분 완료','failed':'실패'}[run['status']]
    def file_link(path, title):
        relative = quote(Path(os.path.relpath(path, output.parent)).as_posix(), safe='/')
        return f'<a class="file" href="{escape(relative)}">{escape(title)}</a>'
    links = [file_link(source, '실행 원장·집계 JSON')]
    retry_note = ''
    candidate_file = source.with_name('candidates.jsonl')
    if candidate_file.is_file():
        links.append(file_link(candidate_file, '시나리오별 후보·근거 JSONL'))
    if verification:
        check = json.loads(verification.read_bytes())
        if (check['run_id'] != run['run_id'] or check['mode'] != run['status'] + '_run'
                or check['candidates_sha256'] != data['candidates_sha256']
                or check['unique_scenarios'] != attempted or check['expected_scenarios'] != total):
            raise ValueError('This independent verification receipt does not match the report.')
        links.append(file_link(verification, '독립 무결성 검증 JSON'))
        if 'retry_history' in check:
            history = check['retry_history']
            retried, previous, recovered, still_partial, still_failed = (
                history[k] for k in ('unique_retried_scenarios','superseded_attempts','recovered_to_completed',
                                     'still_partial','still_failed'))
            distribution = history['candidate_statuses']
            if (any(type(n) is not int or n < 0 for n in (retried, previous, recovered, still_partial, still_failed))
                    or not recovered + still_partial + still_failed == retried <= attempted or previous < retried
                    or still_partial > partial or still_failed > failed or sum(distribution.values()) != recovered
                    or any(k not in STATUS or type(n) is not int or not 0 <= n <= data['candidate_statuses'].get(k,0)
                           for k,n in distribution.items())):
                raise ValueError('The retry history does not reconcile with the run outcomes.')
            retry_note = (f'<p>시나리오 {retried:,}건을 재시도했고, 교체된 이전 시도는 {previous:,}회입니다. '
                          f'최종적으로 {recovered:,}건에서 후보가 생성됐고, 일부 전문가 실패는 {still_partial:,}건, '
                          f'모든 전문가 실패는 {still_failed:,}건입니다.</p>')

    sections = []
    def add(markup):
        sections.append(markup)
    add('<p class="eyebrow">ICS-VEX · 항목 #4</p><h1>시나리오별 취약점 후보 판정</h1>')
    add(f'<p>고정된 모의 운영 관측과 공급사 자료로 다중 에이전트 MoE가 생성한 후보입니다. 독립 전문가가 판정을 검토한 시나리오는 <strong>{run["expert_reviewed_count"]:,}건</strong>입니다.</p>')
    add('<div class="summary">')
    for label, value in [('실행 상태',run_state),('후보 생성',f'{candidates:,}건'),('조사 보류',f'{held:,}건')]:
        add(f'<dl class="stat"><dt>{label}</dt><dd>{value}</dd></dl>')
    add('</div><h2>처리 범위</h2>')
    add(table(['대상','전체','처리','미처리','처리율'], [
        ('CVE',f'{selected:,}',f'{represented:,}',f'{selected-represented:,}',pct(represented,selected)),
        ('시나리오',f'{total:,}',f'{attempted:,}',f'{total-attempted:,}',pct(attempted,total))]))
    add('<p class="note">처리 CVE는 하나 이상의 시나리오 결과가 기록된 고유 CVE입니다. 처리 시나리오는 생성 실패를 포함한 고유 판정 시도 수입니다.</p>')
    add('<h2>후보 상태</h2>')
    rows = []
    for key,label in STATUS.items():
        n = data['candidate_statuses'].get(key,0)
        rows.append((labeled(label,key), f'{n:,}', pct(n,candidates)))
    add(table(['상태','시나리오 수','생성 후보 중 비율'], rows))
    add(f'<p class="note">분모는 모든 필수 전문가 단계가 끝난 후보 {candidates:,}건입니다. 조사 보류도 생성된 후보 상태에 포함됩니다.</p>')
    add('<h2>보류 사유</h2>')
    add(f'<p class="note">분모는 조사 보류 {held:,}건입니다. 시나리오 하나에서 같은 사유는 한 번만 세며, 서로 다른 사유는 각각 한 번씩 셉니다.</p>')
    add(reason_table(data['hold_reasons'], held))
    add('<h3>공급사 근거 세부 사유</h3>')
    add(f'<p class="note">공급사 근거의 충돌 또는 미확인으로 보류한 {supplier_held:,}건을 분모로 계산했습니다.</p>')
    add(reason_table(data['product_hold_reasons'], supplier_held))
    add('<h2>생성 시도와 오류</h2>')
    add(f'<p>판정을 시도한 {attempted:,}건 중 {candidates:,}건에서 후보를 생성했습니다. 후보를 생성하지 못한 시나리오는 {partial + failed:,}건입니다.</p>')
    rows = [('후보 생성 완료',f'{candidates:,}',pct(candidates,attempted)),
            ('일부 전문가 실행 실패',f'{partial:,}',pct(partial,attempted)),
            ('모든 전문가 실행 실패',f'{failed:,}',pct(failed,attempted))]
    add(table(['생성 결과','시나리오 수','판정 시도 중 비율'], rows))
    if retry_note:
        add(retry_note)
    add('<h3>생성 실패 사유</h3>')
    add(f'<p class="note">분모는 일부 또는 모든 전문가 실행이 실패한 {partial + failed:,}건입니다. 같은 시나리오에 여러 오류가 있으면 서로 다른 사유를 각각 셉니다.</p>')
    add(reason_table(data['generation_failure_reasons'], partial+failed))
    failed_replay = source.with_name('independent_failed_expert_serial_replay.json')
    if failed_replay.is_file():
        add(failed_replay_summary(failed_replay, data))
        add('<p>' + file_link(failed_replay, '잔여 생성 실패 독립 재생 JSON') + '</p>')
    if run.get('error'):
        add(f'<p class="error">실행 오류 <code>{escape(run["error"])}</code></p>')
    v1_receipt = source.with_name('v1_rejection_verification.json')
    if v1_receipt.is_file():
        add(v1_summary(v1_receipt, data))
        add('<p>' + file_link(v1_receipt, 'V1 거절 사례 검증 JSON') + '</p>')
    add('<h2>모델 호출과 응답 재사용</h2>')
    experts = data['expert_executions']
    rows = []
    for key in dict.fromkeys([*EXPERT, *experts]):
        n = experts.get(key,0)
        rows.append((labeled(EXPERT.get(key,'기타 실행'),key), f'{n:,}', pct(n,sum(experts.values()))))
    add(table(['전문가 실행 결과','횟수','전문가 실행 중 비율'], rows))
    add('<p class="note">단위는 최종 시나리오 행에 기록된 전문가 실행입니다. 한 시나리오에 여러 실행이 있습니다. 재사용은 같은 모델과 동일한 직렬화 입력에 대한 응답을 뜻합니다. 교체된 이전 시도와 전송 재시도는 이 표에서 제외합니다.</p>')
    if parity:
        add(parity_summary(parity, run))
        add('<p>' + file_link(parity, 'H200 사전 표본 대조 원문 JSON') + '</p>')
    replay = source.with_name('frozen_33_case_replay.json')
    if replay.is_file():
        add(population_replay_summary(replay, data))
        add('<p>' + file_link(replay, '전수 실행의 과거 후보 대조 JSON') + '</p>')
    add('<h2>실행 기록</h2><dl class="meta">')
    backend = data.get('backend_identity') or {}
    def local_time(key):
        return datetime.fromisoformat(run[key]).astimezone(timezone(timedelta(hours=9))).strftime('%Y-%m-%d %H:%M:%S KST')
    metadata = [('실행 ID',run['run_id']),('생성 방식',run['generation_method']),('시작',local_time('created_at')),
                ('종료',local_time('updated_at')),('후보 파일 SHA-256',data['candidates_sha256'])]
    for key, label in [('model','모델'),('device','장치'),('moe_version','MoE 버전')]:
        if backend.get(key):
            metadata.append((label,backend[key]))
    for name,value in metadata:
        add(f'<dt>{name}</dt><dd>{escape(str(value))}</dd>')
    add('</dl><p>' + ' '.join(links) + '</p>')
    content = '<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>ICS-VEX · 시나리오별 후보 판정</title><style>' + CSS + '</style></head><body><main>' + '\n'.join(sections) + '</main></body></html>'
    temp = output.with_suffix('.html.tmp')
    temp.write_text(content, encoding='utf-8')
    temp.replace(output)
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path, help='Path to the completed or partial report.json.')
    parser.add_argument('--output', type=Path, help='Default: report.ko.html alongside report.json.')
    parser.add_argument('--verification', type=Path, help='Optional independent verification receipt.')
    parser.add_argument('--parity', type=Path, help='Optional H200 v2 serial/batch comparison receipt.')
    args = parser.parse_args()
    source = args.report.resolve(strict=True)
    verification = args.verification or source.with_name('independent_verification.json')
    parity = args.parity or source.parent.parent / 'h200_v2_parity_20261121.json'
    print(render(source, (args.output or source.with_name('report.ko.html')).resolve(),
                 verification if args.verification or verification.exists() else None,
                 parity if args.parity or parity.exists() else None))
