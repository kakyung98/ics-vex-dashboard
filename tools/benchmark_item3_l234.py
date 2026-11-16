"""Run the unchanged production P2/P3/P4 core on the full prepared ICS-CERT set."""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, wait, FIRST_COMPLETED
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.preprocess_item3_ics_cert import condition_truth, sha
from src.candidate_snapshot import SnapshotNVD
from src.ics_agent_matcher_full.ics_agent_matcher.matcher import CVE_API, cpe_parts


class EquivalentSnapshotCache(SnapshotNVD):
    """Memoize responses whose production snapshot implementation is identical.

    SnapshotNVD ignores query release/qualifiers when constructing its response:
    its CVE response depends only on part/vendor/product. Actual SBOM versions are
    still compared by the unchanged production lookup_cves/evaluate_configurations.
    """
    def __init__(self, index_path=None):
        super().__init__(index_path)
        self.responses = {}

    def get_all(self, path, params, field):
        if path != CVE_API:
            return super().get_all(path, params, field)
        parts = cpe_parts(params.get('cpeName') or params.get('virtualMatchString', ''))
        key = (field, tuple(parts[:5]) if parts else ())
        if key not in self.responses:
            self.responses[key] = super().get_all(path, params, field)
        return deepcopy(self.responses[key])

CODE = ['src/unified_identification.py', 'src/identity_evidence.py',
        'src/identity_retrieval.py', 'src/identity_versions.py', 'src/l2_candidates.py',
        'src/candidate_snapshot.py', 'src/ics_agent_matcher_full/ics_agent_matcher/matcher.py']
_WORKER_INDEX = None
_WORKER_NVD = None


def dump(path, value):
    pending = path.with_suffix(path.suffix + '.pending')
    pending.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    pending.replace(path)


def compact(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def input_id(sbom_text):
    return hashlib.sha256(sbom_text.encode()).hexdigest()


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def expected_version(value):
    if value is None:
        return None
    return re.sub(r'^[vV](?=\d)', '', value.strip())


def identity(row):
    return tuple(row.get(k) for k in ('part', 'vendor', 'product'))


def score_stages(pred, target):
    expected = identity(target['expected_product'])
    candidates = [tuple(row) for row in pred.get('l2_candidates', [])]
    validation = pred.get('validation') or {}
    accepted = validation.get('status') == 'validated'
    actual = identity(validation)
    version = pred.get('l3') or {}
    supplied = target.get('version') is not None
    normalized = expected_version(target.get('version'))
    observations = [r for r in version.get('observations', []) if r.get('source') == 'version']
    statuses = dict(pred.get('cves', []))
    target_state = statuses.get(target['target_cve'])
    return {'l2_top1': bool(candidates and candidates[0] == expected),
            'l2_top5': expected in candidates[:5], 'l2_top10': expected in candidates[:10],
            'l2_any_candidate': expected in candidates,
            'l3_supplied': supplied,
            'l3_confirmed_correct': supplied and version.get('normalized') == normalized,
            'l3_source_value_preserved': supplied and any(r.get('value') == normalized for r in observations),
            'l3_missing_expected': not supplied,
            'l3_missing_stayed_unknown': not supplied and version.get('normalized') is None,
            'l3_false_confirmation': not supplied and version.get('normalized') is not None,
            'l4_accepted': accepted, 'l4_correct': accepted and actual == expected,
            'l4_wrong': accepted and actual != expected, 'l4_deferred': not accepted,
            'target_positive': target['condition_match'] == 'true',
            'target_returned': target_state in {'match', 'unknown'},
            'target_strict_match': target_state == 'match',
            'target_lookup_state': target_state or 'not_returned',
            'execution_error': bool(pred.get('error'))}


def flat_truth(version, rows, rejected=False):
    """Only explicit local product/version conditions, without platform claims."""
    if rejected or version is None or not rows:
        return None
    states = []
    for row in rows:
        explicit = row.get('version') not in (None, '', '*', '-') or any(
            row.get(k) is not None for k in ('startIncl', 'startExcl', 'endIncl', 'endExcl'))
        states.append(condition_truth(version, row) if explicit else None)
    if True in states:
        return True
    if None in states:
        return None
    return False


def prediction(result):
    row = result['components'][0]
    return {'architecture': result['architecture'], 'llm_used': result.get('llm_used', False),
            'l2_candidates': [list(identity(r)) for r in row['l2']['candidates']],
            'l3': {k: row['l3'].get(k) for k in ('normalized', 'status', 'scheme', 'observations', 'conflicts', 'missing_evidence')},
            'validation': row['validation'],
            'cves': [[r['cve_id'], r['match_status']] for r in row['cves']]}


def load_prediction(conn, key):
    row = conn.execute('SELECT payload FROM predictions WHERE input_id=?', (key,)).fetchone()
    if row is None:
        raise KeyError('Missing prediction: ' + key)
    return json.loads(zlib.decompress(row[0]))


def percentile(values, fraction):
    if not values:
        return None
    values = sorted(values)
    position = (len(values) - 1) * fraction
    left = int(position)
    right = min(left + 1, len(values) - 1)
    return values[left] + (values[right] - values[left]) * (position - left)


def worker_init():
    global _WORKER_INDEX, _WORKER_NVD
    from src.identity_retrieval import get_index
    from src.candidate_snapshot import SnapshotNVD
    _WORKER_INDEX, _WORKER_NVD = get_index(), EquivalentSnapshotCache()


def execute_batch(sboms):
    from src.unified_identification import run_unified
    rows = []
    for sbom_text in sboms:
        begin = time.perf_counter()
        error = None
        try:
            result = prediction(run_unified(json.loads(sbom_text), _WORKER_NVD, index=_WORKER_INDEX,mode='rules'))
            assert result['llm_used'] is False
        except Exception as exc:
            error = type(exc).__name__ + ': ' + str(exc)
            result = {'error': error, 'l2_candidates': [], 'validation': {}, 'l3': {}, 'cves': []}
        seconds = time.perf_counter() - begin
        rows.append((input_id(sbom_text), zlib.compress(compact(result).encode(), 6), seconds, error))
    return rows


def predict_inputs(sboms, workers):
    if workers == 1:
        worker_init()
        for sbom in sboms:
            yield from execute_batch([sbom])
        return
    iterator = iter(sboms)
    def batch():
        chunk = []
        for _ in range(24):
            try:
                chunk.append(next(iterator))
            except StopIteration:
                break
        return chunk
    with ProcessPoolExecutor(max_workers=workers, initializer=worker_init) as pool:
        pending = set()
        for _ in range(workers * 2):
            chunk = batch()
            if chunk:
                pending.add(pool.submit(execute_batch, chunk))
        while pending:
            finished, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in finished:
                yield from future.result()
                chunk = batch()
                if chunk:
                    pending.add(pool.submit(execute_batch, chunk))


def run(dataset, output, resume=False, workers=4, seed=None):
    from src.identity_retrieval import get_index
    from src.candidate_snapshot import SnapshotNVD
    from src.unified_identification import run_unified

    dataset, output = dataset.resolve(), output.resolve()
    if not output.is_relative_to(ROOT / 'results'):
        raise ValueError('Evaluation output must stay in workspace results.')
    if output.exists() and not resume:
        raise FileExistsError('Choose a new run directory or resume the unchanged run.')
    output.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((dataset / 'manifest.json').read_text(encoding='utf-8'))
    for name, info in manifest['artifacts'].items():
        assert sha(dataset / name) == info['sha256'], name
    for name, info in manifest['sources'].items():
        assert sha(ROOT / name) == info['sha256'], name
    fingerprints = {name: sha(ROOT / name) for name in CODE}
    aliases = ROOT / 'data/identity_aliases_v3.json'
    signature = {'dataset_manifest_sha256': sha(dataset / 'manifest.json'), 'production_files': fingerprints, 'workers': workers,
                 'reviewed_aliases_sha256': sha(aliases), 'runner_sha256': sha(Path(__file__))}
    metadata_file = output / 'run_metadata.json'
    if metadata_file.exists():
        metadata = json.loads(metadata_file.read_text(encoding='utf-8'))
        if metadata['signature'] != signature:
            raise ValueError('Code or dataset changed; start a new baseline instead of mixing results.')
    else:
        metadata = {'created_at_utc': datetime.now(timezone.utc).isoformat(), 'signature': signature,
                    'entry_point': 'src.unified_identification.run_unified',
                    'lookup_provider': 'SnapshotNVD with equivalent response memoization by part/vendor/product',
                    'scope': 'P2/P3/P4 core and its local NVD lookup; excludes subsequent UI CISA advisory augmentation',
                    'gold_read_by_prediction_loop': False, 'LLM_used': False,
                    'exact_duplicate_inputs_reuse_identical_deterministic_predictions': True,
                    'added_backend_result_cache': True,
                    'cache_changes_identity_or_version_rules': False}
        dump(metadata_file, metadata)
    source = sqlite3.connect(f'file:{(dataset / "corpus.sqlite3").as_posix()}?mode=ro', uri=True)
    pred_conn = sqlite3.connect(output / 'predictions.sqlite3')
    pred_conn.execute('CREATE TABLE IF NOT EXISTS predictions(input_id TEXT PRIMARY KEY,payload BLOB NOT NULL,seconds REAL NOT NULL,error TEXT,mode TEXT NOT NULL)')
    if seed and not pred_conn.execute('SELECT COUNT(*) FROM predictions').fetchone()[0]:
        seed_metadata = json.loads((seed / 'run_metadata.json').read_text(encoding='utf-8'))
        for key in ('dataset_manifest_sha256', 'production_files', 'reviewed_aliases_sha256'):
            assert seed_metadata['signature'][key] == signature[key], ('Seed differs', key)
        assert seed_metadata['entry_point'] == metadata['entry_point']
        with sqlite3.connect(f'file:{(seed / "predictions.sqlite3").resolve().as_posix()}?mode=ro', uri=True) as previous:
            pred_conn.executemany('INSERT INTO predictions VALUES (?,?,?,?,?)',
                                 ((*row, 'uncached_reference') for row in previous.execute('SELECT input_id,payload,seconds,error FROM predictions')))
        pred_conn.commit()
        metadata['seed_prediction_provenance'] = {'path': str(seed), 'signature': seed_metadata['signature'],
                                                  'completed_predictions': pred_conn.execute('SELECT COUNT(*) FROM predictions').fetchone()[0]}
        dump(metadata_file, metadata)
    total_unique = source.execute('SELECT COUNT(DISTINCT sbom) FROM cases').fetchone()[0]
    total_cases = source.execute('SELECT COUNT(*) FROM cases').fetchone()[0]
    done = pred_conn.execute('SELECT COUNT(*) FROM predictions').fetchone()[0]
    started = time.perf_counter()
    status = {'phase': 'loading_dictionary', 'unique_inputs_completed': done,
              'unique_inputs_total': total_unique, 'dataset_cases_total': total_cases}
    dump(output / 'status.json', status)
    print(f'Predicting with {workers} independent CPU processes; {total_unique} unique inputs / {total_cases} cases', flush=True)
    inputs = [row[0] for row in source.execute('SELECT DISTINCT sbom FROM cases ORDER BY sbom')
              if not pred_conn.execute('SELECT 1 FROM predictions WHERE input_id=?', (input_id(row[0]),)).fetchone()]
    last = time.perf_counter()
    for row in predict_inputs(inputs, workers):
        pred_conn.execute('INSERT INTO predictions VALUES (?,?,?,?,?)', (*row, 'memoized_snapshot_queries'))
        done += 1
        if done % 100 == 0 or time.perf_counter() - last >= 15:
            pred_conn.commit()
            status.update(phase='predicting', unique_inputs_completed=done,
                          elapsed_seconds=round(time.perf_counter() - started, 2))
            dump(output / 'status.json', status)
            print(f'Predicting {done}/{total_unique}, elapsed {status["elapsed_seconds"]:.1f}s', flush=True)
            last = time.perf_counter()
    pred_conn.commit()
    prediction_wall = time.perf_counter() - started
    # No expected labels have been read above. Scoring starts only after all predictions exist.
    status.update(phase='scoring', unique_inputs_completed=done)
    dump(output / 'status.json', status)
    counts = Counter()
    cve_groups = defaultdict(Counter)
    failures = Counter()
    examples = []
    with (output / 'case_outcomes.jsonl').open('w', encoding='utf-8') as handle:
        for case_id, sbom_text, target_text in source.execute('SELECT id,sbom,target FROM cases ORDER BY id'):
            target = json.loads(target_text)
            pred = load_prediction(pred_conn, input_id(sbom_text))
            outcome = score_stages(pred, target)
            counts.update({key: int(value) for key, value in outcome.items() if isinstance(value, bool)})
            counts['cases'] += 1
            if outcome['target_positive']:
                counts['positive_target_returned'] += outcome['target_returned']
                counts['positive_target_strict_match'] += outcome['target_strict_match']
                cve_groups[target['target_cve']]['positive_cases'] += 1
                cve_groups[target['target_cve']]['returned_cases'] += outcome['target_returned']
            for reason in pred.get('validation', {}).get('reasons', []):
                failures[reason] += 1
            issues = [name for name, failed in [('execution_error', outcome['execution_error']),
                      ('l2_target_not_retrieved', not outcome['l2_any_candidate']),
                      ('l3_declared_version_not_confirmed', outcome['l3_supplied'] and not outcome['l3_confirmed_correct']),
                      ('l4_wrong_identity', outcome['l4_wrong']), ('l4_identity_deferred', outcome['l4_deferred']),
                      ('positive_target_cve_not_returned', outcome['target_positive'] and not outcome['target_returned'])] if failed]
            record = {'id': case_id, 'input_id': input_id(sbom_text), 'target_cve': target['target_cve'],
                      'expected_product': target['expected_product'], 'expected_version': target['version'],
                      'predicted_identity': {k: pred.get('validation', {}).get(k) for k in ('status', 'part', 'vendor', 'product', 'reasons')},
                      'predicted_version': pred.get('l3', {}).get('normalized'),
                      'outcome': outcome, 'issues': issues}
            handle.write(compact(record) + '\n')
            if issues and len(examples) < 150:
                examples.append(record)
    # Score all returned CVEs against a separate raw-record oracle, on unique inputs.
    detail = json.loads((ROOT / 'data/nvd_cpe_detail.json').read_text(encoding='utf-8'))
    nvd_meta = json.loads((ROOT / 'data/nvd_cache.json').read_text(encoding='utf-8'))
    oracle = defaultdict(list)
    for cve, rows in detail.items():
        for row in rows:
            oracle[(cve, row.get('vendor'), row.get('product'))].append(row)
    retrieval = Counter()
    for (sbom_text,) in source.execute('SELECT DISTINCT sbom FROM cases'):
        pred = load_prediction(pred_conn, input_id(sbom_text))
        component = json.loads(sbom_text)['components'][0]
        vendor = component['manufacturer']['name']
        product, version = component['name'], component.get('version')
        for cve, state in dict(pred['cves']).items():
            if state == 'no_match':
                continue
            truth = flat_truth(version, oracle.get((cve, vendor, product), []),
                               nvd_meta.get(cve, {}).get('vulnStatus') == 'Rejected')
            retrieval['returned_pairs'] += 1
            retrieval['TP' if truth is True else 'FP' if truth is False else 'unknown_truth'] += 1
            retrieval['returned_as_' + state] += 1
    times = [r[0] for r in pred_conn.execute('SELECT seconds FROM predictions')]
    timing_groups = {}
    for (mode,) in pred_conn.execute('SELECT DISTINCT mode FROM predictions').fetchall():
        group = [r[0] for r in pred_conn.execute('SELECT seconds FROM predictions WHERE mode=?', (mode,))]
        timing_groups[mode] = {'executed_inputs': len(group), 'sum_seconds': sum(group),
                               'median_ms': 1000*percentile(group,.5), 'p95_ms':1000*percentile(group,.95),
                               'max_ms':1000*max(group)}
    n = counts['cases']
    result = {'schema': 'ics-vex-item3-l234-benchmark/1', 'dataset': str(dataset.relative_to(ROOT)),
              'cases': n, 'unique_executed_inputs': total_unique,
              'exact_duplicate_case_reuses': n - total_unique,
              'population_unique_cves': manifest['counts']['unique_cves'],
              'input_covered_cves': manifest['counts']['cves_with_input_cases'],
              'population_cves_without_input': manifest['counts']['unique_cves'] - manifest['counts']['cves_with_input_cases'],
              'L2': {'denominator': n, 'top1_correct': counts['l2_top1'], 'top1_accuracy': ratio(counts['l2_top1'], n),
                     'recall_at_5': ratio(counts['l2_top5'], n), 'recall_at_10': ratio(counts['l2_top10'], n),
                     'returned_candidate_recall': ratio(counts['l2_any_candidate'], n)},
              'L3': {'declared_version_cases': counts['l3_supplied'], 'confirmed_correct': counts['l3_confirmed_correct'],
                     'declared_version_confirmation_rate': ratio(counts['l3_confirmed_correct'], counts['l3_supplied']),
                     'source_observation_preservation_rate': ratio(counts['l3_source_value_preserved'], counts['l3_supplied']),
                     'missing_version_cases': counts['l3_missing_expected'],
                     'missing_stayed_unknown': counts['l3_missing_stayed_unknown'],
                     'missing_version_false_confirmations': counts['l3_false_confirmation']},
              'L4': {'correct_accepted': counts['l4_correct'], 'wrong_accepted': counts['l4_wrong'],
                     'accepted': counts['l4_accepted'], 'deferred': counts['l4_deferred'],
                     'accepted_identity_precision': ratio(counts['l4_correct'], counts['l4_accepted']),
                     'decision_coverage': ratio(counts['l4_accepted'], n),
                     'correct_identity_over_all_inputs': ratio(counts['l4_correct'], n),
                     'deferral_reasons': dict(failures)},
              'CVE_target_retrieval': {'positive_condition_cases': counts['target_positive'],
                     'target_returned_including_unknown': counts['positive_target_returned'],
                     'target_retrieval_rate': ratio(counts['positive_target_returned'], counts['target_positive']),
                     'strict_match_outputs_for_target': counts['positive_target_strict_match'],
                     'strict_match_rate': ratio(counts['positive_target_strict_match'], counts['target_positive']),
                     'macro_cve_retrieval_rate': sum(v['returned_cases']/v['positive_cases'] for v in cve_groups.values())/len(cve_groups) if cve_groups else None,
                     'positive_target_unique_cves': len(cve_groups)},
              'CVE_product_version_subset': {**dict(retrieval),
                     'precision_on_scored_subset': ratio(retrieval['TP'], retrieval['TP'] + retrieval['FP']),
                     'truth_coverage_of_returned_pairs': ratio(retrieval['TP'] + retrieval['FP'], retrieval['returned_pairs']),
                     'unit': '(unique SBOM input, returned CVE), deduplicated',
                     'full_platform_applicability_precision': None},
              'runtime': {'parallel_processes': workers, 'dictionary_loaded_once_per_process': True,
                     'timing_groups': timing_groups, 'mixed_timing_regimes': bool(seed),
                     'prediction_wall_seconds_this_invocation': prediction_wall,
                     'sum_core_call_seconds': sum(times),
                     'median_core_call_ms': 1000 * percentile(times, .5),
                     'p95_core_call_ms': 1000 * percentile(times, .95),
                     'executed_inputs_per_core_second': ratio(total_unique, sum(times)),
                     'execution_errors_unique_inputs': pred_conn.execute('SELECT COUNT(*) FROM predictions WHERE error IS NOT NULL').fetchone()[0]},
              'scope': metadata['scope'], 'production_logic_modified_for_run': False,
              'limitations': ['Controlled inventory built from the same official dictionary/NVD snapshots used by the system; not independent real-SBOM generalization.',
                             'Input cases with missing or ambiguous dictionary identity were not generated; 2,315 population CVEs have no test input.',
                             'Product/version truth is restricted to supported explicit flattened conditions; absent or incomplete evidence is unscored.',
                             'Full platform AND/OR/negation applicability and real-world #3 precision are not established.',
                             'Timing is reported separately for original snapshot queries and equivalent memoized queries; neither is HTTP/network/cold-start latency.']}
    assert {name: sha(ROOT / name) for name in CODE} == fingerprints
    assert n == total_cases == manifest['counts']['input_cases']
    dump(output / 'metrics.json', result)
    dump(output / 'failure_examples.json', examples)
    dump(output / 'cve_retrieval_groups.json', dict(cve_groups))
    status.update(phase='complete', dataset_cases_scored=n, elapsed_seconds=round(time.perf_counter()-started, 2))
    dump(output / 'status.json', status)
    source.close()
    pred_conn.close()
    write_report(output, result)
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return result


def write_report(output, result):
    def pct(value):
        return '산출 불가' if value is None else f'{value*100:.4f}%'
    l2, l3, l4, cve = [result[k] for k in ('L2', 'L3', 'L4', 'CVE_target_retrieval')]
    subset = result['CVE_product_version_subset']
    text = f'''# P2·P3·P4 전체 데이터 성능 시험

현재 생산 코드 `src.unified_identification.run_unified`를 변경 없이 실행했습니다. 로컬 NVD 조회까지 포함하며, 이후 UI의 CISA 권고문 추가 조회는 포함하지 않습니다. LLM은 사용하지 않았습니다.

전체 {result['cases']:,}개 사례의 고유 SBOM {result['unique_executed_inputs']:,}개를 실제 실행했고, 바이트가 동일한 입력에 한해 예측을 재사용했습니다. 모집단 CVE {result['population_unique_cves']:,}개 중 입력이 있는 CVE는 {result['input_covered_cves']:,}개입니다.

| 항목 | 지표 | 결과 |
|---|---|---:|
| P2 | 정답 제품이 1순위 | {pct(l2['top1_accuracy'])} |
| P2 | 정답 제품이 상위 5개 후보에 포함 | {pct(l2['recall_at_5'])} |
| P3 | 선언된 버전의 정확한 확인 | {pct(l3['declared_version_confirmation_rate'])} |
| P3 | 원본 버전 관측 보존 | {pct(l3['source_observation_preservation_rate'])} |
| P4 | 확정한 제품 식별의 정밀도 | {pct(l4['accepted_identity_precision'])} |
| P4 | 전체 입력 중 식별 확정 비율 | {pct(l4['decision_coverage'])} |
| CVE | 양성 조건 사례의 대상 CVE 반환(미확정 후보 포함) | {pct(cve['target_retrieval_rate'])} |

P3 선언 버전 사례 {l3['declared_version_cases']:,}개 중 {l3['confirmed_correct']:,}개가 정확히 확인됐습니다. 버전이 없는 {l3['missing_version_cases']:,}개에서 잘못 버전을 확정한 사례는 {l3['missing_version_false_confirmations']:,}개입니다. P4 확정 정답 {l4['correct_accepted']:,}개, 오확정 {l4['wrong_accepted']:,}개, 유보 {l4['deferred']:,}개입니다.

제품·버전 조건으로 판정 가능한 출력 부분집합: TP={subset.get('TP',0):,}, FP={subset.get('FP',0):,}, 정밀도 {pct(subset['precision_on_scored_subset'])}. 정답 미확정 출력 {subset.get('unknown_truth',0):,}개를 제외했으며 판정 가능 비율은 {pct(subset['truth_coverage_of_returned_pairs'])}입니다. 집계 단위는 `(고유 SBOM 입력, 반환 CVE)`입니다. **전체 플랫폼 적용성과 실제 자산의 #3 정밀도는 산출하지 않습니다.**

CPU 프로세스 {result['runtime']['parallel_processes']}개로 독립 입력을 실행했습니다. 먼저 실행한 원본 조회 결과를 보존하고, 남은 입력에서는 동일한 제품 조회 응답을 재사용했습니다. 판정 함수·버전 대조·임계값은 바꾸지 않았습니다. 원본 조회와 캐시 적용 시간을 섞어 단일 서비스 처리 속도로 해석하면 안 됩니다.

시간 구분: `{json.dumps(result['runtime']['timing_groups'],ensure_ascii=False)}`. 프로세스 내부 경과 시간이며 HTTP·외부 네트워크·매 요청 콜드 스타트 시간이 아닙니다. 캐시 응답과 실제 판정 출력의 동일성을 별도로 확인합니다.

입력과 기대값은 분리했고 전체 예측이 끝난 후 기대값을 읽었습니다. 생성에 쓰인 사전·NVD 스냅샷과 시스템 조회 출처가 같으므로 통제된 일관성 시험입니다. 입력 생성이 불가능했던 CVE {result['population_cves_without_input']:,}개와 미확정 정답을 성공 사례로 계산하지 않았습니다.

상세 자료: `metrics.json`, `case_outcomes.jsonl`, `failure_examples.json`, `predictions.sqlite3`, `run_metadata.json`.
'''
    (output / 'REPORT.md').write_text(text, encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', type=Path, default=ROOT / 'data/item3_ics_cert_full_v1')
    parser.add_argument('--output', type=Path, default=ROOT / 'results/item3_ics_cert_l234_v1')
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--seed-predictions', type=Path)
    args = parser.parse_args()
    if not 1 <= args.workers <= 8:
        parser.error('Use 1 to 8 CPU processes.')
    run(args.dataset, args.output, args.resume, args.workers, args.seed_predictions)
