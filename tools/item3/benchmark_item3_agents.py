"""Checkpointed, paired real-GPU agent/rules evaluation on the full ICS-CERT inputs."""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
import urllib.request
import zlib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.item3.benchmark_item3_i123 import (CODE, EquivalentSnapshotCache, compact, input_id,
                                      prediction, score_stages, ratio, percentile)
from tools.item3.preprocess_item3_ics_cert import sha
from src.common.runtime.training_progress_io import atomic_json; from src.common.runtime.training_progress_io import read_json
from tools.item3.preprocess_item3_all_cpes import occurrences, cpe_parts
from src.item3.matching.sbom_matching_engine import CVE_API

EXTRA_CODE = ['src/item3/agents/identification_model_runtime.py', 'src/item3/agents/evidence_review_agents.py',
              'src/item3/agents/agent_contracts.py', 'src/common/runtime/json_output_constraints.py',
              'src/common/runtime/inference_role_policy.py', 'src/common/runtime/grounded_role_tasks.py',
              'data/identification_runtime.json', 'data/identity_aliases_v3.json',
              'tools/item3/benchmark_item3_agents.py', 'tools/item3/benchmark_item3_i123.py',
              'tools/item3/preprocess_item3_ics_cert.py', 'tools/item3/preprocess_item3_all_cpes.py',
              'tools/item3/audit_item3_all_cpes.py']


class FullConfigurationNVD:
    """Product-scope candidates with original configuration trees, for both arms."""
    def __init__(self, source):
        self.records = {cid: json.loads(payload) for cid, payload in source.execute('SELECT cve,payload FROM cves')}
        self.by_identity = defaultdict(set)
        for cid, record in self.records.items():
            for _, match in occurrences(record.get('configurations', [])):
                parts = cpe_parts(match.get('criteria') if isinstance(match, dict) else None)
                if parts: self.by_identity[tuple(parts[2:5])].add(cid)

    def get_all(self, path, params, field):
        from copy import deepcopy
        if path != CVE_API: raise ValueError('Only local CVE lookup is supported')
        parts = cpe_parts(params.get('cpeName') or params.get('virtualMatchString'))
        ids = sorted(self.by_identity.get(tuple(parts[2:5]), set())) if parts else []
        return {'vulnerabilities': [{'cve': deepcopy(self.records[cid])} for cid in ids]}


def score_target(pred, target):
    result = score_stages(pred, target)
    scorable = target.get('identity_scorable', True)
    result['identity_scorable'] = scorable
    if not scorable:
        result['i3_unscorable_accepted'] = result['i3_accepted']
        result['i3_unscorable_deferred'] = result['i3_deferred']
        for key in list(result):
            if key.startswith(('i1_', 'i3_')) and not key.startswith('i3_unscorable_'):
                del result[key]
    return result


def utc():
    return datetime.now(timezone.utc).isoformat()


def add_outcome(counts, outcome):
    counts.update({k: int(v) for k, v in outcome.items() if isinstance(v, bool)})
    counts['cases'] += 1
    if outcome['target_positive']:
        counts['positive_target_returned'] += outcome['target_returned']
        counts['positive_target_strict_match'] += outcome['target_strict_match']


def stage_metrics(c):
    n = c['identity_scorable']
    return {'cases': c['cases'], 'identity_scorable_cases': n,
            'all_cases': c['cases'], 'identity_unscorable_cases': c['cases'] - n,
            'I1_top1_accuracy': ratio(c['i1_top1'], n),
            'I1_recall_at_5': ratio(c['i1_top5'], n),
            'I1_recall_at_10': ratio(c['i1_top10'], n),
            'I2_declared_version_cases': c['i2_supplied'],
            'I2_confirmed_correct': c['i2_confirmed_correct'],
            'I2_declared_confirmation_rate': ratio(c['i2_confirmed_correct'], c['i2_supplied']),
            'I2_missing_version_false_confirmations': c['i2_false_confirmation'],
            'I3_correct_accepted': c['i3_correct'], 'I3_wrong_accepted': c['i3_wrong'],
            'I3_accepted_precision': ratio(c['i3_correct'], c['i3_accepted']),
            'I3_decision_coverage': ratio(c['i3_accepted'], n),
            'I3_deferred': c['i3_deferred'],
            'I3_unscorable_accepted': c['i3_unscorable_accepted'],
            'I3_unscorable_deferred': c['i3_unscorable_deferred'],
            'positive_condition_cases': c['target_positive'],
            'target_returned_including_unknown': c['positive_target_returned'],
            'target_retrieval_rate_including_unknown': ratio(c['positive_target_returned'], c['target_positive']),
            'target_strict_match_rate': ratio(c['positive_target_strict_match'], c['target_positive']),
            'execution_error_cases': c['execution_error']}


def write_report(output, metrics):
    def fmt(x):
        return '미산출' if x is None else f'{100*x:.4f}%'
    lines = ['# I123 실제 LLM / 규칙 비교 시험', '',
             f"상태: **{metrics['phase']}**. 고유 입력 {metrics['unique_inputs_completed']:,}/{metrics['unique_inputs_total']:,}, "
             f"연결된 조건 사례 {metrics['cases_scored']:,}/{metrics['dataset_cases_total']:,}개 채점.", '',
             '완료 전 수치는 처리된 부분집합의 중간 집계이며, 전체 성능 추정치가 아닙니다.', '',
             '| 지표 | 실제 LLM agents | 같은 입력의 현재 rules |', '|---|---:|---:|']
    for key in ['I1_top1_accuracy', 'I1_recall_at_5', 'I2_declared_confirmation_rate',
                'I3_accepted_precision', 'I3_decision_coverage', 'target_retrieval_rate_including_unknown']:
        lines.append(f"| {key} | {fmt(metrics['agents'][key])} | {fmt(metrics['rules'][key])} |")
    lines += ['', f"실제 모델 호출: {metrics['actual_llm_calls']:,}회. 단계 상태: `{compact(metrics['agent_stage_statuses'])}`.", '',
              f"입력당 warm 중앙값 {metrics['runtime']['warm_agent_median_seconds']}초, "
              f"p95 {metrics['runtime']['warm_agent_p95_seconds']}초. "
              '초기 모델·사전 로딩 시간과 개별 입력의 실행 시간은 별도로 저장합니다.', '',
             f"모집단 및 전체 CPE 범위: `{compact(metrics['population'])}`. "
              '원본 cpeMatch의 중복·중첩·vulnerable=false 플랫폼 조건도 모두 실행합니다. 사전 매칭 여부로 제외하지 않습니다. '
              'CPE 미부여 CVE는 별도 집계하며, 정답 식별을 특정할 수 없는 CPE는 실행 후 식별 정확도 분모와 분리합니다.', '',
              '입력은 사전/NVD로 만든 통제된 자료이며 독립 실제 SBOM 정답이 아닙니다. '
              '대상 CVE 반환율은 미확정 후보를 포함합니다. 전체 출력의 CVE 정밀도와 플랫폼 AND/OR 적용성 정확도는 산출하지 않습니다.', '',
              '고유 SBOM마다 실제 I2→I1→I3 경로를 실행합니다. 단계 응답 캐시는 사용하지 않습니다. '
              '완전히 같은 SBOM을 공유하는 조건 사례만 하나의 예측을 공유합니다. '
              '양쪽 모두 동일한 원본 NVD 구성 트리를 제품 단위로 조회합니다. '
              'UI의 후속 CISA 권고문 추가 조회는 제외합니다.', '',
              '기대값은 각 입력의 양쪽 예측이 끝난 뒤 별도 채점 단계에서 읽습니다. '
              '해시 순서로 실행하며 중간 결과는 CVE별 무작위 표본이 아닙니다.', '',
              '상세 예측·모델 원문·토큰·시간은 predictions.sqlite3, 조건별 점수는 case_outcomes.jsonl, '
              '실행 환경과 지문은 run_metadata.json에 저장합니다.']
    (output / 'REPORT.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')


def run(dataset, output, resume=False, api='http://127.0.0.1:8100'):
    from src.common import gpu_lease
    from src.item3.evidence.product_candidate_search import get_index
    from src.item3.matching.identification_pipeline import run_unified
    from src.item3.agents.identification_model_runtime import get_runtime; from src.item3.agents.identification_model_runtime import release_runtime
    dataset, output = dataset.resolve(), output.resolve()
    if not output.is_relative_to(ROOT / 'results'):
        raise ValueError('Output must stay within workspace results.')
    if output.exists() and not resume:
        raise FileExistsError('Use a new output directory or --resume.')
    output.mkdir(parents=True, exist_ok=True)
    manifest = read_json(dataset / 'manifest.json')
    for name, spec in manifest['artifacts'].items():
        if sha(dataset / name) != spec['sha256']:
            raise ValueError('Dataset changed: ' + name)
    for name, spec in manifest['sources'].items():
        if sha(ROOT / name) != spec['sha256']:
            raise ValueError('Source snapshot changed: ' + name)
    files = dict.fromkeys(CODE + EXTRA_CODE)
    fingerprints = {name: sha(ROOT / name) for name in files}
    adapter = ROOT / 'models/vex-writer-qwen3-8b-v1/adapter_config.json'
    base = Path(read_json(adapter)['base_model_name_or_path'])
    weight_index = base / 'model.safetensors.index.json'
    shards = sorted(set(read_json(weight_index)['weight_map'].values()))
    signature = {'dataset_manifest_sha256': sha(dataset / 'manifest.json'), 'production_files': fingerprints,
                 'base_model': str(base), 'base_config_sha256': sha(base / 'config.json'),
                 'base_weight_index_sha256': sha(weight_index),
                 'base_shards': {name: {'bytes': (base / name).stat().st_size,
                                        'mtime_ns': (base / name).stat().st_mtime_ns} for name in shards},
                 'tokenizer_files': {p.name: sha(p) for p in adapter.parent.iterdir()
                                     if p.is_file() and (p.name.startswith(('tokenizer', 'chat_template', 'special_tokens_map')))}}
    previous = read_json(output / 'run_metadata.json')
    if previous and previous['signature'] != signature:
        raise ValueError('Code/data/model changed: do not mix runs.')
    metadata = previous or {'created_at_utc': utc(), 'signature': signature,
        'entry_point': 'src.item3.matching.identification_pipeline.run_unified', 'paired_modes': ['agents', 'rules'],
        'gold_in_inference_packet': False, 'exact_duplicate_sboms_share_prediction': True,
        'stage_response_cache': False, 'model': 'Qwen3-8B base, local 4-bit, no old identification adapters',
        'scope': 'Every original CPE occurrence; I123 core plus full-configuration NVD lookup; excludes UI advisory augmentation',
        'independent_real_sbom_accuracy': False}
    from tools.item3.audit_item3_all_cpes import audit
    metadata['coverage_audit'] = audit(dataset, output / 'coverage_audit.json')
    atomic_json(output / 'run_metadata.json', metadata)
    source = sqlite3.connect(f'file:{(dataset / "corpus.sqlite3").as_posix()}?mode=ro', uri=True)
    plan = defaultdict(list)
    texts = {}
    # Deliberately no targets read while building the prediction schedule.
    for case_id, text in source.execute('SELECT id,sbom FROM cases'):
        key = input_id(text); texts[key] = text; plan[key].append(case_id)
    db = sqlite3.connect(output / 'predictions.sqlite3')
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('CREATE TABLE IF NOT EXISTS predictions(input_id TEXT PRIMARY KEY,payload BLOB NOT NULL,agent_seconds REAL,rules_seconds REAL)')
    db.execute('CREATE TABLE IF NOT EXISTS case_scores(id TEXT PRIMARY KEY,input_id TEXT,payload TEXT NOT NULL)')
    counts = {'agents': Counter(), 'rules': Counter()}
    for payload, in db.execute('SELECT payload FROM case_scores'):
        record = json.loads(payload)
        for mode in counts: add_outcome(counts[mode], record[mode])
    with (output / 'case_outcomes.jsonl').open('w', encoding='utf-8') as handle:
        for payload, in db.execute('SELECT payload FROM case_scores ORDER BY id'):
            handle.write(payload + '\n')
    done_keys = set(); agent_times = []; rule_times = []; stages = Counter(); actual_calls = 0; tokens = 0
    for key, payload, seconds, rseconds in db.execute('SELECT * FROM predictions'):
        done_keys.add(key); agent_times.append(seconds); rule_times.append(rseconds)
        record = json.loads(zlib.decompress(payload))
        for stage, a in record.get('agent_records', {}).items():
            stages[stage + ':' + a.get('status', 'unknown')] += 1
            actual_calls += int(bool(a.get('llm_used')))
            tokens += (a.get('generation') or {}).get('generated_tokens', 0)
    init_started = time.perf_counter(); owned = False; invocation_start = time.perf_counter()
    phase = 'initializing'; current_key = None; init_seconds = None

    def update(stage=None, error=None):
        warm = agent_times[1:]
        median = percentile(warm, .5)
        metrics = {'schema': 'ics-vex-item3-agent-benchmark/1', 'updated_at_utc': utc(),
            'phase': phase, 'pid': os.getpid(), 'current_input_id': current_key, 'current_stage': stage,
            'unique_inputs_completed': len(done_keys), 'unique_inputs_total': len(texts),
            'cases_scored': counts['agents']['cases'], 'dataset_cases_total': manifest['counts']['input_cases'],
            'population': manifest['counts'],
            'actual_llm_calls': actual_calls, 'generated_tokens': tokens,
            'agent_stage_statuses': dict(stages), 'agents': stage_metrics(counts['agents']),
            'rules': stage_metrics(counts['rules']), 'error': error,
            'runtime': {'initialization_seconds_this_invocation': init_seconds,
                'invocation_elapsed_seconds': time.perf_counter() - invocation_start,
                'cold_first_agent_seconds': agent_times[0] if agent_times else None,
                'warm_agent_median_seconds': median, 'warm_agent_p95_seconds': percentile(warm, .95),
                'warm_rules_median_seconds': percentile(rule_times[1:], .5),
                'sum_agent_seconds': sum(agent_times), 'sum_rules_seconds': sum(rule_times),
                'eta_seconds_at_warm_median': (len(texts) - len(done_keys))*median if median else None},
            'full_population_complete': len(done_keys) == len(texts),
            'independent_real_sbom_accuracy': False, 'CVE_full_output_precision': None}
        atomic_json(output / 'status.json', metrics)
        atomic_json(output / 'metrics.json', metrics)
        write_report(output, metrics)

    update()
    try:
        lease = read_json(gpu_lease.FILE)
        if lease.get('active') and any(gpu_lease.alive(lease.get(k)) for k in ('pid', 'child_pid')):
            raise RuntimeError('Another live GPU owner exists; benchmark not admitted.')
        atomic_json(gpu_lease.FILE, {'pid': os.getpid(), 'active': True, 'phase': 'benchmark',
                    'purpose': 'full ICS-CERT paired I123 agent performance evaluation', 'output': str(output)})
        owned = True
        # Release the idle web runtime before loading this benchmark's single GPU model.
        request = urllib.request.Request(api.rstrip('/') + '/api/cve-match/models/unload', data=b'', method='POST')
        with urllib.request.urlopen(request, timeout=120) as response:
            metadata['web_runtime_release'] = json.load(response)
        import torch
        from importlib.metadata import version
        metadata['environment'] = {'python': sys.version, 'torch': torch.__version__,
            'cuda': torch.version.cuda, 'gpu': torch.cuda.get_device_name(0),
            'packages': {name: version(name) for name in ['transformers', 'peft', 'bitsandbytes', 'lm-format-enforcer']}}
        atomic_json(output / 'run_metadata.json', metadata)
        index = get_index()
        nvd = FullConfigurationNVD(source) if manifest.get('full_configuration_trees_preserved') else EquivalentSnapshotCache()
        runtime = get_runtime()
        runtime._load('vex-writer')
        init_seconds = time.perf_counter() - init_started
        phase = 'predicting'; update()
        no_inference = 0
        for key in sorted(texts):
            if key in done_keys: continue
            if (output / 'STOP').exists():
                phase = 'stopped'; update(); break
            if {name: sha(ROOT / name) for name in files} != fingerprints:
                raise RuntimeError('Production/runner code changed during the run; stopped before mixing versions.')
            current_key = key
            sbom = json.loads(texts[key]); start = time.perf_counter()
            def progress(_done, _total, stage, _name): update(stage)
            captured = {}
            def infer(task, packet):
                response = runtime.identification_agent(task, packet)
                captured[task.lower()] = {**response, 'status': 'model_completed_before_pipeline_error'}
                return response
            try:
                result = run_unified(sbom, nvd, index=index, mode='agents', agents=infer, progress=progress)
                row = result['components'][0]
                records = {s: row[s].get('agent') or {} for s in ('i1', 'i2', 'i3')}
                ap = prediction(result)
            except Exception as exc:
                records = captured
                ap = {'error': type(exc).__name__ + ': ' + str(exc), 'i1_candidates': [],
                      'i2': {}, 'validation': {}, 'cves': [],
                      'llm_used': any(a.get('llm_used') for a in captured.values())}
            seconds = time.perf_counter() - start
            start = time.perf_counter()
            try:
                rp = prediction(run_unified(sbom, nvd, index=index, mode='rules'))
            except Exception as exc:
                rp = {'error': type(exc).__name__ + ': ' + str(exc), 'i1_candidates': [],
                      'i2': {}, 'validation': {}, 'cves': [], 'llm_used': False}
            rseconds = time.perf_counter() - start
            if rp['llm_used']: raise AssertionError('Rules comparison invoked an LLM')
            # Only now read this input's labels, after both independent predictions exist.
            scores = []
            for case_id in plan[key]:
                target = json.loads(source.execute('SELECT target FROM cases WHERE id=?', (case_id,)).fetchone()[0])
                scores.append({'id': case_id, 'input_id': key, 'target': target,
                               'agents': score_target(ap, target), 'rules': score_target(rp, target)})
            payload = {'agents': ap, 'rules': rp, 'agent_records': records}
            with db:
                db.execute('INSERT INTO predictions VALUES (?,?,?,?)',
                           (key, zlib.compress(compact(payload).encode(), 6), seconds, rseconds))
                db.executemany('INSERT INTO case_scores VALUES (?,?,?)',
                               [(r['id'], key, compact(r)) for r in scores])
            with (output / 'case_outcomes.jsonl').open('a', encoding='utf-8') as handle:
                for record in scores: handle.write(compact(record) + '\n')
            for record in scores:
                for mode in counts: add_outcome(counts[mode], record[mode])
            for stage, a in records.items():
                stages[stage + ':' + a.get('status', 'unknown')] += 1
                actual_calls += int(bool(a.get('llm_used')))
                tokens += (a.get('generation') or {}).get('generated_tokens', 0)
            done_keys.add(key); agent_times.append(seconds); rule_times.append(rseconds)
            no_inference = no_inference + 1 if not ap['llm_used'] else 0
            update('input_complete')
            print(f'{len(done_keys)}/{len(texts)} inputs; {counts["agents"]["cases"]} cases; '
                  f'{actual_calls} actual LLM calls; agent {seconds:.2f}s; rules {rseconds:.3f}s', flush=True)
            if no_inference >= 3:
                raise RuntimeError('Three consecutive inputs had no actual inference; stopped instead of scoring a broken runtime as a full run.')
        else:
            phase = 'complete'; update('complete')
    except BaseException as exc:
        phase = 'failed'; update(error=type(exc).__name__ + ': ' + str(exc)); raise
    finally:
        with (output / 'case_outcomes.jsonl').open('w', encoding='utf-8') as handle:
            for payload, in db.execute('SELECT payload FROM case_scores ORDER BY id'):
                handle.write(payload + '\n')
        if owned:
            release_runtime()
            if read_json(gpu_lease.FILE).get('pid') == os.getpid():
                atomic_json(gpu_lease.FILE, {'pid': os.getpid(), 'active': False, 'phase': phase, 'output': str(output)})
        db.close(); source.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', type=Path, default=ROOT / 'data/item3_all_assigned_cpes_v1')
    parser.add_argument('--output', type=Path, default=ROOT / 'results/item3_all_assigned_cpes_agents_v1')
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--api', default='http://127.0.0.1:8100')
    args = parser.parse_args()
    run(args.dataset, args.output, args.resume, args.api)
