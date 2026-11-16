"""Frozen, label-separated #3 benchmark. No gold is passed to identification."""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.training_io import atomic_json

SOURCE = ROOT / 'data/item3_spelling_noise_v10/dataset.sqlite3'
GOLD = ROOT / 'benchmark/item3_gold_v11'


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def connection():
    return sqlite3.connect('file:' + SOURCE.as_posix() + '?mode=ro', uri=True)


class SourceNVD:
    """Pinned raw CPE atoms; product identification only, never platform impact."""
    def __init__(self, db):
        from tools.item3_truth_oracle import parts
        self.records = {}
        self.by_identity = defaultdict(set)
        rejected = {r['cve'] for r in map(json.loads, (ROOT/'item3_ics_cert_full/cves.jsonl').read_text(encoding='utf-8').splitlines()) if r.get('nvd_status') == 'Rejected'}
        for cid, path, text in db.execute('SELECT cve,path,raw_match FROM source_coverage ORDER BY cve,path'):
            match = json.loads(text)
            record = self.records.setdefault(cid, {'id': cid, 'vulnStatus': 'Rejected' if cid in rejected else 'Modified',
                'configurations': [{'operator': 'OR', 'cpeMatch': []}],
                'applicability_scope': 'raw_source_atoms_product_version_edition_identification',
                'platform_configuration_preserved': False})
            record['configurations'][0]['cpeMatch'].append(match)
            p = parts(match.get('criteria'))
            if p:
                self.by_identity[p[:3]].add(cid)

    def get_all(self, path, params, field):
        from tools.item3_truth_oracle import parts
        p = parts(params.get('virtualMatchString') or params.get('cpeName'))
        return {'vulnerabilities': [{'cve': self.records[cid]} for cid in sorted(self.by_identity.get(p[:3], ())) ]} if p else {'vulnerabilities': []}


def export_gold():
    """Recheck every stored label using a separate source-only oracle."""
    from tools.item3_truth_oracle import Oracle
    if GOLD.exists() and any(GOLD.iterdir()):
        raise FileExistsError('Use the existing immutable Gold snapshot or a new version')
    GOLD.mkdir(parents=True, exist_ok=True)
    db = connection()
    nvd = SourceNVD(db)
    memory = sqlite3.connect(':memory:')
    memory.execute('CREATE TABLE cves(cve TEXT,payload TEXT)')
    memory.executemany('INSERT INTO cves VALUES (?,?)', ((cid, json.dumps(r)) for cid, r in nvd.records.items()))
    oracle = Oracle(memory)
    counts = Counter()
    conditions = {}
    disagreements = []
    for cid, fold, fields, stored in db.execute('SELECT id,fold,canonical_fields,gold FROM conditions ORDER BY id'):
        expected = json.loads(stored)
        rebuilt = oracle.labels(tuple(json.loads(fields)))
        if expected['expected_cves'] != rebuilt['expected_cves']:
            raise ValueError('Positive source-only label audit failed: ' + cid)
        if expected['unknown_cves'] != rebuilt['unknown_cves']:
            disagreements.append(dict(condition_id=cid, stored_unknown=expected['unknown_cves'],
                oracle_unknown=rebuilt['unknown_cves'], resolution='conservative_union_unknown'))
            expected['unknown_cves'] = sorted(set(expected['unknown_cves']) | set(rebuilt['unknown_cves']))
        conditions[cid] = (fold, expected)
        if len(conditions) % 5000 == 0:
            print('Audited source conditions', len(conditions), flush=True)
    handles = {}
    for fold in ('train', 'evaluation'):
        for kind in ('inputs', 'labels'):
            folder = GOLD / fold
            folder.mkdir(exist_ok=True)
            handles[fold, kind] = (folder/(kind+'.jsonl')).open('w', encoding='utf-8', newline='\n')
    try:
        for cid, condition, fold, axis, scenario, text, digest in db.execute('SELECT id,condition_id,fold,axis,scenario,sbom,input_sha256 FROM cases ORDER BY id'):
            if hashlib.sha256(text.encode()).hexdigest() != digest:
                raise ValueError('Input integrity failure: ' + cid)
            expected = conditions[condition][1]
            inputs = dict(id=cid, sbom=json.loads(text))
            labels = dict(id=cid, condition_id=condition, fold=fold, axis=axis, scenario=scenario,
                synthetic=True, label_provenance='pinned_NVD_atoms_independent_source_oracle',
                independent_human_gold=False, input_sha256=digest, **expected)
            for kind, row in (('inputs', inputs), ('labels', labels)):
                handles[fold, kind].write(json.dumps(row, ensure_ascii=False, separators=(',', ':'))+'\n')
            counts[fold] += 1
            counts[scenario] += 1
    finally:
        for f in handles.values(): f.close()
    split = json.loads((SOURCE.parent/'CVE_split.json').read_text(encoding='utf-8'))
    assert not set(split['train']) & set(split['evaluation'])
    overlap = db.execute("SELECT count(*) FROM (SELECT semantic_sha256 FROM cases WHERE fold='train' INTERSECT SELECT semantic_sha256 FROM cases WHERE fold='evaluation')").fetchone()[0]
    assert overlap == 0
    atomic_json(GOLD/'CVE_split.json', split)
    atomic_json(GOLD/'label_audit_disagreements.json', disagreements)
    atomic_json(GOLD/'manifest.json', dict(schema='item3-separated-gold/11', source_sha256=sha(SOURCE),
        source_label_audit_conditions=len(conditions), source_label_audit_passed=True,
        unknown_label_disagreements=len(disagreements), unknown_resolution='conservative union; no positive label changed',
        CVE_split_ratio='7:3', split_unit='connected CVE/product groups; paired inputs kept together',
        CVE_counts={k: len(v) for k,v in split.items() if isinstance(v,list)}, counts=dict(counts),
        semantic_input_overlap=overlap, metric='TP/(TP+FP)', target_precision_strictly_greater_than=.8,
        scope='Synthetic declared product/version/edition mapping; runtime influence excluded',
        unknown_policy='Keep unknown labels; count all unjudged emitted positives in precision lower-bound denominator',
        production_predictions_used_for_labels=False, independent_real_asset_gold=False,
        artifacts={str(p.relative_to(GOLD)): sha(p) for p in GOLD.rglob('*.jsonl')}))
    print(json.dumps(dict(gold=str(GOLD), counts=dict(counts)), ensure_ascii=False), flush=True)


def evaluate(mode='rules', fold='evaluation', limit=0, runtime=None, output=None):
    from src.identity_retrieval import get_index
    from src.unified_identification import run_unified
    from tools.item3_v6_metrics import case_score, aggregate
    output = output or ROOT/f'results/item3_precision_v11/{mode}_{fold}'
    output.mkdir(parents=True, exist_ok=True)
    inputs_path = GOLD/fold/'inputs.jsonl'
    labels_path = GOLD/fold/'labels.jsonl'
    manifest = json.loads((GOLD/'manifest.json').read_text(encoding='utf-8'))
    for p in (inputs_path, labels_path):
        if sha(p) != manifest['artifacts'][str(p.relative_to(GOLD))]:
            raise ValueError('Frozen Gold changed')
    # Load labels only in the scorer. The inference call receives only input SBOM.
    labels = {r['id']: r for r in map(json.loads, labels_path.read_text(encoding='utf-8').splitlines())}
    db = connection(); nvd = SourceNVD(db); index = get_index()
    universe = set(nvd.records)
    scores = []; started = time.perf_counter()
    predictions = (output/'predictions.jsonl').open('w', encoding='utf-8')
    atomic_json(output/'run_config.json', dict(mode=mode, fold=fold, limit=limit,
        gold_manifest_sha256=sha(GOLD/'manifest.json'), source_sha256=sha(SOURCE),
        gold_passed_to_inference=False, mapping_scope='identification',
        code={str(p.relative_to(ROOT)):sha(p) for p in [Path(__file__),ROOT/'src/identity_evidence.py',ROOT/'src/identification_cve_matching.py']}))
    try:
        for number, line in enumerate(inputs_path.open(encoding='utf-8'), 1):
            if limit and number > limit: break
            item = json.loads(line); label = labels[item['id']]
            try:
                result = run_unified(item['sbom'], nvd, index=index, mode='rules' if mode=='rules' else 'agents',
                    agents=runtime.identification_agent if runtime else None, mapping_scope='identification')
            except Exception as exc:
                result = {'components': [], 'error': type(exc).__name__+': '+str(exc)}
            score = case_score(result, label, universe)
            scores.append((label['scenario'], fold, score))
            predictions.write(json.dumps(dict(id=item['id'], score=score, result=result), ensure_ascii=False)+'\n')
            if number % 100 == 0:
                atomic_json(output/'status.json', dict(phase='evaluating', completed=number,
                    total=min(limit,len(labels)) if limit else len(labels), seconds=time.perf_counter()-started))
                print(number, flush=True)
    finally:
        predictions.close()
    report = aggregate(scores, min(limit,len(labels)) if limit else len(labels))
    m = report['all_BOMs_latent_asset_mapping_metrics']
    p = m['precision_percent']
    lower = m['precision_lower_bound_percent']
    report.update(mode=mode, fold=fold, synthetic=True, real_asset_precision=None,
        threshold_strict=True, target_precision=.8, precision=p/100 if p is not None else None,
        target_met=bool(p is not None and p>80 and report['execution_errors']==0 and report['full_population_complete']),
        conservative_lower_bound_target_met=bool(lower is not None and lower>80 and report['execution_errors']==0 and report['full_population_complete']),
        gold_passed_to_inference=False, elapsed_seconds=time.perf_counter()-started)
    atomic_json(output/'precision_report.json', report)
    atomic_json(output/'status.json', dict(phase='complete', completed=len(scores), total=report['total_BOMs']))
    print(json.dumps(report, ensure_ascii=False), flush=True)
    return report


def evaluate_trained(runtime=None):
    """Resume exact-packet GPU batching over the complete frozen test set."""
    from functools import partial
    from src.identity_retrieval import get_index
    from src.unified_identification import run_unified
    from src.precision_role_runtime import PrecisionRoleRuntime
    from src.identification_batch_flow import PacketCache, resolve_window
    from tools.item3_v6_metrics import case_score, aggregate
    output=ROOT/'results/item3_precision_v11/trained_evaluation';output.mkdir(parents=True,exist_ok=True)
    runtime=runtime or PrecisionRoleRuntime()
    marker=json.loads((runtime.folder/'training_complete.json').read_text(encoding='utf-8'))
    frozen_code={str(p.relative_to(ROOT)):sha(p) for p in sorted((ROOT/'src').glob('*.py'))}
    signature=dict(adapter=marker['adapter_sha256'],gold_manifest=sha(GOLD/'manifest.json'),code=frozen_code,
        mode='fine_tuned_shared_14B',mapping_scope='identification',gold_passed_to_inference=False,
        scheduler_packet_batch=16,runtime_max_forward_batch=8,runtime_padded_token_limit=8192,
        driver_sha256=sha(Path(__file__)))
    run_path=output/'run_config.json'
    if run_path.exists() and json.loads(run_path.read_text(encoding='utf-8'))!=signature:
        raise ValueError('Frozen implementation/model/data changed; choose a new evaluation version')
    atomic_json(run_path,signature)
    manifest=json.loads((GOLD/'manifest.json').read_text(encoding='utf-8'))
    for kind in ('inputs','labels'):
        path=GOLD/'evaluation'/(kind+'.jsonl')
        if sha(path)!=manifest['artifacts'][str(path.relative_to(GOLD))]:raise ValueError('Gold changed')
    inputs=[json.loads(line) for line in (GOLD/'evaluation/inputs.jsonl').open(encoding='utf-8')]
    labels={r['id']:r for r in map(json.loads,(GOLD/'evaluation/labels.jsonl').read_text(encoding='utf-8').splitlines())}
    source=connection();nvd=SourceNVD(source);index=get_index();universe=set(nvd.records)
    db=sqlite3.connect(output/'predictions.sqlite3')
    db.execute('CREATE TABLE IF NOT EXISTS predictions(id TEXT PRIMARY KEY,scenario TEXT,score TEXT,result TEXT)')
    done={r[0] for r in db.execute('SELECT id FROM predictions')}
    remaining=[r for r in inputs if r['id'] not in done]
    cache=PacketCache(output/'packet_cache.sqlite3',digest_json(signature))
    started=time.perf_counter()
    def infer(task,packets,**ignored):
        return runtime.identification_batch(task,packets,batch_size=4,max_padded_tokens=8192,compact_wire=True)
    try:
        for start in range(0,len(remaining),64):
            chunk=remaining[start:start+64]
            # No labels, canonical values, source condition IDs or perturbations.
            results=resolve_window({r['id']:r['sbom'] for r in chunk},cache,infer,index=index,nvd=nvd,
                batch_size=16,core=partial(run_unified,mapping_scope='identification'))
            with db:
                for row in chunk:
                    result,trace=results[row['id']]
                    label=labels[row['id']]
                    scored=case_score(result,label,universe)
                    db.execute('INSERT INTO predictions VALUES (?,?,?,?)',(row['id'],label['scenario'],json.dumps(scored),json.dumps(dict(result=result,trace=trace))))
                    done.add(row['id'])
            atomic_json(output/'status.json',dict(phase='evaluating',completed=len(done),total=len(inputs),
                elapsed_seconds=time.perf_counter()-started,actual_llm_requests=cache.statistics()['actual_llm_requests']))
            print('trained evaluation',len(done),'/',len(inputs),flush=True)
        report=aggregate(((s,'evaluation',json.loads(t)) for s,t in db.execute('SELECT scenario,score FROM predictions')),len(inputs))
        m=report['all_BOMs_latent_asset_mapping_metrics'];p=m['precision_percent'];low=m['precision_lower_bound_percent']
        report.update(synthetic=True,real_asset_precision=None,mode='fine_tuned_shared_Qwen2.5-Coder-14B',
            precision=p/100 if p is not None else None,target_precision=.8,threshold_strict=True,
            target_met=bool(p is not None and p>80 and report['execution_errors']==0 and report['full_population_complete']),
            conservative_lower_bound_target_met=bool(low is not None and low>80 and report['execution_errors']==0 and report['full_population_complete']),
            runtime_statistics=cache.statistics(),training_examples=marker['examples'],optimizer_updates=marker['optimizer_updates'],
            gold_passed_to_inference=False)
        atomic_json(output/'precision_report.json',report)
        atomic_json(output/'status.json',dict(phase='complete',completed=len(done),total=len(inputs)))
        print(json.dumps(report),flush=True)
    finally:db.close();cache.close();source.close()


def digest_json(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('action', choices=['export', 'evaluate', 'evaluate-trained'])
    p.add_argument('--fold', choices=['train','evaluation'], default='evaluation')
    p.add_argument('--limit', type=int, default=0)
    a = p.parse_args()
    if a.action=='export':export_gold()
    elif a.action=='evaluate-trained':evaluate_trained()
    else:evaluate(fold=a.fold,limit=a.limit)
