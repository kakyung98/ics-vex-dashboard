"""Build full-population clustering, review contracts, questionnaires and VEX traces.

python tools/build_context_vex_pipeline.py --help
No external calls. Source/candidate hashes and unresolved work are recorded.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import html
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.context_vex_pipeline import validate_review, select_questions, evaluate_review, approved, leaves
from tools.discover_ics_clusters import clean_description, fit_text, model_for, sha, write_json, write_jsonl


def read_rows(path):
    with Path(path).open(encoding='utf-8-sig') as stream:
        return [json.loads(line) for line in stream if line.strip()]


def unique(rows, field):
    result = {r[field]: r for r in rows}
    if len(result) != len(rows):
        raise ValueError('Duplicate ' + field)
    return result


def cluster(records, output, ks, dimensions, embeddings=None):
    import numpy as np
    from sklearn.metrics import silhouette_score, davies_bouldin_score, calinski_harabasz_score, adjusted_rand_score
    from sklearn.preprocessing import normalize
    from threadpoolctl import threadpool_limits
    texts = [clean_description(' '.join(s['text'] for s in r['sources']), 'context') for r in records]
    # Full source coverage; no first-N-character truncation or condition-based filter.
    with threadpool_limits(limits=4):
        vectorizer, sparse, matrix, svd = fit_text(texts, dimensions)
        if embeddings:
            bundle = Path(embeddings)
            metadata = json.loads((bundle/'summary.json').read_text(encoding='utf-8'))
            if sha(bundle/'description_vectors.npy') != metadata['artifacts']['description_vectors.npy'] or sha(bundle/'cve_index.jsonl') != metadata['artifacts']['cve_index.jsonl']:
                raise ValueError('Embedding artifact hash mismatch')
            if [r['cve'] for r in read_rows(bundle/'cve_index.jsonl')] != [r['cve'] for r in records]:
                raise ValueError('Embedding CVE order mismatch')
            matrix = np.load(bundle/'description_vectors.npy')
        sample = np.sort(np.random.default_rng(42).choice(len(records), min(2000, len(records)), replace=False))
        metrics, models = [], {}
        for k in ks:
            if not 1 < k < len(records):
                continue
            model = model_for(k, 42).fit(matrix)
            labels = model.predict(matrix)
            sample_labels = labels[sample]
            if len(set(sample_labels)) < 2:
                continue
            seed_labels = model_for(k, 43).fit(matrix).predict(matrix)
            indices = np.random.default_rng(44).choice(len(matrix), len(matrix), replace=True)
            bootstrap_labels = model_for(k, 44).fit(matrix[indices]).predict(matrix)
            # Random projection tests sensitivity; transformer coordinates have no LSA ordering.
            reduced = normalize(matrix @ np.random.default_rng(42).normal(size=(matrix.shape[1], max(2,matrix.shape[1]//2)))) if embeddings else normalize(matrix[:, :max(2, matrix.shape[1]//2)])
            representation_labels = model_for(k, 42).fit(reduced).predict(reduced)
            metric = dict(k=k, silhouette_cosine=float(silhouette_score(matrix[sample], sample_labels, metric='cosine')),
                davies_bouldin=float(davies_bouldin_score(matrix, labels)),
                calinski_harabasz=float(calinski_harabasz_score(matrix, labels)),
                seed_ari=float(adjusted_rand_score(labels, seed_labels)),
                bootstrap_ari=float(adjusted_rand_score(labels, bootstrap_labels)),
                dimension_sensitivity_ari=float(adjusted_rand_score(labels, representation_labels)),
                realized_clusters=len(set(labels)), min_cluster_size=int(np.bincount(labels).min()),
                max_cluster_size=int(np.bincount(labels).max()))
            metrics.append(metric)
            models[k] = (model, labels)
            write_json(output/'cluster_metrics.json', metrics)
            print('cluster candidate', k, flush=True)
    if not metrics:
        raise ValueError('No usable K candidates')
    stable = [m for m in metrics if min(m['seed_ari'], m['bootstrap_ari']) >= .6]
    chosen = max(metrics, key=lambda m: (m['silhouette_cosine'], -m['k']))
    model, labels = models[chosen['k']]
    from sklearn import config_context
    with threadpool_limits(limits=4), config_context(working_memory=256):
        chosen['silhouette_cosine_full_population'] = float(silhouette_score(matrix, labels, metric='cosine'))
    chosen['search_silhouette_sample_size'] = len(sample)
    terms = vectorizer.get_feature_names_out()
    topics = []
    for label in sorted(set(labels)):
        indexes = np.flatnonzero(labels == label)
        weights = np.asarray(sparse[indexes].mean(axis=0)).ravel()
        topics.append(dict(cluster_id=int(label), size=len(indexes),
                           topic_terms=terms[np.argsort(-weights)[:12]].tolist(),
                           interpretation='Descriptive text topic, not shared necessity'))
    write_json(output/'clusters.json', topics)
    write_json(output/'embedding.json', dict(method='Sentence Transformer all-mpnet-base-v2' if embeddings else 'TF-IDF word/bigram + LSA', dimensions=matrix.shape[1],
        seed=42, all_source_text_used=True, sentence_transformer=bool(embeddings),
        representation_check='Random projection sensitivity' if embeddings else 'Half-dimensional LSA sensitivity; not independent model-family validation',
        embedding_bundle=str(embeddings) if embeddings else None,
        topic_lsa_explained_variance=float(svd.explained_variance_ratio_.sum()),
        vocabulary_sha256=hashlib.sha256('\n'.join(terms).encode()).hexdigest()))
    return {r['cve']: int(label) for r, label in zip(records, labels)}, chosen, bool(stable)


def proposal(record, profile, semantic=None):
    sources = {}
    for source in record['sources']:
        sources[source['id']] = source
        for alias in source.get('duplicate_source_ids', []):
            sources[alias] = source
    conditions, questions, invalid = [], [], []
    findings = []
    for f in profile.get('findings', []):
        findings.append(dict(predicate=f['feature'], source_id=f['source_id'], span=f['span'], quote=f['quote'],
                             text=f['question'], method='existing_rule_assisted_candidate', necessity='not_established'))
    for f in (semantic or {}).get('facts', []):
        findings.append(dict(predicate=f['condition'], source_id=f['source_id'], span=f['source_span'], quote=f['source_quote'],
                             text='이 자산에서 다음 조건의 대상과 성립 여부를 근거로 확인해 주세요: '+f['condition'],
                             method='model_proposed_candidate', necessity=f['necessity']))
    for f in findings:
        source = sources.get(f['source_id'])
        start, end = f['span']
        if source is None or not (0 <= start < end <= len(source['text'])) or source['text'][start:end] != f['quote']:
            invalid.append(f)
            continue
        cid = record['cve']+':condition:'+str(len(conditions)+1)
        conditions.append(dict(id=cid, predicate=f['predicate'], target='unresolved', operator_observable=None,
            necessity='not_established', proposed_necessity=f['necessity'], validation_status='pending_review',
            extraction_method=f['method'], source_refs=[dict(source_id=source['id'], span=f['span'], quote=f['quote'])]))
        questions.append(dict(id=cid+':question', text=f['text'], target='unresolved', cost=1,
            validation_status='pending_review', answer_type='investigation_text', mappings=[],
            reason='Reviewer must specify target and validate Yes/No/Unknown implications before operator use'))
    return dict(cve=record['cve'], conditions=conditions, questions=questions, formula=None,
        identity_ambiguous=record.get('identity_ambiguous', False), source_record_status=record.get('original_nvd_status'),
        extraction_state=(semantic or {}).get('extraction_state', 'semantic_extraction_pending'),
        rejected_candidate_spans=invalid)


def run(args):
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    records = sorted(read_rows(args.inputs), key=lambda r:r['cve'])
    bycve = unique(records, 'cve')
    advisory = json.loads(Path(args.advisories).read_text(encoding='utf-8-sig'))
    population = {c.upper() for a in advisory.values() for c in a.get('cves', [])}
    if set(bycve) != population or len(records) != args.expected_population:
        raise ValueError('Input CVEs must exactly equal the declared advisory population')
    for r in records:
        for s in r['sources']:
            if hashlib.sha256(s['text'].encode()).hexdigest() != s['text_sha256']:
                raise ValueError('Source hash mismatch: '+s['id'])
    profiles = unique(read_rows(args.candidates), 'cve') if args.candidates else {}
    semantic = unique(read_rows(args.semantic), 'cve') if args.semantic else {}
    reviews = unique(read_rows(args.reviews), 'cve') if args.reviews else {}
    if (set(reviews) | set(semantic) | set(profiles)) - population:
        raise ValueError('Review/candidate records outside population')
    fingerprint = {name: sha(path) for name, path in vars(args).items()
                   if name in ('inputs', 'advisories', 'candidates', 'semantic', 'reviews', 'cases') and path}
    if args.embeddings:
        meta = json.loads((Path(args.embeddings)/'summary.json').read_text(encoding='utf-8'))
        if meta['fingerprint']['inputs_sha256'] != fingerprint['inputs']:
            raise ValueError('Embeddings belong to different source snapshot')
        fingerprint['embeddings_summary'] = sha(Path(args.embeddings)/'summary.json')
    cache_key = dict(inputs=fingerprint['inputs'], ks=args.ks, dimensions=args.dimensions,
                     embeddings=sha(Path(args.embeddings)/'summary.json') if args.embeddings else None,
                     script=sha(__file__))
    cache_file = output/'cluster_cache.json'
    if args.reuse_clusters and cache_file.exists() and json.loads(cache_file.read_text(encoding='utf-8')) == cache_key:
        assignments = unique(read_rows(output/'assignments.jsonl'), 'cve')
        if set(assignments) != population:
            raise ValueError('Cached population mismatch')
        labels = {c:r['cluster_id'] for c,r in assignments.items()}
        selection = json.loads((output/'cluster_selection.json').read_text(encoding='utf-8'))
        chosen, stable = selection['selected'], selection['stable_candidate_exists']
    else:
        labels, chosen, stable = cluster(records, output, args.ks, args.dimensions, args.embeddings)
        write_jsonl(output/'assignments.jsonl', [dict(cve=r['cve'], cluster_id=labels[r['cve']], excluded=False) for r in records])
        write_json(output/'cluster_selection.json', dict(selected=chosen, stable_candidate_exists=stable,
            rule='Exploratory maximum cosine silhouette; stability reported separately, no ARI hard filter',
            selected_at_upper_boundary=chosen['k']==max(args.ks),
            vex_fitness_validated=False))
        write_json(cache_file, cache_key)
    plans, questionnaires, queue = [], [], []
    support, sizes = defaultdict(Counter), Counter(labels.values())
    for record in records:
        cve = record['cve']
        plan = reviews.get(cve) or proposal(record, profiles.get(cve, {}), semantic.get(cve))
        plan['identity_ambiguous'] = record.get('identity_ambiguous', False)
        plan['source_record_status'] = record.get('original_nvd_status')
        validate_review(plan, record)
        plan['cluster_id'] = labels[cve]
        selected = select_questions(plan['conditions'], plan['questions'],
            leaves(plan['formula']['expression']) if plan.get('formula') else None)
        plan['selection'] = selected
        plans.append(plan)
        questionnaires.append(dict(cve=cve, cluster_id=labels[cve], **selected,
            questions=[q for q in plan['questions'] if q['id'] in selected['selected_question_ids']]))
        reasons = []
        if not plan.get('formula') or not approved(plan['formula']): reasons.append('CVE_formula_not_reviewed')
        if not (plan.get('formula') or {}).get('coverage_complete'): reasons.append('route_completeness_unproven')
        if selected['unresolved_condition_ids']: reasons.append('conditions_without_validated_questions')
        if any(not approved(c) for c in plan['conditions']): reasons.append('candidate_conditions_need_semantic_review')
        if not plan['conditions']: reasons.append('no_verified_conditions_available')
        if plan['identity_ambiguous']: reasons.append('identity_ambiguous')
        if plan['source_record_status'] == 'Rejected': reasons.append('rejected_record_requires_identity_review')
        if reasons: queue.append(dict(cve=cve, reasons=reasons))
        for predicate in {c['predicate'] for c in plan['conditions']}:
            support[labels[cve]][predicate] += 1
    write_jsonl(output/'review_contracts.jsonl', plans)
    write_jsonl(output/'questionnaires.jsonl', questionnaires)
    write_jsonl(output/'review_queue.jsonl', queue)
    write_json(output/'cluster_condition_support.json', [dict(cluster_id=k, population=sizes[k],
        candidates=[dict(predicate=p, count=n, support=n/sizes[k], necessity_proven=False) for p,n in counts.most_common()],
        note='Candidate observation only; unknown is not false') for k,counts in sorted(support.items())])
    # Reuse is enabled only for identical reviewed meaning and target, not text topic.
    shared = defaultdict(list)
    for p in plans:
        conds = {c['id']:c for c in p['conditions']}
        for q in p['questions']:
            if q['id'] not in p['selection']['selected_question_ids']: continue
            signature = json.dumps([q['text'], q['target'], sorted(
                (conds[m['condition_id']]['predicate'], json.dumps(m['answers'], sort_keys=True))
                for m in q['mappings'] if approved(m) and m['coverage'] == 'FULL')], ensure_ascii=False, sort_keys=True)
            shared[signature].append(dict(cve=p['cve'], question_id=q['id'], cluster_id=p['cluster_id']))
    write_json(output/'question_reuse.json', [dict(signature=hashlib.sha256(k.encode()).hexdigest(), members=v,
        shared=len({m['cve'] for m in v}) > 1, runtime_rule='Reuse answers only within identical asset/product/build/configuration/mode and validity period')
        for k,v in shared.items()])
    plan_byid = {p['cve']:p for p in plans}
    cases = read_rows(args.cases) if args.cases else []
    results = []
    for case in cases:
        cve = case['binding']['cve']
        if cve not in plan_byid: raise ValueError('Asset case outside population')
        results.append(evaluate_review(plan_byid[cve], case))
    write_jsonl(output/'asset_decisions.jsonl', results)
    statuses = Counter(r['status'] for r in results)
    # Missing operator scope is not silently turned into an asset-specific VEX.
    write_jsonl(output/'population_readiness.jsonl', [dict(cve=p['cve'], assessment_status='awaiting_asset_evidence',
        vex_status=None, formula_reviewed=bool(p.get('formula') and approved(p['formula']))) for p in plans])
    summary = dict(population=len(records), selected_k=chosen['k'], stable_candidate_exists=stable,
        candidate_conditions=sum(len(p['conditions']) for p in plans),
        approved_conditions=sum(approved(c) for p in plans for c in p['conditions']),
        approved_formulas=sum(bool(p.get('formula') and approved(p['formula'])) for p in plans),
        selected_question_count=sum(len(p['selection']['selected_question_ids']) for p in plans),
        cves_requiring_review=len(queue), asset_cases=len(cases), asset_vex_statuses=dict(statuses),
        semantic_extraction_complete=bool(len(semantic)==len(records) and all(s.get('all_packets_read') for s in semantic.values())),
        sentence_transformer_embeddings_complete=bool(args.embeddings),
        extraction_precision=None, not_affected_precision=None,
        evaluation_note='No accuracy claim without independent expert truth and asset scenarios',
        generated_at=datetime.now(timezone.utc).isoformat(), input_hashes=fingerprint,
        implementation_hashes={p:sha(ROOT/p) for p in ['tools/build_context_vex_pipeline.py','src/context_vex_pipeline.py']})
    write_json(output/'summary.json', summary)
    # A portable report links to every reproducible intermediate artifact.
    links = ['summary.json','cluster_metrics.json','clusters.json','assignments.jsonl','review_contracts.jsonl',
             'questionnaires.jsonl','question_reuse.json','review_queue.jsonl','asset_decisions.jsonl']
    report = '<!doctype html><html lang="ko"><meta charset="utf-8"><title>ICS 운영 맥락 VEX 전수 파이프라인</title><style>body{font:16px/1.7 system-ui;max-width:1000px;margin:40px auto;padding:24px}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>ICS 운영 맥락 VEX 전수 파이프라인</h1><p>군집은 질문 재사용 후보입니다. 검토된 CVE별 조건·논리식과 자산 증거가 있어야 VEX를 평가합니다.</p>'
    report += '<p>모집단 '+str(len(records))+'개 · 탐색 군집 '+str(chosen['k'])+'개 · 검토 대기 '+str(len(queue))+'개</p>'
    report += '<p>자동 의미 추출 및 전문가 검증은 완료되지 않았습니다. 기존 규칙 후보와 검토 완료 조건을 구분합니다.</p>'
    report += '<ul>'+''.join('<li><a href="'+name+'">'+name+'</a></li>' for name in links)+'</ul><pre>'+html.escape(json.dumps(summary, ensure_ascii=False, indent=2))+'</pre></html>'
    (output/'index.html').write_text(report, encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False, indent=2))


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inputs', default=str(ROOT/'results/ics_condition_semantic_full_v2/full_inputs.jsonl'))
    p.add_argument('--advisories', default=str(ROOT/'data/cisa_advisories.json'))
    p.add_argument('--candidates', default=str(ROOT/'results/ics_condition_evidence_v4/profiles.jsonl'))
    p.add_argument('--semantic', help='Optional source-linked model extraction JSONL; never silently substituted')
    p.add_argument('--reviews', help='Reviewed condition/question/formula contracts JSONL')
    p.add_argument('--cases', help='Scoped asset answers and evidence JSONL')
    p.add_argument('--output', default=str(ROOT/'results/ics_context_vex_pipeline_v1'))
    p.add_argument('--expected-population', type=int, default=12418)
    p.add_argument('--ks', type=int, nargs='+', default=[2,4,6,8,10,12,16,20,24,32,48,64,96,128,192,256])
    p.add_argument('--embeddings', help='Verified output directory from embed_context_cves.py')
    p.add_argument('--dimensions', type=int, default=128)
    p.add_argument('--reuse-clusters', action='store_true')
    return p


if __name__ == '__main__':
    run(parser().parse_args())
