"""Discover CVE text clusters without CWE, the old taxonomy, or VEX labels.

Offline research experiment; outputs are proposals for review, never production
taxonomy changes. Run with --help. Cached MPNet weights are used locally on CPU.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import html
import importlib.metadata
import json
from pathlib import Path
import re
import time

import numpy as np
from sklearn.cluster import MiniBatchKMeans
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS, TfidfVectorizer
from sklearn.metrics import adjusted_rand_score, silhouette_score
from sklearn.preprocessing import normalize
from threadpoolctl import threadpool_limits

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 'ics-unsupervised-discovery/1'
# A broad exploration grid, independent of the previous 17-family taxonomy.
DEFAULT_K = [2, 4, 6, 8, 10, 12, 16, 20, 24, 32, 40, 48, 64, 80, 96]
EXTRA_STOP = {'vulnerability', 'vulnerabilities', 'affected', 'affects', 'versions',
              'version', 'cve', 'cwe', 'https', 'http', 'www', 'com'}


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for part in iter(lambda: f.read(1024 * 1024), b''):
            h.update(part)
    return h.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')


def write_jsonl(path, rows):
    with Path(path).open('w', encoding='utf-8') as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False)+'\n')


def clean_description(text, profile='minimal'):
    """No weakness keyword lists, vendor lookup tables, CWE or old labels."""
    if profile == 'context':
        # Sensitivity experiment for nuisance templates found in the minimal run.
        # These are document-format rules, not vulnerability-family labels.
        text = re.sub(r'(?is)^a vulnerability has been identified in .{0,20000}?\)\.\s+', '', text.strip())
        text = re.sub(r'(?i)^in the linux kernel, the following vulnerability has been resolved:\s*', '', text)
        text = re.split(r'(?i)\b(?:call trace|backtrace|panic trace):', text, maxsplit=1)[0]
        text = re.sub(r'(?i)\(?\b(?:CVSS:\d[\d.]*|AV:[NALP])/[a-z0-9:/._-]+\)?', ' ', text)
        text = re.sub(r'(?i)\bCVSS\s*(?:(?:v(?:ersion)?\s*)?\d(?:\.\d+)?\s*)?(?:base\s*)?score(?:\s+of)?\s*:?\s*\d+(?:\.\d+)?', ' ', text)
        text = re.sub(r'(?i)\bCVSS\s*(?:v\d\s*)?(?:vector(?:\s+string)?|base score)\s*:?', ' ', text)
    elif profile != 'minimal':
        raise ValueError('Unknown text profile: '+profile)
    text = re.sub(r'https?://\S+', ' ', text.lower())
    text = re.sub(r'\b(?:cve-\d{4}-\d+|cwe-\d+)\b', ' ', text)
    text = re.sub(r'\b0x[0-9a-f]+\b', ' ', text)
    text = re.sub(r'\b[v]?\d+(?:[.\-]\d+)*(?:[a-z]\d*)?\b', ' ', text)
    return re.sub(r'\s+', ' ', text).strip()


def prepare(rows, text_profile='minimal'):
    """Fit one sample per identical normalized description; keep every CVE."""
    groups, excluded, seen = {}, [], set()
    for row in sorted(rows, key=lambda r: r['cve']):
        if row['cve'] in seen:
            raise ValueError('Duplicate CVE: '+row['cve'])
        seen.add(row['cve'])
        text = clean_description(row.get('description') or '', text_profile)
        reason = ('rejected' if str(row.get('nvd_status', '')).lower() == 'rejected'
                  else 'missing_description' if not text else None)
        if reason:
            excluded.append({'cve':row['cve'], 'reason':reason, 'vex_status':None})
        else:
            groups.setdefault(text, []).append(row)
    texts = sorted(groups)
    return texts, [groups[t] for t in texts], excluded


def fit_text(texts, dimensions=128):
    vectorizer = TfidfVectorizer(stop_words=sorted(ENGLISH_STOP_WORDS | EXTRA_STOP),
        ngram_range=(1, 2), min_df=2, max_df=.95, max_features=60000,
        sublinear_tf=True, dtype=np.float32, token_pattern=r'(?u)\b[a-z][a-z_]+\b')
    sparse = vectorizer.fit_transform(texts)
    if min(sparse.shape) < 3:
        raise ValueError('Too few informative documents/features')
    svd = TruncatedSVD(n_components=min(dimensions, min(sparse.shape)-1), random_state=42)
    latent = normalize(svd.fit_transform(sparse)).astype(np.float32)
    return vectorizer, sparse, latent, svd


def model_for(k, seed):
    return MiniBatchKMeans(n_clusters=k, random_state=seed, n_init=5,
        batch_size=1024, max_iter=150, max_no_improvement=20, reassignment_ratio=.005)


def choose_candidate(metrics):
    eligible = [m for m in metrics if m['eligible']]
    pool = eligible or metrics
    # Silhouette is an internal geometry criterion, not semantic ground truth.
    chosen = max(pool, key=lambda m: (m['silhouette_cosine'], -m['k']))
    return chosen['k'], bool(eligible)


def sweep(x, ks, output, label):
    rng = np.random.default_rng(42)
    sample = np.sort(rng.choice(len(x), min(2000, len(x)), replace=False))
    metrics, models = [], {}
    for k in ks:
        if k >= len(x):
            continue
        started = time.monotonic()
        model = model_for(k, 42).fit(x)
        labels = model.predict(x)
        counts = np.bincount(labels, minlength=k)
        sample_labels = labels[sample]
        silhouette = float(silhouette_score(x[sample], sample_labels, metric='cosine')) if 1 < len(set(sample_labels)) < len(sample) else -1.
        stability = []
        for seed in (43, 44):
            indices = np.random.default_rng(seed).choice(len(x), max(k+1, int(.8*len(x))), replace=False)
            other = model_for(k, seed).fit(x[indices]).predict(x)
            stability.append(float(adjusted_rand_score(labels, other)))
        metric = dict(k=k, silhouette_cosine=silhouette, stability_ari=stability,
            stability_ari_mean=float(np.mean(stability)), min_unique_size=int(counts.min()),
            max_unique_share=float(counts.max()/len(x)), realized_clusters=int(np.count_nonzero(counts)),
            inertia=float(model.inertia_), elapsed_seconds=round(time.monotonic()-started, 2))
        metric['eligible'] = bool(metric['stability_ari_mean'] >= .6 and counts.min() >= 10 and counts.max()/len(x) <= .5)
        metrics.append(metric)
        models[k] = (model, labels)
        write_json(output/'search_metrics.json', metrics)
        print(label, json.dumps(metric), flush=True)
    if not metrics:
        raise ValueError('No candidate cluster count is smaller than the dataset')
    k, passed = choose_candidate(metrics)
    return metrics, k, models[k], passed


def encode_mpnet(texts, output, model_path, threads):
    import torch
    from sentence_transformers import SentenceTransformer
    torch.set_num_threads(threads)
    model_path = Path(model_path).resolve()
    fingerprint = {p.name:sha(p) for p in model_path.iterdir()
                   if p.is_file() and p.suffix in {'.json', '.safetensors', '.txt'}}
    metadata = dict(model='sentence-transformers/all-mpnet-base-v2', local_revision=model_path.name,
        model_files_sha256=fingerprint, device='cpu', fine_tuned_on_this_corpus=False,
        text_sha256=hashlib.sha256('\n'.join(texts).encode()).hexdigest())
    cache, meta_file = output/'mpnet_embeddings.npy', output/'mpnet_embedding_metadata.json'
    if cache.exists() and meta_file.exists():
        old = json.loads(meta_file.read_text(encoding='utf-8'))
        if all(old.get(k) == v for k, v in metadata.items()) and old.get('embedding_sha256') == sha(cache):
            print('Reuse verified MPNet embedding cache', flush=True)
            return np.load(cache), old
    model = SentenceTransformer(str(model_path), device='cpu', local_files_only=True)
    # Preserve the model default rather than silently shortening CVE evidence.
    metadata['max_seq_length'] = model.max_seq_length
    lengths = [len(ids) for ids in model.tokenizer(texts, truncation=False, padding=False)['input_ids']]
    metadata['truncated_unique_descriptions'] = sum(n > model.max_seq_length for n in lengths)
    metadata['unique_descriptions'] = len(texts)
    pieces = []
    for start in range(0, len(texts), 256):
        pieces.append(model.encode(texts[start:start+256], batch_size=16, normalize_embeddings=True,
                                   show_progress_bar=False, convert_to_numpy=True))
        print('MPNet embeddings', min(start+256, len(texts)), '/', len(texts), flush=True)
    x = np.concatenate(pieces).astype(np.float32)
    np.save(cache, x)
    metadata['embedding_sha256'] = sha(cache)
    write_json(meta_file, metadata)
    return x, metadata


def export_clusters(output, texts, groups, vectorizer, sparse, x, labels, model, seed=42):
    names = vectorizer.get_feature_names_out()
    center_similarity = x @ normalize(model.cluster_centers_).T
    order = np.argsort(-center_similarity, axis=1)
    own = center_similarity[np.arange(len(x)), labels]
    alternate = np.where(order[:, 0] == labels, order[:, 1], order[:, 0])
    margins = own-center_similarity[np.arange(len(x)), alternate]
    nearest = order[:, 0]
    assignments, clusters, review = [], [], []
    rng = np.random.default_rng(seed)
    for label in sorted(set(labels)):
        indices = np.flatnonzero(labels == label)
        mean = np.asarray(sparse[indices].mean(axis=0)).ravel()
        top = names[np.argsort(-mean)[:15]].tolist()
        core = indices[np.argsort(-own[indices])[:3]].tolist()
        boundary = [int(i) for i in indices[np.argsort(margins[indices])] if int(i) not in core][:3]
        remaining = [int(i) for i in indices if int(i) not in core+boundary]
        random = rng.choice(remaining, min(3, len(remaining)), replace=False).tolist() if remaining else []
        cvcount = sum(len(groups[i]) for i in indices)
        cluster = dict(cluster_id=int(label), unique_descriptions=len(indices), cve_count=cvcount,
            top_terms=top, proposed_descriptor=' / '.join(top[:5]), semantic_label=None,
            review_status='pending', centroid_similarity_mean=float(own[indices].mean()),
            non_nearest_centroid_count=int(sum(nearest[indices] != label)), samples=[])
        for category, selected in [('representative',core), ('boundary',boundary), ('random',random)]:
            for i in selected:
                row = groups[i][0]
                sample = dict(cluster_id=int(label), sample_type=category, cve=row['cve'],
                    description=row['description'], normalized_description=texts[i],
                    same_description_cves=[r['cve'] for r in groups[i]],
                    advisory_ids=row.get('advisory_ids',[]), references=row.get('references',[]),
                    centroid_similarity=float(own[i]), margin=float(margins[i]),
                    alternative_cluster=int(alternate[i]), reviewer_label=None,
                    operational_questions=[], missing_conditions=[], merge_or_split=None,
                    reviewer=None, review_status='pending', vex_status=None)
                cluster['samples'].append(sample)
                review.append(sample)
        clusters.append(cluster)
    for i, group in enumerate(groups):
        for row in group:
            assignments.append(dict(cve=row['cve'], cluster_id=int(labels[i]),
                text_sha256=hashlib.sha256(texts[i].encode()).hexdigest(),
                centroid_similarity=float(own[i]), margin=float(margins[i]),
                alternative_cluster=int(alternate[i]), review_required=True, vex_status=None))
    assignments.sort(key=lambda r: r['cve'])
    write_jsonl(output/'assignments.jsonl', assignments)
    write_json(output/'clusters.json', clusters)
    write_jsonl(output/'review_queue.jsonl', review)
    # Metadata is introduced only AFTER fitting and selecting k.
    cross = defaultdict(Counter)
    for i, group in enumerate(groups):
        for row in group:
            cross[int(labels[i])].update(row.get('cwes') or ['not_reported'])
    write_json(output/'reported_cwe_posthoc.json', {str(k):dict(v) for k,v in cross.items()})
    safe = html.escape
    parts = ['<!doctype html><meta charset="utf-8"><title>Unsupervised CVE cluster review</title>',
        '<style>body{font:16px/1.6 system-ui;max-width:1100px;margin:32px auto;padding:16px}details{border:1px solid #ccc;padding:12px;margin:12px 0}blockquote{white-space:pre-wrap;overflow-wrap:anywhere}small{color:#555}</style>',
        '<h1>비지도 CVE 군집 검토</h1><p>자동 발견한 설명문 군집입니다. 유형 명칭·운영 질문·VEX 상태는 확정되지 않았습니다. 대표·경계·무작위 사례를 함께 검토합니다.</p>']
    for c in clusters:
        parts.append(f'<details><summary>Cluster {c["cluster_id"]}: {c["cve_count"]} CVEs · {safe(c["proposed_descriptor"])}</summary>')
        parts.append('<p>'+safe(', '.join(c['top_terms']))+'</p>')
        for s in c['samples']:
            parts.append(f'<h3>{safe(s["cve"])} · {s["sample_type"]}</h3><blockquote>{safe(s["description"])}</blockquote><small>margin={s["margin"]:.4f}; alternative={s["alternative_cluster"]}</small>')
        parts.append('</details>')
    (output/'review.html').write_text('\n'.join(parts), encoding='utf-8')
    return clusters, assignments


def plot_search(output, metrics):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    for ax, field, title in zip(axes, ['silhouette_cosine','stability_ari_mean'], ['Cosine silhouette (fixed sample)','Stability ARI (80% subsampling)']):
        ax.plot([m['k'] for m in metrics], [m[field] for m in metrics], marker='o')
        ax.set(xlabel='Candidate cluster count', ylabel=title, title=title)
        ax.grid(alpha=.25)
    fig.tight_layout()
    fig.savefig(output/'cluster_search.png', dpi=180)
    plt.close(fig)


def run(args):
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = Path(args.source).resolve()
    rows = [json.loads(line) for line in source.read_text(encoding='utf-8').splitlines() if line.strip()]
    texts, groups, excluded = prepare(rows, getattr(args, 'text_profile', 'minimal'))
    ks = sorted(set(int(k) for k in args.k.split(',')))
    if not ks or min(ks) < 2:
        raise ValueError('Candidate k must be at least 2')
    write_jsonl(output/'excluded.jsonl', excluded)
    protocol = dict(schema=SCHEMA, created_at=datetime.now(timezone.utc).isoformat(),
        source=str(source), source_sha256=sha(source), script_sha256=sha(__file__),
        total_cves=len(rows), included_cves=sum(map(len, groups)), unique_descriptions=len(texts),
        text_profile=getattr(args, 'text_profile', 'minimal'), threads=args.threads,
        excluded_reasons=dict(Counter(r['reason'] for r in excluded)),
        training_fields=['normalized_description'], excluded_training_fields=['cwe','old_17_families','cvss','vendor_metadata','vex_status'],
        deduplication='One equal-weight observation per identical normalized description; map all CVEs back afterwards',
        candidate_k=ks, random_seeds=[42,43,44], stability='Train two additional 80% subsamples; ARI against full fit on all unique descriptions',
        selection='Highest cosine silhouette on a fixed uniform sample of <=2000 unique descriptions among eligible candidates; otherwise provisional highest with failed-gate warning',
        eligibility=dict(min_mean_ari=.6, min_unique_cluster_size=10, max_unique_cluster_share=.5),
        thresholds_status='Exploratory declared engineering criteria, not validated statistical cutoffs',
        semantic_validation='pending', production_taxonomy_modified=False, emits_vex_status=False,
        versions={name:importlib.metadata.version(name) for name in ['scikit-learn','numpy','scipy','sentence-transformers','torch']},
        references=['https://scikit-learn.org/stable/auto_examples/text/plot_document_clustering.html',
                    'https://huggingface.co/sentence-transformers/all-mpnet-base-v2'])
    write_json(output/'protocol.json', protocol)
    with threadpool_limits(limits=args.threads):
        vectorizer, sparse, latent, svd = fit_text(texts)
        summary = dict(protocol=protocol, experiments=[])
        for representation in args.representations.split(','):
            dest = output/representation
            dest.mkdir(exist_ok=True)
            if representation == 'tfidf_lsa':
                x = latent
                metadata = dict(features=int(sparse.shape[1]), dimensions=int(x.shape[1]),
                                explained_variance=float(svd.explained_variance_ratio_.sum()))
            elif representation == 'mpnet':
                if not args.model_path:
                    raise ValueError('MPNet requires an explicit locally cached --model-path')
                x, metadata = encode_mpnet(texts, output, args.model_path, args.threads)
            else:
                raise ValueError('Unknown representation: '+representation)
            metrics, k, (model, labels), eligible = sweep(x, ks, dest, representation)
            clusters, assignments = export_clusters(dest, texts, groups, vectorizer, sparse, x, labels, model)
            plot_search(dest, metrics)
            np.savez_compressed(dest/'fitted_cluster_centers.npz', centers=model.cluster_centers_)
            result = dict(representation=representation, selected_k=k, eligibility_passed=eligible,
                selected_at_search_boundary=k in {min(ks),max(ks)}, selected_metric=next(m for m in metrics if m['k']==k),
                metadata=metadata, clustered_cves=len(assignments), reviewed_cluster_count=0,
                review_queue_size=sum(len(c['samples']) for c in clusters),
                interpretation='Exploratory text grouping; selected k is not a validated number of vulnerability types')
            write_json(dest/'summary.json', result)
            summary['experiments'].append(result)
            write_json(output/'summary.json', summary)
        manifest = {str(p.relative_to(output)):sha(p) for p in output.rglob('*') if p.is_file() and p.name != 'manifest.json'}
        write_json(output/'manifest.json', dict(schema=SCHEMA, files=manifest))
    print(json.dumps(summary, ensure_ascii=True, indent=2), flush=True)
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', default=str(ROOT/'data/item3_ics_cert_full_v1/cves.jsonl'))
    parser.add_argument('--output', default=str(ROOT/'results/ics_unsupervised_v1'))
    parser.add_argument('--k', default=','.join(map(str, DEFAULT_K)))
    parser.add_argument('--representations', default='tfidf_lsa,mpnet')
    parser.add_argument('--model-path')
    parser.add_argument('--threads', type=int, default=4)
    parser.add_argument('--text-profile', choices=['minimal','context'], default='minimal')
    run(parser.parse_args())
