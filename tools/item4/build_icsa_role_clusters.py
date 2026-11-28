"""Cluster advisories first; project their explicit CVE links without changing VEX."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from collections import Counter, defaultdict
import csv
import hashlib
import json
import re

import numpy as np
from scipy.sparse import csr_matrix
from sklearn.cluster import KMeans
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import normalize
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.metrics import silhouette_samples

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'results/icsa_role_clusters_k18'
# These are lexical evidence features, not assignments to MITRE asset types.
ROLE_PATTERNS = {
    'HMI': r'\bhuman[ -]machine interfaces?\b|\bHMI\b',
    'PLC': r'\bprogrammable logic controllers?\b|\bPLCs?\b',
    'RTU': r'\bremote terminal units?\b|\bRTUs?\b',
    'DCS': r'\bdistributed control systems?\b|\bDCS\b',
    'SCADA': r'\bsupervisory control and data acquisition\b|\bSCADA\b',
    'Safety control': r'\bsafety (?:controllers?|systems?|relays?)\b',
    'Protection relay': r'\bprotection relays?\b|\bprotective relays?\b|\bIEDs?\b|\bintelligent electronic devices?\b',
    'PAC': r'\bprogrammable automation controllers?\b|\bPACs?\b',
    'Field I/O': r'\b(?:remote|field|distributed) I/?O\b|\binput/output modules?\b',
    'Engineering tools': r'\bengineering (?:tools?|software|workstations?|systems?)\b|\bprogramming (?:tools?|software)\b',
    'Workstation': r'\bworkstations?\b',
    'Historian': r'\bhistorians?\b',
    'Gateway': r'\bgateways?\b',
    'Protocol conversion': r'\bprotocol (?:converters?|conversion|translators?|translation)\b',
    'Router': r'\brouters?\b',
    'Network switch': r'\b(?:ethernet|network|industrial|managed|unmanaged) switches?\b',
    'Firewall': r'\bfirewalls?\b',
    'VPN': r'\bVPN\b|\bvirtual private network\b',
    'Remote access': r'\bremote (?:access|desktop|maintenance)\b|\bjump hosts?\b',
    'Control server': r'\bcontrol servers?\b',
    'Application server': r'\bapplication servers?\b',
    'Web server': r'\bweb servers?\b',
    'Database': r'\bdatabases?\b',
    'Monitoring': r'\bmonitoring (?:software|systems?|devices?|platforms?)\b',
    'Building automation': r'\bbuilding (?:automation|management)\b',
    'Drive / motion': r'\b(?:servo|motor|variable frequency) drives?\b|\bmotion controllers?\b|\bVFDs?\b',
    'Robot': r'\brobots?\b|\brobotics\b',
    'Meter': r'\b(?:smart|power|energy|electricity) meters?\b',
    'Camera': r'\bcameras?\b|\bvideo surveillance\b',
    'Wireless': r'\bwireless (?:access points?|devices?|gateways?|routers?)\b',
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def product_names(tree):
    """Read declared product names, never security impact or mitigation prose."""
    names = []
    for branch in tree.get('branches', []):
        if branch.get('category') in {'product_name', 'product_family'}:
            names.append(branch['name'])
        names.extend(product_names(branch))
    return names


def features(parts):
    evidence = []
    for field, text in parts:
        for role, pattern in ROLE_PATTERNS.items():
            match = re.search(pattern, text, re.I)
            if match:
                evidence.append(dict(role=role, field=field, text=text,
                                     quote=match.group(), span=[match.start(), match.end()]))
    return sorted({e['role'] for e in evidence}), evidence


def function_sentences(text):
    """Conservative declarative function candidates; retain the exact source text."""
    # Overview snapshots can contain the entire advisory, including boilerplate.
    text = re.split(r'\b(?:MITIGATIONS?|RECOMMENDATIONS?|RECOMMENDED PRACTICES)\b', text)[0]
    for sentence in re.split(r'(?<=[.!?])\s+|[\r\n]+', text):
        if not 15 <= len(sentence) <= 1200:
            continue
        if re.search(r'\b(?:vulnerab\w*|attack\w*|exploit\w*|mitigat\w*|recommend\w*|should|could|CVE|CWE|CVSS|malicious|patch\w*|unauthorized|buffer|overflow|disclosure|secure|security|recogniz\w*|required|never|ensure|disable|restrict|CISA|ICS-CERT|shall|if|users?|filters?|affected|versions?|measures|place|apply|traffic)\b', sentence, re.I):
            continue
        if re.search(r'\b(?:(?:is|are) (?:a|an|the)|provides?|used (?:to|for)|designed (?:to|for)|offers?|supports?)\b', sentence, re.I) and any(
                re.search(pattern, sentence, re.I) for pattern in ROLE_PATTERNS.values()):
            yield sentence


def build():
    OUT.mkdir(parents=True, exist_ok=True)
    inputs = {}
    index_path = ROOT/'site/advisories_list.json'
    population_path = ROOT/'cve_clusters_cisa_context_svd16.csv'
    index = json.loads(index_path.read_text(encoding='utf-8'))['advisories']
    with population_path.open(encoding='utf-8-sig', newline='') as f:
        population = list(csv.DictReader(f))
    cve_ids = {r['cve'] for r in population}
    assert len(cve_ids) == len(population) == 12418
    inputs['site/advisories_list.json'] = sha(index_path)
    inputs[population_path.name] = sha(population_path)
    by_id = {a['id']: a for a in index}
    links = defaultdict(set)
    for row in population:
        for aid in filter(None, row['cisa_advisory_ids'].split('|')):
            assert aid in by_id, aid
            links[aid].add(row['cve'])
    # Also retain the explicit advisory-index links inside the fixed CVE population.
    for a in index:
        links[a['id']].update(set(a.get('cves', [])) & cve_ids)
    records = []
    details = {}
    for path in sorted((ROOT/'site').glob('advisory_details_*.json')):
        details.update(json.loads(path.read_text(encoding='utf-8')))
        inputs[path.relative_to(ROOT).as_posix()] = sha(path)
    for a in sorted(index, key=lambda a: a['id']):
        path = ROOT/'icsa/csaf'/f"{a['id']}.json"
        parts = [('advisory_title', a['title'])]
        parts += [('advisory_function_sentence', text) for text in function_sentences(details.get(a['id'], {}).get('overview', ''))]
        if path.is_file():
            value = json.loads(path.read_text(encoding='utf-8-sig'))
            inputs[path.relative_to(ROOT).as_posix()] = sha(path)
            parts += [('csaf_product_name', name) for name in sorted(set(product_names(value.get('product_tree', {}))))]
            links[a['id']].update({v.get('cve') for v in value.get('vulnerabilities', [])} & cve_ids)
        parts = list(dict.fromkeys(parts))
        roles, evidence = features(parts)
        records.append(dict(id=a['id'], title=a['title'], url=a['url'],
            cves=sorted(links[a['id']]), roles=roles, evidence=evidence,
            source_status='csaf_available' if path.is_file() else 'advisory_index_only',
            assignment_basis='explicit_role_phrase' if roles else 'product_title_fallback',
            uncertain=not bool(roles),
            feature_text=' '.join(dict.fromkeys(text for _, text in parts))))
    # Similar products may supply provisional role estimates, never source evidence.
    # All advisories then participate in the same role-space K-means fit.
    role_names = list(ROLE_PATTERNS)
    roles = csr_matrix([[float(role in r['roles']) for role in role_names] for r in records])
    lexical = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=12000,
        sublinear_tf=True, stop_words='english')
    texts = [re.sub(r'\b(?:CVE-\d{4}-\d+|ICSA-\S+|CWE-\d+)\b', ' ', r['feature_text'], flags=re.I) for r in records]
    context = lexical.fit_transform(texts)
    role_vectors = normalize(roles).toarray()
    supported = np.array([i for i, r in enumerate(records) if r['roles']])
    missing = np.array([i for i, r in enumerate(records) if not r['roles']])
    similarities = cosine_similarity(context[missing], context[supported])
    prior = role_vectors[supported].mean(axis=0)
    for local, index in enumerate(missing):
        nearest = np.argsort(-similarities[local], kind='stable')[:5]
        donors = [j for j in nearest if similarities[local, j] >= 0.15]
        if donors:
            weights = similarities[local, donors]
            role_vectors[index] = np.average(role_vectors[supported[donors]], axis=0, weights=weights)
            records[index]['role_estimate_basis'] = 'similar_product_context'
            records[index]['role_estimate_donors'] = [dict(advisory_id=records[supported[j]]['id'],
                cosine_similarity=round(float(similarities[local, j]), 6)) for j in donors]
        else:
            role_vectors[index] = prior
            records[index]['role_estimate_basis'] = 'corpus_role_prior_no_similar_donor'
            records[index]['role_estimate_donors'] = []
        records[index]['assignment_basis'] = records[index]['role_estimate_basis']
    role_matrix = normalize(role_vectors)
    for i, r in enumerate(records):
        r['role_vector'] = {name: round(float(role_matrix[i, j]), 6) for j, name in enumerate(role_names) if role_matrix[i, j] > 0}
    # Final partition uses source-text TF-IDF, not imputed role vectors or priors.
    selected_path = OUT/'tfidf_svd_search/best.json'
    selected = json.loads(selected_path.read_text(encoding='utf-8'))
    candidates = json.loads((OUT/'tfidf_svd_search/search.json').read_text(encoding='utf-8'))
    assert len(candidates)==42 and all(c['n']==3881 and c['k']==18 for c in candidates)
    assert selected == max(candidates, key=lambda c:c['full_svd_cosine_silhouette'])
    cluster_vectorizer = TfidfVectorizer(ngram_range=tuple(selected['ngrams']), min_df=1,
        max_features=20000, sublinear_tf=True, stop_words='english', dtype=np.float32)
    matrix = cluster_vectorizer.fit_transform(texts)
    zero_rows = matrix.getnnz(axis=1)==0
    for i, record in enumerate(records):
        record['tfidf_feature_status'] = 'zero_vector' if zero_rows[i] else 'observed_text_features'
        if zero_rows[i]:
            record['uncertain'] = True
    svd = TruncatedSVD(n_components=selected['dimensions'], random_state=42)
    reduced = normalize(svd.fit_transform(matrix))
    model = KMeans(n_clusters=18, random_state=selected['seed'], n_init=10, max_iter=500)
    labels = model.fit_predict(reduced)
    assert len(set(labels)) == 18
    native_scores = silhouette_samples(reduced, labels, metric='cosine')
    original_scores = silhouette_samples(matrix, labels, metric='cosine')
    assert float(native_scores.mean()) > 0.5, 'Full-population target not achieved'
    assert abs(float(native_scores.mean())-selected['full_svd_cosine_silhouette']) < 1e-6
    metrics = dict(population=len(records), metric='cosine', full_population=True,
        svd_cosine_silhouette=float(native_scores.mean()),
        original_tfidf_cosine_silhouette=float(original_scores.mean()),
        svd_explained_variance=float(svd.explained_variance_ratio_.sum()),
        negative_silhouette_advisories=int((native_scores<0).sum()),
        zero_tfidf_rows=int(zero_rows.sum()),
        unique_feature_documents=len(set(texts)),
        svd_dimensions=selected['dimensions'], selection_candidates=42,
        selection_policy='Maximum full-population SVD-space cosine silhouette among the recorded 42 candidates; K fixed at 18.',
        independent_accuracy_validated=False)
    np.savez_compressed(OUT/'projection.npz', reduced=reduced, labels=labels,
        components=svd.components_, centroids=model.cluster_centers_,
        native_silhouettes=native_scores, original_silhouettes=original_scores)
    # Canonicalize numbering by stable advisory membership, rather than K-means label order.
    remap = {old: f'ICSA-G{i+1:02}' for i, old in enumerate(sorted(set(labels),
        key=lambda label: min(r['id'] for r, v in zip(records, labels) if v == label)))}
    for r, label in zip(records, labels):
        r['group_id'] = remap[label]
    distances = model.transform(reduced)
    ordered = np.sort(distances, axis=1)
    for i, r in enumerate(records):
        r['distance_to_centroid'] = round(float(distances[i, labels[i]]), 6)
        r['centroid_margin'] = round(float(ordered[i, 1]-ordered[i, 0]), 6)
        r['assignment_basis'] = 'source_text_tfidf_svd'
        r['svd_cosine_silhouette'] = round(float(native_scores[i]), 6)
        # A centroid tie remains uncertain even when a phrase was observed.
        r['uncertain'] = r['uncertain'] or r['centroid_margin'] < 0.05
    groups = []
    for gid in sorted(remap.values()):
        members = [r for r in records if r['group_id'] == gid]
        counts = Counter(role for r in members for role in r['roles'])
        weights = Counter()
        for r in members:
            weights.update(r['role_vector'])
        top = [role for role, _ in weights.most_common(3)]
        group_cves = sorted({c for r in members for c in r['cves']})
        fallback_count = sum(not r['roles'] for r in members)
        prior_count = sum(r.get('role_estimate_basis')=='corpus_role_prior_no_similar_donor' for r in members)
        # Source-text clusters may follow vendors/products. Never call these verified roles.
        indices = [i for i, r in enumerate(records) if r['group_id']==gid]
        term_weights = np.asarray(matrix[indices].mean(axis=0)).ravel()
        vocabulary = cluster_vectorizer.get_feature_names_out()
        keywords = []
        for i in np.argsort(term_weights)[::-1]:
            term = vocabulary[i]
            if term_weights[i] > 0 and not any(term in t or t in term for t in keywords):
                keywords.append(term)
            if len(keywords)==3:
                break
        if fallback_count > len(members)/2:
            name = ' / '.join(keywords)+' · role unverified'
        else:
            name = ' / '.join(top)
        groups.append(dict(id=gid, name=name, keywords=keywords,
            mean_svd_cosine_silhouette=float(native_scores[indices].mean()),
            role_counts=dict(counts.most_common()), role_vector_totals=dict(weights.most_common()), advisory_ids=[r['id'] for r in members],
            advisory_count=len(members), cves=group_cves, cve_count=len(group_cves),
            uncertain_advisories=sum(r['uncertain'] for r in members),
            fallback_advisories=fallback_count, prior_only_advisories=prior_count))
    memberships = defaultdict(list)
    for r in records:
        for cve in r['cves']:
            memberships[cve].append(dict(advisory_id=r['id'], group_id=r['group_id'], uncertain=r['uncertain']))
    assert set(memberships) == cve_ids
    assert len(records) == len(by_id) == 3881
    summary = dict(advisories=len(records), clusters=18, cves=len(cve_ids),
        advisory_cve_links=sum(len(r['cves']) for r in records),
        multiple_group_cves=sum(len({m['group_id'] for m in rows}) > 1 for rows in memberships.values()),
        fallback_advisories=sum(not r['roles'] for r in records),
        prior_only_advisories=sum(r.get('role_estimate_basis')=='corpus_role_prior_no_similar_donor' for r in records),
        uncertain_advisories=sum(r['uncertain'] for r in records),
        cves_only_uncertain_links=sum(all(m['uncertain'] for m in rows) for rows in memberships.values()),
        unlinked_cves=0, unassigned_advisories=0, independent_accuracy_validated=False)
    method = dict(algorithm='ICSA source text → TF-IDF → SVD → L2 normalization → K-means',
        k=18, random_state=selected['seed'], svd_random_state=42, n_init=10,
        svd_dimensions=selected['dimensions'], ngram_range=selected['ngrams'], min_df=1,
        max_features=20000, sublinear_tf=True, dtype='float32',
        role_annotations_only=True, neighbors=5, min_donor_cosine=0.15,
        uncertainty='No explicit role phrase, or nearest/second-nearest centroid distance margin < 0.05.',
        limitations=['Similar product/title context does not prove identical function; role estimates are uncertain.',
            'Role estimates and corpus priors are retained as uncertain annotations only; they are not used for the new partition.',
            'SVD-space silhouette can exceed original TF-IDF separation, and source text can cluster by vendor/product rather than function.',
            'Zero-feature advisories remain in fitting, scoring, and the final partition with an explicit uncertainty flag; no features are invented.',
            'Role phrases may denote overlapping or ambiguous roles; no independent semantic accuracy validation.',
            'ICSA membership does not establish a CVE affected asset role, prerequisite, or VEX status.'])
    output = dict(version='icsa-role-k18/2', summary=summary, method=method, metrics=metrics,
                  groups=groups, advisories=records, cve_memberships=dict(sorted(memberships.items())))
    encoded = json.dumps(output, ensure_ascii=False, separators=(',', ':'))+'\n'
    (OUT/'groups.json').write_text(encoded, encoding='utf-8')
    (ROOT/'site/asset_vulntology/icsa_role_groups.json').write_text(encoded, encoding='utf-8')
    with (OUT/'icsa_clusters.csv').open('w', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f); writer.writerow(['advisory_id','group_id','roles','uncertain','assignment_basis','cve_count'])
        writer.writerows([r['id'],r['group_id'],'|'.join(r['roles']),r['uncertain'],r['assignment_basis'],len(r['cves'])] for r in records)
    with (OUT/'cve_cluster_memberships.csv').open('w', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f);writer.writerow(['cve','group_id','advisory_id','uncertain'])
        writer.writerows([cve,m['group_id'],m['advisory_id'],m['uncertain']] for cve, rows in sorted(memberships.items()) for m in rows)
    manifest = dict(summary=summary, method=method, metrics=metrics, input_sha256=inputs,
        builder_sha256=sha(Path(__file__)), groups_sha256=sha(OUT/'groups.json'),
        svd_explained_variance=float(svd.explained_variance_ratio_.sum()))
    import sklearn, scipy
    manifest['package_versions'] = dict(numpy=np.__version__,scipy=scipy.__version__,sklearn=sklearn.__version__)
    manifest['search_sha256'] = sha(OUT/'tfidf_svd_search/search.json')
    manifest['selected_settings_sha256'] = sha(selected_path)
    manifest['projection_sha256'] = sha(OUT/'projection.npz')
    (OUT/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=True))


if __name__ == '__main__':
    build()
