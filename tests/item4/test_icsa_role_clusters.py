import csv
import hashlib
import json
from pathlib import Path

from tools.item4.build_icsa_role_clusters import features, function_sentences, product_names

ROOT = Path(__file__).resolve().parents[2]


def test_function_candidates_exclude_mitigation_and_vulnerability_context():
    rejected = [
        'When remote access is required, use more secure methods, such as VPNs.',
        'Also recognize VPN is only as secure as its connected devices.',
        'Place remote access systems used for remote control system access outside the control network.',
        'If remote access to a system is a customer requirement, the system shall operate behind a firewall.',
        'A PLC is affected by a buffer overflow vulnerability.',
    ]
    for text in rejected:
        assert list(function_sentences(text)) == []
    text = 'ClearSCADA is an integrated SCADA host platform that includes a historian and web server.'
    assert list(function_sentences(text)) == [text]
    assert list(function_sentences('MITIGATION '+text)) == []


def test_role_phrases_preserve_source_quotes_and_multiple_roles():
    text = 'HMI and PLC engineering software'
    roles, evidence = features([('advisory_title', text)])
    assert {'HMI', 'PLC', 'Engineering tools'} <= set(roles)
    for e in evidence:
        assert text[slice(*e['span'])] == e['quote']


def test_full_population_advisory_partition_and_cve_projection():
    data = json.loads((ROOT/'site/asset_vulntology/icsa_role_groups.json').read_text(encoding='utf-8'))
    index = json.loads((ROOT/'site/advisories_list.json').read_text(encoding='utf-8'))['advisories']
    with (ROOT/'cve_clusters_cisa_context_svd16.csv').open(encoding='utf-8-sig', newline='') as f:
        population = list(csv.DictReader(f))
    assert len(data['groups']) == data['method']['k'] == 18
    advisories = {r['id']: r for r in data['advisories']}
    assert set(advisories) == {a['id'] for a in index}
    assert len(advisories) == 3881
    assert set(data['cve_memberships']) == {r['cve'] for r in population}
    for group in data['groups']:
        members = [advisories[aid] for aid in group['advisory_ids']]
        assert members
        assert all(a['group_id'] == group['id'] for a in members)
        assert set(group['cves']) == {cve for a in members for cve in a['cves']}
        assert group['cve_count'] == len(set(group['cves']))
    # Every original relationship survives; no primary-cluster collapse.
    for row in population:
        expected = set(filter(None, row['cisa_advisory_ids'].split('|')))
        actual = {m['advisory_id'] for m in data['cve_memberships'][row['cve']]}
        assert expected <= actual
    for cve, memberships in data['cve_memberships'].items():
        for m in memberships:
            a = advisories[m['advisory_id']]
            assert cve in a['cves'] and m['group_id'] == a['group_id']
            assert m['uncertain'] == a['uncertain']
    for a in advisories.values():
        assert a['assignment_basis'] == 'source_text_tfidf_svd'
        if not a['roles']:
            assert a['uncertain'] and a['role_estimate_basis'] in {'similar_product_context','corpus_role_prior_no_similar_donor'}
            for donor in a['role_estimate_donors']:
                assert advisories[donor['advisory_id']]['roles']
                assert donor['cosine_similarity'] >= 0.15
        for e in a['evidence']:
            assert e['text'][slice(*e['span'])] == e['quote']


def test_evidence_text_is_present_in_owning_advisory_snapshot():
    data = json.loads((ROOT/'site/asset_vulntology/icsa_role_groups.json').read_text(encoding='utf-8'))
    index = {a['id']:a for a in json.loads((ROOT/'site/advisories_list.json').read_text(encoding='utf-8'))['advisories']}
    details = {}
    for path in (ROOT/'site').glob('advisory_details_*.json'):
        details.update(json.loads(path.read_text(encoding='utf-8')))
    for a in data['advisories']:
        for e in a['evidence']:
            if e['field'] == 'advisory_title':
                assert e['text'] == index[a['id']]['title']
            elif e['field'] == 'advisory_function_sentence':
                assert e['text'] in details[a['id']]['overview']
            else:
                csaf = json.loads((ROOT/'icsa/csaf'/f"{a['id']}.json").read_text(encoding='utf-8-sig'))
                assert e['text'] in product_names(csaf.get('product_tree', {}))


def test_published_snapshot_and_manifest_match():
    generated = ROOT/'results/icsa_role_clusters_k18/groups.json'
    assert generated.read_bytes() == (ROOT/'site/asset_vulntology/icsa_role_groups.json').read_bytes()
    manifest = json.loads((generated.parent/'manifest.json').read_text(encoding='utf-8'))
    assert hashlib.sha256(generated.read_bytes()).hexdigest() == manifest['groups_sha256']
    for relative, digest in manifest['input_sha256'].items():
        assert hashlib.sha256((ROOT/relative).read_bytes()).hexdigest() == digest


def test_full_population_silhouette_is_reproducible_and_above_target():
    import numpy as np
    from sklearn.metrics import silhouette_score
    data = json.loads((ROOT/'site/asset_vulntology/icsa_role_groups.json').read_text(encoding='utf-8'))
    projection = np.load(ROOT/'results/icsa_role_clusters_k18/projection.npz')
    assert len(projection['labels']) == len(projection['reduced']) == 3881
    assert len(set(projection['labels'])) == 18
    score = float(silhouette_score(projection['reduced'],projection['labels'],metric='cosine'))
    assert score > 0.5 and abs(score-data['metrics']['svd_cosine_silhouette']) < 1e-6
    zero_rows = np.linalg.norm(projection['reduced'],axis=1)==0
    assert data['metrics']['zero_tfidf_rows'] == int(zero_rows.sum())
    assert all(data['advisories'][i]['uncertain'] for i in np.flatnonzero(zero_rows))
    assert data['metrics']['full_population']
    assert data['method']['role_annotations_only']
    assert np.isclose(projection['original_silhouettes'].mean(),data['metrics']['original_tfidf_cosine_silhouette'])
