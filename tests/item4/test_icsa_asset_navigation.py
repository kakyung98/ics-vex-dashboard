import hashlib,json,re
from pathlib import Path
import numpy as np
from sklearn.metrics import silhouette_score
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'results/icsa_fixed18_reclassification'

def dataset():
    nav=json.loads((OUT/'assignments.json').read_text(encoding='utf-8'))
    source=json.loads((OUT/('source_advisories_fulltext_v3.json' if nav['settings']['variant']=='source_v3' else 'source_advisories.json')).read_text(encoding='utf-8'))
    return nav,{r['id']:r for r in source['advisories']}

def test_fixed_names_full_primary_partition_and_cve_links():
    nav,rows=dataset();catalog=json.loads((ROOT/'site/asset_vulntology/catalogue.json').read_text(encoding='utf-8'))
    assert [(c['id'],c['name']) for c in nav['categories']]==[(c['asset_id'],c['name']) for c in catalog['assets']]
    groups=nav['categories']+[nav['unassigned']];ids=[aid for g in groups for aid in g['advisory_ids']]
    assert len(ids)==len(set(ids))==3881 and set(ids)==set(rows)
    assert len({c for g in groups for c in g['cves']})==12418
    for g in groups:
        assert g['cve_count']==len(set(g['cves']))
        assert set(g['cves'])=={c for aid in g['advisory_ids'] for c in rows[aid]['cves']}
    assert nav['summary']['unassigned_advisories']<=500
    assert nav['summary']['assigned_advisories']+nav['summary']['unassigned_advisories']==3881
    assert (OUT/'assignments.json').read_bytes()==(ROOT/'site/asset_vulntology/icsa_asset_navigation.json').read_bytes()

def test_each_assignment_has_verbatim_phrase_or_actual_positive_term():
    nav,rows=dataset();literal=0;estimated=0
    for aid,d in nav['assignment_details'].items():
        text=rows[aid]['feature_text'];assert hashlib.sha256(text.encode()).hexdigest()==d['source_feature_sha256']
        if not d['asset_id']:
            assert d['status']=='unassigned' and d['reason'];continue
        assert d['literal_evidence'] or d['term_contributions']
        for e in d['literal_evidence']:
            t=nav['taxonomy_templates'][e['template_key']];assert t['parent_id']==d['asset_id']
            assert text[slice(*e['span'])].strip();literal+=1
        for e in d['term_contributions']:
            quote=text[slice(*e['span'])]
            assert re.fullmatch(r'\W+'.join(re.escape(t) for t in e['term'].split()),quote,re.I)
            assert e['contribution']>0;estimated+=1
    assert literal and estimated
    templates=list(nav['taxonomy_templates'].values());related=[t for t in templates if t['kind']=='related_asset']
    assert len(related)==43 and len({re.sub(r'\s+',' ',t['name']).casefold() for t in related})==39

def test_metrics_use_actual_primary_labels_and_include_rejected_records():
    nav,rows=dataset();projection=np.load(OUT/'projection.npz')
    assert len(projection['labels'])==len(projection['reduced'])==3881
    actual=float(silhouette_score(projection['reduced'],projection['labels'],metric='cosine'))
    assert np.isclose(actual,nav['metrics']['full_svd_cosine_silhouette'],atol=1e-6)
    assert int((projection['labels']==-1).sum())==nav['summary']['unassigned_advisories']
    assert nav['metrics']['target_silhouette_met']==(actual>.5)
    assert not nav['metrics']['independent_accuracy_validated']

def test_model_term_contribution_matches_decision_projection():
    from tools.item4.fixed_asset_model import prepare
    nav,rows=dataset();p=prepare(nav['settings']['variant']);projection=np.load(OUT/'projection.npz')
    term_index=p['vectorizer'].vocabulary_;classes=p['classes'];checked=0
    for i,row in enumerate(p['rows']):
        d=nav['assignment_details'][row['id']]
        if d['status']!='model_estimate' or not d['term_contributions']:continue
        e=d['term_contributions'][0];a=classes.index(d['asset_id']);b=classes.index(e['rival_asset_id']);column=term_index[e['term']]
        weights=projection['components'].T@(projection['centers'][a]-projection['centers'][b])
        denominator=float(np.linalg.norm(p['x'][i]@projection['components'].T)) or 1
        actual=float(p['x'][i,column]*weights[column]/denominator)
        assert np.isclose(actual,e['contribution'],atol=1e-7)
        checked+=1
        if checked==8:break
    assert checked==8


def test_improved_model_meets_targets_without_changing_taxonomy_or_learning_predictions():
    nav,rows=dataset()
    assert nav['metrics']['full_embedding_cosine_silhouette']>.5
    assert nav['metrics']['target_silhouette_met']
    assert nav['summary']['unassigned_advisories']<=500
    assert nav['metrics']['metric_space'].endswith('LDA16')
    assert nav['metrics']['prediction_labels_used_for_projection_training'] is False
    from tools.item4.fixed_asset_model import prepare,reference_labels
    assert nav['metrics']['source_training_references']==int((reference_labels(prepare(nav['settings']['variant']),consistent=True)>=0).sum())
    baseline=json.loads((OUT/'history/20261117_baseline_024607/assignments.json').read_text(encoding='utf-8'))
    assert nav['taxonomy_templates']==baseline['taxonomy_templates']


def test_source_quotes_match_original_structured_fields():
    nav,rows=dataset();files={};checked=0
    for aid,d in nav['assignment_details'].items():
        for e in d['literal_evidence']+d['term_contributions']:
            assert rows[aid]['feature_text'][slice(*e['span'])]==e['quote']
            assert e['source_excerpt'][slice(*e['excerpt_span'])]==e['quote']
            if not e.get('source_artifact'):continue
            path=ROOT/e['source_artifact']
            if str(path) not in files:files[str(path)]=json.loads(path.read_text(encoding='utf-8'))
            value=files[str(path)]
            for key in e['source_json_path']:value=value[key]
            assert value[slice(*e['original_span'])]==e['quote'];checked+=1
    assert checked>0
