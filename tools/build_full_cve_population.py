"""Build a common, real-CVE source foundation without inventing impact labels."""
from collections import defaultdict,Counter
import hashlib,json,sqlite3,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.asset_vulntology import DATA,digest
from src.training_io import atomic_json

OUT=ROOT/'benchmark/cve_population_12418_v1'
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b)
    return h.hexdigest()

def build():
    if OUT.exists():raise FileExistsError(OUT)
    OUT.mkdir(parents=True)
    records={}
    for p in sorted(DATA.glob('records_*.json')):records.update(json.loads(p.read_text(encoding='utf-8')))
    ids=sorted(r['cve'] for r in json.loads((DATA/'catalogue.json').read_text(encoding='utf-8'))['cves'])
    assert len(ids)==len(set(ids))==12418 and set(ids)==set(records)
    targets=set(ids);reverse=defaultdict(list);atoms=defaultdict(list);conditions=defaultdict(set);goldlinks=defaultdict(lambda:defaultdict(set))
    index=ROOT/'icsa/sbom_index.json'
    for asset in json.loads(index.read_text(encoding='utf-8'))['assets']:
        for c in asset.get('cves',[]):
            cid=c.get('id')
            if cid in targets:
                reverse[cid].append(dict(asset_id=asset['asset_id'],sbom_file='icsa/documents/'+asset['file'],
                    component=c.get('component'),advisories=asset.get('advisories',[]),
                    provenance='Existing advisory-derived SBOM index explicit CVE/component link',
                    real_deployment_verified=False,independent_accuracy_verified=False))
    db=sqlite3.connect('file:'+str(ROOT/'data/item3_spelling_noise_v10/dataset.sqlite3').replace('\\','/')+'?mode=ro',uri=True)
    for cid,path,condition,raw in db.execute('SELECT cve,path,condition_id,raw_match FROM source_coverage ORDER BY cve,path'):
        assert cid in targets
        atoms[cid].append(dict(path=path,condition_id=condition,match=json.loads(raw)))
        if condition:conditions[cid].add(condition)
    for fold in ('train','evaluation'):
        for line in (ROOT/'benchmark/item3_gold_v11'/fold/'labels.jsonl').open(encoding='utf-8'):
            r=json.loads(line)
            for cid in r['expected_cves']:
                if cid in targets:goldlinks[cid][fold].add(r['id'])
    clusters={r['cve']:r for r in map(json.loads,(ROOT/'results/item4_condition_clusters_v1/cve_assignments.jsonl').open(encoding='utf-8'))}
    counts=Counter();counts['target_CVEs']=len(ids)
    with (OUT/'inputs.jsonl').open('w',encoding='utf-8') as inputs,(OUT/'labels.jsonl').open('w',encoding='utf-8') as labels,(OUT/'reverse_links.jsonl').open('w',encoding='utf-8') as links:
        for cid in ids:
            r=records[cid]
            assert digest({k:v for k,v in r.items() if k!='record_digest'})==r['record_digest'],cid
            for source in r['sources']:assert hashlib.sha256(source['text'].encode()).hexdigest()==source['text_sha256']
            package=dict(id=cid,cve=cid,description=r['description'],source_status=r['original_nvd_status'],
                products=r['products'],sources=r['sources'],item3_source_atoms=atoms[cid],
                advisory_sbom_candidates=reverse[cid],item4_scenario_drafts=r['scenarios'],
                item4_cluster=clusters[cid],source_record_digest=r['record_digest'])
            inputs.write(json.dumps(package,ensure_ascii=False)+'\n')
            label=dict(id=cid,cve=cid,item3=dict(source_condition_ids=sorted(conditions[cid]),
                label_state='source_CPE_conditions_available' if atoms[cid] else 'unknown_no_CPE_truth',
                existing_benchmark_positive_input_ids={f:sorted(v) for f,v in goldlinks[cid].items()},
                independent_real_asset_gold=False),item4=dict(actual_affected=None,label_state='unknown_no_independent_context_impact_gold',
                semantic_reviewed=False,source_drafts_are_not_impact_labels=True))
            labels.write(json.dumps(label,ensure_ascii=False)+'\n')
            links.write(json.dumps(dict(cve=cid,CPE_atoms=len(atoms[cid]),sbom_links=reverse[cid],
                advisory_ids=r['advisory_ids'],product_keys=[p['key'] for p in r['products']],
                source_ids=[s['id'] for s in r['sources']]),ensure_ascii=False)+'\n')
            counts['with_CPE_atoms']+=bool(atoms[cid]);counts['with_SBOM_reverse_links']+=bool(reverse[cid])
            counts['with_products']+=bool(r['products']);counts['with_sources']+=bool(r['sources'])
            counts['with_item4_drafts']+=bool(r['scenarios']);counts['item3_existing_test_positive_CVEs']+=bool(goldlinks[cid]['evaluation'])
            counts['item3_existing_train_positive_CVEs']+=bool(goldlinks[cid]['train'])
            counts['no_CPE_but_SBOM_reverse_links']+=not atoms[cid] and bool(reverse[cid])
    db.close()
    manifest=dict(schema='common-real-CVE-population/1',**dict(counts),
        id_policy='Original real CVE identifiers; exactly the same fixed 12418 IDs for items 3 and 4',
        source_records=str(DATA.relative_to(ROOT)),sbom_index_sha256=sha(index),
        source_linkage_is_not_independent_gold=True,unknown_CVEs_retained=True,
        old_item4_fictional_benchmark_is_not_this_population=True,
        artifacts={p.name:sha(p) for p in OUT.glob('*.jsonl')})
    atomic_json(OUT/'manifest.json',manifest)
    report=dict(required_population=12418,manifest='benchmark/cve_population_12418_v1/manifest.json',
        coverage=dict(counts),item3=dict(full_population_precision=None,full_population_target_met=None,
            reason='Existing held-out benchmark is a subset; reverse links are candidate evidence, not independent new labels'),
        item4=dict(full_population_precision=None,full_population_target_met=None,
            independently_labelled_context_cases=0,reason='Real-CVE sources and scenario drafts linked; operational impact labels require independent source/context validation'),
        old_metrics_scope='Separate partial/fictional synthetic benchmarks; not precision validated on all 12418 CVEs')
    dest=ROOT/'results/cve_population_12418_v1';dest.mkdir(parents=True,exist_ok=True)
    atomic_json(dest/'coverage_report.json',report)
    print(json.dumps(report,ensure_ascii=False))

if __name__=='__main__':build()
