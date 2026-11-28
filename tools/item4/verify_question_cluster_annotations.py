"""Independently verify BOM preservation, full question coverage and scenario labels."""
from pathlib import Path
from collections import Counter
import argparse
import csv
import hashlib
import json
import random

ROOT=Path('C:/ICS-VEX')
def read(path): return json.loads(path.read_bytes())
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def verify(data):
    manifest=read(data/'manifest.json');index=read(data/'index.json')['entries']
    source=ROOT/manifest['source_snapshot']
    published={r['file']:r for r in read(source/'manifest.json')['files']}
    assert len(index)==len(published)==3881
    assert len({r['original_filename'] for r in index})==len(published)
    assert {r['original_filename'] for r in index}==set(published)
    assert {p.name for p in (data/'sboms').glob('*.json')}=={f'sbom_{i:06d}.json' for i in range(1,len(index)+1)}
    assert {p.name for p in (data/'annotations').glob('*.json')}=={p.name for p in (data/'sboms').glob('*.json')}
    rows=list(csv.DictReader((data/'catalog/operator_asset_keys_clustered.csv').open(encoding='utf-8-sig',newline='')))
    questions={(r['asset_type_id'],r['key']):r for r in rows}
    catalog=read(data/'catalog/question_clusters.json')
    assert len(questions)==505 and len(catalog['profiles'])==18
    assert len({r['내부클러스터_ID'] for r in rows})==120
    assert sha(data/'catalog/operator_asset_keys_clustered.csv')==manifest['question_catalog_sha256']
    assert sha(data/'catalog/asset_navigation_snapshot.json')==manifest['asset_navigation_sha256']
    observed=set();clusters=set();cves=set();scenario_count=0;empty=0;without_cves=0
    shared={};shared_refs={};sampling_report={};mixed_clusters=set()
    for ref in read(data/'catalog/scenario_sets.json')['sets']:
        assert sha(data/ref['file'])==ref['sha256']
        group=read(data/ref['file']);aid=ref['asset_type_id'];profile=catalog['profiles'][aid]
        assert group['asset_type_id']==aid and group['base_seed']==20261125
        cases=group['scenarios'];assert len(cases)==ref['count']==30
        assert len({s['id'] for s in cases})==30
        vectors=set();cluster_counts=[];question_counts=[]
        for case in cases:
            sampling=case['sampling'];assignment=case['inputs']['answer_assignment']
            assert assignment['default_value']=='unknown' and assignment['cluster_values']=={}
            selected=sampling['selected_clusters'];individual=assignment['question_values']
            assert sampling['selected_cluster_count']==len(selected)
            assert 1<=len(selected)<=len(profile['clusters'])
            expected_seed=int(hashlib.sha256(f"seeded-cluster-question-sampling/1:20261125:{aid}:{sampling['draw_number']}".encode()).hexdigest()[:16],16)
            assert sampling['draw_seed']==expected_seed
            # Reproduce the random draws directly from their recorded seed.
            rng=random.Random(expected_seed)
            chosen=sorted(rng.sample(profile['clusters'],rng.randint(1,len(profile['clusters']))),key=lambda c:c['id'])
            assert [c['id'] for c in chosen]==[c['cluster_id'] for c in selected]
            selected_qids=[];replayed={}
            for cluster,record in zip(chosen,selected):
                qids=sorted(rng.sample(cluster['question_ids'],rng.randint(1,min(4,len(cluster['question_ids'])))))
                assert qids==record['question_ids'] and len(qids)==record['question_count']
                for qid in qids:replayed[qid]=rng.choice(('o','x','unknown'))
                selected_qids.extend(qids)
            assert replayed==individual and len(individual)==sampling['selected_question_count']
            assert len(set(selected_qids))==len(selected_qids) and set(selected_qids)==set(individual)
            vector=tuple(individual.get(q['id'],'unknown') for q in profile['questions'])
            vectors.add(vector);cluster_counts.append(len(selected));question_counts.append(len(individual))
            for c in profile['clusters']:
                values={individual.get(qid,'unknown') for qid in c['question_ids']}
                if len(values)>1:mixed_clusters.add(c['id'])
        assert len(vectors)==30
        shared[aid]=cases;shared_refs[aid]=ref
        sampling_report[aid]=dict(patterns=30,selected_clusters_min=min(cluster_counts),selected_clusters_max=max(cluster_counts),
            selected_questions_min=min(question_counts),selected_questions_max=max(question_counts),
            recorded_seed_reproduction_passed=True)
    assert len(shared)==18 and sum(len(cases) for cases in shared.values())==540
    used_types=set()
    for i,record in enumerate(index,1):
        name=f'sbom_{i:06d}.json'
        assert record['index']==i and record['id']==name[:-5]
        bpath=data/record['sbom_file'];apath=data/record['annotation_file']
        assert bpath.name==apath.name==name
        assert sha(bpath)==record['sbom_sha256']==published[record['original_filename']]['sha256']
        assert bpath.read_bytes()==(source/'documents'/record['original_filename']).read_bytes()
        assert sha(apath)==record['annotation_sha256']
        bom=read(bpath);annotation=read(apath)
        assert annotation['id']==record['id']
        assert annotation['sbom_file_sha256']==record['sbom_sha256']
        assert annotation['gold']['actual_affected'] is None and annotation['gold']['actual_status'] is None
        assert annotation['generation']['llm_used'] is False
        # Read every native CVE declaration, including nested components, independently.
        extracted=set()
        def visit(obj):
            if isinstance(obj,list):
                for value in obj: visit(value)
            elif isinstance(obj,dict):
                for field in ('vulnerabilities','cves'):
                    for value in obj.get(field,[]):
                        cve=value if isinstance(value,str) else value.get('id') or value.get('cve')
                        if isinstance(cve,str) and cve.startswith('CVE-'): extracted.add(cve.upper())
                for key,value in obj.items():
                    if key not in ('vulnerabilities','cves'):visit(value)
        visit(bom)
        assert extracted==set(annotation['inventory']['declared_cves'])
        assert extracted=={v['cve'] for v in annotation['gold']['cve_labels']}
        cves.update(extracted)
        empty+=not bool(bom.get('components'));without_cves+=not bool(extracted)
        for label in annotation['gold']['cve_labels']:
            assert label['actual_affected'] is None and label['actual_status'] is None
            assert label['path_coverage_complete'] is False
        scenario_lookup={}
        for ref in annotation['scenario_sets']:
            aid=ref['asset_type_id'];assert ref==shared_refs[aid]
            scenario_lookup.update({s['id']:s for s in shared[aid]});used_types.add(aid)
        referenced_scenarios=set()
        assert 'expected_question_results' not in json.dumps(annotation['inputs'])
        for profile in annotation['inputs']['question_profiles']:
            aid=profile['asset_type_id']
            expected={key for at,key in questions if at==aid}
            assert {q['key'] for q in profile['questions']}==expected
            assert profile['confirmed_asset_type'] is False and profile['component_refs']==[]
            for q in profile['questions']:
                original=questions[aid,q['key']]
                assert q['id']==aid+':'+q['key'] and q['cluster_id']==original['내부클러스터_ID']
                for field,source_field in [('question','확인항목'),('o_criterion','o_판정기준'),('x_criterion','x_판정기준'),('target_unit','확인대상단위')]:
                    assert q[field]==original[source_field]
                assert q['value']=='unknown' and q['target_ref'] is None and q['evidence_refs']==[]
                observed.add((aid,q['key']));clusters.add(q['cluster_id'])
            grouped={c['id']:set(c['question_ids']) for c in profile['clusters']}
            assert set.union(*grouped.values())=={q['id'] for q in profile['questions']}
            assert sum(len(s) for s in grouped.values())==len(profile['questions'])
            scenarios=[scenario_lookup[sid] for sid in profile['scenario_ids']]
            assert all('expected_question_results' not in json.dumps(s['inputs']) for s in scenarios)
            referenced_scenarios.update(profile['scenario_ids'])
            if not annotation['asset_classification']['candidate_asset_type_ids']:
                assert annotation['asset_classification']['status']=='unresolved'
                assert not scenarios and not scenario_lookup
                continue
            assert len(scenarios)==30 and profile['scenario_set_ref']==shared_refs[aid]['file']
            assert len({s['id'] for s in scenarios})==len(scenarios)
            vectors=set()
            for s in scenarios:
                assert s['actual_affected'] is None and s['expected_vex_status'] is None
                assignment=s['inputs']['answer_assignment'];default=assignment['default_value'];overrides=assignment['cluster_values']
                individual=assignment.get('question_values',{})
                assert default in ('o','x','unknown') and set(overrides)<=set(grouped)
                assert set(individual)<={q['id'] for q in profile['questions']}
                assert all(v in ('o','x','unknown') for v in individual.values())
                vals={q['id']:individual.get(q['id'],overrides.get(q['cluster_id'],default)) for q in profile['questions']}
                vectors.add(tuple(vals.values()))
                expected_results={e['cluster_id']:e for e in s['expected_question_results']}
                assert set(expected_results)==set(grouped)
                for cid,qids in grouped.items():
                    counts=Counter(vals[q] for q in qids);e=expected_results[cid]
                    assert e['o_count']==counts['o'] and e['x_count']==counts['x'] and e['unknown_count']==counts['unknown']
                    assert e['has_o']==any(vals[q]=='o' for q in qids)
                    assert e['all_x']==all(vals[q]=='x' for q in qids)
                    assert e['coverage']==('incomplete' if counts['unknown'] else 'complete')
                scenario_count+=1
            assert len(vectors)==len(scenarios)
        assert referenced_scenarios==set(scenario_lookup)
    assert observed==set(questions) and len(clusters)==120
    assert manifest['counts']['unique_cves']==len(cves)
    assert manifest['counts']['synthetic_question_scenarios']==scenario_count
    result=dict(passed=True,boms=len(index),annotations=len(index),
        source_boms_byte_identical=len(index),all_original_cve_declarations_preserved=True,
        unique_cves=len(cves),question_definitions_verified=len(observed),clusters_verified=len(clusters),
        synthetic_scenarios_verified=scenario_count,empty_component_boms=empty,boms_without_cves=without_cves,
        no_final_vex_labels_fabricated=True,all_x_distinguished_from_unknown=True,
        shared_patterns_verified=sum(len(cases) for cases in shared.values()),
        used_shared_patterns=sum(len(shared[aid]) for aid in used_types),
        sampling=sampling_report,random_seed_reproducible=True,
        no_unselected_question_assigned_o_or_x=True,
        pairwise_or_exhaustive_coverage_claimed=False,
        within_cluster_mixed_answers_verified=len(mixed_clusters),
        no_unclassified_bom_scenarios=True,
        original_schema_evaluation_scripts_compatible=False)
    path=data/'verification.json';path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False,indent=2),flush=True)
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--data',type=Path,default=ROOT/'benchmark/item4_evaluation')
    verify(p.parse_args().data)
