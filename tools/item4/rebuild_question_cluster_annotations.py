# HISTORICAL: v3 random asset-question clusters; not the active CVSS operational evaluation.
"""One unchanged public BOM and one indexed, clustered questionnaire annotation.

Question-response scenarios test grouping and missing-value handling. They are
not CVE exploitability gold and never turn cluster membership into prerequisites.
"""
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import argparse
import csv
import hashlib
import io
import json
import re
import shutil
import random
import platform

ROOT = Path('C:/ICS-VEX')
WORK = ROOT/'results/item4_question_cluster_rebuild_20261125'
SOURCE = WORK/'public_source'
VERSION = 'item4-asset-question-cluster-annotations/3'
SEED = 20261125
PATTERNS_PER_TYPE = 30
SAMPLER = 'seeded-cluster-question-sampling/1'

def sha(raw): return hashlib.sha256(raw).hexdigest()
def read(path): return json.loads(path.read_bytes())
def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n',encoding='utf-8')

def catalogue(raw):
    profiles={}
    rows=list(csv.DictReader(io.StringIO(raw.decode('utf-8-sig'))))
    for row in rows:
        aid=row['asset_type_id']; cid=row['내부클러스터_ID']; qid=aid+':'+row['key']
        p=profiles.setdefault(aid,dict(asset_type_id=aid,name_ko=row['자산유형'],name_en=row['asset_type_en'],questions=[],clusters={}))
        assert cid.startswith(aid+'-C')
        assert qid not in {q['id'] for q in p['questions']}
        p['questions'].append(dict(id=qid,key=row['key'],cluster_id=cid,
            question=row['확인항목'],target_unit=row['확인대상단위'],
            o_criterion=row['o_판정기준'],x_criterion=row['x_판정기준'],
            evidence_guidance=row['확인자료'],interpretation_rule=row['확인규칙'],
            purpose=row['VEX_대조항목'],selection_basis=row['선정근거'],
            asset_type_source=row['MITRE_자산유형출처']))
        cluster=p['clusters'].setdefault(cid,dict(id=cid,name=row['내부클러스터명'],question_ids=[]))
        cluster['question_ids'].append(qid)
    for p in profiles.values(): p['clusters']=list(p['clusters'].values())
    assert len(profiles)==18 and sum(len(p['questions']) for p in profiles.values())==505
    assert sum(len(p['clusters']) for p in profiles.values())==120
    return dict(version=VERSION,source_sha256=sha(raw),profiles=profiles,
        allowed_values=['o','x','unknown','not_applicable','mixed'],
        unknown_policy='Missing, not applicable, or conflicting evidence does not establish x.',
        cluster_policy='Question groups; not complete CVE attack paths.')

def components(bom):
    output=[]
    def walk(items,pointer):
        for i,c in enumerate(items):
            path=pointer+'/'+str(i)
            output.append(dict(ref=c.get('bom-ref') or path,pointer=path,name=c.get('name'),version=c.get('version')))
            walk(c.get('components',[]),path+'/components')
    root=bom.get('metadata',{}).get('component')
    if root:
        output.append(dict(ref=root.get('bom-ref') or '/metadata/component',pointer='/metadata/component',name=root.get('name'),version=root.get('version')))
        walk(root.get('components',[]),'/metadata/component/components')
    walk(bom.get('components',[]),'/components')
    return output

def declarations(bom):
    output=[]
    def collect(items,path,default=None):
        for i,v in enumerate(items):
            name=v if isinstance(v,str) else v.get('id') or v.get('cve') if isinstance(v,dict) else None
            if not isinstance(name,str) or not re.fullmatch(r'CVE-\d{4}-\d{4,}',name,re.I): continue
            refs=[a.get('ref') for a in v.get('affects',[]) if isinstance(a,dict)] if isinstance(v,dict) else []
            if default: refs.append(default)
            output.append(dict(cve=name.upper(),pointer=path+'/'+str(i),component_refs=sorted(set(r for r in refs if isinstance(r,str)))))
    collect(bom.get('vulnerabilities',[]),'/vulnerabilities')
    collect(bom.get('cves',[]),'/cves')
    for c in components(bom):
        obj=bom
        for part in c['pointer'].strip('/').split('/'): obj=obj[int(part)] if isinstance(obj,list) else obj[part]
        collect(obj.get('vulnerabilities',[]),c['pointer']+'/vulnerabilities',c['ref'])
        collect(obj.get('cves',[]),c['pointer']+'/cves',c['ref'])
    return output

def expand_answers(profile, assignment):
    """Compact assignment has an explicit value for every questionnaire key."""
    overrides=assignment.get('cluster_values',{})
    assert set(overrides)<={c['id'] for c in profile['clusters']}
    individual=assignment.get('question_values',{})
    assert set(individual)<={q['id'] for q in profile['questions']}
    return {q['id']:individual.get(q['id'],overrides.get(q['cluster_id'],assignment['default_value'])) for q in profile['questions']}

def summaries(profile, answers):
    output=[]
    for c in profile['clusters']:
        counts=Counter(answers[qid] for qid in c['question_ids'])
        unresolved=sum(counts[v] for v in ('unknown','mixed','not_applicable'))
        output.append(dict(cluster_id=c['id'],o_count=counts['o'],x_count=counts['x'],
            unknown_count=unresolved,has_o=counts['o']>0,
            all_x=counts['x']==len(c['question_ids']),
            coverage='complete' if unresolved==0 else 'incomplete'))
    return output

def scenarios(profile, count=PATTERNS_PER_TYPE, seed=SEED):
    aid=profile['asset_type_id']
    qids=[q['id'] for q in profile['questions']]
    output=[];seen=set();attempt=0
    while len(output)<count:
        attempt+=1
        if attempt>10000:raise ValueError('Unable to sample enough distinct answer vectors')
        draw_seed=int(sha(f'{SAMPLER}:{seed}:{aid}:{attempt}'.encode())[:16],16)
        rng=random.Random(draw_seed)
        selected=sorted(rng.sample(profile['clusters'],rng.randint(1,len(profile['clusters']))),key=lambda c:c['id'])
        individual={};selection=[]
        for c in selected:
            chosen=sorted(rng.sample(c['question_ids'],rng.randint(1,min(4,len(c['question_ids'])))))
            for qid in chosen:individual[qid]=rng.choice(('o','x','unknown'))
            selection.append(dict(cluster_id=c['id'],question_ids=chosen,question_count=len(chosen)))
        assignment=dict(default_value='unknown',cluster_values={},question_values=individual)
        answers=expand_answers(profile,assignment)
        vector=tuple(answers[qid] for qid in qids)
        if vector in seen:continue
        seen.add(vector)
        output.append(dict(id=f'{aid}__random_{len(output)+1:03d}',synthetic=True,
            scope='separate hypothetical instance of this asset type; not a verified BOM installation',
            inputs=dict(asset_type_id=aid,answer_assignment=assignment),
            sampling=dict(generator=SAMPLER,base_seed=seed,draw_seed=draw_seed,draw_number=attempt,
                selected_cluster_count=len(selection),selected_clusters=selection,
                selected_question_count=len(individual),python_version=platform.python_version()),
            expected_question_results=summaries(profile,answers),
            expected_vex_status=None,actual_affected=None,
            label_state='question_response_gold_only; CVE-path and runtime bindings unresolved'))
    return output

def load_scenarios(annotation, data_root=None):
    root=Path(data_root or ROOT/'benchmark/item4_evaluation').resolve()
    result=[]
    for ref in annotation['scenario_sets']:
        path=(root/ref['file']).resolve()
        if not path.is_relative_to(root):raise ValueError('Scenario reference escapes dataset')
        raw=path.read_bytes()
        if sha(raw)!=ref['sha256']:raise ValueError('Scenario set changed')
        result.extend(json.loads(raw)['scenarios'])
    return result

def model_input(annotation, scenario_id, data_root=None):
    """Expand one case without exposing expected aggregates or VEX label fields."""
    scenario=next(s for s in load_scenarios(annotation,data_root) if s['id']==scenario_id)
    profile=next(p for p in annotation['inputs']['question_profiles']
                 if p['asset_type_id']==scenario['inputs']['asset_type_id'])
    public=deepcopy(profile)
    public.pop('scenario_ids',None)
    public.pop('scenario_set_ref',None)
    values=expand_answers(profile,scenario['inputs']['answer_assignment'])
    for question in public['questions']: question['value']=values[question['id']]
    return dict(schema_version=VERSION,synthetic=True,sbom_file=annotation['sbom_file'],
        scope=scenario['scope'],question_profile=public,
        assessment_context=deepcopy(annotation['inputs']['assessment_context']))

def build(stage):
    if stage.exists(): raise FileExistsError(stage)
    source_manifest=read(SOURCE/'manifest.json')
    source_index=read(SOURCE/'public_index.json')
    raw=(ROOT/'data/operator_asset_keys_clustered.csv').read_bytes()
    cat=catalogue(raw)
    nav_path=ROOT/'site/asset_vulntology/icsa_asset_navigation.json'
    nav_raw=nav_path.read_bytes(); nav=json.loads(nav_raw)
    stage.mkdir(parents=True)
    (stage/'sboms').mkdir(); (stage/'annotations').mkdir(); (stage/'catalog').mkdir()
    (stage/'catalog/operator_asset_keys_clustered.csv').write_bytes(raw)
    (stage/'catalog/asset_navigation_snapshot.json').write_bytes(nav_raw)
    write(stage/'catalog/question_clusters.json',cat)
    scenario_sets={}; pattern_sets={}
    for aid,p in cat['profiles'].items():
        cases=scenarios(p);path=stage/'scenarios'/f'{aid}.json'
        write(path,dict(version=VERSION,asset_type_id=aid,base_seed=SEED,
            generator=SAMPLER,question_catalog_sha256=cat['source_sha256'],scenarios=cases))
        scenario_sets[aid]=dict(asset_type_id=aid,file=f'scenarios/{aid}.json',sha256=sha(path.read_bytes()),count=len(cases))
        pattern_sets[aid]=cases
    write(stage/'catalog/scenario_sets.json',dict(version=VERSION,sets=list(scenario_sets.values())))
    index=[]; counts=Counter(); cves=set(); all_questions=set(); all_clusters=set()
    used_scenario_types=set()
    published={a['file']:a for a in source_index['assets']}
    for number,entry in enumerate(source_manifest['files'],1):
        filename=f'sbom_{number:06d}.json'; identity=filename[:-5]
        payload=(SOURCE/'documents'/entry['file']).read_bytes()
        assert sha(payload)==entry['sha256']
        bom=json.loads(payload); comps=components(bom); decl=declarations(bom)
        ids=sorted({d['cve'] for d in decl}); cves.update(ids)
        advisory=entry['asset_id']; detail=deepcopy(nav['assignment_details'].get(advisory,{}))
        candidates=sorted(set(nav['advisory_asset_ids'].get(advisory,[]))&set(cat['profiles']))
        applicable=candidates or sorted(cat['profiles'])
        profiles=[]; refs=[]
        for aid in applicable:
            p=deepcopy(cat['profiles'][aid])
            p.update(selection='advisory_context_candidate' if candidates else 'unselected_discovery_alternative',
                confirmed_asset_type=False,component_refs=[],
                binding_status='requires_component_asset_type_and_target_confirmation')
            for q in p['questions']:
                q.update(value='unknown',evidence_refs=[],target_ref=None)
                all_questions.add(q['id']);all_clusters.add(q['cluster_id'])
            generated=pattern_sets[aid] if candidates else []
            p['scenario_ids']=[s['id'] for s in generated]
            p['scenario_set_ref']=scenario_sets[aid]['file'] if candidates else None
            if candidates:
                refs.append(scenario_sets[aid]);used_scenario_types.add(aid)
            counts['synthetic_question_scenarios']+=len(generated)
            profiles.append(p)
        annotation=dict(schema_version=VERSION,id=identity,index=number,
            sbom_file='sboms/'+filename,sbom_file_sha256=entry['sha256'],
            annotation_kind='public_bom_asset_type_cluster_questionnaire',synthetic=True,
            source=dict(public_url=entry['url'],original_filename=entry['file'],advisory_id=advisory,
                actual_download_sha256=entry['sha256'],public_index_sha256=source_manifest['public_index_sha256'],
                index_declared_sbom_sha256=entry['index_sha256'],index_hash_matches=entry['index_hash_matches'],
                index_metadata_used_as_bom_content=False),
            inventory=dict(components=comps,cve_declarations=decl,declared_cves=ids,
                component_cve_associations='Preserved exactly in copied BOM; no new links inferred'),
            asset_classification=dict(status='candidate_requires_confirmation' if candidates else 'unresolved',
                candidate_asset_type_ids=candidates,confirmed_asset_type_id=None,
                scope='advisory context only; not assigned to every component',source_detail=detail),
            inputs=dict(question_profiles=profiles,
                assessment_context=dict(asset_ref=None,component_ref=None,running_version=None,
                    configuration=None,mode='unknown',actor_origin='unknown',deployment='unknown',inventory_coverage='unknown')),
            scenario_sets=refs,
            gold=dict(level='cluster_question_response_only',actual_affected=None,actual_status=None,
                cve_labels=[dict(cve=cve,actual_affected=None,actual_status=None,
                    question_condition_links=[],path_coverage_complete=False,
                    label_state='unresolved_source_condition_and_component_scope') for cve in ids],
                real_asset_impact_verified=False,independent_semantic_accuracy_verified=False),
            generation=dict(llm_used=False,method=SAMPLER,base_seed=SEED,
                question_catalog_sha256=cat['source_sha256'],asset_navigation_sha256=sha(nav_raw),
                source_condition_question_mapping='not available as a verified complete snapshot',
                policy='No O is a cluster summary, not proof of no attack vector or not_affected.'),
            assumptions=['BOM product/version alternatives are not a verified simultaneous installation.',
                'Type candidates only select collection context; synthetic scenarios do not confirm classification.',
                'No CVE count batching or fixed five scenarios per CVE.',
                'All-X and all-unknown remain distinguishable; neither supplies missing CVE path completeness.'])
        (stage/'sboms'/filename).write_bytes(payload)
        write(stage/'annotations'/filename,annotation)
        annotation_sha=sha((stage/'annotations'/filename).read_bytes())
        index.append(dict(index=number,id=identity,sbom_file='sboms/'+filename,
            annotation_file='annotations/'+filename,original_filename=entry['file'],
            source_url=entry['url'],sbom_sha256=entry['sha256'],annotation_sha256=annotation_sha,
            cve_count=len(ids),component_count=len(comps)))
        counts['boms']+=1;counts['annotations']+=1;counts['components']+=len(comps)
        counts['cve_occurrences']+=len(ids);counts['empty_component_boms']+=not bool(comps)
        counts['boms_without_cves']+=not bool(ids);counts['unresolved_asset_type_boms']+=not bool(candidates)
        if number%800==0: print('Built',number,flush=True)
    counts.update(unique_cves=len(cves),catalog_asset_types=len(cat['profiles']),
        catalog_questions=len(all_questions),catalog_clusters=len(all_clusters),
        shared_synthetic_patterns=sum(len(x) for x in pattern_sets.values()),
        used_shared_patterns=sum(len(pattern_sets[aid]) for aid in used_scenario_types),
        scenario_sets=len(scenario_sets))
    write(stage/'index.json',dict(version=VERSION,entries=index))
    write(stage/'manifest.json',dict(version=VERSION,created_at=datetime.now(timezone.utc).isoformat(),
        counts=dict(counts),source_url=source_manifest['source_url'],
        source_download_manifest_sha256=sha((SOURCE/'manifest.json').read_bytes()),
        question_catalog_sha256=cat['source_sha256'],asset_navigation_sha256=sha(nav_raw),
        public_index_hash_mismatches=source_manifest['index_hash_mismatches'],
        unclassified_scenario_policy='defer_until_asset_type_classified; no scenarios generated',
        bom_bytes_preserved=True,source_population_preserved=True,llm_used=False,
        complete_vex_gold=False,cve_fixed_five_scenarios=False,
        scenario_design=dict(version=SAMPLER,base_seed=SEED,patterns_per_type=PATTERNS_PER_TYPE,
            values=['o','x','unknown'],all_question_pairs_covered=False,
            all_n_way_combinations_enumerated=False,random_sampling=True,
            cluster_count_sampling='uniform integer 1..number of clusters',
            question_count_sampling='uniform integer 1..min(4, cluster question count)',
            value_sampling='equal probability o/x/unknown for each selected question',
            unselected_question_value='unknown',duplicates_removed=True,
            storage='shared type files referenced by BOM annotation; count applications separately'),
        source_snapshot=str(SOURCE.relative_to(ROOT))))
    (stage/'README.txt').write_text(README,encoding='utf-8')
    print(json.dumps(dict(counts),ensure_ascii=False,indent=2),flush=True)

README='''#4 자산 유형별 질문 클러스터 annotation (2026-11-25)

1. 공개 BOM 하나당 annotation 하나입니다. 두 폴더의 같은 sbom_000001.json이 서로 대응합니다.
   실제 공개 다운로드 바이트를 복사했습니다. 제품, 버전, 컴포넌트 참조, CVE, affects는 변경하지 않았습니다.
   숫자 인덱스는 원래 공개 파일명을 정렬해 부여합니다. index.json에 원본 파일명·URL·해시가 있습니다.
   공개 목록의 제품·해시와 실제 다운로드가 다를 수 있으므로 실제 파일을 기준으로 합니다.

2. catalog/question_clusters.json은 18개 유형·120개 클러스터·505개 질문 전체의 동결 사본입니다.
   annotation의 inputs.question_profiles에는 해당 권고문의 유형 후보별 질문을 담았습니다.
   자산 유형이 미분류이면 18개 유형의 질문을 미선택 대안으로 제공하고 시나리오는 생성하지 않습니다.
   권고문 분류는 컴포넌트별 확정 분류가 아닙니다. 실제 자산 유형·대상 확인 후 사용할 묶음을 선택해야 합니다.
   모든 기본 답변은 unknown이며 o/x 기준과 확인 자료를 질문마다 보존합니다.

3. scenarios/A0001.json 등 18개 공통 파일에 유형당 서로 다른 30개, 총 540개 패턴을 저장합니다.
   annotation.scenario_sets 및 질문 프로필의 scenario_set_ref/scenario_ids가 공통 패턴을 참조합니다.
   유형 후보가 있는 BOM에는 해당 유형 30개를 적용하고, 미분류 BOM에는 시나리오 참조를 넣지 않습니다.
   공통 패턴 540개와 BOM 적용 건수는 서로 다른 집계입니다. BOM마다 파일을 복제하지 않습니다.
   난수 기본 시드는 20261125입니다. 유형·추출 회차로 개별 draw_seed를 만들어 random.Random에 사용합니다.
   각 패턴에서 클러스터를 1~전체 개수만큼 무작위 선택하고,
   선택한 클러스터마다 질문을 1~min(4, 해당 질문 수)개 비복원 추출합니다.
   선택한 질문은 o/x/unknown을 같은 확률로 부여하고 선택하지 않은 질문은 unknown으로 둡니다.
   같은 질문 답변 벡터가 나오면 재추출하여 유형별 30개를 채웁니다.
   sampling에는 선택한 클러스터·질문 ID·개수, 기본 시드·draw_seed·추출 회차·Python 버전을 기록합니다.
   같은 클러스터 내부에서도 O/X/모름이 섞일 수 있습니다. 전수·쌍별 조합 보장은 주장하지 않습니다.
   통제 합성 입력이며 실제 현장의 설정 타당성·설치 사실을 보장하지 않습니다.
   answer_assignment.question_values에 선택 질문의 값을, default_value에 unknown을 저장합니다.
   expected_question_results는 클러스터별 O/X/모름 개수와 has_o/all_x/응답 완전성의 채점 참조입니다.
   모델에는 annotation.inputs와 선택한 scenario.inputs만 제공하고 sampling·채점 필드는 숨겨야 합니다.
   tools.item4.rebuild_question_cluster_annotations.model_input(annotation, scenario_id, data_root)는
   공통 패턴의 해시를 검사하고 개별 답변을 펼치며 채점 필드를 제외한 입력을 반환합니다.

4. 현재 gold는 질문 응답·클러스터 집계 정답입니다. CVE 악용 가능성·VEX 정답은 null입니다.
   같은 클러스터라는 이유로 CVE 조건을 공유하거나, O가 없다는 이유로 not_affected를 생성하지 않습니다.
   원문 조건↔질문↔컴포넌트↔경로 및 전체 경로 완전성이 확인되지 않은 부분은 미확인으로 유지합니다.
   LLM을 호출하지 않았으며 운영환경의 독립 검증이나 최종 VEX 정확도를 주장하지 않습니다.

5. 이전 FULL-/SYN-/icsa- annotation과 BOM은 docs/archive/item4_question_cluster_rebuild_*/에 보관합니다.
   과거 VEX 정답은 새 annotation으로 복사하지 않았습니다. 기존 생성·평가 스크립트는 과거 스키마용입니다.
   재생성: python -m tools.item4.rebuild_question_cluster_annotations --stage <새 경로>
   검증: python -m tools.item4.verify_question_cluster_annotations --data benchmark/item4_evaluation
'''

def publish(stage):
    target=ROOT/'benchmark/item4_evaluation'
    backup=ROOT/'docs/archive'/('item4_question_cluster_rebuild_'+datetime.now().strftime('%Y%m%d_%H%M%S'))
    for path in (stage,target,backup):
        assert path.resolve().is_relative_to(ROOT.resolve())
    assert not backup.exists()
    backup.parent.mkdir(parents=True,exist_ok=True)
    shutil.move(str(target),str(backup))
    try: shutil.move(str(stage),str(target))
    except Exception:
        shutil.move(str(backup),str(target));raise
    write(WORK/'delivery.json',dict(target=str(target),backup=str(backup),
        manifest_sha256=sha((target/'manifest.json').read_bytes())))
    print('Published',target,'backup',backup,flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--stage',type=Path,default=WORK/'staged')
    parser.add_argument('--publish',action='store_true');args=parser.parse_args()
    build(args.stage)
    from tools.item4.verify_question_cluster_annotations import verify
    verify(args.stage)
    from tools.item4.document_question_cluster_dataset import document
    document(args.stage)
    if args.publish: publish(args.stage)
