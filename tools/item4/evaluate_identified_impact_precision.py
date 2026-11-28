"""Freeze all BOM/CVE candidates and evaluate the clarified identification baseline.

Paired synthetic worlds are a controlled information-limit test. Their labels
are known by construction, not independently verified real-CVE impact gold.
No extraction/classification model is run and no production decisions change.
"""
from pathlib import Path
import argparse
from collections import Counter
from copy import deepcopy
from datetime import datetime,timezone
import hashlib
from html import escape
import json
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from src.item4.evaluation.identified_impact_precision import controlled_truth,score


def digest(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def write(path,value):path.write_bytes(json.dumps(value,ensure_ascii=False,indent=2).encode())


def run(output):
    if output.exists():raise FileExistsError('Choose a new result directory; frozen runs are not overwritten.')
    output.mkdir(parents=True)
    index_path=ROOT/'site/sbom_index.json';index_raw=index_path.read_bytes();index=json.loads(index_raw)
    catalogue_path=ROOT/'site/asset_vulntology/catalogue.json'
    catalogue_raw=catalogue_path.read_bytes()
    expected_cves={r['cve'] for r in json.loads(catalogue_raw)['cves']}
    assets=index['assets']
    assert len(assets)==3881 and len(expected_cves)==12418
    source=ROOT/'benchmark/icsa-cpe-synthetic sbom/sbom'
    definition=next(ROOT.glob('전남대*.hwp'))
    world=dict(component_deployed=True,cve_vulnerable_implementation_present=True,
        complete_exploitation_route_active=True,required_actor_control_available=True,
        effective_inline_protection=False)
    worlds=[]
    for source_available in (True,False):
        for route_active in (True,False):
            facts=dict(world,complete_exploitation_route_active=route_active)
            wid=('source_available' if source_available else 'source_unavailable')+('-route_active' if route_active else '-route_absent')
            worlds.append(dict(id=wid,synthetic=True,source_code_available=source_available,
                physical_facts=facts,
                statement='Hypothetical fixture: an exact CVE-vulnerable implementation is present; the complete impact-producing route is '+('active.' if route_active else 'absent.'),
                origin='Explicit simulator assumption; not a claim extracted from this CVE advisory or a verified field record.'))
    protocol=dict(version='identified-impact-paired-worlds/1',frozen_at=datetime.now(timezone.utc).isoformat(),
        official_definition=dict(path=str(definition),sha256=digest(definition.read_bytes()),target_percent=85),
        user_clarification='Every CVE identified from BOM component information is a positive prediction before VEX/context filtering.',
        unit='BOM × component-ref × CVE × hypothetical operating world; unbound declarations are retained explicitly.',
        candidate_source='Exact existing declarations in all 3,881 original v3 BOMs; no matcher is rerun.',
        excluded_boms=0,excluded_cves=0,worlds_per_candidate=4,
        paired_world_design='Same candidate/BOM bytes across active and absent routes and source-available/unavailable branches.',
        synthetic_gold=True,independent_real_asset_gold=False,
        semantic_limit='Five simulator facts define impact only in the hypothetical world. No assertion that these are sufficient source-derived conditions for every real CVE.',
        prevalence_limit='One positive and one negative per source branch: 50% impact prevalence is fixed by design. Baseline precision is consequently fixed at 50%, not a measured deployed-model accuracy.',
        confidence_intervals='Not computed: paired worlds and reused CVE/product records are dependent and not field samples.',
        llm_used=False,production_vex_filter_used=False,
        inputs=dict(sbom_index_sha256=digest(index_raw),cve_catalogue_sha256=digest(catalogue_raw)),
        code_sha256={str(p.relative_to(ROOT)):digest(p.read_bytes()) for p in
            [Path(__file__),ROOT/'src/item4/evaluation/identified_impact_precision.py']})
    write(output/'protocol.json',protocol)
    write(output/'controlled_worlds.private.json',worlds)
    all_cves=set();candidate_counts=Counter();bom_cve_pairs=0;source_receipts=[];unbound=0;duplicates=0
    by_cve=Counter();by_bom=Counter();hash_mismatches=[]
    # Publish every positive prediction using BOM-only inputs, before opening
    # the gold labels. The labels cannot affect selection or positive status.
    with (output/'identified_candidates.jsonl').open('wb') as candidate_stream, \
         (output/'predictions.jsonl').open('wb') as prediction_stream, \
         (output/'bom_receipts.jsonl').open('wb') as receipt_stream:
        for asset in assets:
            filename=asset['file'];path=source/filename;raw=path.read_bytes();bom=json.loads(raw)
            actual_sha=digest(raw)
            if actual_sha!=asset['sbom_sha256']:hash_mismatches.append(filename)
            components={}
            def walk(items,pointer):
                for i,c in enumerate(items):
                    ptr=pointer+'/'+str(i);components[c.get('bom-ref') or ptr]=c
                    walk(c.get('components',[]),ptr+'/components')
            walk(bom.get('components',[]),'/components')
            root=bom.get('metadata',{}).get('component')
            if root:
                components[root.get('bom-ref') or '/metadata/component']=root
                walk(root.get('components',[]),'/metadata/component/components')
            declarations={}
            for v in bom.get('vulnerabilities',[]):
                cve=v.get('id','').upper()
                if not cve.startswith('CVE-'):continue
                refs={a['ref'] for a in v.get('affects',[]) if isinstance(a,dict) and a.get('ref')}
                declarations.setdefault(cve,set()).update(refs)
            indexed={c if isinstance(c,str) else c['id'] for c in asset.get('cves',[])}
            if set(declarations)!=indexed:raise ValueError('Index/BOM CVE mismatch: '+filename)
            all_cves.update(declarations);bom_cve_pairs+=len(declarations)
            before=sum(candidate_counts.values())
            for cve,refs in sorted(declarations.items()):
                for ref in sorted(refs) if refs else [None]:
                    c=components.get(ref,{})
                    cid='candidate-'+digest(encoded([asset['asset_id'],ref,cve]))[:32]
                    candidate=dict(id=cid,bom_id=asset['asset_id'],bom_file=filename,bom_sha256=actual_sha,
                        component_ref=ref,cve=cve,component_name=c.get('name'),bom_version=c.get('version'),
                        cpe=c.get('cpe'),association_resolved=ref in components,
                        real_actual_affected=None,real_asset_ref=None,
                        input_semantics='Original advisory/NVD product-version candidate; installed build and operating state are unverified.')
                    unbound+=ref not in components
                    candidate_stream.write(encoded(candidate)+b'\n')
                    by_cve[cve]+=1;by_bom[asset['asset_id']]+=1
                    candidate_counts['component_bound' if ref in components else 'unbound']+=1
                    for w in worlds:
                        prediction_stream.write(encoded(dict(candidate_id=cid,world_id=w['id'],identified_positive=True,
                            input_projection='BOM component and declared CVE only',llm_used=False))+b'\n')
            receipt=dict(bom_id=asset['asset_id'],file=filename,sha256=actual_sha,
                hash_matches_index=actual_sha==asset['sbom_sha256'],components=len(components),
                cves=len(declarations),candidates=sum(candidate_counts.values())-before)
            receipt_stream.write(encoded(receipt)+b'\n');source_receipts.append(receipt)
    if hash_mismatches:raise ValueError('Original BOM hashes changed: '+str(hash_mismatches[:10]))
    if all_cves!=expected_cves:raise ValueError('Full target population differs: '+str(sorted(expected_cves-all_cves)[:20]))
    # Generate private truth with an implementation independent of matching and
    # model verdicts. No public input contains an impact status or world facts.
    total_candidates=sum(candidate_counts.values())
    truth=Counter();branch_truth={True:Counter(),False:Counter()}
    with (output/'identified_candidates.jsonl').open('rb') as stream, (output/'gold.private.jsonl').open('wb') as gold:
        for line in stream:
            candidate=json.loads(line)
            for w in worlds:
                actual=controlled_truth(w['physical_facts'])
                row=dict(candidate_id=candidate['id'],world_id=w['id'],actual_affected=actual,
                    synthetic=True,actual_state_origin='Controlled hypothetical physical facts',
                    cve_specific_semantic_accuracy_verified=False,field_verified=False)
                gold.write(encoded(row)+b'\n');truth[actual]+=1;branch_truth[w['source_code_available']][actual]+=1
    # Join exact candidate/world keys from the published prediction and truth
    # files. Do not use generated counts as a substitute for scoring outputs.
    labels=[];seen=set()
    with (output/'predictions.jsonl').open('rb') as p, (output/'gold.private.jsonl').open('rb') as g:
        for pl,gl in zip(p,g):
            pred,gold=json.loads(pl),json.loads(gl)
            key=(pred['candidate_id'],pred['world_id'])
            if key!=(gold['candidate_id'],gold['world_id']) or key in seen:raise ValueError('Mismatched or duplicate prediction/gold key')
            assert pred['identified_positive'] is True
            seen.add(key);labels.append(gold['actual_affected'])
        assert p.readline()==g.readline()==b''
    assert len(labels)==total_candidates*len(worlds)
    # Full CVE/BOM coverage is proved with the actual scored rows, rather than
    # adding unrelated IDs to an unscored supplementary ledger.
    synthetic=score(labels)
    real=score([None]*total_candidates)
    report=dict(protocol=protocol['version'],coverage=dict(boms=len(assets),unique_cves=len(all_cves),
        bom_cve_pairs=bom_cve_pairs,identified_candidates=total_candidates,
        candidate_counts=dict(candidate_counts),unresolved_component_associations=unbound,
        synthetic_scored_cases=len(labels),source_branches=2,
        boms_without_declared_cves=sum(r['cves']==0 for r in source_receipts),
        excluded_boms=0,excluded_cves=0,original_bom_hash_mismatches=hash_mismatches,
        all_target_cves_have_scored_controlled_cases=all(by_cve[c]>0 for c in expected_cves)),
        synthetic_identification_baseline=synthetic,
        synthetic_by_source_branch={str(k):score([True]*v[True]+[False]*v[False]) for k,v in branch_truth.items()},
        real_asset_identification_precision=real,
        deployed_operational_vex_precision=None,deployed_model_inference_executed=False,
        interpretation_ko='전수 포함한 합성 통제환경의 식별 후보 기준선이다. 50%는 동일 BOM의 영향/비영향 환경을 1:1로 만든 설계값이며, 현장 성능 또는 배포 모델의 측정 정확도가 아니다. 실제 운영 정답이 없는 전체 데이터의 Precision과 85% 달성 여부는 미확정이다.',
        source_branch_limit='Source availability is a simulation branch; no real source code or patches were collected or tested.',
        no_cvss_or_source_match_as_impact_gold=True,
        per_cve_candidate_counts=dict(sorted(by_cve.items())))
    write(output/'report.json',report)
    write(output/'cve_population.json',dict(cves=sorted(all_cves),counts=dict(sorted(by_cve.items()))))
    artifact_names=['protocol.json','controlled_worlds.private.json','identified_candidates.jsonl',
                    'predictions.jsonl','gold.private.jsonl','bom_receipts.jsonl','cve_population.json','report.json']
    write(output/'artifact_hashes.json',{n:digest((output/n).read_bytes()) for n in artifact_names})
    html='''<!doctype html><html lang="ko"><meta charset="utf-8"><title>#4 Precision 전수 평가</title>
<style>body{font:17px/1.7 system-ui;max-width:1000px;margin:40px auto;padding:0 24px;color:#1d2733}table{border-collapse:collapse;width:100%}td,th{padding:12px;border:1px solid #ccd3df;text-align:left}.note{padding:20px;background:#fff1cf}code{overflow-wrap:anywhere}</style>
<h1>#4 Precision 전수 평가</h1><p>판정 기준: 컴포넌트 정보만으로 식별한 모든 CVE 후보를 양성으로 고정. Precision = TP/(TP+FP). 목표 ≥85%.</p>
<p class="note">합성 통제환경은 실제 성능 측정과 구분해야 합니다. 동일 BOM에 영향/비영향 환경을 1:1로 붙였으므로 50%는 실험 설계에서 정해진 기준선입니다. 배포된 #4 모델의 추론 정확도와 공인시험 통과를 주장하지 않습니다.</p>
<table><tr><th>항목</th><th>결과</th></tr>'''
    rows=[('원본 BOM',f'{len(assets):,}개'),('고유 CVE',f'{len(all_cves):,}개'),
        ('BOM–CVE 쌍',f'{bom_cve_pairs:,}건'),('컴포넌트–CVE 식별 후보',f'{total_candidates:,}건'),
        ('합성 통제환경 평가 행',f'{len(labels):,}건'),('합성 TP',f'{synthetic["TP"]:,}'),
        ('합성 FP',f'{synthetic["FP"]:,}'),('합성 식별 기준선 Precision','50.00% (설계상 1:1)'),
        ('현재 데이터의 실제 영향 정답','0건'),('실제 현장 Precision / 85% 달성 여부','산출 불가 / 미확정'),
        ('원본 바이트 해시 불일치 / 제외 CVE','0 / 0')]
    html+=''.join('<tr><th>'+escape(k)+'</th><td>'+escape(v)+'</td></tr>' for k,v in rows)
    html+='''</table><h2>정답의 생성과 한계</h2><p>원본 SBOM은 바꾸지 않았습니다. 각 식별 후보에 소스 확보 가능/불가 두 분기와 완전한 영향 경로 활성/부재 두 환경을 붙였습니다. 패치·실행 경로를 포함한 물리 상태는 명시적인 가상 전제입니다. 실제 CVE별 충분조건을 권고문에서 검증한 정답이 아닙니다. 동일한 환경 템플릿을 반복하므로 평가 행 수를 독립 현장 표본 수로 해석할 수 없습니다.</p>
<p>예측 파일은 모든 후보를 양성으로 저장한 후 정답과 ID로 대조했습니다. 운영 VEX의 최종 affected 출력으로 분모를 줄이지 않았고, 미분류·CPE 부재·컴포넌트 연결 미확정도 제거하지 않았습니다. CVE가 없는 BOM도 원본 목록과 해시 검증에 포함되며 가짜 CVE를 추가하지 않았습니다.</p>
<h2>파일</h2><ul><li><a href="report.json">전체 결과 JSON</a></li><li><a href="protocol.json">동결 평가 규약</a></li><li><a href="gold.private.jsonl">생성한 합성 정답</a></li><li><a href="identified_candidates.jsonl">전체 원본 식별 후보</a></li><li><a href="predictions.jsonl">필터 전 양성 예측</a></li><li><a href="bom_receipts.jsonl">3,881개 원본 BOM 해시 확인</a></li></ul></html>'''
    (output/'report.html').write_text(html,encoding='utf-8')
    print(json.dumps(dict(coverage=report['coverage'],synthetic=synthetic,real=real,output=str(output)),ensure_ascii=False,indent=2))


if __name__=='__main__':
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--output',type=Path,default=ROOT/'results/item4_precision_full_population_20261125')
    run(cli.parse_args().output.resolve())
