"""Source-grounded conditional gold without inventing missing CVE conditions.

Keep every candidate and the full target population. A small, explicitly
bounded literal manufacturer reference table supplies hypothetical scenarios;
all unsupported product/CVE scopes retain null labels in the denominator.
"""
from pathlib import Path
import argparse
from collections import Counter
from html import escape
import hashlib,json,sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from src.item4.evaluation.identified_impact_precision import score
from tools.item4.build_auto_vex_benchmark import REFERENCE


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def write(path,value):path.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf8')


def label(spec,release,configuration):
    """Literal reference labels, independent of production version/route logic."""
    if release=='unresolved':return None
    if release in ('fixed','unaffected'):return False
    states=[spec['dimensions'][k][configuration[k]] for k in spec['dimensions']]
    if spec['op']=='and':return all(states)
    if spec['op']=='or':return any(states)
    if spec['op']=='not':return not states[0]
    if spec['op']=='single':return states[0]
    raise ValueError('Unsupported reference connective')


def run(population,sources):
    output=population/'supplier_grounded'
    if output.exists():raise FileExistsError('Frozen gold already exists')
    output.mkdir()
    registry=json.loads((sources/'rules.json').read_bytes())
    pinned={}
    for sid,row in registry['sources'].items():
        source=json.loads((sources/row['file']).read_bytes())
        assert hashlib.sha256(source['text'].encode()).hexdigest()==row['sha256']
        pinned[sid]=source
    # Exact aliases only: a CVE mention in a Siemens/Ubuntu product does not
    # prove that its own running version is an OpenSSL or PAN-OS version.
    aliases={'OpenSSL':{'openssl','openssl library','openssl project openssl','openssl openssl'},
             'PAN-OS':{'pan os','panos','palo alto networks pan os','paloalto pan os'}}
    labels=[];coverage=Counter();per_cve={};by_reason=Counter();candidates=set();boms=set();cves=set()
    with (population/'identified_candidates.jsonl').open(encoding='utf8') as stream, \
         (output/'gold.private.jsonl').open('w',encoding='utf8') as gold, \
         (output/'operating_inputs.jsonl').open('w',encoding='utf8') as inputs:
        for line in stream:
            row=json.loads(line);cve=row['cve'];spec=REFERENCE.get(cve)
            candidates.add(row['id']);boms.add(row['bom_id']);cves.add(cve)
            name=' '.join(str(row['component_name']).lower().replace('-',' ').split())
            actual=None;context=None;refs=[]
            reason='No manually source-grounded CVE-specific reference; gold remains unknown.'
            if spec and name in aliases[spec['model']] and row['association_resolved']:
                rule=registry['rules'][cve]
                refs=[rule['source']]+rule['fix_sources']
                for ref in refs:
                    text=pinned[ref['source_id']]['text'];a,b=ref['span']
                    assert text[a:b]==ref['quote']
                # A deterministic hypothetical runtime may differ from the
                # unmodified BOM's reported/source-range version. This is
                # explicitly recorded, never asserted as a real installation.
                seed=int(hashlib.sha256((row['id']+':source-gold-v1').encode()).hexdigest(),16)
                versions=list(spec['versions']);version=versions[seed%len(versions)];seed//=len(versions)
                selected={}
                for key,options in spec['dimensions'].items():
                    choices=list(options);selected[key]=choices[seed%len(choices)];seed//=len(choices)
                context=dict(synthetic=True,source_code_available=False,runtime_version=version,
                    configuration=selected,scope='One hypothetical deployment of the identified component',
                    bom_version_preserved=row['bom_version'],
                    caveat='Manufacturer affected configuration modeled conditionally; no actual operating record or independent expert certification.')
                actual=label(spec,spec['versions'][version],selected)
                reason='Pinned manufacturer reference plus hypothetical runtime/configuration; independent expert review pending.'
                if actual is None:reason='Manufacturer-specific build membership is unresolved in the literal reference.'
                coverage['source_bound_candidates']+=1
            elif spec:
                reason='CVE has a manufacturer reference, but its version/conditions cannot be transferred to this component identity.'
            coverage['known' if actual is not None else 'unknown']+=1
            by_reason[reason]+=1;labels.append(actual);per_cve.setdefault(cve,[]).append(actual)
            gold.write(json.dumps(dict(candidate_id=row['id'],bom_id=row['bom_id'],component_ref=row['component_ref'],
                cve=cve,actual_affected=actual,synthetic=context is not None,real_asset_verified=False,
                independent_semantic_accuracy_verified=False,reason=reason,source_refs=refs),ensure_ascii=False)+'\n')
            inputs.write(json.dumps(dict(candidate_id=row['id'],context=context),ensure_ascii=False)+'\n')
    full=json.loads((population/'report.json').read_bytes())
    assert len(candidates)==full['coverage']['identified_candidates'] and len(cves)==12418
    result=score(labels)
    report=dict(kind='full-population-source-grounded-conditional-gold',population=full['coverage'],
        candidate_count=len(candidates),cves=len(cves),boms_with_candidates=len(boms),
        source_coverage=dict(coverage),metrics=result,
        per_cve={c:score(values) for c,values in sorted(per_cve.items())},reasons=dict(by_reason),
        full_population_exclusions=0,
        independent_real_asset_precision=None,model_rerun=False,
        positive_prediction='Every frozen BOM-component/CVE identification; final VEX status is not used for selection.',
        source_gold_limit='Conditional synthetic manufacturer-reference model; known labels still require independent semantic review and are not field truth.',
        unsupported_labels_policy='Retain null in all-candidate denominator; do not extrapolate reference rules to other CVEs/products.',
        source_hashes={p.name:sha(p) for p in sources.glob('*.json')},
        code_hashes={str(p.relative_to(ROOT)):sha(p) for p in [Path(__file__),ROOT/'tools/item4/build_auto_vex_benchmark.py',ROOT/'src/item4/evaluation/identified_impact_precision.py']})
    write(output/'report.json',report)
    summary=dict(coverage=full['coverage'],source_grounded_metrics=result,source_coverage=dict(coverage),
        simulator_sanity_check=full['synthetic_identification_baseline'],
        primary_conclusion='All 3,881 BOMs and 12,418 CVEs are retained. Complete Precision and the 85% threshold remain unmeasured because source-grounded impact labels are incomplete. The separate 50% simulator check is fixed by construction and is not measured system performance.',
        source_grounded_report='supplier_grounded/report.json',real_asset_gold_count=0,model_inference_rerun=False)
    write(population/'evaluation_summary.json',summary)
    pct=result['judged_only_precision']
    rows=[('BOM / 고유 CVE','3,881 / 12,418'),('식별 후보',f'{len(candidates):,}건'),
        ('공급자 근거가 있는 합성 정답',f'{coverage["known"]:,}건'),('정답 미확정',f'{coverage["unknown"]:,}건'),
        ('부분 TP / FP',f'{result["TP"]:,} / {result["FP"]:,}'),
        ('정답이 있는 부분의 Precision',f'{100*pct:.2f}%' if pct is not None else '정의되지 않음'),
        ('전체 Precision / 85% 달성','미확정 / 판정 불가'),('실제 현장 정답','0건'),
        ('제외 BOM / CVE','0 / 0')]
    html='''<!doctype html><html lang="ko"><meta charset="utf-8"><title>#4 전수 Precision 평가 결과</title>
<style>body{font:17px/1.7 system-ui;max-width:1050px;margin:40px auto;padding:0 24px;color:#223}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd;padding:12px;text-align:left}.note{background:#fff0c9;padding:20px}a{color:#3652a0}</style>
<h1>#4 전수 Precision 평가</h1><p>분모: SBOM 컴포넌트 정보로 식별된 모든 후보. 최종 affected 판정만 선별하지 않음. 공인시험 문서의 목표는 85% 이상.</p>
<p class="note">전체 Precision은 아직 확정할 수 없습니다. 아래 부분 점수는 제조사 권고문을 적용한 합성 운영 환경만의 값이며, 12,418개 CVE 전체의 현장 성능이나 배포 모델 정확도가 아닙니다.</p><table><tr><th>항목</th><th>값</th></tr>'''
    html+=''.join('<tr><th>'+escape(k)+'</th><td>'+escape(v)+'</td></tr>' for k,v in rows)
    html+='''</table><h2>생성한 정답</h2><p>원본 BOM 3,881개의 바이트와 식별 후보를 고정했습니다. OpenSSL 및 PAN-OS의 제조사 조건과 수정 버전의 수동 기준표를 적용할 수 있는 컴포넌트에는 합성 실행 버전·설정과 조건부 정답을 생성했습니다. 근거가 없는 CVE나 다른 제품에 해당 조건을 전파하지 않았습니다. 미확정 항목도 전체 분모에 보존했습니다.</p>
<p><a href="supplier_grounded/report.json">전수 정답·정밀도 집계</a> · <a href="supplier_grounded/gold.private.jsonl">근거·정답 원장</a> · <a href="evaluation_summary.json">통합 요약 JSON</a></p>
<h2>통제 시뮬레이터 검사</h2><p>별도로 모든 식별 후보에 영향/비영향 환경을 1:1로 구성한 891,224행의 검사도 저장했습니다. 여기서의 50%는 설계로 정해진 값이며 성능 측정 결과로 사용하면 안 됩니다. 실제 코드 수집·패치 검증 또는 배포 모델 추론은 이번 집계에서 실행하지 않았습니다.</p>
<h2>근거</h2><p><a href="https://openssl-library.org/news/secadv/20140605.txt">OpenSSL 2014-06-05</a> · <a href="https://openssl-library.org/news/secadv/20140407.txt">Heartbleed</a> · <a href="https://security.paloaltonetworks.com/CVE-2024-3400">PAN-OS CVE-2024-3400</a></p></html>'''
    (population/'evaluation.html').write_text(html,encoding='utf8')
    print(json.dumps(dict(metrics=result,coverage=dict(coverage)),ensure_ascii=False))


if __name__=='__main__':
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--population',type=Path,default=ROOT/'results/item4_precision_full_population_20261125')
    cli.add_argument('--sources',type=Path,default=ROOT/'results/item4_precision_20261125/supplier_sources')
    args=cli.parse_args();run(args.population,args.sources)
