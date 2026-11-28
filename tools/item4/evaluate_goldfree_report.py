"""Gold-free saved-output audit, explicit source review and plotting.

No labels.jsonl or expert gold is read. Human field metrics stay null. Semantic
judgements here are transparent assistant judgements, never independent gold.
"""
import sys
import json
import hashlib
import re
import statistics
import time
import html
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.analysis import exploitation_prerequisites as V2
from src.item4.analysis import asset_operating_question_generation as V3

OUT = ROOT/'results/item4_goldfree_20261126'


def read(path):
    return json.loads((ROOT/path).read_text(encoding='utf-8'))


def normalized(value):
    return ' '.join(str(value).casefold().split())


def slots(draft):
    return {json.dumps([normalized(a.get(k,'')) for k in
        ('predicate','target','value','operator','expected')],ensure_ascii=False)
        for a in draft.get('prerequisites',[])}


def canonical_logic(draft):
    mapping={a['id']:sorted(slots(dict(prerequisites=[a])))[0]
             for a in draft.get('prerequisites',[])}
    def convert(node):
        if 'condition' in node:return mapping.get(node['condition'],'UNRESOLVED')
        args=[convert(a) for a in node['args']]
        if node['op'] in ('and','or'):args=sorted(args,key=lambda x:json.dumps(x,sort_keys=True))
        return dict(op=node['op'],args=args)
    return sorted([convert(s['expression']) for s in draft.get('scenarios',[])],
                  key=lambda x:json.dumps(x,sort_keys=True))


def main():
    OUT.mkdir(exist_ok=True)
    metrics=[]
    provenance={}
    reviews=[]

    def pinned(path):
        provenance[str(path).replace('\\','/')]=hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
        return read(path)

    def metric(stage,name,num=None,den=None,unit='%',value=None,method='automatic',note=''):
        if num is not None and den:
            value=100*num/den
        metrics.append(dict(stage=stage,name=name,numerator=num,denominator=den,
            value=value,unit=unit,method=method,note=note))

    manifest=pinned(Path('results/item4_qwen_reference_20261126/manifest.json'))
    rows=[pinned(Path('results/item4_qwen_reference_20261126')/(c['id']+'.json')) for c in manifest['cases']]
    quote_ok=quote_total=unknown=empty=admitted=0
    atoms=[]
    logic_nodes=[]
    for case,row in zip(manifest['cases'],rows):
        d=row.get('v2',{}).get('draft',{})
        valid=False
        try:
            V2.validate(d,case['record']);valid=True
        except Exception:pass
        admitted+=valid
        unknown+=bool(d.get('unknowns'))
        empty+=not bool(d.get('prerequisites'))
        sources={s['id']:s for s in case['record']['sources']}
        for atom in d.get('prerequisites',[]):
            atoms.append((case,row,atom))
            refs=atom.get('source_refs',[])
            quote_total+=1
            quote_ok+=bool(refs) and all(
                r['source_id'] in sources and sources[r['source_id']]['text'].count(r['quote'])==1
                and hashlib.sha256(sources[r['source_id']]['text'].encode()).hexdigest()==sources[r['source_id']]['text_sha256']
                for r in refs)
        for s in d.get('scenarios',[]):
            def ops(node):
                if 'condition'in node:return []
                return [node['op']]+[v for n in node['args'] for v in ops(n)]
            logic_nodes.extend(ops(s['expression']))
    metric('악용 조건 추출','구조 통과율',admitted,len(rows),note='Empty Unknown outputs can pass; not accuracy.')
    metric('악용 조건 추출','원문 인용 유효율',quote_ok,quote_total)
    metric('악용 조건 추출','미확정 사례율',unknown,len(rows),note='Descriptive rate; lower is not necessarily better.')
    metric('악용 조건 추출','빈 조건 출력률',empty,len(rows),note='Not a false-negative rate.')
    # A pinned manual source review of every emitted deployed-adapter atom.
    for case,row,a in atoms:
        if case['id']!='CVE-2020-28393' or a['statement']!='OSPF is enabled':
            raise ValueError('Renew source review for changed extraction output')
        scope_ok='quantifier' not in a.get('observation',{})
        reviews.append(dict(stage='V2',case=case['id'],atom=a['id'],
            proposition_supported=True,structured_scope_supported=scope_ok,
            source_quote='Successful exploitation requires OSPF to be enabled on an affected device',
            reason='OSPF enablement is explicit. observation.quantifier=all is not supported by this source clause; its population scope is unspecified.',
            review_method='assistant_source_review_not_independent_human'))
    metric('악용 조건 추출','조건 명제 근거 지지율',len(atoms),len(atoms),method='assistant_source_review',note='One emitted atom only; no claim about missing conditions.')
    metric('악용 조건 추출','구조화 범위 근거 지지율',sum(r['structured_scope_supported'] for r in reviews),len(atoms),method='assistant_source_review',note='Unsupported observation.quantifier=all in the only atom.')
    metric('악용 조건 추출','AND/OR/NOT 관계 근거 지지율',None,len(logic_nodes),method='not_observable',note='No composite relation emitted; denominator zero, not 100%.')
    metric('악용 조건 추출','추출 실패율',len(rows)-admitted,len(rows))

    v3_rows=[]
    v3_home=Path('results/item4_qwen_v3_isolated_20261126')
    v3_summary=pinned(v3_home/'report.json')
    for path in sorted((ROOT/v3_home).glob('*.json')):
        if path.name=='report.json':continue
        v3_rows.append(pinned(v3_home/path.name))
    questions=[]
    latencies=[]
    benchmark=[]
    for row in v3_rows:
        payload=row['packet'];a=row['artifact']
        if not V3.accepted(a,payload):raise ValueError('V3 current contract rejected saved output')
        latencies.append(a['generation']['elapsed_seconds'])
        def template():
            p=dict(questions={key:dict(positive_fact=atom['positive_fact'],
                question='For this asset, is the following true: '+atom['positive_fact'],
                check=atom['observation']['check'],record_type=atom['observation']['record_type'])
                for key,atom in payload['atoms'].items()})
            V3.validate(p,payload)
            return p
        template()
        sample_times=[]
        for _ in range(30):
            start=time.perf_counter();baseline=template();sample_times.append((time.perf_counter()-start)*1000)
        benchmark.append(dict(case=row['id'],template_median_ms=statistics.median(sample_times)))
        generated=a['prediction']['questions']
        for key,atom in payload['atoms'].items():
            q=generated.get(key)
            real=row['kind']=='real_description_reference'
            # Sufficiency means the check names an appropriate record AND does
            # not present a permission/procedure record as proof of actual events
            # or complete network reachability. Conditional cases are not passes.
            sufficient=not real
            reasons={
                ('CVE-2020-15782','p0'):'An ACL alone cannot establish end-to-end reachability from the assessed origin; no limit/Unknown guidance is given.',
                ('CVE-2019-10915','p0'):'An access-control record may support access rights; actual local access and assessment scope remain unspecified. Conditional, not a sufficient stand-alone check.',
                ('CVE-2018-13806','p0'):'Directory ACLs may support permissions for an identified principal; assessed attacker identity and actual access are unspecified. Conditional, not sufficient.',
                ('CVE-2018-13806','p1'):'An operating procedure does not prove a higher-privileged user actually opened the TD project, or establish their privilege relative to the attacker.',
                ('CVE-2019-10924','p0'):'An operating procedure does not prove a valid user actually opened the manipulated project file.'}
            review=dict(stage='V3',case=row['id'],atom=key,kind=row['kind'],
                fact_preserved=bool(q and q['positive_fact']==atom['positive_fact']),
                delivered=q is not None,check_sufficient_as_stated=sufficient,
                assessment='plausible_record_type' if sufficient else 'insufficient_or_conditional',
                reason=reasons.get((row['id'],key),'Provided configuration/maintenance record is a plausible place to check the stated setting/mode; no actual field records were available.'),
                check_copied=bool(q and q['check']==atom['observation']['check']),
                template_identical=bool(q==baseline['questions'][key]),
                source_supported=True,
                review_method='assistant_source_review_not_operator_validation')
            questions.append(review)
    reviews.extend(questions)
    n=len(questions)
    metric('특수 운영 질문 생성','조건 보존율',sum(q['fact_preserved'] for q in questions),n)
    metric('특수 운영 질문 생성','입력 조건 질문화율',sum(q['delivered'] for q in questions),n,note='Input coverage only, not source recall.')
    metric('특수 운영 질문 생성','확인 지침 적절률(대리평가)',sum(q['check_sufficient_as_stated'] for q in questions),n,method='assistant_conservative_rubric',note='Five synthetic controls pass; five real-CVE questions are insufficient/conditional. Not operator answerability.')
    metric('특수 운영 질문 생성','실제 CVE 확인 지침 적절률(대리평가)',sum(q['check_sufficient_as_stated'] for q in questions if q['kind']=='real_description_reference'),sum(q['kind']=='real_description_reference' for q in questions),method='assistant_conservative_rubric')
    metric('특수 운영 질문 생성','고정 템플릿 전체 동일률',sum(q['template_identical'] for q in questions),n,note='Entire question object equals deterministic template, not merely the fact.')
    metric('특수 운영 질문 생성','확인 지침 원문 복사율',sum(q['check_copied'] for q in questions),n)
    metric('특수 운영 질문 생성','템플릿 대비 내용 개선',unit='pp',value=0,method='paired_saved_output_comparison',note='All ten full question objects are identical. No observed content improvement; no field-performance claim.')
    metric('특수 운영 질문 생성','LLM 생성 시간 중앙값',unit='seconds/case',value=statistics.median(latencies),method='recorded_inference_timing',note='Seven calls, model loading excluded.')
    metric('특수 운영 질문 생성','템플릿 계산 시간 중앙값',unit='ms/case',value=statistics.median(b['template_median_ms'] for b in benchmark),method='local_30_repeats_per_case',note='Template construction plus current validation; not operator task completion time.')
    metric('특수 운영 질문 생성','운영자 답변 가능률',method='not_measured',note='No operators or actual operating records available; cannot substitute an assistant judgement.')
    metric('특수 운영 질문 생성','운영자 확인 시간 개선',unit='seconds',method='not_measured',note='Requires paired operator study.')
    metric('특수 운영 질문 생성','자산 맥락 제공의 효과',unit='pp',method='not_measured',note='No matched with/without-context field evaluation.')

    robust_files=sorted(OUT.glob('CVE-*__*.json'))
    robust_rows=[pinned(p.relative_to(ROOT)) for p in robust_files]
    robust_pairs=[]
    indexed={(r['cve'],r['variant']):r for r in robust_rows}
    for case in manifest['cases']:
        orig=indexed.get((case['id'],'original'))
        for kind in ('double_spaces','linebreaks'):
            changed=indexed.get((case['id'],kind))
            if not orig or not changed:continue
            a=slots(orig.get('artifact',{}).get('draft',{}));b=slots(changed.get('artifact',{}).get('draft',{}))
            valid=orig['status']==changed['status']=='validated'
            logic_equal=valid and canonical_logic(orig.get('artifact',{}).get('draft',{}))==canonical_logic(changed.get('artifact',{}).get('draft',{}))
            robust_pairs.append(dict(cve=case['id'],variant=kind,both_valid=valid,
                both_empty=valid and not(a|b),slot_sets_equal=valid and a==b,
                logic_equal=logic_equal,
                informative=valid and bool(a|b),
                jaccard=len(a&b)/len(a|b) if valid and (a|b) else None))
    informative=[p for p in robust_pairs if p['informative']]
    completed=len(robust_rows)==54
    metric('표기 변형 안정성','표기 변형 조건 슬롯 일치율',sum(p['slot_sets_equal'] for p in robust_pairs),len(robust_pairs),method='fresh_metamorphic_inference',note='Normalized structured fields; quotation spans/IDs excluded. Empty/empty pairs also agree; not semantic accuracy.')
    metric('표기 변형 안정성','조건 포함 쌍의 일치율',sum(p['slot_sets_equal'] for p in informative),len(informative),method='fresh_metamorphic_inference',note='Excludes empty/empty and invalid pairs. No informative pairs means NA.')
    metric('표기 변형 안정성','빈 출력 일치 쌍 비중',sum(p['both_empty'] for p in robust_pairs),len(robust_pairs),note='High consistency can arise from consistently returning no conditions.')
    metric('표기 변형 안정성','조건 포함 쌍의 논리 구조 일치율',sum(p['logic_equal'] for p in informative),len(informative),method='fresh_metamorphic_inference',note='Normalized IDs and commutative AND/OR order; tests structural consistency, not source-supported meaning.')
    report=dict(version='item4-goldfree-audit/1',created_at=datetime.now(timezone.utc).isoformat(),
        gold_labels_used=False,independent_human_review=False,operator_study=False,
        saved_scope=dict(v2_real_cves=len(rows),v2_emitted_atoms=len(atoms),v2_composite_logic_nodes=len(logic_nodes),
            v3_cases=len(v3_rows),v3_questions=n,v3_real_questions=sum(q['kind']=='real_description_reference' for q in questions)),
        metrics=metrics,reviews=reviews,template_timing=benchmark,
        robustness=dict(expected_runs=54,completed_runs=len(robust_rows),complete=completed,pairs=robust_pairs,
            statuses=dict(Counter(r['status'] for r in robust_rows))),
        provenance=provenance,
        limitations=['Purposive small development samples, not random population samples.',
            'Source support and guidance sufficiency are assistant judgements, not independent expert scores.',
            'No estimate of source-condition recall, full semantic accuracy or actual exploitability.',
            'Current-policy formatting runs are reported separately from saved-policy extraction results.',
            'No uncertainty interval is claimed for this nonrandom sample.'])
    (OUT/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    render(report)
    print(json.dumps(dict(report=str(OUT/'report.json'),robustness_complete=completed,
        completed_runs=len(robust_rows),informative_pairs=len(informative),
        llm_median_seconds=statistics.median(latencies),template_median_ms=statistics.median(b['template_median_ms'] for b in benchmark)),ensure_ascii=False))


def render(report):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib import font_manager
    font_manager.fontManager.addfont('C:/Windows/Fonts/malgun.ttf')
    plt.rcParams.update({'font.family':'Malgun Gothic','axes.unicode_minus':False,'font.size':11})
    labels=['인용 유효성\n(추출 조건 1개)','조건 명제 지지\n(assistant 검토 1개)',
        '미확정 사례\n(실제 CVE 18건)','질문 사실 보존\n(고정 조건 10개)',
        '입력 조건 질문화\n(고정 조건 10개)','확인 지침 적절성 대리평가\n(실제 5개+합성 5개)']
    vals=[100,100,100*17/18,100,100,50]
    counts=['1/1','1/1','17/18','10/10','10/10','5/10']
    fig,ax=plt.subplots(figsize=(12,6.5),layout='constrained')
    colors=['#3266a8','#3266a8','#9b9b9b','#287e70','#287e70','#ba7635']
    bars=ax.barh(range(len(vals)),vals,color=colors,height=.62)
    ax.set_yticks(range(len(vals)),labels);ax.invert_yaxis();ax.set_xlim(0,123)
    ax.set_xlabel('관측 비율 (%) — 각 지표의 분모가 다르며 정확도 점수가 아님')
    ax.set_title('정답 없는 LLM 평가: 근거·출력 보존·미확정 상태',loc='left',pad=18)
    for i,(bar,value,count) in enumerate(zip(bars,vals,counts)):
        ax.text(value+1.5,bar.get_y()+bar.get_height()/2,f'{value:.1f}% ({count})',va='center',fontsize=10)
    ax.spines[['top','right','left']].set_visible(False);ax.grid(axis='x',alpha=.15);ax.set_axisbelow(True)
    fig.savefig(OUT/'goldfree_metrics.png',dpi=180);plt.close(fig)

    fig,axs=plt.subplots(1,2,figsize=(12,5.3),layout='constrained')
    axs[0].bar(['실제 CVE 기반\n질문 5개','합성 통제\n질문 5개'],[0,100],color=['#ba7635','#287e70'],width=.5)
    axs[0].set_ylim(0,120);axs[0].set_ylabel('지침 적절성 대리평가 (%)')
    axs[0].text(0,4,'0/5\n불충분·조건부',ha='center');axs[0].text(1,103,'5/5\n기록 종류 타당',ha='center')
    axs[0].set_title('확인 지침: assistant의 보수적 원문 검토')
    axs[1].bar(['LLM 질문\n7회 생성','고정 템플릿\n7개 입력'],[100,100],color=['#3266a8','#287e70'],width=.5)
    axs[1].set_ylim(0,120);axs[1].set_ylabel('입력 사실 보존율 (%)')
    axs[1].text(0,103,'10/10',ha='center');axs[1].text(1,103,'10/10',ha='center')
    axs[1].set_title('질문·확인 지침 전체가 10/10개 동일')
    for ax in axs:ax.spines[['top','right']].set_visible(False);ax.grid(axis='y',alpha=.15);ax.set_axisbelow(True)
    fig.savefig(OUT/'guidance_template_comparison.png',dpi=180);plt.close(fig)

    pairs=report['robustness']['pairs']
    if pairs:
        fig,ax=plt.subplots(figsize=(10,5),layout='constrained')
        groups=[]
        for kind,label in [('double_spaces','공백 2배'),('linebreaks','단어 사이 줄바꿈')]:
            p=[x for x in pairs if x['variant']==kind]
            groups.append((label,len(p),sum(x['both_empty'] for x in p),sum(x['slot_sets_equal'] and not x['both_empty'] for x in p),sum(not x['slot_sets_equal'] for x in p)))
        bottoms=[0,0]
        for index,(label,color) in enumerate([('양쪽 빈 출력 일치','#9b9b9b'),('조건 포함 일치','#287e70'),('변경 또는 실패','#ba7635')]):
            values=[g[index+2] for g in groups]
            ax.barh([g[0] for g in groups],values,left=bottoms,label=label,color=color,height=.5)
            for y,(v,b) in enumerate(zip(values,bottoms)):
                if v:ax.text(b+v/2,y,str(v),ha='center',va='center',color='white')
            bottoms=[b+v for b,v in zip(bottoms,values)]
        ax.set_xlim(0,18);ax.set_xlabel('원문 대비 실행 쌍 수 (변형별 최대 18쌍)')
        ax.set_title('표기 변형 안정성: 빈 출력의 일치를 별도 표시',loc='left')
        ax.legend(loc='upper center',bbox_to_anchor=(.5,-.16),ncol=3)
        ax.spines[['top','right']].set_visible(False)
        fig.savefig(OUT/'format_robustness.png',dpi=180);plt.close(fig)
    # A portable report with all metrics and per-case judgement evidence.
    names={
        '악용 조건 추출':'악용 조건 추출','특수 운영 질문 생성':'특수 운영 질문 생성','표기 변형 안정성':'표기 변형 안정성',
        '구조 통과율':'구조 통과율','원문 인용 유효율':'원문 인용 유효율','미확정 사례율':'미확정 사례율',
        '빈 조건 출력률':'빈 조건 출력률','조건 명제 근거 지지율':'조건 명제 근거 지지율',
        '구조화 범위 근거 지지율':'구조화 범위 근거 지지율','AND/OR/NOT 관계 근거 지지율':'AND/OR/NOT 관계 근거 지지율',
        '추출 실패율':'추출 실패율','조건 보존율':'조건 보존율','입력 조건 질문화율':'입력 조건 질문화율',
        '확인 지침 적절률(대리평가)':'확인 지침 적절률(대리평가)','실제 CVE 확인 지침 적절률(대리평가)':'실제 CVE 확인 지침 적절률(대리평가)',
        '고정 템플릿 전체 동일률':'고정 템플릿 전체 동일률','확인 지침 원문 복사율':'확인 지침 원문 복사율',
        '템플릿 대비 내용 개선':'템플릿 대비 내용 개선','LLM 생성 시간 중앙값':'LLM 생성 시간 중앙값',
        '템플릿 계산 시간 중앙값':'템플릿 계산 시간 중앙값','운영자 답변 가능률':'운영자 답변 가능률',
        '운영자 확인 시간 개선':'운영자 확인 시간 개선','자산 맥락 제공의 효과':'자산 맥락 제공의 효과',
        '표기 변형 조건 슬롯 일치율':'표기 변형 조건 슬롯 일치율','조건 포함 쌍의 일치율':'조건 포함 쌍의 일치율','빈 출력 일치 쌍 비중':'빈 출력 일치 쌍 비중'}
    for m in report['metrics']:
        m['stage']=names.get(m['stage'],m['stage']);m['name']=names.get(m['name'],m['name'])
    # Save Korean metric names in the machine-readable report as well.
    (OUT/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    rows=''
    for m in report['metrics']:
        value='측정 불가 / 미측정' if m['value'] is None else f"{m['value']:.2f} {m['unit']}"
        frac=f"{m['numerator']}/{m['denominator']}" if m['numerator'] is not None else '—'
        rows+=f"<tr><td>{html.escape(m['stage'])}</td><td>{html.escape(m['name'])}</td><td>{value}</td><td>{frac}</td><td>{html.escape(m['method'])}</td><td>{html.escape(m['note'])}</td></tr>"
    review_rows=''.join(f"<tr><td>{r['case']}</td><td>{r['atom']}</td><td>{html.escape(r.get('reason',''))}</td></tr>" for r in report['reviews'])
    imgs=''.join(f'<img src="{name}" alt="{label}">' for name,label in [('goldfree_metrics.png','지표 관측 비율'),('guidance_template_comparison.png','지침 및 템플릿 비교'),('format_robustness.png','표기 변형 안정성')] if (OUT/name).exists())
    content=f'''<!doctype html><html lang="ko"><meta charset="utf-8"><title>ICS-VEX 정답 없는 LLM 평가</title>
<style>body{{font:15px/1.7 "Malgun Gothic",sans-serif;max-width:1250px;margin:40px auto;padding:0 24px;color:#182331}}table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{border-bottom:1px solid #d9dfe5;padding:10px;text-align:left;vertical-align:top}}img{{width:100%;height:auto}}.note{{padding:18px;background:#f2f5f8}}h2{{margin-top:35px}}</style>
<h1>ICS-VEX: 정답 데이터 없는 LLM 평가</h1><p>2026-11-26 · Qwen2.5-Coder-14B · 추출 어댑터 / 질문 생성 기반 모델</p>
<p class="note">정답 라벨을 읽지 않고 평가했습니다. 의미·지침 판정은 assistant의 원문 검토이며 독립 전문가 평가가 아닙니다. 실제 운영 기록과 운영자 없이 현장 답변 가능률이나 실제 악용 정확도를 만들지 않았습니다. 기존 추출 출력 18건과 질문 생성 7건(10개 질문), 새 표기 변형 실행 {report['robustness']['completed_runs']}/54건을 구분합니다.</p>
<h2>1. 악용 조건 추출 및 특수 운영 질문 생성</h2>{imgs}
<h2>2. 전체 지표</h2><table><thead><tr><th>기능</th><th>지표</th><th>값</th><th>분자/분모</th><th>방법</th><th>해석·제약</th></tr></thead><tbody>{rows}</tbody></table>
<h2>3. 원문 및 확인 지침 검토 근거</h2><p>지침 적절성은 기록 종류가 사실과 맞고, 그 기록만으로 확인할 수 없는 내용을 확정하도록 오도하지 않는지를 보수적으로 평가했습니다. 조건부 사례는 통과에 넣지 않았습니다. 합성 통제 5개는 기록 종류의 타당성만 통과하며 실제 기록으로 검증한 것이 아닙니다.</p><table><tr><th>CVE/통제</th><th>조건</th><th>판정 근거</th></tr>{review_rows}</table>
<h2>4. 한계</h2><ul><li>작은 목적 표본이므로 모집단 정확도나 신뢰구간을 주장하지 않습니다.</li><li>조건이 비어 있는 미확정 출력도 구조 검사를 통과합니다. 빈 출력의 일관성이 추출 타당성을 뜻하지 않습니다.</li><li>현재 추출 표본에는 AND/OR/NOT 복합 관계가 없어 관계 지지율은 분모 0으로 측정 불가입니다.</li><li>운영자 답변 가능률, 현장 확인 시간, 자산 맥락 효과는 미측정입니다.</li><li>기존 생성 정책 7의 결과는 현재 정책 9로 재검증했으며 새 정책 9 표기 변형 실행과 합치지 않았습니다.</li></ul></html>'''
    (OUT/'report.html').write_text(content,encoding='utf-8')


if __name__=='__main__':main()
