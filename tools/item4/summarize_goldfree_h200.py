"""Gold-free H200 measurements and transparent assistant source-review scores."""
import sys
import json
import html
import hashlib
import statistics
import time
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from src.item4.analysis import asset_operating_question_generation as V3
from tools.item4.evaluate_goldfree_report import slots,canonical_logic
OUT=ROOT/'results/item4_goldfree_h200_20261126'


def main():
    home=OUT/'outputs'
    read=lambda p:json.loads(p.read_text(encoding='utf-8'))
    status=read(home/'status.json')
    if status['state']!='complete':raise ValueError('H200 run is not complete')
    manifest=read(home/'manifest.json')
    if 'H200' not in manifest['identity']['device']:raise ValueError('Unexpected device')
    v2=[read(p) for p in sorted(home.glob('CVE-*__original.json'))]
    variants=[read(p) for p in sorted(home.glob('CVE-*__*.json'))]
    v3=[read(p) for p in sorted(home.glob('v3__*__with_context.json'))]
    ablations=[read(p) for p in sorted(home.glob('v3__*__without_context.json'))]
    if (len(v2),len(variants),len(v3),len(ablations))!=(18,54,7,7):raise ValueError('Missing runs')
    reviews=read(OUT/'assistant_source_review.json')
    review_v2={(r['cve'],r['atom']):r for r in reviews['v2']}
    review_v3={(r['case'],r['atom']):r for r in reviews['v3']}
    metrics=[]
    def metric(stage,name,num=None,den=None,value=None,unit='%',method='자동 검사',note=''):
        if num is not None and den:value=100*num/den
        metrics.append(dict(stage=stage,name=name,numerator=num,denominator=den,value=value,unit=unit,method=method,note=note))
    atoms=[];logic_relations=[];quote_pass=[]
    for row in v2:
        d=row.get('artifact',{}).get('draft',{})
        sources={s['id']:s for s in row['record']['sources']}
        for a in d.get('prerequisites',[]):
            r=review_v2[(row['cve'],a['id'])]
            if r['statement']!=a['statement']:raise ValueError('Renew manual source review')
            atoms.append(r)
            refs=a['source_refs']
            quote_pass.append(bool(refs) and all(x['source_id'] in sources and sources[x['source_id']]['text'].count(x['quote'])==1 and hashlib.sha256(sources[x['source_id']]['text'].encode()).hexdigest()==sources[x['source_id']]['text_sha256'] for x in refs))
        for s in d.get('scenarios',[]):
            def collect(n):
                if 'condition'in n:return []
                return [n['op']]+[o for a in n['args'] for o in collect(a)]
            logic_relations.extend(collect(s['expression']))
    metric('조건 추출','원문 인용 유효율',sum(quote_pass),len(quote_pass),note='추출된 조건에 한정. 누락을 측정하지 않음.')
    metric('조건 추출','조건 명제 근거 지지율',sum(a['proposition_supported'] for a in atoms),len(atoms),method='assistant 원문 검토',note='독립 전문가 지표가 아님. 대상·상태·필요성을 검토.')
    metric('조건 추출','추출 시나리오의 조건·미확정 보존율',sum(a['scenario_preserves_source_conditions'] for a in atoms),len(atoms),method='assistant 원문 검토',note='추출한 시나리오에 한해 원문에 명시된 추가 조건이 표현되거나 미확정으로 남았는지 검토. 전체 원문 Recall 아님.')
    metric('조건 추출','범위 한정어 검토 필요율',sum(not a['structured_scope_supported'] for a in atoms),len(atoms),method='assistant 원문 검토',note='원문에서 집합 범위가 특정되지 않은 observation.quantifier 등. 실제 판정 영향은 별도 검증 필요.')
    metric('조건 추출','AND/OR/NOT 관계 근거 지지율',den=len(logic_relations),method='관측된 관계가 없으면 측정 불가',note='단일 조건 leaf는 복합 관계 정확도의 분모가 아님.')
    unknown=sum(bool(r.get('artifact',{}).get('draft',{}).get('unknowns')) for r in v2)
    failed=sum(r['status']!='validated' for r in v2)
    metric('조건 추출','미확정 설명이 있는 CVE 비율',unknown,len(v2),note='해소되지 않은 원문·범위 문제를 포함. 실패율과 별도.')
    metric('조건 추출','빈 조건 출력률',sum(not r.get('artifact',{}).get('draft',{}).get('prerequisites') for r in v2),len(v2),note='실패를 포함. 미추출률·FN으로 해석하지 않음.')
    metric('조건 추출','추출 실패율',failed,len(v2),note='검증 거부·추론 오류도 분모에 유지.')
    index={(r['cve'],r['variant']):r for r in variants}
    pairs=[]
    for r in v2:
        for kind in ['double_spaces','linebreaks']:
            b=index[(r['cve'],kind)]
            a_slots=slots(r.get('artifact',{}).get('draft',{}));b_slots=slots(b.get('artifact',{}).get('draft',{}))
            valid=r['status']==b['status']=='validated'
            both_empty=valid and not(a_slots|b_slots)
            same=valid and a_slots==b_slots
            informative=valid and bool(a_slots|b_slots)
            logic_same=valid and canonical_logic(r.get('artifact',{}).get('draft',{}))==canonical_logic(b.get('artifact',{}).get('draft',{}))
            pairs.append(dict(cve=r['cve'],variant=kind,valid=valid,both_empty=both_empty,
                informative=informative,slots_equal=same,logic_equal=logic_same,
                original_atoms=len(a_slots),variant_atoms=len(b_slots)))
    informative=[p for p in pairs if p['informative']]
    metric('조건 추출','표기 변형 조건 슬롯 일치율',sum(p['slots_equal'] for p in pairs),len(pairs),method='H200 새 추론 54건',note='유형·대상·값·비교연산·기대값의 정규화 일치. 인용/ID/문장 표현은 제외. 빈 출력 일치 포함.')
    metric('조건 추출','조건 포함 쌍의 슬롯 일치율',sum(p['slots_equal'] for p in informative),len(informative),method='H200 새 추론',note='양쪽 빈 출력·실패 쌍 제외. 정규화한 필드의 일치이며 의미 동등성 판정이 아님.')
    metric('조건 추출','조건 포함 쌍의 논리 구조 일치율',sum(p['logic_equal'] for p in informative),len(informative),method='H200 새 추론',note='조건 ID와 AND/OR 순서를 정규화. 원문 관계의 정확도와 별개.')
    metric('조건 추출','양쪽 빈 출력 일치 쌍 비율',sum(p['both_empty'] for p in pairs),len(pairs),note='안정성 점수가 빈 출력 때문에 높아지는지 확인.')

    question_rows=[];times=[];template_times=[];paired_context=[]
    context_index={r['id']:r for r in ablations}
    for r in v3:
        p=r['packet'];artifact=r.get('artifact',{})
        pred=artifact.get('prediction',{}).get('questions',{})
        if artifact:times.append(artifact['generation']['elapsed_seconds'])
        baseline=dict(questions={k:dict(positive_fact=a['positive_fact'],question='For this asset, is the following true: '+a['positive_fact'],check=a['observation']['check'],record_type=a['observation']['record_type']) for k,a in p['atoms'].items()})
        V3.validate(baseline,p)
        for _ in range(30):
            start=time.perf_counter()
            b=dict(questions={k:dict(positive_fact=a['positive_fact'],question='For this asset, is the following true: '+a['positive_fact'],check=a['observation']['check'],record_type=a['observation']['record_type']) for k,a in p['atoms'].items()})
            V3.validate(b,p)
            template_times.append((time.perf_counter()-start)*1000)
        for k,a in p['atoms'].items():
            q=pred.get(k);review=review_v3[(r['id'],k)]
            if review['check']!=(q or {}).get('check'):raise ValueError('Renew manual question review')
            row=dict(case=r['id'],atom=k,kind=r['kind'],delivered=q is not None,
                fact_preserved=bool(q and q['positive_fact']==a['positive_fact']),
                contract_pass=bool(artifact and V3.accepted(artifact,p)),
                check_copied=bool(q and q['check']==a['observation']['check']),
                template_equal=q==baseline['questions'][k],review=review)
            question_rows.append(row)
        without=context_index[r['id']]
        wp=without.get('artifact',{}).get('prediction',{}).get('questions',{})
        paired_context.append(dict(case=r['id'],both_valid=r['status']==without['status']=='validated',
            output_equal=pred==wp,checks_changed=sum(pred.get(k,{}).get('check')!=wp.get(k,{}).get('check') for k in p['atoms']),
            atoms=len(p['atoms'])))
    n=len(question_rows)
    metric('질문 생성','조건 보존율',sum(q['fact_preserved'] for q in question_rows),n,note='고정 사실의 정확 일치. 원문 조건 전체의 보존율이 아님.')
    metric('질문 생성','입력 조건 질문화율',sum(q['delivered'] for q in question_rows),n,note='주어진 조건만 분모로 사용. 추출 누락 복구를 측정하지 않음.')
    metric('질문 생성','확인 지침 적절률(대리평가)',sum(q['review']['guidance_sufficient'] for q in question_rows),n,method='assistant 보수적 원문 검토',note='실제 기록·운영자 확인이 없는 탐색적 평가. 조건부는 통과에 포함하지 않음.')
    reals=[q for q in question_rows if q['kind']=='real_description_reference']
    metric('질문 생성','실제 CVE 지침 적절률(대리평가)',sum(q['review']['guidance_sufficient'] for q in reals),len(reals),method='assistant 보수적 원문 검토')
    metric('질문 생성','고정 템플릿 전체 동일률',sum(q['template_equal'] for q in question_rows),n,note='질문 객체 전체를 비교. 사실·질문·확인 방법·기록 종류 포함.')
    metric('질문 생성','확인 지침 원문 복사율',sum(q['check_copied'] for q in question_rows),n)
    llm_guidance=sum(q['review']['guidance_sufficient'] for q in question_rows)
    base_guidance=sum(q['review']['template_guidance_sufficient'] for q in question_rows)
    metric('질문 생성','템플릿 대비 지침 적절률 차이',value=100*(llm_guidance-base_guidance)/n,unit='pp',method='동일 입력 10개 쌍 비교',note='assistant 지침 평가의 차이. 현장 성과 차이 아님.')
    metric('질문 생성','LLM 생성 시간 중앙값',value=statistics.median(times) if times else None,unit='초/호출',method='H200 생성 로그',note='모델 로딩 제외. 7회 생성 중 중앙값. 공유 GPU·제약 디코딩 환경의 관측값이며 전용 GPU 속도 벤치마크가 아님.')
    metric('질문 생성','템플릿 생성·검증 시간 중앙값',value=statistics.median(template_times),unit='ms/호출',method='로컬 CPU 반복 측정',note='각 입력 30회. 하드웨어가 다르므로 속도 배수는 주장하지 않음.')
    metric('질문 생성','자산 맥락 제거 시 출력 변경률',sum(not p['output_equal'] for p in paired_context),len(paired_context),method='H200 맥락 포함/제거 7쌍',note='민감도 검사. 출력 변화가 개선이나 악화를 뜻하지 않음.')
    metric('질문 생성','운영자 답변 가능률',method='미측정',note='현장 운영자·실제 운영 기록 부재. assistant 판정으로 대체하지 않음.')
    metric('질문 생성','운영자 확인 시간 개선',unit='초',method='미측정',note='같은 현장 조건의 운영자 비교 실험 필요.')
    metric('질문 생성','자산 맥락 제공의 유용성 개선',unit='pp',method='미측정',note='맥락 제거 실험은 수행했지만 운영자 유용성 정답은 없음.')
    report=dict(version='goldfree-h200-final/1',created_at=datetime.now(timezone.utc).isoformat(),
        device=manifest['identity']['device'],model=manifest['identity'],policy=manifest['policy'],
        gold_used=False,independent_experts=0,operators=0,metrics=metrics,
        v2_cases=len(v2),v2_atoms=len(atoms),v2_composite_relations=len(logic_relations),
        robustness_runs=len(variants),robustness_pairs=pairs,
        v3_cases=len(v3),v3_questions=n,context_pairs=paired_context,
        question_rows=question_rows,source_reviews=reviews,
        input_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(home.glob('*.json'))},
        limitations=['작은 목적 표본이며 독립 블라인드 시험이 아님.',
            '원문 지지·지침 적절성은 assistant 검토이며 독립 전문가/운영자 평가가 아님.',
            '빈 출력의 일관성은 조건 추출 정확도가 아님. 전체 조건 누락률은 측정하지 않음.',
            '동일 모델·어댑터·토크나이저 바이트를 확인했지만 Linux SDPA와 기존 Windows 실행의 수치적 동일성을 주장하지 않음.',
            '실제 악용 가능성, 현장 답변 가능률, 운영자 시간 개선을 측정하지 않음.'])
    (OUT/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    render(report)
    print(json.dumps(dict(v2_cases=len(v2),v2_atoms=len(atoms),pairs=len(pairs),v3_questions=n,metrics=metrics),ensure_ascii=False))


def render(r):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib import font_manager
    font_manager.fontManager.addfont('C:/Windows/Fonts/malgun.ttf')
    plt.rcParams.update({'font.family':'Malgun Gothic','axes.unicode_minus':False,'font.size':11})
    index={m['name']:m for m in r['metrics']}
    names=['원문 인용 유효율','조건 명제 근거 지지율','미확정 설명이 있는 CVE 비율','조건 보존율','입력 조건 질문화율','확인 지침 적절률(대리평가)']
    labels=['원문 인용 유효율','조건 명제 지지 (assistant)','미확정 CVE 비율','고정 조건 보존율','입력 조건 질문화율','확인 지침 적절성 (assistant)']
    fig,ax=plt.subplots(figsize=(12,6),layout='constrained')
    values=[index[n]['value'] or 0 for n in names]
    bars=ax.barh(range(6),values,color=['#3266a8','#3266a8','#9b9b9b','#287e70','#287e70','#ba7635'],height=.6)
    ax.set_yticks(range(6),labels);ax.invert_yaxis();ax.set_xlim(0,126)
    for i,b in enumerate(bars):
        m=index[names[i]];label=f"{m['value']:.1f}% ({m['numerator']}/{m['denominator']})" if m['value'] is not None else '측정 불가'
        ax.text(b.get_width()+1.5,b.get_y()+b.get_height()/2,label,va='center',fontsize=10)
    ax.set_title('H200 · 동일 Qwen 가중치로 측정한 정답 없는 LLM 평가',loc='left',pad=15)
    ax.set_xlabel('관측 비율 (%) · 지표별 분모가 다르며 정확도 점수가 아님')
    ax.spines[['top','right','left']].set_visible(False);ax.grid(axis='x',alpha=.15);ax.set_axisbelow(True)
    fig.savefig(OUT/'metrics.png',dpi=180);plt.close(fig)
    fig,ax=plt.subplots(figsize=(11,4.5),layout='constrained')
    groups=[]
    for kind,label in [('double_spaces','공백 2배'),('linebreaks','단어 사이 줄바꿈')]:
        p=[p for p in r['robustness_pairs'] if p['variant']==kind]
        groups.append((label,sum(x['both_empty'] for x in p),sum(x['slots_equal'] and not x['both_empty'] for x in p),sum(not x['slots_equal'] for x in p)))
    bottoms=[0,0]
    for i,(label,color) in enumerate([('양쪽 빈 출력 일치','#9b9b9b'),('조건 포함 일치','#287e70'),('변경 또는 실패','#ba7635')]):
        v=[g[i+1] for g in groups]
        ax.barh([g[0] for g in groups],v,left=bottoms,color=color,label=label,height=.5)
        for y,(n,b) in enumerate(zip(v,bottoms)):
            if n:ax.text(b+n/2,y,str(n),ha='center',va='center',color='white')
        bottoms=[b+n for b,n in zip(bottoms,v)]
    ax.set_xlim(0,18);ax.set_xlabel('원문 대비 실행 쌍 수 · 변형별 18쌍')
    ax.set_title('입력 표기 변형 안정성 · 빈 출력 일치는 따로 표시',loc='left')
    ax.legend(loc='upper center',bbox_to_anchor=(.5,-.2),ncol=3);ax.spines[['top','right']].set_visible(False)
    fig.savefig(OUT/'robustness.png',dpi=180);plt.close(fig)
    fig,axs=plt.subplots(1,2,figsize=(12,5),layout='constrained')
    real=[q for q in r['question_rows'] if q['kind']=='real_description_reference']
    synthetic=[q for q in r['question_rows'] if q['kind']!='real_description_reference']
    counts=[sum(q['review']['guidance_sufficient'] for q in rows) for rows in [real,synthetic]]
    axs[0].bar(['실제 CVE 질문','합성 통제 질문'],[100*counts[0]/len(real),100*counts[1]/len(synthetic)],color=['#ba7635','#287e70'],width=.5)
    for i,(n,rows) in enumerate(zip(counts,[real,synthetic])):axs[0].text(i,100*n/len(rows)+3,f'{n}/{len(rows)}',ha='center')
    axs[0].set_title('확인 지침 적절성 · assistant 대리평가');axs[0].set_ylabel('통과 비율 (%)')
    baseline=sum(q['review']['template_guidance_sufficient'] for q in r['question_rows'])
    llm=sum(counts)
    axs[1].bar(['LLM 생성 지침','고정 템플릿 지침'],[100*llm/r['v3_questions'],100*baseline/r['v3_questions']],color=['#3266a8','#287e70'],width=.5)
    for i,n in enumerate([llm,baseline]):axs[1].text(i,100*n/r['v3_questions']+3,f"{n}/{r['v3_questions']}",ha='center')
    axs[1].set_title('동일 조건의 고정 템플릿과 비교');axs[1].set_ylabel('지침 적절성 대리평가 (%)')
    for ax in axs:ax.set_ylim(0,120);ax.spines[['top','right']].set_visible(False);ax.grid(axis='y',alpha=.15);ax.set_axisbelow(True)
    fig.savefig(OUT/'question_comparison.png',dpi=180);plt.close(fig)
    rows=''
    for m in r['metrics']:
        value='측정 불가 / 미측정' if m['value'] is None else f"{m['value']:.2f} {m['unit']}"
        fraction=f"{m['numerator']}/{m['denominator']}" if m['numerator'] is not None else '—'
        rows+=f"<tr><td>{m['stage']}</td><td>{m['name']}</td><td>{value}</td><td>{fraction}</td><td>{html.escape(m['method'])}</td><td>{html.escape(m['note'])}</td></tr>"
    details=''.join(f"<tr><td>{html.escape(x.get('cve',x.get('case','')))}</td><td>{x['atom']}</td><td>{html.escape(x['reason'])}</td></tr>" for x in r['source_reviews']['v2']+r['source_reviews']['v3'])
    content=f'''<!doctype html><html lang="ko"><meta charset="utf-8"><title>ICS-VEX H200 LLM 평가</title>
<style>body{{font:15px/1.7 "Malgun Gothic",sans-serif;max-width:1250px;margin:40px auto;padding:0 24px;color:#182331}}table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{border-bottom:1px solid #d9dfe5;padding:10px;text-align:left;vertical-align:top}}img{{width:100%;height:auto}}.note{{padding:18px;background:#f2f5f8}}h2{{margin-top:35px}}</style>
<h1>ICS-VEX: H200에서 수행한 정답 없는 LLM 평가</h1><p>2026-11-26 · Qwen2.5-Coder-14B · 추출 어댑터 / 질문 생성 기반 모델</p>
<p class="note">H200에서 새로 수행한 68개 실행: 실제 CVE 18건 × 원문·공백·줄바꿈 3형태 = 54건, 고정 조건 질문 생성 7건 × 자산 맥락 포함·제거 2형태 = 14건. 기반 가중치·추출 어댑터·토크나이저 해시를 현재 시스템과 대조했습니다. 정답 라벨을 사용하지 않았으며 의미·지침 판정은 assistant 원문 검토입니다. 운영자는 참여하지 않았습니다.</p>
<h2>1. 악용 조건 추출</h2><img src="metrics.png" alt="전체 지표"><img src="robustness.png" alt="표기 변형 안정성">
<h2>2. 특수 운영 질문 생성</h2><img src="question_comparison.png" alt="질문 지침과 템플릿 비교">
<h2>3. 전체 지표</h2><table><tr><th>기능</th><th>지표</th><th>값</th><th>분자/분모</th><th>방법</th><th>해석</th></tr>{rows}</table>
<h2>4. 원문 검토와 지침 판정 근거</h2><p>지침 판정은 기록 종류가 조건과 맞고, 그 기록만으로 확인할 수 없는 사실을 확정하도록 오도하지 않는지를 보수적으로 검토했습니다. 조건부 사례는 통과에 포함하지 않았습니다. 기준은 이 개발 감사의 탐색적 기준이며 사전 등록된 독립 평가가 아닙니다. 합성 통제의 통과는 기록 종류의 타당성으로, 실제 현장 기록을 통한 검증이 아닙니다.</p><table><tr><th>CVE/통제</th><th>조건</th><th>근거</th></tr>{details}</table>
<h2>5. 한계</h2><ul>{''.join('<li>'+html.escape(x)+'</li>' for x in r['limitations'])}</ul></html>'''
    (OUT/'report.html').write_text(content,encoding='utf-8')


if __name__=='__main__':main()
