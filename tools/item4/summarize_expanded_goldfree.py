"""Larger-cohort objective metrics and separately labelled cross-model proxies."""
import sys,json,hashlib,statistics,math,html
from pathlib import Path
from collections import Counter,defaultdict
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from tools.item4.evaluate_goldfree_report import slots,canonical_logic
from tools.item4.expanded_eval_contract import frozen_v3,baseline_questions,content_questions
V3=frozen_v3()
from tools.item4.expanded_question_views import effective_questions
OUT=ROOT/'results/item4_goldfree_expanded_20261126'


def main():
    load=lambda p:json.loads(p.read_text(encoding='utf-8'))
    inputs=load(OUT/'inputs.json');cohort=load(OUT/'cohort_manifest.json');home=OUT/'outputs'
    status=load(home/'status.json')
    named_status=load(home/'named_context_status.json') if (home/'named_context_status.json').exists() else {}
    complete=status.get('state')=='complete' and named_status.get('state')=='complete'
    originals=[load(p) for p in sorted(home.glob('CVE-*__original.json'))]
    variants=[load(p) for p in sorted(home.glob('CVE-*__*.json'))]
    original_questions=[load(p) for p in sorted(home.glob('v3__*__with_context.json'))]
    questions=effective_questions(OUT)
    named_rows=[load(p) for p in sorted(home.glob('v3__*__named_context.json'))]
    ablations={r['id']:r for r in [load(p) for p in sorted(home.glob('v3__*__without_context.json'))]}
    cases={c['id']:c for c in inputs['cases']};metric=[];atoms=[]
    def add(stage,name,num=None,den=None,value=None,unit='%',method='자동 검사',note=''):
        if num is not None and den:value=100*num/den
        metric.append(dict(stage=stage,name=name,numerator=num,denominator=den,value=value,unit=unit,method=method,note=note))
    n=len(originals);counts=Counter(r['status'] for r in originals)
    def failure_kind(r):
        if r['status']=='source_unavailable':return 'source_unavailable'
        if r['status']!='failed':return None
        e=r.get('error','')
        if '6144' in e or 'context' in e.lower():return 'context_limit'
        if 'HTTP' in e or 'timeout' in e.lower() or 'Connection' in e:return 'inference_system'
        if 'Invalid VEP' in e:return 'output_schema'
        return 'semantic_or_relation_guard'
    failure_counts=Counter(failure_kind(r) for r in originals if failure_kind(r))
    failed=sum(r['status']=='failed' for r in originals);missing=sum(r['status']=='source_unavailable' for r in originals)
    empty=sum(not r.get('artifact',{}).get('draft',{}).get('prerequisites') for r in originals)
    unknown=sum(bool(r.get('artifact',{}).get('draft',{}).get('unknowns')) for r in originals)
    add('조건 추출','원문 불가 비율',missing,n,note='제외하지 않고 모집단·표본에 유지.')
    add('조건 추출','추론·검증 실패율',failed,n)
    add('조건 추출','빈 조건 출력률(표본)',empty,n,note='원문 불가·실패 포함. FN/Recall이 아님.')
    add('조건 추출','미확정 설명 포함률',unknown,n)
    by_stratum=defaultdict(list)
    for r in originals:by_stratum[cases[r['cve']]['stratum']].append(r)
    weighted=None;weighted_ci=None
    if len(originals)==500:
        total=sum(cohort['sampling_frame_by_stratum'].values());estimate=variance=0
        for s,rs in by_stratum.items():
            population=cohort['sampling_frame_by_stratum'][s];m=len(rs);w=population/total
            p=sum(not r.get('artifact',{}).get('draft',{}).get('prerequisites') for r in rs)/m
            estimate+=w*p
            if m>1:variance+=w*w*(1-m/population)*p*(1-p)/(m-1)
        weighted=100*estimate;error=1.96*math.sqrt(variance)*100
        weighted_ci=[max(0,weighted-error),min(100,weighted+error)]
    add('조건 추출','빈 조건 출력률(층화 가중 추정)',value=weighted,method='포함 확률에 따른 층화 가중',note='기존 개발 18건을 제외한 12,400-CVE 프레임 추정. 정확도 추정이 아님.')
    quote_ok=0;logic_ops=[]
    for r in originals:
        src={s['id']:s for s in r['record'].get('sources',[])}
        def operators(node):
            if 'condition' in node:return []
            return [node['op']]+[v for child in node['args'] for v in operators(child)]
        for scenario in r.get('artifact',{}).get('draft',{}).get('scenarios',[]):logic_ops.extend(operators(scenario['expression']))
        for a in r.get('artifact',{}).get('draft',{}).get('prerequisites',[]):
            refs=a.get('source_refs',[])
            ok=bool(refs) and all(x['source_id'] in src and src[x['source_id']]['text'].count(x['quote'])==1 and hashlib.sha256(src[x['source_id']]['text'].encode()).hexdigest()==src[x['source_id']]['text_sha256'] for x in refs)
            quote_ok+=ok;atoms.append(dict(cve=r['cve'],id=a['id'],statement=a['statement'],quote_valid=ok))
    add('조건 추출','원문 인용 유효율',quote_ok,len(atoms),note='인용의 존재·해시 검사. 의미 지지율이 아님.')
    add('조건 추출','AND/OR/NOT 관계 근거 지지율',den=len(logic_ops),method='별도 관계 검토 필요',note='출력 복합 관계가 0개이면 분모 없음. 원문 전제 누락은 시나리오 직접 감사에서 별도로 검사.')
    manual_path=OUT/'assistant_source_review.json'
    manual=load(manual_path).get('rows',[]) if manual_path.exists() else []
    known={(a['cve'],a['id']) for a in atoms}
    reviewed=[a for a in manual if (a['cve'],a['atom']) in known]
    add('원문 직접 감사','추출 명제 근거 지지율',sum(a['proposition_supported'] for a in reviewed),len(reviewed),method='assistant 원문 검토',note='독립 전문가 정확도 아님. 검토 범위를 별도 표시.')
    add('원문 직접 감사','운영 사실형 조건 적합률',sum(a.get('operating_fact_valid',False) for a in reviewed),len(reviewed),method='assistant 원문·계약 검토',note='현재 운영 사실과 악용 필요성 규칙/숨은 공격자 상태를 구분. 현장 답변 가능률 아님.')
    add('원문 직접 감사','추출 시나리오 조건 보존율',sum(a['scenario_preserved'] for a in reviewed),len(reviewed),method='assistant 원문 검토',note='원문에 명시된 전제를 보존하거나 미확정으로 남기는지 검토. Recall 아님.')
    add('원문 직접 감사','추출 조건 감사 완료율',len(reviewed),len(atoms),method='검토 범위',note='해당 원문 500건에서 실제 출력된 조건만 대상.')
    index={(r['cve'],r['variant']):r for r in variants};pairs=[]
    for c in inputs['cases']:
        if not c['robustness_selected']:continue
        a=index.get((c['id'],'original'))
        for kind in ('double_spaces','linebreaks'):
            b=index.get((c['id'],kind))
            if not a or not b:continue
            x=slots(a.get('artifact',{}).get('draft',{}));y=slots(b.get('artifact',{}).get('draft',{}))
            valid=a['status']==b['status']=='validated'
            pairs.append(dict(cve=c['id'],variant=kind,both_valid=valid,both_empty=valid and not(x|y),
                informative=valid and bool(x|y),slots_equal=valid and x==y,
                logic_equal=valid and canonical_logic(a.get('artifact',{}).get('draft',{}))==canonical_logic(b.get('artifact',{}).get('draft',{})),
                source_unavailable=a['status']=='source_unavailable' or b['status']=='source_unavailable'))
    informative=[p for p in pairs if p['informative']]
    add('조건 추출','표기 변형 슬롯 일치율',sum(p['slots_equal'] for p in pairs),len(pairs),note='빈 출력 일치 포함. 출처 불가·실패는 일치 성공으로 세지 않음.')
    add('조건 추출','조건 포함 쌍의 슬롯 유지율',sum(p['slots_equal'] for p in informative),len(informative),note='분모가 0이면 미측정. 의미 동등성이 아닌 정규화 슬롯 일치.')
    add('조건 추출','조건 포함 쌍의 논리 구조 유지율',sum(p['logic_equal'] for p in informative),len(informative))
    add('조건 추출','양쪽 빈 출력 일치 쌍 비율',sum(p['both_empty'] for p in pairs),len(pairs))
    qrows=[];context_pairs=[]
    for r in questions:
        p=r['packet'];a=r.get('artifact',{});prediction=a.get('prediction',{}).get('questions',{})
        baseline=baseline_questions(p)
        for k,x in p['atoms'].items():
            q=prediction.get(k)
            try:V3.validate(dict(questions=baseline),p);baseline_valid=True
            except Exception:baseline_valid=False
            qrows.append(dict(cve=r['id'],atom=k,delivered=q is not None,
                preserved=bool(q and q['positive_fact']==x['positive_fact']),
                contract_pass=bool(a and V3.accepted(a,p)),template_equal=content_questions({k:q})==content_questions({k:baseline[k]}) if q else False,
                baseline_contract_pass=baseline_valid,
                check_copied=bool(q and q['check']==x['observation']['check'])))
        b=ablations.get(r['id'])
        if b and r.get('effective_context')=='named_context':
            bp=b.get('artifact',{}).get('prediction',{}).get('questions',{})
            context_pairs.append(dict(cve=r['id'],both_valid=r['status']==b['status']=='validated',same=prediction==bp))
    delivered=sum(q['delivered'] for q in qrows)
    add('질문 생성','조건 보존율',sum(q['preserved'] for q in qrows),delivered,note='수용된 질문 내 고정 사실 보존. 거부/실패는 질문화율에 반영. 원문 정답 정확도 아님.')
    add('질문 생성','입력 조건 질문화율',sum(q['delivered'] for q in qrows),len(qrows))
    add('질문 생성','출력 계약 통과율',sum(q['contract_pass'] for q in qrows),len(qrows))
    add('질문 생성','고정 템플릿 출력 계약 통과율',sum(q['baseline_contract_pass'] for q in qrows),len(qrows),note='동일 입력·동일 검증기로 비교. 모델 정확도가 아닌 출력 계약 준수.')
    add('질문 생성','고정 템플릿 전체 동일률',sum(q['template_equal'] for q in qrows),delivered,note='수용된 질문만 비교. 실패·거부는 질문화율과 계약 통과율에 반영.')
    add('질문 생성','확인 지침 복사율',sum(q['check_copied'] for q in qrows),delivered)
    identical_all=bool(qrows) and all(q['template_equal'] for q in qrows)
    add('질문 생성','템플릿 대비 내용 개선',value=0 if identical_all else None,unit='pp',method='동일 입력의 객체 대조',note='모든 출력이 템플릿과 같을 때만 내용 개선 0으로 표시. 다른 출력이 있으면 현장 유용성 개선을 자동 추정하지 않음.')
    cp=[p for p in context_pairs if p['both_valid']]
    add('질문 생성','맥락 제거 시 출력 변경률',sum(not p['same'] for p in cp),len(cp),note='유형 이름을 제공한 98건 중 양쪽 유효 실행만 비교. 유용성 개선 점수가 아님.')
    add('질문 생성','맥락 비교 실패율',sum(not p['both_valid'] for p in context_pairs),len(context_pairs))
    add('질문 생성','운영자 답변 가능률',method='미측정',note='현장 운영자·실제 운영 기록 없음.')
    add('질문 생성','운영자 확인 시간 개선',unit='초',method='미측정',note='CPU/GPU 생성 속도로 대체하지 않음.')
    add('질문 생성','자산 맥락의 운영 유용성 개선',unit='pp',method='미측정',note='맥락 민감도와 별개.')
    source_judge_dir=OUT/'judge_source_final' if (OUT/'judge_source_final').exists() else OUT/'judge'
    judge=[load(p) for p in sorted(source_judge_dir.glob('*.json'))] if source_judge_dir.exists() else []
    jr={j['id']:j for j in judge if j['status']=='completed'}
    # Empty output is never a supported-condition success, regardless of a
    # judge's erroneous use of a generic 'supported' label on absent fields.
    v2_judged=[r for r in originals if r.get('artifact',{}).get('draft',{}).get('prerequisites') and r['cve']+'__original' in jr]
    def applicable_counts(items,key):
        values=[j['prediction'][key] for j in items if j['prediction'][key]!='not_applicable']
        return sum(v=='supported' for v in values),len(values)
    v2_reviews=[jr[r['cve']+'__original'] for r in v2_judged]
    supported,support_n=applicable_counts(v2_reviews,'output_source_support')
    scenario,scenario_n=applicable_counts(v2_reviews,'scenario_preservation')
    add('교차 모델 대리평가','출력 원문 지지율',supported,support_n,method='Nemotron 교차 검토',note='비어 있지 않은 추출 사례 중 적용 가능한 검토만 해당. 전문가 정확도·Precision 아님.')
    add('교차 모델 대리평가','시나리오 보존율',scenario,scenario_n,method='Nemotron 교차 검토',note='교차 LLM의 판단이며 독립 정답이 아님. not_applicable은 분모 제외.')
    effective_judge=[load(p) for p in (OUT/'judge_effective').glob('*.json')] if (OUT/'judge_effective').exists() else []
    qjudge=[j for j in effective_judge if j['status']=='completed']
    input_ok,input_n=applicable_counts(qjudge,'input_source_support')
    guidance_ok,guidance_n=applicable_counts(qjudge,'guidance_sufficiency')
    add('교차 모델 대리평가','질문 입력 후보 원문 지지율',input_ok,input_n,method='Nemotron 자기 후보 재검토',note='후보 생성 모델과 검토 모델이 같음. 독립 검증으로 사용 불가. 진단 참고값만 제공.')
    add('교차 모델 대리평가','확인 지침 충분성 지지율',guidance_ok,guidance_n,method='Nemotron 교차 검토',note='실제 운영자 답변 가능률 아님. 검토 모델 자체 오류 가능. not_applicable은 분모 제외.')
    grounded_qjudge=[j for j in qjudge if j['prediction']['input_source_support']=='supported']
    grounded_guidance_ok,grounded_guidance_n=applicable_counts(grounded_qjudge,'guidance_sufficiency')
    add('교차 모델 대리평가','원문 지지 입력의 지침 충분성 지지율',grounded_guidance_ok,grounded_guidance_n,method='Nemotron 조건부 대리평가',note='상류 후보 입력 오류와 질문 확인 지침을 구분. 전문가/운영자 지표 아님.')
    # Conditional scores selected by the reviewer's own N/A abstentions are not
    # representative quality estimates. Preserve raw values, but do not headline
    # tiny, self-selected 100% figures as validation of the generator.
    for item in metric:
        if item['name'] in ['질문 입력 후보 원문 지지율','확인 지침 충분성 지지율','원문 지지 입력의 지침 충분성 지지율']:
            item['raw_conditional_value']=item['value'];item['value']=None
            item['note']+=' 판정 없음이 다수이며 검토 모델이 스스로 선택한 부분집합의 비율이라 성능 점수로 사용하지 않음. 원시 조건부 수치는 JSON에 보존.'
    add('교차 모델 대리평가','질문 입력 근거 판정 커버리지',input_n,len(qjudge),method='검토 범위 진단',note='미판정/N/A 때문에 점수화할 수 있는 범위를 표시. 정확도 아님.')
    add('교차 모델 대리평가','수용 질문 지침 판정 커버리지',guidance_n,delivered,method='검토 범위 진단',note='수용된 질문 중 검토 모델이 적용 가능한 판정을 내린 수.')
    agreement=[]
    for a in reviewed:
        j=jr.get(a['cve']+'__original')
        if j and j['prediction']['output_source_support'] in ['supported','unsupported']:
            agreement.append((j['prediction']['output_source_support']=='supported')==a['proposition_supported'])
    add('교차 모델 대리평가','assistant 감사와 검토 모델 일치율',sum(agreement),len(agreement),method='두 AI 검토의 일치',note='일치가 정답임을 뜻하지 않음. 독립 전문가 정답은 0건.')
    pair_judgements=[load(p) for p in (OUT/'paired_judge_effective').glob('*.json')] if (OUT/'paired_judge_effective').exists() else []
    good_pairs=[p for p in pair_judgements if p['status']=='completed']
    preferences=Counter(p['preferred'] for p in good_pairs)
    add('템플릿 쌍 비교 대리평가','LLM 질문 선호율',preferences.get('generated',0),len(good_pairs),method='출처를 가린 A/B Nemotron 비교',note='수용된 질문에 한정. confidence 제외. 실제 운영자 선호·시간 개선 아님.')
    add('템플릿 쌍 비교 대리평가','고정 템플릿 선호율',preferences.get('template',0),len(good_pairs),method='출처를 가린 A/B Nemotron 비교')
    add('템플릿 쌍 비교 대리평가','동등 판정 비율',preferences.get('equal',0),len(good_pairs),method='출처를 가린 A/B Nemotron 비교')
    suff_pairs=[p for p in good_pairs if p.get('llm_used')]
    delta=100*sum((p['generated_sufficiency']=='supported')-(p['template_sufficiency']=='supported') for p in suff_pairs)/len(suff_pairs) if suff_pairs else (0 if good_pairs else None)
    add('템플릿 쌍 비교 대리평가','지침 충분성 지지율 차이',value=delta,unit='pp',method='동일 입력 A/B 대리평가',note='자산 유형명을 동일하게 제공한 기계적 템플릿과 비교. 현장 성과나 전문가 정답 점수 아님.')
    if complete:
        assert len(originals)==500 and len(variants)==700 and len(questions)==180 and len(ablations)==180 and len(named_rows)==180
        assert len(pairs)==200 and len(qrows)==180
    strata=[]
    for s in sorted(cohort['sampling_frame_by_stratum']):
        rs=by_stratum.get(s,[])
        strata.append(dict(stratum=s,population=cohort['sampling_frame_by_stratum'][s],planned=cohort['allocation'][s],completed=len(rs),
            source_missing=sum(r['status']=='source_unavailable' for r in rs),failed=sum(r['status']=='failed' for r in rs),
            empty=sum(not r.get('artifact',{}).get('draft',{}).get('prerequisites') for r in rs)))
    report=dict(version='expanded-goldfree-report/1',created_at=datetime.now(timezone.utc).isoformat(),complete=complete,
        cohort=cohort,status=status,named_context_status=named_status,gold_used=False,independent_experts=0,operators=0,metrics=metric,
        frozen_question_contract_version=V3.VERSION,frozen_question_prompt_sha256=V3.digest(V3.SYSTEM),
        completed_original_cves=n,completed_v2_runs=len(variants),completed_v3_runs=len(original_questions)+len(ablations)+len(named_rows),
        effective_question_cases=len(questions),protocol_amendment=load(OUT/'protocol_amendment_named_context.json'),
        emitted_atoms=len(atoms),original_statuses=dict(counts),sampling_strata=strata,
        failure_categories=dict(failure_counts),
        emitted_logic_operator_counts=dict(Counter(logic_ops)),
        assistant_source_reviews=reviewed,
        paired_judge_statuses=dict(Counter(p['status'] for p in pair_judgements)),paired_judge_preferences=dict(preferences),
        weighted_empty_rate=weighted,weighted_empty_rate_approx_design_ci95=weighted_ci,
        robustness_pairs=pairs,question_rows=qrows,context_pairs=context_pairs,
        judge_statuses=dict(Counter(j['status'] for j in judge+effective_judge)),judged_source_cases=len(v2_judged),judged_question_cases=len(qjudge),
        judgement_limit='Cross-model source-review proxies are not expert gold. Non-applicable judge fields on empty extractions are excluded.',
        backend=load(home/'manifest.json').get('identity') if (home/'manifest.json').exists() else None,
        exposure_audit=load(OUT/'exposure_audit.json') if (OUT/'exposure_audit.json').exists() else None,
        diversity_audit=load(OUT/'diversity_audit.json') if (OUT/'diversity_audit.json').exists() else None,
        current_code_drift_audit=load(OUT/'current_code_drift_audit.json') if (OUT/'current_code_drift_audit.json').exists() else None,
        execution_provenance={p.name:load(p) for p in (OUT/'provenance').glob('*.json')} if (OUT/'provenance').exists() else {},
        output_file_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(home.glob('*.json'))},
        limitations=['500-CVE sample covers the eligible frame by source-token strata; these strata are not gold semantic labels.',
            'V3 candidate bank has only 190 eligible unique CVEs, of which 180 were sampled. This is not a representative sample of all 12,418 CVEs.',
            'V3 inputs are prior source-linked candidates, not independently adjudicated conditions or current V2 successes.',
            'The V3 candidate bank was generated by the same pinned Nemotron model used as reviewer. Its input-support review is self-review, not independent validation.',
            'Two V3 CVEs overlap the earlier small V3 development sample; retained and disclosed rather than silently resampled.',
            'The expanded vLLM inference/grammar backend differs from the deployed Transformers runtime. Same weights do not establish exact runtime parity; HF diagnostics and the pilot are not pooled.',
            'Workspace V3 code changed during evaluation. Scoring uses the archived V3 snapshot executed on H200, not the later workspace version.',
            'Template confidence=0 is an unassessed placeholder. Confidence is excluded from content comparisons and is not treated as a correctness probability.',
            'The deterministic baseline uses the same supplied asset-type name when available; it does not infer asset configuration or improve the supplied checking instruction.',
            'No claim of source-condition recall, expert semantic accuracy or field exploitability accuracy.',
            'Sampling intervals describe only the observed empty-output proxy, not correctness.'])
    (OUT/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    render(report)
    print(json.dumps(dict(complete=complete,original_cves=n,v2_runs=len(variants),v3_runs=report['completed_v3_runs'],effective_question_cases=len(questions),emitted_atoms=len(atoms),judge_cases=len(judge)+len(effective_judge)),ensure_ascii=False))


def render(r):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib import font_manager
    font_manager.fontManager.addfont('C:/Windows/Fonts/malgun.ttf')
    plt.rcParams.update({'font.family':'Malgun Gothic','font.size':11,'axes.unicode_minus':False})
    translate={'source_missing':'원문 없음','default_or_mitigation':'기본 설정·완화 표현','negative_or_quantified':'부정·전체/일부 표현','explicit_condition':'조건 표현','and_or':'AND/OR 표현','no_explicit_marker':'명시적 표지 없음'}
    s=r['sampling_strata'];fig,ax=plt.subplots(figsize=(11,5.2),layout='constrained')
    bars=ax.barh([translate[x['stratum']] for x in s],[x['planned'] for x in s],color='#3266a8')
    for bar,x in zip(bars,s):ax.text(bar.get_width()+2,bar.get_y()+bar.get_height()/2,str(x['planned']),va='center')
    ax.set_xlim(0,max(x['planned'] for x in s)*1.15);ax.set_xlabel('사전에 선정한 실제 CVE 수 · 합계 500건')
    ax.set_title('12,418개 CVE 모집단에서 추출한 층화 표본',loc='left');ax.spines[['top','right']].set_visible(False)
    fig.savefig(OUT/'sampling.png',dpi=180);plt.close(fig)
    fig,ax=plt.subplots(figsize=(11,5.2),layout='constrained')
    labels=[translate[x['stratum']]+' · n='+str(x['completed']) for x in s]
    all_rows={r['stratum']:[] for r in s}
    for p in (OUT/'outputs').glob('CVE-*__original.json'):
        value=json.loads(p.read_text(encoding='utf-8'));all_rows[value['stratum']].append(value)
    bottoms=[0]*len(s)
    category_functions=[('조건 있음','#287e70',lambda x:x['status']=='validated' and bool(x.get('artifact',{}).get('draft',{}).get('prerequisites'))),
        ('빈 조건','#999999',lambda x:x['status']=='validated' and not x.get('artifact',{}).get('draft',{}).get('prerequisites')),
        ('실패','#ba7635',lambda x:x['status']=='failed'),('원문 없음','#d5d9de',lambda x:x['status']=='source_unavailable')]
    for label,color,fn in category_functions:
        values=[100*sum(fn(x) for x in all_rows[a['stratum']])/len(all_rows[a['stratum']]) if all_rows[a['stratum']] else 0 for a in s]
        ax.barh(labels,values,left=bottoms,label=label,color=color,height=.6);bottoms=[b+v for b,v in zip(bottoms,values)]
    ax.set_xlim(0,100);ax.set_xlabel('각 층에서 관측한 비율 (%) · 조건 없음은 정답 음성이 아님')
    ax.set_title('실제 CVE 표본의 원문별 추출 결과',loc='left');ax.legend(loc='upper center',bbox_to_anchor=(.5,-.2),ncol=4);ax.spines[['top','right']].set_visible(False)
    fig.savefig(OUT/'extraction_outcomes.png',dpi=180);plt.close(fig)
    if r['robustness_pairs']:
        fig,ax=plt.subplots(figsize=(11,4.5),layout='constrained');pairs=r['robustness_pairs']
        labels=['공백 2배','단어 사이 줄바꿈'];bottom=[0,0]
        groups=[[p for p in pairs if p['variant']==kind] for kind in ['double_spaces','linebreaks']]
        values=[[sum(p['both_empty'] for p in g) for g in groups],
            [sum(p['slots_equal'] and not p['both_empty'] for p in g) for g in groups],
            [sum(not p['slots_equal'] and not p['source_unavailable'] for p in g) for g in groups],
            [sum(p['source_unavailable'] for p in g) for g in groups]]
        for vals,label,color in zip(values,['빈 출력 일치','조건 포함 일치','변경·실패','원문 없음'],['#999999','#287e70','#ba7635','#d5d9de']):
            ax.barh(labels,vals,left=bottom,label=label,color=color,height=.5)
            for i,(v,b) in enumerate(zip(vals,bottom)):
                if v:ax.text(b+v/2,i,str(v),va='center',ha='center',color='white' if color!='#d5d9de' else '#182331')
            bottom=[b+v for b,v in zip(bottom,vals)]
        ax.set_xlim(0,100);ax.set_xlabel('원문 대비 실행 쌍 수 · 변형별 100쌍 예정');ax.set_title('확대 표본의 입력 표기 안정성',loc='left')
        ax.legend(loc='upper center',bbox_to_anchor=(.5,-.2),ncol=4);ax.spines[['top','right']].set_visible(False)
        fig.savefig(OUT/'robustness.png',dpi=180);plt.close(fig)
    if r['question_rows']:
        ix={m['name']:m for m in r['metrics']};fig,axes=plt.subplots(1,2,figsize=(12,5),layout='constrained')
        data=[ix['출력 계약 통과율'],ix['고정 템플릿 출력 계약 통과율']]
        axes[0].bar(['LLM 생성','고정 템플릿'],[m['value'] or 0 for m in data],color=['#3266a8','#999999'],width=.5)
        for i,m in enumerate(data):axes[0].text(i,(m['value'] or 0)+3,f"{m['numerator']}/{m['denominator']}",ha='center')
        axes[0].set_title('동결 v3 출력 계약 통과율');axes[0].set_ylabel('통과율 (%)')
        checks=[ix['조건 보존율'],ix['확인 지침 복사율']]
        axes[1].bar(['고정 사실 보존','확인 지침 복사'],[m['value'] or 0 for m in checks],color=['#3266a8','#999999'],width=.5)
        for i,m in enumerate(checks):axes[1].text(i,(m['value'] or 0)+3,f"{m['numerator']}/{m['denominator']}",ha='center')
        axes[1].set_title('수용된 질문 67개의 내용');axes[1].set_ylabel('관측 비율 (%)')
        for ax in axes:ax.set_ylim(0,120);ax.spines[['top','right']].set_visible(False);ax.grid(axis='y',alpha=.15);ax.set_axisbelow(True)
        fig.supxlabel('형식 검증·고정 사실 보존 결과이며 의미 정확도 점수가 아닙니다.',fontsize=10)
        fig.savefig(OUT/'questions.png',dpi=180);plt.close(fig)
    rows=''
    for m in r['metrics']:
        value='미측정 / 평가 불충분' if m['value'] is None else f"{m['value']:.2f} {m['unit']}"
        frac=f"{m['numerator']}/{m['denominator']}" if m['numerator'] is not None else '—'
        rows+=f"<tr><td>{m['stage']}</td><td>{m['name']}</td><td>{value}</td><td>{frac}</td><td>{m['method']}</td><td>{m['note']}</td></tr>"
    audit_rows=''.join(f"<tr><td>{a['cve']}</td><td>{a['atom']}</td><td>{'지지' if a['proposition_supported'] else '미지지'}</td><td>{html.escape(a['reason'])}</td></tr>" for a in r['assistant_source_reviews'])
    imgs=''.join(f'<img src="{n}" alt="{n}">' for n in ['sampling.png','extraction_outcomes.png','robustness.png','questions.png'] if (OUT/n).exists())
    state='완료' if r['complete'] else '진행 중 — 최종 성능 수치 아님'
    content=f'''<!doctype html><html lang="ko"><meta charset="utf-8"><title>ICS-VEX 확대 LLM 평가</title><style>body{{font:15px/1.7 "Malgun Gothic",sans-serif;max-width:1250px;margin:40px auto;padding:0 24px;color:#182331}}table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{border-bottom:1px solid #d9dfe5;padding:10px;text-align:left;vertical-align:top}}img{{width:100%;height:auto}}.note{{padding:18px;background:#f2f5f8}}</style>
<h1>H200 LLM 확대 평가 · {state}</h1><p>조건 추출: 실제 CVE 500건 + 100건의 표기 변형 200회. 원문 보유 480건의 정규화 원문은 모두 다릅니다. 질문 생성: 별도 실제 CVE 180건 × 원래 ID 맥락 포함/제거 = 360회, 실제 웹처럼 유형 이름을 제공하는 보완 실험 180기록(98건 실제 생성, 82건 맥락 미확정 기록). 질문 입력의 고유 원문은 162개, 고유 사실 문장은 116개입니다. 총 1,240개 평가 기록이며 반복·추론 생략 기록도 포함하므로 실제 추론 횟수와는 다릅니다.</p>
<p class="note">정답 라벨 없음. 자동 계약 검사와 Nemotron 대리평가를 구분했습니다. 교차 모델 점수는 독립 전문가 정확도가 아닙니다. 질문 입력은 기존 원문 연결 후보이며 현재 추출 모델이 성공한 사례만 골라 만든 것이 아닙니다. 주 분석은 이름을 제공할 수 있는 98건의 보완 출력과 맥락 미확정 82건의 원 출력을 사용합니다. 보완 출력이 실패해도 앞선 성공 출력으로 대체하지 않습니다. 원문 불가·실패·빈 출력을 보존했습니다. 현재 원문 {r['completed_original_cves']}/500건, V2 {r['completed_v2_runs']}/700기록, V3 {r['completed_v3_runs']}/540기록.</p>
<p class="note">실행 스냅샷 기준 평가입니다. 실행 중 작업 폴더의 V2 프롬프트와 V3 입력 수용 게이트가 바뀌었습니다. 질문 생성 프롬프트와 출력 검증 함수는 동일하지만 현재 V4는 V2 추출 confidence &gt; 0.8을 요구합니다. 이 후보 은행에는 그 confidence가 없으므로 최신 V4 전체 흐름의 성능으로 전용할 수 없습니다. 질문 결과는 생성기 단독 스트레스 테스트입니다. 템플릿은 동일 자산 유형명을 사용하며 confidence=0은 미평가 자리표시자입니다. confidence를 정확도나 A/B 내용 비교에 사용하지 않았습니다.</p>{imgs}
<h2>전체 지표</h2><table><tr><th>기능</th><th>지표</th><th>결과</th><th>분자/분모</th><th>방법</th><th>해석</th></tr>{rows}</table>
<h2>원문 직접 감사 · assistant 검토이며 독립 전문가 정답이 아님</h2><table><tr><th>CVE</th><th>조건</th><th>명제 지지</th><th>검토 근거</th></tr>{audit_rows}</table>
<h2>제약</h2><ul>{''.join('<li>'+html.escape(x)+'</li>' for x in r['limitations'])}</ul></html>'''
    (OUT/'report.html').write_text(content,encoding='utf-8')


if __name__=='__main__':main()
