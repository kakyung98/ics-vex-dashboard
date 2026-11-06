"""Generate actual Pillar membership results and reproducible routing traces.

This evaluates the router, not source code, operator answers or VEX accuracy.
Real cached CVEs and constructed controls are always labeled separately.
"""
from collections import Counter
from pathlib import Path
import argparse,json,sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.cwe_evidence_policy import catalog,policy,json_fingerprint
from src.vex_routing import classify
from src.cve_source_evidence import catalog as evidence_catalog

PILLAR_KO={
 'CWE-284':'접근 제어 부적절',
 'CWE-435':'정상 동작 개체 사이의 부적절한 상호작용',
 'CWE-664':'수명 주기 전반의 자원 제어 부적절',
 'CWE-682':'잘못된 계산',
 'CWE-691':'제어 흐름 관리 불충분',
 'CWE-693':'보호 메커니즘 실패',
 'CWE-697':'잘못된 비교',
 'CWE-703':'예외 조건의 확인·처리 부적절',
 'CWE-707':'부적절한 중화',
 'CWE-710':'코딩 표준 준수 부적절',
}
REQ_KO={'required':'소스 필요','not_required':'운영 검토 가능','undetermined':'추가 근거·전문 자료'}
OP_KO={'required':'필수','conditional_on_CVE_context':'CVE 문맥에 따라 추가','undetermined':'미정'}
LOC_KO={'source':'소스','operator':'운영','specialist':'전문 자료','cve_evidence':'CVE 메커니즘'}
BRANCH_KO={'source_only':'① 소스만','source_to_operational':'② 소스+운영',
 'source_missing':'③ 소스 분석 결과 대기','operational_only':'④ 운영만','routing_unknown':'분류 유보'}
REAL_IDS=['CVE-2023-27309','CVE-2023-27411','CVE-2026-24455','CVE-2022-21940',
          'CVE-2026-9651','CVE-2026-61892','CVE-2019-1563','CVE-2020-10932']


def control_cases():
    specs=[
      ('memory','CWE-787','An out-of-bounds write occurs.','운영 문구가 없는 메모리 결함'),
      ('remote-memory','CWE-787','A remote attacker triggers an out-of-bounds write.','운영 문맥이 추가되는 메모리 결함'),
      ('authorization-code','CWE-862','The handler fails to check for proper permissions when remote users access it.','인가 검사 구현 누락'),
      ('authorization-config','CWE-862','Authentication is misconfigured by an access policy setting.','명시적인 접근 정책 설정 문제'),
      ('crypto-unspecified','CWE-327','The product uses TLS.','TLS라는 단어만 있는 암호 유형'),
      ('crypto-config','CWE-327','The server supports TLS with weak cipher settings.','명시적인 TLS 암호 설정 문제'),
      ('default-key','CWE-1394','The product uses a default cryptographic key.','기본 키의 배포 기록 검토'),
      ('embedded-key','CWE-1394','The device uses a hardcoded default cryptographic key.','하드코딩된 키로 메커니즘 보정'),
      ('java-declaration','CWE-493','A critical public variable lacks the final modifier.','Java 선언 속성의 직접 예외'),
      ('hardware','CWE-1252','The CPU hardware is not configured for the required memory protection.','하드웨어 전문 증거 요구'),
      ('reported-cwe-preserved','CWE-119','A buffer overflow occurs.','입력에 기록된 CWE-119 유지'),
      ('mixed-unknown',['CWE-787','CWE-999999'],'A remote buffer overflow occurs.','여러 CWE 중 미확정 항목 보존'),
    ]
    return [{'id':'control-'+key,'kind':'constructed_control_not_real_CVE','title':title,
        'case':{'cve':'CVE-2099-'+str(96000+i),'cwe':cwe if isinstance(cwe,list) else [cwe],
                'description':description},'input_source':'문서 재현용 통제 입력. 실제 CVE 기록이 아님.'}
        for i,(key,cwe,description,title) in enumerate(specs)]


def validate_quotes(case,result):
    texts={'description':case.get('description','')}
    texts.update({s['id']:s['text'] for s in case.get('routing_sources',[])})
    evidence=[e for d in result['decisions'] for e in d['evidence']]+result['operational_requirement_evidence']
    for e in evidence:
        a,b=e['span'];assert texts[e['source_id']][a:b]==e['quote'],e


def build_results(as_of='2026-11-06',data=None):
    data=data or catalog();summary=data['summary'];profiles=data['profiles']
    pillars=[]
    for pid,aggregate in summary['per_pillar'].items():
        members=sorted((r for r in profiles.values() if pid in r['pillars']),key=lambda r:int(r['cwe'][4:]))
        assert len(members)==aggregate['memberships']
        pillars.append({'pillar':pid,'name':aggregate['name'],'korean_label':PILLAR_KO[pid],
            'memberships':len(members),'by_source_requirement':dict(Counter(r['source_requirement'] for r in members)),
            'by_resolution':dict(Counter(r['resolution'] for r in members)),
            'members':[{'cwe':r['cwe'],'name':r['name'],'pillars':r['pillars'],
                'definition_url':r['definition_url'],'source_requirement':r['source_requirement'],
                'operational_requirement':r['operational_requirement'],'required_facts':r['required_facts'],
                'matched_rules':r['matched_rules'],'resolution':r['resolution'],
                'evidence_plan':r['evidence_plan']} for r in members]})
    assert len(pillars)==10 and sum(p['memberships'] for p in pillars)==1201
    assert {m['cwe'] for p in pillars for m in p['members']}==set(profiles)

    cases=[];cache_path=ROOT/'data/nvd_cache.json'
    cache=json.loads(cache_path.read_text(encoding='utf-8')) if cache_path.is_file() else {}
    missing=[]
    for cid in REAL_IDS:
        rec=cache.get(cid)
        if not rec or not rec.get('description') or not rec.get('cwes'):
            missing.append(cid);continue
        cases.append({'id':cid,'kind':'real_CVE_from_local_snapshot','title':cid,
            'case':{'cve':cid,'cwe':rec['cwes'],'description':rec['description'],
                    'routing_sources':evidence_catalog(cid,rec['description'])},
            'input_source':'data/nvd_cache.json + pinned local CSAF source catalog',
            'record_sha256':json_fingerprint(rec),'feed_timestamp':rec.get('feed_timestamp'),
            'last_modified_in_snapshot':rec.get('lastModified'),
            'reference_urls':list(dict.fromkeys(rec.get('references',[]))),
            'review_note':None})
    cases+=control_cases()
    for row in cases:
        row['routes']={}
        for available in [False,True]:
            r=classify(row['case'],source_available=available);validate_quotes(row['case'],r)
            row['routes']['source_result_present' if available else 'source_result_absent']=r
        assert row['routes']['source_result_absent']['requirement']==row['routes']['source_result_present']['requirement']
        row['routing_is_not_exploitability_gold']=True

    generic=Counter()
    for cid in profiles:
        r=classify({'cve':'CVE-2099-99999','cwe':[cid],'description':'A product vulnerability exists.'},source_available=True)
        generic[r['workflow_branch']]+=1
    return {'schema':'ics-vex-cwe-routing-documentation-results/1','documentation_date_kst':as_of,
        'policy_version':summary['version'],'policy_sha256':summary['policy_sha256'],
        'taxonomy_xml_sha256':summary['taxonomy_xml_sha256'],
        'official_metadata_sha256':summary['official_metadata_sha256'],
        'scope':'Reproducible router outputs. No source analysis, operator assessment or VEX correctness evaluation.',
        'pillar_count':10,'unique_detailed_cwes':len(profiles),'membership_count':sum(p['memberships'] for p in pillars),
        'baseline_counts':summary['by_source_requirement'],'plan_summary':summary['evidence_plans'],
        'generic_description_source_result_present_counts':dict(generic),
        'pillars':pillars,'cases':cases,'missing_local_real_CVE_records':missing,
        'independent_expected_labels':None,'semantic_accuracy_measured':False,
        'source_result_present_is_counterfactual_input_not_collection_claim':True}


def cell(value):return str(value).replace('|','/').replace('\n',' ')


def section3(report):
    lines=['### 3.1 공식 계층과 증거 계획의 범위','',
        '고유 CWE 944개 각각에 증거 수집 계획을 작성했다. Pillar 소속을 모두 나열하면 중복 포함 1,201행이다. 각 계획은 해당 CWE 자체의 공식 정의와 Detection_Methods를 근거로 한다. 소속 관계에서 방법을 상속하지 않는다.','',
        f'고유 944개 중 {report["plan_summary"]["entry_specific_method_available"]}개는 해당 항목의 공식 탐지 방법을 연결했고, {report["plan_summary"]["mechanism_first"]}개는 CVE·벤더 메커니즘 우선 확인을 지정했다. 이 계획 수는 정확도나 최종 필수 증거 확정 수가 아니다.','',
        '| Pillar | 공식 이름 | 세부 CWE 소속 수 | 증거 계획 기록 수 |',
        '| --- | --- | ---: | ---: |']
    for p in report['pillars']:
        lines.append(f'| {p["pillar"]} | {p["name"]} | {p["memberships"]} | {p["memberships"]} |')
    lines += ['', '### 3.2 세부 CWE 원문과 소속 목록','',
        '각 행의 권장 경로는 증거 수집의 대안이다. 여러 경로가 있으면 모두 필수라는 뜻이 아니다. 공식 방법 미기재 항목도 CVE·벤더 메커니즘 우선 확인이라는 첫 단계를 지정했다. 개별 자산의 최종 소스/운영 필요 여부는 아직 확정하지 않는다. 정의 원문 전문·해당 방법의 원문 설명·자료 요청·출처는 JSON/CSV에 포함된다.','']
    for p in report['pillars']:
        lines += ['<details>',f'<summary>{p["pillar"]} · {p["name"]} · {p["memberships"]}개 소속</summary>','',
            '| 세부 CWE | 공식 이름 | 권장 증거 수집 경로 (대안) | 해당 CWE 자체의 근거 |','| --- | --- | --- | --- |']
        for r in p['members']:
            plan=r['evidence_plan']
            methods='<br>'.join(cell(a['method']) for a in plan['alternatives']) or '공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인'
            lines.append(f'| [{r["cwe"]}]({r["definition_url"]}) | {cell(r["name"])} | {"<br>".join(plan["route_labels_ko"])} | {methods} |')
        lines += ['', '</details>','']
    return '\n'.join(lines)


def section4(report):
    lines=['### 4.1 현재 실행 결과','',
        '944개 증거 수집 계획을 제공한다. 탐지 방법은 가능한 자료 수집 대안이지 최종 필수 증거의 선언이 아니다. 자산별 CVE 메커니즘에 적합한 방법과 자료가 선택되기 전에는 자동 상태 판단 경로로 전환하지 않는다.','',
        '| 전체 고유 세부 CWE | 최종 소스 필수 자동 확정 | 운영만으로 충분하다고 확정 | CVE별 증거 적합성 확인 필요 |',
        '| ---: | ---: | ---: | ---: |',
        '| 944 | 0 | 0 | 944 |','',
        '이 숫자는 평가 정확도가 아니다. 기존의 584/144/26/190 경로 집계도 현재 결과로 사용하지 않는다.','',
        '### 4.2 실제/통제 입력 재실행','',
        '실제 CVE는 로컬 스냅샷 입력이며, 통제 입력은 구성한 사례다. 모두 현재 라우터의 미지정 처리를 확인하는 용도이며 정답 데이터가 아니다.','',
        '| 입력 | 구분 | 보고된 CWE | 소스 결과 없음 | 소스 결과 있다고 가정 |',
        '| --- | --- | --- | --- | --- |']
    for row in report['cases']:
        kind='실제 CVE 로컬 기록' if row['kind']=='real_CVE_from_local_snapshot' else '구성한 통제 입력'
        lines.append('| '+' | '.join([row['id'],kind,', '.join(row['case']['cwe']),BRANCH_KO[row['routes']['source_result_absent']['workflow_branch']],BRANCH_KO[row['routes']['source_result_present']['workflow_branch']]])+' |')
    lines += ['', '신규 검토에는 해당 CWE의 증거 수집 계획을 함께 제공하지만, 최종 필수 증거가 정해지지 않았으므로 `routing_unknown` / `under_investigation`으로 시작한다. 원문에 연결된 CWE ID를 바꾸지 않는다. 실행 관찰 자료와 운영자 질문은 같은 것이 아니며, 이 계획은 동적 시험·바이너리 분석을 자동 실행하지 않는다.','',
        '전체 입력과 반환값: [criteria_results.json](../data/cwe_routing/v2/criteria_results.json).',
        '재생성: `python tools/build_cwe_evidence_policy.py`.','',
        '정책 버전: `'+report['policy_version']+'` / 정책 해시: `'+report['policy_sha256']+'`.']
    return '\n'.join(lines)


def replace_section(text,number,body):
    start=f'<!-- BEGIN GENERATED SECTION {number} RESULTS -->'
    end=f'<!-- END GENERATED SECTION {number} RESULTS -->'
    block=start+'\n\n'+body+'\n\n'+end+'\n\n'
    if start in text:
        a=text.index(start);b=text.index(end,a)+len(end)
        return text[:a]+block.rstrip()+'\n\n'+text[b:].lstrip('\r\n')
    anchor='### 상속 원칙과 예외' if number==3 else '## 5. 보고된 CWE 유지와 근거 부족 처리'
    if anchor not in text:raise ValueError('Documentation section anchor missing: '+anchor)
    return text.replace(anchor,block+anchor,1)


def write_results(as_of='2026-11-06',data=None):
    report=build_results(as_of,data);folder=ROOT/'data/cwe_routing/v2';folder.mkdir(parents=True,exist_ok=True)
    (folder/'criteria_results.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    doc=ROOT/'docs/CWE_ROUTING_CRITERIA.md';text=doc.read_text(encoding='utf-8')
    text=replace_section(text,3,section3(report));text=replace_section(text,4,section4(report))
    doc.write_text(text,encoding='utf-8')
    print(json.dumps({'pillars':report['pillar_count'],'unique_cwes':report['unique_detailed_cwes'],
        'membership_rows':report['membership_count'],'real_cases':len([r for r in report['cases'] if r['kind']=='real_CVE_from_local_snapshot']),
        'controlled_cases':len([r for r in report['cases'] if r['kind']=='constructed_control_not_real_CVE']),
        'generic_routes':report['generic_description_source_result_present_counts'],'doc_bytes':doc.stat().st_size}))
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--as-of',default='2026-11-06');args=parser.parse_args()
    write_results(args.as_of)
