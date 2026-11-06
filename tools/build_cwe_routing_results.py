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
      ('mapping-advisory','CWE-119','A buffer overflow occurs.','Discouraged도 기존 CWE를 유지하고 메모리 증거로 진행'),
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
            'official_mapping_usage':dict(Counter(r['cve_mapping_gate']['usage'] for r in members)),
            'members':[{'cwe':r['cwe'],'name':r['name'],'pillars':r['pillars'],
                'definition_url':r['definition_url'],'source_requirement':r['source_requirement'],
                'operational_requirement':r['operational_requirement'],'required_facts':r['required_facts'],
                'matched_rules':r['matched_rules'],'resolution':r['resolution'],
                'mapping_usage':r['cve_mapping_gate']['usage']} for r in members]})
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
            'review_note':('현재 규칙은 CWE-732 기본값을 따라 운영 경로를 선택한다. 그러나 설명의 token 수정이 구현 검증을 필요로 하는지는 이 규칙이 확정하지 못한다. 올바른 경로의 독립 정답으로 사용하지 말고 추가 메커니즘 검토 대상으로 남긴다.' if cid=='CVE-2026-61892' else None)})
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
        'baseline_counts':summary['by_source_requirement'],
        'generic_description_source_result_present_counts':dict(generic),
        'pillars':pillars,'cases':cases,'missing_local_real_CVE_records':missing,
        'independent_expected_labels':None,'semantic_accuracy_measured':False,
        'source_result_present_is_counterfactual_input_not_collection_claim':True}


def cell(value):return str(value).replace('|','/').replace('\n',' ')


def section3(report):
    lines=['### 3.1 구분해야 하는 네 가지 숫자','',
        '| 구분 | 수 | 의미 |','| --- | ---: | --- |',
        '| Pillar | **10개** | 공식 계층의 상위 유형 |',
        '| 고유 세부 CWE | **944개** | 이번 정책표의 대상 |',
        '| 증거 기본값 | 3종 | 소스 / 운영 / 추가 근거·전문 자료 |',
        '| 실행 경로 | 4종 | 소스만 / 소스+운영 / 필수 소스 대기 / 운영만 |','',
        '따라서 728·26·190은 Pillar 수가 아니다. 10개 Pillar 아래의 고유 CWE 944개를 증거 기본값으로 나눈 수다. 분류 근거 부족은 별도 유보이며 새로운 Pillar가 아니다.','',
        '### 3.2 10개 Pillar 전체의 실제 집계 결과','',
        '| Pillar | 공식 명칭 / 설명 | 소속 수 | 소스 기본값 | 운영 기본값 | 추가 근거·전문 자료 |',
        '| --- | --- | ---: | ---: | ---: | ---: |']
    for p in report['pillars']:
        c=p['by_source_requirement']
        lines.append(f'| {p["pillar"]} | {p["name"]}<br>{p["korean_label"]} | {p["memberships"]} | {c.get("required",0)} | {c.get("not_required",0)} | {c.get("undetermined",0)} |')
    totals={k:sum(p['by_source_requirement'].get(k,0) for p in report['pillars']) for k in ['required','not_required','undetermined']}
    lines += [f'| **소속 합계: 중복 포함** | 한 CWE의 여러 Pillar 소속을 모두 계산 | **1201** | **{totals["required"]}** | **{totals["not_required"]}** | **{totals["undetermined"]}** |',
        '| **고유 CWE 합계** | 각 CWE를 한 번만 계산 | **944** | **728** | **26** | **190** |','',
        '**합계 해석:** 235개 세부 CWE가 여러 Pillar에 속하므로 Pillar별 소속 수 합계는 1,201개다. 같은 CWE를 한 번만 세면 944개다. Pillar별 열을 합쳐 728·26·190과 바로 비교하면 중복 계산이 된다.','',
        '### 3.3 직접 적용·상속·CVE 매핑 참고 정보의 실제 집계','',
        '| Pillar | 자체 기준/조건 | 상위 세부 기준점에서 상속 | Allowed | Allowed-with-Review | Discouraged | Prohibited |',
        '| --- | ---: | ---: | ---: | ---: | ---: | ---: |']
    for p in report['pillars']:
        r=p['by_resolution'];m=p['official_mapping_usage']
        lines.append('| '+' | '.join([p['pillar'],str(r.get('direct',0)),str(r.get('inherited',0)),*[str(m.get(k,0)) for k in ['Allowed','Allowed-with-Review','Discouraged','Prohibited']]])+' |')
    lines += ['', '이 표도 Pillar 소속 기준이므로 중복을 포함한다. 오른쪽 네 열은 CWE를 새로 부여하는 작성자를 위한 공식 매핑 지침이며, 이미 CVE에 연결된 CWE의 분석을 허용·금지하는 등급이 아니다. 현재 시스템은 보고된 CWE를 유지하며 이 등급으로 경로를 차단하지 않는다. 왼쪽 두 열과 오른쪽 네 열은 같은 집합을 별개 기준으로 집계하므로 모두 더하지 않는다.','',
        '### 3.4 Pillar별 모든 세부 CWE의 분류 결과','',
        '아래 10개 펼침 항목에 전체 1,201개 소속 행을 싣는다. 고유 CWE 944개를 모두 포함하며, 중복 소속 CWE는 해당 Pillar마다 다시 나타난다. 각 행은 **기본 증거 요구**이고, 실제 CVE 메커니즘 보정을 적용한 실행 결과는 4절에서 구분한다.','']
    for p in report['pillars']:
        lines += ['<details>',f'<summary>{p["pillar"]} · {p["name"]} · {p["memberships"]}개 소속</summary>','',
            '| 세부 CWE / 이름 | 기본 요구 / 운영 필요 | 필요한 사실의 소재 | 적용 규칙과 기준점 | CVE 매핑 Usage |',
            '| --- | --- | --- | --- | --- |']
        for r in p['members']:
            facts='<br>'.join(f'{f["id"]} ({LOC_KO[f["location"]]})' for f in r['required_facts'])
            rules='<br>'.join(m['rule_id']+' @ '+', '.join(a['cwe'] for a in m['anchors'])+f' / 거리 {m["distance"]}' for m in r['matched_rules'])
            lines.append('| '+' | '.join([f'[{r["cwe"]}]({r["definition_url"]}) {cell(r["name"])}',
                REQ_KO[r['source_requirement']]+'<br>운영: '+OP_KO[r['operational_requirement']],facts,rules,r['mapping_usage']])+' |')
        lines += ['', '</details>','']
    return '\n'.join(lines)


def section4(report):
    lines=['### 4.1 실제 적용 순서와 기록하는 결과','',
        '| 순서 | 검사 내용 | 기록하는 필드 / 결과 |','| --- | --- | --- |',
        '| 1 | 보고된 세부 CWE와 모든 Pillar 경로 확인 | `cwes`, `pillars`, `decisions[].paths` |',
        '| 2 | CWE 기본 증거 유형 확인; 매핑 Usage는 참고로 보존 | `baseline_source_requirement`, `cve_mapping_gate` |',
        '| 3 | 직접 기준·가장 가까운 상위 세부 기준 적용 | `matched_rules`, `distance`, `anchors[].path` |',
        '| 4 | 명시적 구현 결함 문구 확인 | `refinement_rules`, `evidence[].quote/span/source_id` |',
        '| 5 | 허용한 유형에서 명시적 운영 설정 메커니즘 확인 | 구현 결함 근거가 우선. 허용된 경우에만 운영 경로로 보정 |',
        '| 6 | 실제 역할·접근·설정 등 운영 문맥 신호 확인 | `operational_required`, `operational_requirement_evidence` |',
        '| 7 | 여러 CWE의 요구 합치기 | 필요 증거가 미확정인 항목이 하나라도 있으면 `routing_unknown` |',
        '| 8 | 소스 분석 결과 등록 여부 적용 | `source_available`, `workflow_branch` |','',
        '이 순서는 경로 결정의 실행 결과를 설명한다. 소스를 분석하거나 운영 답변의 진위를 검증하거나 최종 VEX 상태를 평가한 결과가 아니다.','',
        '### 4.2 고유 CWE 944개 전체에 동일한 중립 입력을 넣은 결과','',
        '입력 설명을 모든 CWE에서 `A product vulnerability exists.`로 고정하고 `source_available=True`로 놓아 실행했다. 이 값은 **분석 결과가 있다고 가정한 라우터 인자**이며, 944개 제품의 소스를 수집했다는 뜻이 아니다. 실제 CVE 분포나 분류 정확도도 아니다.','',
        '| 실행 결과 | 수 |','| --- | ---: |']
    for key in ['source_only','source_to_operational','source_missing','operational_only','routing_unknown']:
        lines.append(f'| {BRANCH_KO[key]} | {report["generic_description_source_result_present_counts"].get(key,0)} |')
    lines += ['', '소스 기본값 728개는 CWE 자체가 요구하는 운영 사실에 따라 소스만/소스+운영으로 나뉜다. 운영 기본값 26개와 미확정 190개는 중립 입력에서 그대로 유지된다. 매핑 Usage는 실행 경로를 차단하지 않는다. 중립 입력은 구체적인 CVE 메커니즘 보정을 유발하지 않는다.','',
        '### 4.3 로컬에 저장된 실제 CVE 입력의 경로 결과','',
        '아래는 로컬 NVD/CSAF 스냅샷의 실제 CVE 설명과 보고된 CWE를 넣어 실행한 결과다. 최신 온라인 원문을 새로 조사한 결과가 아니다. `자료 없음/있음`은 같은 입력에서 **소스 분석 결과 등록 여부만 바꾼 대조**이며, 실제 소스 수집 여부에 대한 주장이 아니다.','',
        '| 실제 CVE | 보고된 CWE | 자료 없음 | 자료 있다고 가정 | 적용한 기준 / 보정 |',
        '| --- | --- | --- | --- | --- |']
    real=[r for r in report['cases'] if r['kind']=='real_CVE_from_local_snapshot']
    for row in real:
        r=row['routes']['source_result_present'];rules=sorted({d['rule_id'] for d in r['decisions']});refines=sorted({v for d in r['decisions'] for v in d['refinement_rules']})
        lines.append('| '+' | '.join([row['id'],', '.join(row['case']['cwe']),BRANCH_KO[row['routes']['source_result_absent']['workflow_branch']],
            BRANCH_KO[r['workflow_branch']],'<br>'.join(rules+refines)])+' |')
    lines += ['', '**주의할 실제 사례:** `CVE-2026-61892`는 현재 코드상 운영 경로다. 설명에는 token 수정이 나오므로, 구현 결함인지 배포 권한 문제인지 별도 검토가 필요할 수 있다. 이 출력은 라우터의 현 상태를 공개한 것이며, 운영 경로가 충분하다는 독립 정답으로 간주하지 않는다.','',
        '### 4.4 문서 재현용 통제 입력의 대조 결과','',
        '다음 항목은 **실제 CVE가 아닌 구성한 입력**이다. 같은 CWE에서도 구현/설정 설명이 달라지면 어떻게 동작하는지, 그리고 정보 부족을 유보하는지 확인하는 용도다.','',
        '| 통제 사례 | 입력 CWE | 자료 없음 | 자료 있다고 가정 |',
        '| --- | --- | --- | --- |']
    controls=[r for r in report['cases'] if r['kind']=='constructed_control_not_real_CVE']
    for row in controls:
        lines.append('| '+' | '.join([row['title'],', '.join(row['case']['cwe']),
            BRANCH_KO[row['routes']['source_result_absent']['workflow_branch']],BRANCH_KO[row['routes']['source_result_present']['workflow_branch']]])+' |')
    lines += ['', '### 4.5 각 입력의 원문·상속 경로·매칭 인용·필요한 사실','',
        '아래 펼침 항목은 위 표의 모든 실제/통제 입력을 상세히 추적한다. 문구가 매칭되지 않으면 “매칭 없음”으로 기록한다. 매칭된 인용을 실제 악용 조건이 모두 파악됐다는 뜻으로 해석하지 않는다.','']
    for row in report['cases']:
        r=row['routes']['source_result_present'];kind='실제 CVE의 로컬 스냅샷' if row['kind']=='real_CVE_from_local_snapshot' else '통제 입력: 실제 CVE 아님'
        lines += ['<details>',f'<summary>{row["id"]} · {row["title"]} · {kind}</summary>','',
            f'- 입력 종류: **{kind}**',f'- 입력 CWE: `{", ".join(row["case"]["cwe"])}`',
            f'- 자료 없음: **{BRANCH_KO[row["routes"]["source_result_absent"]["workflow_branch"]]}**',
            f'- 자료 있다고 가정: **{BRANCH_KO[r["workflow_branch"]]}**',
            f'- 증거 요구: `{r["requirement"]}` / 운영 필요: `{r["operational_required"]}`']
        if row.get('record_sha256'):lines.append(f'- 로컬 입력 레코드 해시: `{row["record_sha256"]}`')
        if row.get('feed_timestamp'):lines.append(f'- 로컬 수집 시각 필드: `{row["feed_timestamp"]}`')
        lines += ['', '**입력 설명 원문**','',*['> '+line for line in row['case']['description'].splitlines()],'']
        if row.get('review_note'):lines += ['**해석 한계:** '+row['review_note'],'']
        for d in r['decisions']:
            lines += [f'**{d["cwe"]}: {d.get("name") or "알 수 없는 유형"}**','',
                f'- Pillar: `{", ".join(d["pillars"]) or "없음"}`',
                f'- 기본값 → 이번 입력: `{d["baseline_source_requirement"]}` → `{d["source_requirement"]}`',
                f'- 매핑 Usage: `{d["cve_mapping_gate"]["usage"]}`',
                f'- 결정 이유: {d["reason"]}']
            for m in d['matched_rules']:
                paths=' / '.join(' → '.join(a['path']) for a in m['anchors'])
                lines.append(f'- 기준: `{m["rule_id"]}` / 거리 `{m["distance"]}` / 경로 `{paths}`')
            lines += ['', '| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |',
                '| --- | --- | --- | --- |']
            for e in d['evidence']:
                lines.append('| '+' | '.join([e['rule_id'],cell(e['quote']),str(e['span']),e['source_id']])+' |')
            if not d['evidence']:lines.append('| 없음 | 매칭 없음 | 해당 없음 | 해당 없음 |')
            lines += ['', '| 필요한 사실 | 소재 |','| --- | --- |']
            for f in d['required_facts']:lines.append(f'| `{f["id"]}`: {cell(f["label"])} | {LOC_KO[f["location"]]} |')
            if not d['required_facts']:lines.append('| 매핑/기준이 미확정이어서 필요한 사실도 확정하지 않음 | 미정 |')
            lines += ['']
        contexts=r['operational_requirement_evidence']
        if contexts:lines += ['운영 문맥으로 매칭한 원문 조각: '+', '.join('`'+q+'`' for q in dict.fromkeys(e['quote'] for e in contexts))+'. 이 조각들은 전제조건 충족의 증거가 아니다.','']
        if row['kind']=='real_CVE_from_local_snapshot':
            lines += ['원문 확인 링크: [NVD 기록](https://nvd.nist.gov/vuln/detail/'+row['id']+'). 링크의 현재 내용과 로컬 스냅샷은 다를 수 있다.','']
        lines += ['</details>','']
    lines += ['### 4.6 재현 파일과 검증 범위','',
        '- 전체 실행 입력과 출력: [criteria_results.json](../data/cwe_routing/v2/criteria_results.json)',
        '- 재생성: `python tools/build_cwe_routing_results.py --as-of '+report['documentation_date_kst']+'`',
        f'- 정책 해시: `{report["policy_sha256"]}`',
        f'- 공식 XML 해시: `{report["taxonomy_xml_sha256"]}`','',
        '문서 생성 시 모든 매칭 인용에 대해 `원문[시작:끝] == 인용`을 확인하고, 소스 자료 유무만 바꾸었을 때 증거 요구 자체가 바뀌지 않는지 검사한다. 이 검사는 문서·코드의 일치성 검사다. 독립 정답 라벨, 분류 정확도, Cohen\'s kappa, 소스 분석 성공률 또는 최종 VEX 정확도를 측정한 것은 아니다.']
    return '\n'.join(lines)


def replace_section(text,number,body):
    start=f'<!-- BEGIN GENERATED SECTION {number} RESULTS -->'
    end=f'<!-- END GENERATED SECTION {number} RESULTS -->'
    block=start+'\n\n'+body+'\n\n'+end+'\n\n'
    if start in text:
        a=text.index(start);b=text.index(end,a)+len(end)
        return text[:a]+block.rstrip()+'\n\n'+text[b:].lstrip('\r\n')
    anchor='### 상속 원칙과 예외' if number==3 else '## 5. 잘못되거나 넓은 CVE 매핑 처리'
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
