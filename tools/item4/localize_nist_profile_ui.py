"""English presentation of the reviewed mapping; canonical profiles stay intact."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from copy import deepcopy
from pathlib import Path
import json,re
from bs4 import BeautifulSoup
from tools.item4.build_nist_operating_information import render

ROOT=Path(__file__).resolve().parents[2]
LIVE=Path('D:/ICS-VEX/local-service/sbom-vex/vex_operational_logic_20261117/english_ui')

from src.common.paths import source_path

def main():
    data=json.loads((ROOT/'site/nist-operating-information.json').read_text(encoding='utf-8'))
    labels=dict(line.split('|',1) for line in (ROOT/'src/research/ui/nist_profile_details.en.txt').read_text(encoding='utf-8').splitlines() if line)
    assert set(labels)=={e['id'] for r in data['rows'] for e in r['collection_elements']}
    notes=[
        'This is organizational or design information; it does not establish a prerequisite for exploiting an individual CVE.',
        'This restates a source concept as information to collect. Verify the value, subject, and applicability separately; do not infer the current state.',
        'The source describes the existence and impact of changes. It does not prescribe a change-history record format.',
        'Do not add an algorithm list or allowed/prohibited criteria that the source does not specify.',
        'The source describes possible attacks. It does not establish that a security assessment has been completed.',
        'This concerns potential impacts listed in the source, not a mandatory classification of actual AI uses.',
        'The source describes delays caused by regression testing. It does not define a new testing procedure.',
        'Specific account, target, and path descriptions are collection-design choices, not official source fields.',
        'The wording is limited to the source scope; it does not introduce independent fields for every service-support or activation state.',
        'This describes a DoS impact. It does not assert successful exploitation or require an operator to perform an attack test.',
        'This is operational-impact information, not by itself a VEX prerequisite.',
        'The source describes a possible effect. Installation alone does not establish protection against a particular CVE.',
        'Operators must not guess. Retain unknown when vendor, advisory, or analysis evidence is unavailable.',
        'Configuration observations alone do not demonstrate code validation.',
        'Selecting evidence sources is part of the collection procedure. The table does not define a separate advisory-evidence field.',
        'The source does not define numerical criteria for adequacy.',
        'The source describes limited or absent security capabilities. Support, configuration, and actual effectiveness are distinct states.',
        'Do not derive specific encryption methods, strength requirements, or mandatory support lists from this row alone.',
        'Implementation defects remain unknown without supporting code analysis, vendor analysis, or equivalent evidence.',
        'This is limited to wireless configuration protection for sensors and final elements. Do not generalize it to ordinary PLC key switches.'
    ]
    original_notes=list(dict.fromkeys(e['interpretation_note'] for r in data['rows'] for e in r['collection_elements']))
    assert len(original_notes)==len(notes)==20
    note_map=dict(zip(original_notes,notes))
    categories=dict(zip(list(dict.fromkeys(r['category'] for r in data['rows'])),[
        'Design and management','Condition candidate','Monitoring and detection','Condition candidate / design',
        'Impact and design','Asset identification','Condition candidate / management','Response and management',
        'Condition candidate / response','Management and validation','Recovery','Management','Monitoring and prevention',
        'Management and impact','Impact / vulnerability evidence','Environment and impact','Availability and recovery',
        'Code / vulnerability evidence','Condition candidate / implementation evidence','Dependencies and impact']))
    rows=deepcopy(data['rows'])
    for row in rows:
        row['label']=row['title'];row['category']=categories[row['category']]
        for item in row['collection_elements']:
            item['label']=labels[item['id']];item['interpretation_note']=note_map[item['interpretation_note']]
    scope=dict(zip(['asset_ref','product','build','config_baseline','mode','origin','reviewer','observed_at','valid_until'],[
        'Actual asset/component ID','Actual manufacturer, product, and model','Running software/firmware version or survey limitation',
        'Assessed configuration baseline','Assessed operating mode','Access-review origin/actor','Author/reviewer',
        'Observation time (include time zone)','Evidence valid until (include time zone)']))
    presentation=dict(rows=rows,details=labels,scope=scope)
    (ROOT/'src/item4/assets/operating_profile_translations.json').write_text(json.dumps(presentation,ensure_ascii=False,indent=2),encoding='utf-8')
    replacements={
      'Operational VEX · 54개 원문 항목 / 167개 세부정보 입력':'Asset operational information · 54 source items / 167 details',
      'NIST SP 800-82 Rev.4 IPD 표 12–17과 프로파일 명세 v0.4에 따른 입력 화면입니다. 모든 항목과 영어 근거를 아래에 표시합니다. 세부 수집정보는 연구자 재서술이며 167개 모두가 필수 응답은 아닙니다. 자산 유형만으로 적용성·관측값·CVE 영향 여부를 채우지 않습니다.':'Based on NIST SP 800-82 Rev.4 IPD, Tables 12–17, and profile specification v0.4. Each detail includes its English source evidence. Collection fields are project interpretations; not all 167 require an answer. Asset type alone does not establish applicability, observed facts, or CVE impact.',
      '변경 내용은 이 탭에 유지됩니다. 새로고침 전 JSON을 내려받거나 BOM 워크플로에서 저장하세요. 이전 82개 양식은 자동 변환하지 않습니다. 관측·설정 근거와 CVE별 전제조건 연결 검토가 필요하며, 이 화면 입력만으로 VEX 상태를 확정하지 않습니다. 비밀번호·키·토큰 원문은 입력하지 마세요.':'Edits remain in this tab. Download JSON or save in the BOM workflow before refreshing. Legacy 82-field profiles are not automatically migrated. Operational evidence and CVE-specific mapping review are required; form completion alone does not establish VEX status. Do not enter passwords, keys, or tokens.',
      '평가 추적용 메타데이터입니다. NIST 167개 수집정보의 일부로 계산하지 않습니다.':'Assessment provenance metadata; these fields are not counted among the 167 collection details.',
      '평가 대상·범위·관측 시각·작성자':'Assessment target, scope, observation time, and author',
      'Table 12 · 구조·설계':'Table 12 · Architecture and design','Table 13 · 설정·유지보수':'Table 13 · Configuration and maintenance',
      'Table 14 · 물리적 조건':'Table 14 · Physical conditions','Table 15 · 소프트웨어 개발':'Table 15 · Software development',
      'Table 16 · 통신·네트워크':'Table 16 · Communication and networks','Table 17 · 현장 장치·자산 관리':'Table 17 · Field devices and asset management',
      '입력 구조·적용성 검증':'Validate structure and applicability','현재 입력 JSON 다운로드':'Download current draft JSON',
      '빈 양식 다운로드':'Download blank template','입력 JSON 불러오기':'Import draft JSON','167개 관측값은 모두 미확인으로 시작합니다.':'All 167 observations start as unknown.',
      '자산 유형':'Asset type','전체 표':'All tables','검색':'Search','표 ':'Table ','C13-08, 포트, password 등':'C13-08, port, password',
      '미확인 / Unknown':'Unknown','관측 기록 있음 / Known':'Observation recorded / Known','조사 범위에서 없음 확인':'Absence confirmed within surveyed scope',
      '비해당 확인':'Not applicable, confirmed','근거 충돌 / Conflicting':'Conflicting evidence','적용성 미확인':'Applicability unknown','적용 대상 확인':'Applicable, confirmed',
      ' 관측 근거 출처':' evidence source',' 관측 근거 내용':' supporting observation',' 조사 범위':' surveyed scope','응답 상태':'Observation status',' 상태':' status',' 관측값':' observed value',
      '이 항목을 비해당으로 기록하려면 상위 C항목의 적용성 비해당과 조사 근거를 먼저 확인하세요.':'To record this detail as not applicable, confirm non-applicability of the parent source item and provide scoped evidence.',
      '이 원문 항목이 실제 자산·시스템의 검토 대상인가요?':'Does this source item apply to the actual asset or system under review?',
      '적용성은 취약한 상태인지에 대한 답변이 아닙니다. 확인된 대상·기능·범위를 기록하고, 판단 근거가 없으면 미확인으로 두세요.':'Applicability does not state whether the asset is vulnerable. Record the verified subject, function, and scope; retain unknown when evidence is unavailable.',
      ' 적용성':' applicability',' · 인쇄 p.':' · Printed p.','NIST 원문 · 표/페이지 열기 ↗':'NIST source · Open table/page ↗','영어 근거 · ':'English evidence · ',
      '해석상 주의: ':'Interpretation note: ','전체 54개 원문 항목 · 167개 세부정보 / 현재 표시 ':'54 source items · 167 details / Displayed: ',
      '개 항목 · ':' items · ','개 세부정보. 영어 원문 근거와 해석상 주의를 각 항목에 표시합니다.':' details. English evidence and interpretation notes are shown for each detail.',
      '54개 항목 / 167개 세부정보 구조 검증 통과':'54 source items / 167 details: structure checks passed',
      '\\n기록 ':'\\nRecorded: ',' · 미확인 ':' · Unknown: ',' · 비해당 ':' · Not applicable: ',' · 근거 충돌 ':' · Conflicting: ',
      '\\n평가 범위 미입력: ':'\\nMissing assessment scope: ','없음':'None',
      '\\n실제 자산 운영 정보이나 CVE/VEX 판정의 정확성을 검증한 결과는 아닙니다.':'\\nThese checks do not verify asset operational information or CVE/VEX decision accuracy.',
      '검증/불러오기 실패: ':'Validation/import failed: ','JSON은 2 MiB 이하여야 합니다.':'JSON must be no larger than 2 MiB.',
      '검증 중 현재 입력이 변경됐습니다.':'The current draft changed during validation.'
    }
    backup=ROOT/'results/nist_information_20261118/before_english';backup.mkdir(exist_ok=True)
    for name in ['nist_table_profiles.html','nist_table_profiles_ui.js']:
        p=source_path(name, root=ROOT)
        if not (backup/name).exists():(backup/name).write_bytes(p.read_bytes())
        text=p.read_text(encoding='utf-8')
        for old,new in sorted(replacements.items(),key=lambda x:len(x[0]),reverse=True):text=text.replace(old,new)
        if name.endswith('.js') and 'const englishPresentation=' not in text:
            anchor="const catalog=JSON.parse(document.getElementById('op-template-data').textContent);"
            extra='''
const englishPresentation=PRESENTATION;
catalog.rows=englishPresentation.rows;catalog.scope_fields=englishPresentation.scope;
if(window.icsVexEnglish){const oldPlan=window.icsVexEnglish.plan;window.icsVexEnglish.plan=p=>{p=oldPlan(p);for(const f of p.fields||[])if(englishPresentation.details[f.id])f.label=f.id+' · '+englishPresentation.details[f.id];return p;};}
'''.replace('PRESENTATION',json.dumps(presentation,ensure_ascii=False))
            assert anchor in text;text=text.replace(anchor,anchor+extra)
        assert not re.search('[가-힣]',text),(name,re.findall('[가-힣][^\n]{0,100}',text)[:4])
        p.write_text(text,encoding='utf-8')
    # Localize the reference page while preserving the archived profile appendix.
    old=BeautifulSoup((LIVE/'derivation.html').read_text(encoding='utf-8'),'html.parser')
    archive=old.find(id='profile-derivation')
    page=BeautifulSoup(render(rows),'html.parser');page.html['lang']='en'
    notice=page.select_one('.notice')
    notice.clear();notice.append('All 54 source items and 167 collection details are included with their IDs, English evidence, source columns, page references, and interpretation notes. Collection details are project interpretations, not official NIST fields. Quote matching is verified; independent expert validation of the derivation remains separate.')
    for n in list(page.find_all(string=True)):
        if n.parent.name in {'script','style'}:continue
        text=str(n).replace('활용 구분(연구자 분류): ','Use category (project classification): ').replace('세부 수집정보와 영어 근거 · ','Collection details and English evidence · ').replace('원문 열: ','Source column: ').replace('인쇄 p.','Printed p.').replace('해석상 주의: ','Interpretation note: ')
        text=re.sub(r'(\d+)개',r'\1 details',text)
        n.replace_with(text)
    page.find(id='catalog-rows')['id']='nist-source-catalogue'
    page.find('a',string='Asset profile derivation')['href']='#profile-derivation'
    if archive:page.main.append(archive.extract())
    assert not re.search('[가-힣]',page.get_text())
    for p in [LIVE/'derivation.html',ROOT/'site/nist-operating-information.html',ROOT/'site/operating-profile-derivation.en.html']:
        p.write_text(str(page),encoding='utf-8')
    print(json.dumps(dict(source_items=54,detail_labels=len(labels),interpretation_notes=len(notes),canonical_profiles_changed=False)))

if __name__=='__main__':main()
