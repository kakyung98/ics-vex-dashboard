"""Render two self-contained, offline forms from neutral #4 review cases."""
import json
from pathlib import Path


def render_review_forms(out_dir, cases, *, packet_id):
    """Write reviewer_a/index.html and reviewer_b/index.html, keyed by packet_id."""
    cases = list(cases)
    if not isinstance(packet_id, str) or not packet_id.strip() or not cases:
        raise ValueError('A packet ID and at least one case are required.')
    review_ids = set()
    for case in cases:
        if set(case) != {'review_id', 'cve', 'component', 'evidence'}:
            raise ValueError('Only neutral review case fields can enter the forms.')
        review_id = case['review_id']
        if not isinstance(review_id, str) or not review_id or review_id in review_ids:
            raise ValueError('Expected a unique blind identifier.')
        review_ids.add(review_id)
        evidence_ids = set()
        for item in case['evidence']:
            if set(item) != {'evidence_id', 'kind', 'title', 'facts', 'source'}:
                raise ValueError('Unexpected evidence fields.')
            identifier = item['evidence_id']
            if not isinstance(identifier, str) or not identifier or identifier in evidence_ids:
                raise ValueError('Expected a unique evidence identifier within each case.')
            evidence_ids.add(identifier)
    rendered = []
    for slot in ('reviewer_a', 'reviewer_b'):
        payload = json.dumps(dict(packet_id=packet_id, reviewer_slot=slot, cases=cases),
                             ensure_ascii=False, separators=(',', ':'), allow_nan=False)
        # HTML's raw-text parser still recognizes </script> in JSON string literals.
        payload = payload.replace('<', r'\u003c').replace('>', r'\u003e').replace('&', r'\u0026')
        target = Path(out_dir) / slot / 'index.html'
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(PAGE.replace('<!--PACKET-->', payload), encoding='utf-8')
        rendered.append(target)
    return rendered


PAGE = r"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>시나리오 독립 검토</title>
<style>
:root{color-scheme:light;--ink:#192b36;--muted:#4c606a;--line:#c4d0d2;--paper:#fff;--green:#165848;--pale:#f1f6f4}
*{box-sizing:border-box}body{margin:0;background:#eef2f0;color:var(--ink);font:16px/1.55 "Malgun Gothic","맑은 고딕",system-ui,sans-serif}
main{max-width:1080px;margin:0 auto;padding:1.3rem clamp(.7rem,3vw,2.4rem) 3rem}
h1,h2,h3,p,dl{margin:0}h1{font-size:clamp(1.5rem,3.7vw,2.2rem);line-height:1.2}h2{font-size:1.27rem}h3{font-size:1.03rem}
header,.panel{background:var(--paper);border:1px solid var(--line);border-radius:9px;padding:clamp(1rem,2.3vw,1.55rem);margin-bottom:.85rem}
header{border-top:5px solid var(--green)}.muted{color:var(--muted);font-size:.92rem}.gap{margin-top:.7rem}
.row{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap}.between{justify-content:space-between}
label,.block{display:block}button,select,input,textarea{font:inherit;max-width:100%;color:inherit}
button,select,input,textarea{border:1px solid #8a9c9e;border-radius:5px;background:#fff;padding:.4rem .65rem}
button{cursor:pointer;white-space:normal}button:hover{background:var(--pale)}button:disabled{color:var(--muted);cursor:default;background:#edf0ef}
button.primary{background:var(--green);border-color:var(--green);color:white}button.primary:hover{background:#0c493b}
:focus-visible{outline:3px solid #d18526;outline-offset:2px}#who{width:min(12rem,100%)}#jump{max-width:100%;min-width:min(14rem,100%)}
.section-heading{margin:0 0 .6rem}.target{overflow-wrap:anywhere}.target strong{margin-right:.4rem}
.record{border:1px solid var(--line);border-radius:6px;margin-top:.55rem;background:#fff;overflow-wrap:anywhere}.record>summary{cursor:pointer;padding:.65rem .8rem;font-weight:650}
.record-body{padding:0 .8rem .8rem}.key{font-family:ui-monospace,Consolas,monospace;color:var(--green);margin-right:.45rem;font-size:.9em}
.kv{margin:0;display:grid;grid-template-columns:minmax(7rem,26%) minmax(0,1fr)}.kv>dt,.kv>dd{margin:0;padding:.2rem .5rem;border-bottom:1px solid #e0e6e4}
.kv>dt{color:var(--muted)}.array{margin:0;padding-left:1.15rem}.array>li+li{margin-top:.25rem}
.raw{font: .86em/1.45 ui-monospace,Consolas,monospace;color:var(--muted)}.source{margin-top:.5rem}.source summary{cursor:pointer;color:var(--green)}
.cite{display:inline-flex;align-items:center;gap:.4rem;margin-top:.65rem}.cite input{width:1.1em;height:1.1em}
textarea{width:100%;min-height:5.5rem;resize:vertical;display:block}.rating-fields{display:grid;gap:.9rem}
#progress{font-variant-numeric:tabular-nums}.message{min-height:1.4rem;color:var(--green);font-size:.95rem;overflow-wrap:anywhere}.error{color:#8b2d23}
#persist{margin-top:.5rem;color:var(--muted)}#persist.error{color:#8b2d23}small{font-size:.9em}
@media(max-width:600px){.kv{display:block}.kv>dt{padding-top:.35rem;border:0;font-weight:600}.kv>dd{padding-left:.7rem}
.row label{max-width:100%}#jump{width:100%}main{padding-top:.6rem}}
</style></head>
<body><main>
<header><h1>시나리오 독립 검토 <span id="role"></span></h1>
<p class="gap">동결한 합성 운영 입력과 공급사 문서를 읽고 해당 시나리오의 상태를 판정합니다. 평가 대상 설비의 현장 확인 여부는 근거의 출처에서 확인하세요.</p>
<p class="muted gap">각 검토자는 이 파일과 자신의 결과만 사용합니다. 다른 검토자의 판정은 최초 검토를 마친 뒤 대조합니다.</p>
<div class="row gap"><label>검토자 식별자 <input id="who" maxlength="160" autocomplete="off" placeholder="이름 또는 부여된 코드"></label>
<button id="download" type="button">내 검토 내보내기</button><button id="restore" type="button">내 파일 불러오기</button>
<input type="file" id="file" accept=".json,application/json" hidden></div>
<p id="persist" role="status"></p></header>
<nav class="panel" aria-label="검토할 사례">
<div class="row between"><label>사례 선택 <select id="jump"></select></label><strong id="progress"></strong></div>
<div class="row gap"><button type="button" id="prev">이전 사례</button><button type="button" id="next">다음 사례</button>
<button type="button" id="todo">다음 미완료 사례</button></div></nav>
<section class="panel" aria-labelledby="case-title"><div class="row between"><h2 id="case-title"></h2><span class="raw" id="review-id"></span></div>
<div class="target gap" id="target"></div></section>
<section class="panel" aria-labelledby="evidence-title"><h2 id="evidence-title" class="section-heading">검토 근거</h2>
<p class="muted">근거 항목을 열어 원문 값과 출처를 확인하고 판단에 사용한 항목을 선택하세요. 공급사 문서의 상태는 문서에 기재된 제품·버전 범위에 적용됩니다.</p>
<p id="coverage" class="gap"></p>
<div id="evidence"></div></section>
<section class="panel" aria-labelledby="rating-title"><div class="row between section-heading"><h2 id="rating-title">내 판정</h2><span id="phase"></span></div>
<div class="rating-fields"><label>시나리오 상태 <select id="status"><option value="">선택 전</option><option value="affected">영향 있음</option><option value="not_affected">미영향</option><option value="fixed">수정됨</option><option value="under_investigation">조사 보류</option></select></label>
<label>판단 사유 <textarea id="why" maxlength="12000" placeholder="대상 범위와 관측 사실, 인용한 근거가 판정으로 이어지는 이유"></textarea></label>
<label>누락된 근거·필요한 확인 자료 <textarea id="need" maxlength="12000" placeholder="확인이 필요한 자산·버전·기록의 종류와 범위"></textarea></label></div>
<div class="row gap"><button class="primary" id="finish" type="button">이 사례 검토 완료</button></div>
<p class="message gap" id="feedback" role="status" aria-live="polite"></p></section>
<noscript>검토 양식은 브라우저의 자바스크립트가 필요합니다.</noscript>
</main>
<script id="sample" type="application/json"><!--PACKET--></script>
<script>
'use strict';
const bundle = JSON.parse(document.getElementById('sample').textContent);
const cases = bundle.cases, slot = bundle.reviewer_slot, packet = bundle.packet_id;
const schema = 'item4-blind-review-ratings/1', scope = 'frozen_synthetic_scenario';
const key = JSON.stringify([schema, packet, slot]);
const byId = new Map(cases.map(c => [c.review_id,c]));
const states = ['', 'affected', 'not_affected', 'fixed', 'under_investigation'];
const get = id => document.getElementById(id);
const records = new Map();
let at = 0, reviewer = '';
const labels = {
  ref:'구성요소 참조',name:'제품명',vendor:'공급사',version:'버전',cpes:'CPE',scope:'적용 범위',component_ref:'구성요소 참조',
  product_id:'제품 ID',product_name:'제품명',deployment:'배포 상태',runtime:'실행 버전',inventory_coverage:'재고 완전성',
  context:'운영 입력',answers:'기록된 응답',question_id:'질문 ID',label:'질문',value:'입력값',record_type:'기록 유형',
  file:'파일',pointer:'원문 위치',document_sha256:'문서 SHA-256',sha256:'SHA-256',url:'문서 주소',source_kind:'자료 유형',
  origin:'관측 위치',mode:'운전 모드',title:'문서 제목',status:'문서 상태',quote:'발췌',version_membership:'버전 범위 포함 여부',
  synthetic:'합성 자료 표시',fields:'필드',document_id:'문서 식별자',source:'출처',product_status:'문서의 제품 상태',
  cve:'CVE',advisory_id:'권고문 ID',source_expression:'원문 근거에 연결된 조건식',
  operator_condition_excerpts:'조건별 원문 발췌',condition_id:'조건 ID',scope_product_keys:'적용 제품 식별자',
  text_sha256:'추출문 SHA-256',character_span:'원문 문자 범위',field_present:'필드 기재 여부',
  recorded_context:'기록된 운영 입력',inventory_coverage_present:'재고 범위 필드 기재 여부',document_sha:'문서 SHA-256',
  condition_ids:'조건 ID',product_ids:'제품 ID',running_version:'실행 버전',source_product_id:'원문 제품 ID',
  component:'구성요소',bom_properties:'BOM 원문 속성',publisher:'발행자',record_format:'원문 형식',
  cve_status_row_count:'이 CVE의 원문 제품 상태 행 수',product_ids_without_unique_tree_entry:'제품 목록에서 하나로 식별되지 않는 제품 ID',
  branch_category:'제품 트리 분류',branch_name:'제품 트리 원문',source_version:'원문 버전',source_status:'공급사 원문 상태',
  product_pointer:'원문 제품 위치',status_pointer:'원문 상태 위치',product_scope:'적용 제품 범위',source_scenario_id:'원문 조건 경로 ID',
  record_digest:'레코드 지문',packet_sha256:'입력 패킷 SHA-256',bom_sha256:'BOM SHA-256',aggregate_file:'전체 입력 파일',
  original_line_sha256:'원본 입력 행 SHA-256',indexed_sha256:'색인에 기재된 SHA-256',question_pointer:'질문 원문 위치',value_label:'선택지 원문'
};
const meanings = {
  current_single:'현재 단일 자산',not_deployed:'미배포로 응답',running:'배포 중',bom:'BOM 기재 버전과 일치',unknown:'미확인',
  mixed:'관측 혼재',complete:'완전',partial:'부분',different:'불일치',conflicting:'상충',not_installed:'미설치로 응답'
};
function node(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}
function fields(value) {
  if (value === null) return node('span','기재 없음 (null)','muted');
  if (Array.isArray(value)) {
    if (!value.length) return node('span','기재된 항목 없음','muted');
    const list = node('ul',undefined,'array');
    for (const v of value) { const li=node('li'); li.append(fields(v)); list.append(li); }
    return list;
  }
  if (typeof value === 'object') {
    const dl=node('dl',undefined,'kv');
    if (!Object.keys(value).length) return node('span','기재된 필드 없음','muted');
    for (const [k,v] of Object.entries(value)) {
      const dt=node('dt',Object.hasOwn(labels,k) ? labels[k] : k);
      dt.title=k;
      const dd=node('dd'); dd.append(fields(v)); dl.append(dt,dd);
    }
    return dl;
  }
  const s=String(value);
  return node('span',Object.hasOwn(meanings,s) ? meanings[s]+' ('+s+')' : s || '빈 문자열');
}
function blank(c) {
  return {review_id:c.review_id,status:'',evidence_ids:[],rationale:'',needed_records:'',reviewed_at:null};
}
function issue(row,c) {
  if (!row.status) return '시나리오 상태를 선택하세요.';
  if (!row.rationale.trim()) return '판단 사유를 입력하세요.';
  if (row.status==='under_investigation' && !row.needed_records.trim()) return '조사 보류에 필요한 추가 근거를 적어 주세요.';
  if (!row.evidence_ids.length && (c.evidence.length || row.status!=='under_investigation')) return '판단에 사용한 근거를 하나 이상 인용하세요.';
  return '';
}
function pack() {
  const result={schema_version:schema,scope,packet_id:packet,reviewer_slot:slot,reviewer_id:reviewer,ratings:[],drafts:[]};
  for (const c of cases) {
    const row=records.get(c.review_id);
    if (row) result[row.reviewed_at ? 'ratings':'drafts'].push(row);
  }
  return result;
}
function unpack(data) {
  if (!data || data.schema_version!==schema || data.packet_id!==packet || data.reviewer_slot!==slot || data.scope!==scope)
    throw Error('이 패킷과 검토자 양식에 해당하는 파일을 선택하세요.');
  if (typeof data.reviewer_id!=='string' || data.reviewer_id.length>160 ||
      !Array.isArray(data.ratings) || !Array.isArray(data.drafts)) throw Error('검토 파일의 형식을 확인하세요.');
  const loaded=new Map();
  for (const [rows,complete] of [[data.ratings,true],[data.drafts,false]]) {
    for (const row of rows) {
      if (!row || typeof row!=='object') throw Error('검토 행의 형식을 확인하세요.');
      const c=byId.get(row.review_id);
      if (!c || loaded.has(row.review_id)) throw Error('중복되거나 이 패킷에 없는 사례가 있습니다.');
      const available=new Set(c.evidence.map(e=>e.evidence_id));
      if (!states.includes(row.status) || typeof row.rationale!=='string' || typeof row.needed_records!=='string' ||
          row.rationale.length>12000 || row.needed_records.length>12000 || !Array.isArray(row.evidence_ids) ||
          new Set(row.evidence_ids).size!==row.evidence_ids.length || row.evidence_ids.some(id=>!available.has(id)))
        throw Error('판정 또는 인용 근거가 사례와 일치하지 않습니다.');
      if (complete) {
        if (!data.reviewer_id.trim() || typeof row.reviewed_at!=='string' || Number.isNaN(Date.parse(row.reviewed_at)) || issue(row,c))
          throw Error('완료된 행에 필요한 검토 정보가 없습니다.');
      } else if (row.reviewed_at!==null) throw Error('작성 중인 행의 완료 시점이 유효하지 않습니다.');
      loaded.set(row.review_id,{review_id:row.review_id,status:row.status,evidence_ids:[...row.evidence_ids],
        rationale:row.rationale,needed_records:row.needed_records,reviewed_at:row.reviewed_at});
    }
  }
  return loaded;
}
function persist() {
  try {
    localStorage.setItem(key,JSON.stringify(pack()));
    get('persist').className=''; get('persist').textContent='이 브라우저에 저장했습니다. 파일을 옮기거나 전달할 때는 내보내기를 사용하세요.';
  } catch {
    get('persist').className='error'; get('persist').textContent='브라우저 저장을 사용할 수 없습니다. 닫기 전에 내 검토를 내보내세요.';
  }
}
function tell(message,error=false) {
  get('feedback').className='message gap'+(error?' error':'');
  get('feedback').textContent=message;
}
function sync() {
  const n=cases.filter(c=>records.get(c.review_id)?.reviewed_at).length;
  get('progress').textContent='검토 완료 '+n+' / '+cases.length+'건';
  get('who').readOnly=records.size>0 && Boolean(reviewer.trim());
  get('who').title=get('who').readOnly?'기록된 응답에 사용한 검토자 식별자입니다.':'';
  get('todo').disabled=n===cases.length;
  const current=records.get(cases[at].review_id);
  get('phase').textContent=current?.reviewed_at?'검토 완료':current?'작성 중':'미검토';
  get('finish').disabled=Boolean(current?.reviewed_at);
  const options=get('jump').options;
  cases.forEach((c,i)=>{
    const rec=records.get(c.review_id);
    options[i].textContent=[i+1,c.cve,rec?.reviewed_at?'완료':rec?'작성 중':'미검토'].join(' · ');
  });
}
function update(row) {
  row.reviewed_at=null;
  const hasValue=row.status || row.evidence_ids.length || row.rationale || row.needed_records;
  if (hasValue) records.set(row.review_id,row); else records.delete(row.review_id);
  tell(''); persist(); sync();
}
function present(index) {
  at=index;
  const c=cases[at], row=records.get(c.review_id) || blank(c);
  get('jump').value=String(at);
  get('prev').disabled=at===0; get('next').disabled=at===cases.length-1;
  get('case-title').textContent=c.cve; get('review-id').textContent=c.review_id;
  get('target').replaceChildren(fields(c.component));
  const evidence=get('evidence'); evidence.replaceChildren();
  const count=k=>c.evidence.filter(e=>e.kind===k).length;
  get('coverage').textContent='권고문 '+count('advisory_reference')+'건 · 공급사 제품별 상태 원문 '+count('published_product_status')+
    '건 · 범위가 연결된 조건 대조 '+count('source_condition_mapping')+'건';
  if (count('synthetic_operator_input') && c.evidence.every(e=>['synthetic_operator_input','synthetic_bom_component',
        'advisory_reference','published_product_status','source_condition_mapping'].includes(e.kind))) {
    get('coverage').append(document.createElement('br'),document.createTextNode('이 사례의 운영 근거는 동결한 합성 입력입니다. 해당 설비를 확인한 현장 운영 원본은 미첨부입니다.'));
  }
  let openedSupplier=false;
  for (const e of c.evidence) {
    const block=node('details',undefined,'record');
    const isSupplier=e.evidence_id.startsWith('S');
    block.open=e.evidence_id==='O01' || (!openedSupplier && isSupplier);
    if (isSupplier) openedSupplier=true;
    const summary=node('summary');
    summary.append(node('span',e.evidence_id,'key'),document.createTextNode(e.title));
    const body=node('div',undefined,'record-body');
    const src=node('details',undefined,'source'); src.append(node('summary','출처와 원문 위치'),fields(e.source));
    const label=node('label',undefined,'cite'), box=node('input');
    box.type='checkbox'; box.value=e.evidence_id; box.checked=row.evidence_ids.includes(e.evidence_id);
    label.append(box,document.createTextNode(e.evidence_id+' 근거 인용'));
    body.append(fields(e.facts));
    if (e.kind==='synthetic_operator_input' && e.facts.context && !Object.hasOwn(e.facts.context,'inventory_coverage'))
      body.append(node('p','원본 운영 입력의 inventory_coverage 필드는 미기재입니다.','muted gap'));
    body.append(src,label); block.append(summary,body); evidence.append(block);
  }
  if (!c.evidence.length) evidence.append(node('p','이 사례에는 첨부된 근거가 없습니다.','muted'));
  get('status').value=row.status; get('why').value=row.rationale; get('need').value=row.needed_records;
  sync(); tell('');
}
function inputRow() {
  return {review_id:cases[at].review_id,status:get('status').value,
    evidence_ids:Array.from(get('evidence').querySelectorAll('input:checked'),box=>box.value),
    rationale:get('why').value,needed_records:get('need').value,reviewed_at:null};
}
for (const id of ['why','need']) get(id).addEventListener('input',()=>update(inputRow()));
for (const id of ['status','evidence']) get(id).addEventListener('change',()=>update(inputRow()));
get('who').addEventListener('input',()=>{
  reviewer=get('who').value;
  persist();
});
get('who').addEventListener('change',sync);
get('finish').onclick=()=>{
  if (!reviewer.trim()) { get('who').focus(); tell('검토자 식별자를 입력하세요.',true); return; }
  const row=inputRow(), problem=issue(row,cases[at]);
  if (problem) { tell(problem,true); return; }
  row.reviewed_at=new Date().toISOString(); records.set(row.review_id,row);
  persist(); sync(); tell('이 사례의 검토를 완료했습니다.');
};
get('jump').onchange=()=>present(Number(get('jump').value));
get('prev').onclick=()=>present(at-1); get('next').onclick=()=>present(at+1);
get('todo').onclick=()=>{
  for (let offset=1;offset<=cases.length;offset++) {
    const i=(at+offset)%cases.length;
    if (!records.get(cases[i].review_id)?.reviewed_at) { present(i); return; }
  }
};
get('download').onclick=()=>{
  const blob=new Blob([JSON.stringify(pack(),null,2)+'\n'],{type:'application/json'});
  const a=node('a'); a.href=URL.createObjectURL(blob);
  a.download=slot+'-ratings.json'; document.body.append(a); a.click(); a.remove();
  setTimeout(()=>URL.revokeObjectURL(a.href),1000);
};
get('restore').onclick=()=>get('file').click();
get('file').onchange=async()=>{
  const file=get('file').files[0]; get('file').value=''; if (!file) return;
  try {
    const data=JSON.parse(await file.text()), loaded=unpack(data);
    if ((reviewer.trim() || records.size) && !confirm('현재 검토 내용을 불러온 파일의 내용으로 바꿀까요?')) return;
    records.clear(); for (const [id,row] of loaded) records.set(id,row);
    reviewer=data.reviewer_id; get('who').value=reviewer;
    persist(); present(at); get('persist').textContent+=' 내 검토 파일을 불러왔습니다.';
  } catch (err) { get('persist').className='error'; get('persist').textContent='불러오기 실패. '+err.message; }
};
get('role').textContent=slot==='reviewer_a'?'A':'B';
document.title+=' '+get('role').textContent;
try {
  const saved=localStorage.getItem(key);
  if (saved) {
    const data=JSON.parse(saved); for (const [id,row] of unpack(data)) records.set(id,row);
    reviewer=data.reviewer_id; get('who').value=reviewer; get('persist').textContent='이 브라우저에 저장된 내 검토를 불러왔습니다.';
  } else get('persist').textContent='입력 내용은 이 브라우저에 저장됩니다. 다른 장치로 옮길 때는 내보내기를 사용하세요.';
} catch { get('persist').className='error'; get('persist').textContent='저장된 응답을 불러올 수 없습니다. 가지고 있는 내보내기 파일을 불러오세요.'; }
cases.forEach((c,i)=>get('jump').add(new Option('',String(i))));
present(0);
</script></body></html>"""
