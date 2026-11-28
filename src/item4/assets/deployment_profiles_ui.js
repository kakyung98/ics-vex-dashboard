/* Operating inventory only; never adds an observation to a CVE assessment. */
(()=>{'use strict';
const $=id=>document.getElementById('op-'+id),data=$('template-data');if(!data)return;
const catalog=JSON.parse(data.textContent),drafts=new Map();let selected=null,draft=null;
const clone=x=>JSON.parse(JSON.stringify(x));
const names={interface:'대상 인터페이스',protocol:'프로토콜',transport:'전송 방식',port:'포트 (없음·비IP는 빈칸)',enabled:'활성 여부',origin:'출발 구간 / 주체',target:'목적 자산 / 구간',service:'대상 서비스',mechanism:'접속 방식',state:'경로 상태',rule_id:'규칙 식별자',action:'허용 / 차단',applied:'실제 적용 여부',input_kind:'입력 파일 / 데이터 종류',processor:'처리 도구 / 서비스',allowed:'처리 허용 여부',name:'운전 모드 / 설정 이름',value:'실제 설정 값',authentication:'인증 방식',roles:'역할 / 권한 (쉼표 구분)',location:'설치 / 접근 위치',access_control:'접근 통제',maintenance_exceptions:'정비 예외',permitted_transitions:'허용되는 모드 전환 (쉼표 구분)',detail:'실제 운영 내용 / 기록'};
function el(tag,text){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;return e}
function note(text,error=false){$('status').textContent=text;$('status').dataset.error=String(error)}
function label(title,input){const x=el('label',title);x.append(input);return x}
function option(value,text){const x=el('option',text);x.value=value;return x}
function shapeMatches(schema,v){
 if(schema.oneOf)return schema.oneOf.filter(s=>shapeMatches(s,v)).length===1;
 if('const'in schema&&JSON.stringify(schema.const)!==JSON.stringify(v))return false;
 if(schema.enum&&!schema.enum.includes(v))return false;
 const types=Array.isArray(schema.type)?schema.type:[schema.type];
 if(schema.type&&!types.some(t=>t==='null'?v===null:t==='array'?Array.isArray(v):t==='object'?v!==null&&typeof v==='object'&&!Array.isArray(v):t==='integer'?Number.isInteger(v):typeof v===t))return false;
 if(typeof v==='string'&&schema.minLength!==undefined&&v.length<schema.minLength)return false;
 if(typeof v==='number'&&(!Number.isFinite(v)||(schema.minimum!==undefined&&v<schema.minimum)||(schema.maximum!==undefined&&v>schema.maximum)))return false;
 if(Array.isArray(v)){if((schema.minItems!==undefined&&v.length<schema.minItems)||(schema.maxItems!==undefined&&v.length>schema.maxItems))return false;if(schema.items&&!v.every(x=>shapeMatches(schema.items,x)))return false}
 if(v&&typeof v==='object'&&!Array.isArray(v)&&schema.properties){if((schema.required||[]).some(k=>!(k in v)))return false;if(schema.additionalProperties===false&&Object.keys(v).some(k=>!(k in schema.properties)))return false;for(const k of Object.keys(v))if(schema.properties[k]&&!shapeMatches(schema.properties[k],v[k]))return false}
 return true;
}
function check(value,profile){
 const exact=['version','asset_type_id','template_sha256','scope','inventory','evidence'];
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==exact.length||exact.some(k=>!(k in value)))throw Error('プロファイル形式が一致しません。'.replace('プロファイル形式が一致しません。','運営プロファイルの形式が一致しません。'));
 if(value.version!==catalog.version||value.asset_type_id!==profile.asset.id||value.template_sha256!==profile.definition.definition_sha256)throw Error('テンプレートの版または資産種別が一致しません。'.replace('テンプレートの版または資産種別が一致しません。','템플릿 버전 또는 자산 유형이 다릅니다.'));
 if(!shapeMatches(profile.definition.schema,value.inventory))throw Error('운영 항목의 필수값·포트·상태를 확인하십시오. 기록이 있는 항목은 빈 행을 둘 수 없습니다.');
 if(!value.scope||Array.isArray(value.scope)||Object.keys(value.scope).length!==Object.keys(catalog.scope_fields).length||Object.keys(catalog.scope_fields).some(k=>typeof value.scope[k]!=='string'||value.scope[k].length>2000))throw Error('자산·평가 범위를 확인하십시오.');
 if(!value.evidence||Array.isArray(value.evidence)||typeof value.evidence!=='object'||Object.keys(value.evidence).length>200)throw Error('근거 목록을 확인하십시오.');
 for(const x of Object.values(value.evidence))if(!x||Object.keys(x).sort().join(',')!=='excerpt,source'||![x.source,x.excerpt].every(v=>typeof v==='string'&&v.trim()&&v.length<=20000))throw Error('기록된 항목마다 근거 출처와 확인 내용이 필요합니다.');
 for(const x of Object.values(value.inventory.values))if(x.evidence_ids.some(id=>!Object.hasOwn(value.evidence,id)))throw Error('항목에서 참조한 근거가 없습니다.');
 const dates={};for(const k of ['observed_at','valid_until'])if(value.scope[k].trim()){if(!/(Z|[+-]\d\d:\d\d)$/.test(value.scope[k])||!Number.isFinite(Date.parse(value.scope[k])))throw Error('관측 시각과 유효기한은 시간대를 포함한 ISO 8601로 입력하십시오.');dates[k]=Date.parse(value.scope[k])}
 if(dates.valid_until!==undefined&&dates.observed_at!==undefined&&dates.valid_until<=dates.observed_at)throw Error('유효기한은 관측 시각보다 뒤여야 합니다.');
 const mode=value.inventory.values.operating_mode;if(mode.state==='recorded'&&value.scope.mode.trim()&&mode.data.name!==value.scope.mode.trim())throw Error('운전 모드 기록과 평가 범위의 모드가 다릅니다.');
 const values=Object.values(value.inventory.values),unknown=values.filter(x=>x.state==='unknown').length;
 const missing=Object.values(value.scope).filter(x=>!x.trim()).length;
 return `기록 ${values.length-unknown}개 · 모름 ${unknown}개 · 범위 미입력 ${missing}개`+(dates.valid_until<=Date.now()?' · 근거 유효기간 만료':'')+(dates.observed_at>Date.now()?' · 관측 시각이 미래입니다':'')+' · 운영 기록 초안이며 VEX 판정이 아닙니다.';
}
function emptyRow(schema){return Object.fromEntries(Object.entries(schema.properties).map(([k,v])=>[k,v.type==='array'?[]:Array.isArray(v.type)&&v.type.includes('null')?null:'']))}
function paint(){
 $('scope').replaceChildren();$('fields').replaceChildren();$('editor').hidden=!selected;if(!selected)return;
 $('type-source').replaceChildren(document.createTextNode(selected.asset.name+' · '));const a=el('a','자산 유형 정의');a.href=selected.asset.source_url;a.target='_blank';a.rel='noopener';$('type-source').append(a);
 for(const [key,title]of Object.entries(catalog.scope_fields)){const input=el('input');input.value=draft.scope[key];input.maxLength=2000;if(['observed_at','valid_until'].includes(key))input.placeholder='2026-11-17T16:00:00+09:00';input.oninput=()=>{draft.scope[key]=input.value};$('scope').append(label(title,input))}
 for(const field of selected.definition.fields){
  const box=el('details'),summary=el('summary',field.question),content=el('div');box.append(summary,content);$('fields').append(box);
  const value=draft.inventory.values[field.id],state=el('select');state.setAttribute('aria-label',field.question+' · 응답 상태');state.append(option('unknown','모름 / 미확인'),option('recorded','기록 있음'));if(field.data_kind!=='mode')state.append(option('recorded_empty','조사 범위에서 항목 없음'));state.value=value.state;content.append(label('기록 상태',state));
  state.onchange=()=>{for(const id of value.evidence_ids)delete draft.evidence[id];value.state=state.value;value.evidence_ids=[];delete value.coverage_scope;value.data=null;if(value.state!=='unknown'){value.evidence_ids=['evidence-'+field.id];draft.evidence[value.evidence_ids[0]]={source:'',excerpt:''};const shape=selected.row_shapes[field.data_kind];value.data=value.state==='recorded_empty'?[]:field.data_kind==='mode'?emptyRow(shape):[emptyRow(shape)];if(value.state==='recorded_empty')value.coverage_scope=''}paint();Array.from($('fields').children).find(x=>x.firstChild.textContent===field.question).open=true};
  if(value.state==='unknown')continue;
  if(value.state==='recorded_empty'){const input=el('textarea');input.value=value.coverage_scope;input.oninput=()=>value.coverage_scope=input.value;content.append(label('실제로 조사한 범위와 인터페이스',input))}
  else{
   const shape=selected.row_shapes[field.data_kind],rows=field.data_kind==='mode'?[value.data]:value.data;
   rows.forEach((row,index)=>{const wrap=el('div');wrap.className='op-record';const grid=el('div');grid.className='op-grid';wrap.append(grid);content.append(wrap);
    for(const[key,schema]of Object.entries(shape.properties)){let input;
     if(schema.enum){input=el('select');input.append(option('','선택하십시오'));for(const v of schema.enum)input.append(option(v,({true:'예',false:'아니오',unknown:'모름',allowed:'허용',blocked:'차단',allow:'허용',deny:'차단'})[v]||v));input.value=row[key]}
     else{input=el('input');input.value=Array.isArray(row[key])?row[key].join(', '):row[key]??'';input.maxLength=20000;if(schema.type?.includes?.('integer')){input.type='number';input.min='0';input.max='65535'}}
     input.oninput=()=>{row[key]=schema.type==='array'?input.value.split(',').map(x=>x.trim()).filter(Boolean):schema.type?.includes?.('integer')?(input.value===''?null:Number(input.value)):input.value};grid.append(label(names[key]||key,input));
    }
    if(field.data_kind!=='mode'){const remove=el('button','이 행 삭제');remove.type='button';remove.onclick=()=>{value.data.splice(index,1);paint()};wrap.append(remove)}
   });
   if(field.data_kind!=='mode'){const add=el('button','기록 행 추가');add.type='button';add.onclick=()=>{value.data.push(emptyRow(shape));paint()};content.append(add)}
  }
  for(const id of value.evidence_ids){const evidence=draft.evidence[id];for(const[k,title]of [['source','근거 출처 (문서·설정 백업·운영 기록 식별자)'],['excerpt','실제 확인 내용 / 근거 인용']]){const input=el('textarea');input.value=evidence?.[k]||'';input.maxLength=20000;input.oninput=()=>{(draft.evidence[id]||={source:'',excerpt:''})[k]=input.value};content.append(label(title,input))}}
 }
}
function choose(id){selected=catalog.profiles.find(p=>p.asset.id===id)||null;draft=selected?(drafts.get(id)||clone(selected.blank)):null;if(draft)drafts.set(id,draft);$('type').value=id;paint();note(selected?'모든 항목을 실제 설치 자산의 운영 기록으로 확인하십시오.':'자산 유형을 선택하십시오.')}
for(const p of catalog.profiles)$('type').append(option(p.asset.id,p.asset.name));$('type').onchange=()=>choose($('type').value);
document.addEventListener('click',event=>{const button=event.target.closest?.('#av-assets [data-group]');if(button)choose(button.dataset.group)});
$('validate').onclick=()=>{try{note(check(draft,selected))}catch(e){note(e.message,true)}};
function save(value){const blob=new Blob([JSON.stringify(value,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),a=el('a');a.href=url;a.download='operating-profile-'+value.asset_type_id+'-'+(value.scope.asset_ref||'blank').replace(/[^a-zA-Z0-9_-]/g,'_').slice(0,80)+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
$('export').onclick=()=>{try{note(check(draft,selected));save(draft)}catch(e){note(e.message,true)}};
$('blank').onclick=()=>save(clone(selected.blank));$('import-button').onclick=()=>$('import').click();
$('import').onchange=async()=>{try{const file=$('import').files[0];if(!file)return;if(file.size>2*1024*1024)throw Error('JSON은 2 MiB 이하만 불러올 수 있습니다.');const value=JSON.parse(await file.text()),profile=catalog.profiles.find(p=>p.asset.id===value.asset_type_id);if(!profile)throw Error('등록되지 않은 자산 유형입니다.');const result=check(value,profile);drafts.set(value.asset_type_id,value);choose(value.asset_type_id);note('불러오기 완료 · '+result)}catch(e){note(e.message,true)}finally{$('import').value=''}};
})();
