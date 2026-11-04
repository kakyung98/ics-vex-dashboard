"""Embed the candidate workflow inside the original ICS-VEXForge application shell."""
import re
from src.candidate_match_page import CANDIDATE_MATCH_PAGE


def scope_css(css):
    result=[];position=0
    while position<len(css):
        opening=css.find('{',position)
        if opening<0:break
        header=css[position:opening].strip();depth=1;end=opening+1
        while depth and end<len(css):
            depth+=(css[end]=='{')-(css[end]=='}');end+=1
        body=css[opening+1:end-1]
        if header.startswith('@media'):
            result.append(header+'{'+scope_css(body)+'}')
        elif header!=':root':
            selectors=['#candidate-workspace' if s.strip()=='body' else '#candidate-workspace '+s.strip()
                       for s in header.split(',') if not re.match(r'^aside\b',s.strip())]
            if selectors:result.append(','.join(selectors)+'{'+body+'}')
        position=end
    return '\n'.join(result)


def widget_parts():
    source=CANDIDATE_MATCH_PAGE
    css=source.split('<style>',1)[1].split('</style>',1)[0]
    content=source.split('<main>',1)[1].split('</main>',1)[0]
    script=source.split('<script>',1)[1].split('</script>',1)[0]
    ids=re.findall(r'\bid="([^"]+)"',content)
    for name in ids:
        content=content.replace(f'id="{name}"',f'id="cm-{name}"').replace(f'for="{name}"',f'for="cm-{name}"')
    content=content.replace('<h1>SBOM에서 CVE 후보까지</h1>','<h2>Find CVE candidates</h2>')
    content=content.replace('IDENTIFICATION WORKSPACE','Step 1 · Identify')
    content=re.sub(r'<div class="notice"><strong>(.*?)</strong>(.*?)</div>',
        r'<div class="notice" role="note"><strong>Experimental identification — review candidates before making a VEX decision.</strong><details><summary>Model limitations</summary><p>\2</p></details></div>',content,count=1,flags=re.S)
    content=re.sub(r'(<input id="cm-file"[^>]+>)',r'<span class="file-picker"><span aria-hidden="true">Choose JSON</span>\1</span>',content,count=1)
    content=re.sub(r'(<section class="panel settings">)(.*?)(<div class="modelinfo">)',
        r'\1<h2 class="setup-title">Analysis setup</h2><p class="hint">Keep the defaults to begin. Open settings to compare methods or change the evidence source.</p><details class="advanced-settings"><summary>Evidence settings</summary>\2</details>\3',content,count=1,flags=re.S)
    content=content.replace('<strong style="font-size:13px">','<strong>')
    script=script.replace('document.getElementById(id)',"document.getElementById('cm-'+id)")
    script=script.replace("document.querySelectorAll('[data-stage]')","document.querySelectorAll('#candidate-workspace [data-stage]')")
    script=script.replace('Unified identification · Qwen3-8B + evidence checks','Local AI · Qwen3-8B')
    css=scope_css(css)
    for old,new in {'#101827':'var(--card2)','#0e1624':'var(--bg)','#111a2a':'var(--card)',
                    '#0f1726':'var(--bg)','#0c1422':'var(--bg)','#192438':'var(--card2)',
                    '#1c263a':'var(--card2)','#262541':'var(--card2)','#252844':'var(--card2)',
                    '#241f1a':'var(--card2)','#57472f':'var(--und)','#dfcdaa':'var(--ink2)',
                    '#46506a':'var(--line)','#d5e3f5':'var(--ink)','#ff9f9f':'var(--aff)','#111525':'var(--bg)'}.items():
        css=css.replace(old,new)
    css+='\n#candidate-workspace{--panel:var(--card);--muted:var(--ink2);--green:var(--safe);--amber:var(--und);font:inherit;background:transparent;margin:0} '
    css+='\n#candidate-workspace .panel,#candidate-workspace .component{border-radius:12px} '
    css+='\n#candidate-workspace textarea,#candidate-workspace select{font-family:var(--sans);font-size:14px} '
    css+='\n#candidate-workspace textarea,#candidate-workspace pre,#candidate-workspace code{font-family:var(--mono)} '
    css+='\n#candidate-workspace button,#candidate-workspace select{min-height:42px;border-radius:8px} '
    css+='\n#candidate-workspace .identity-diagnostics{border-top:1px solid var(--line);margin:18px 0;padding-top:16px} #candidate-workspace .identity-diagnostics h3,#candidate-workspace .analysis-scope h3{font-size:19px;margin:0 0 12px} #candidate-workspace .diagnostic-stages{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:14px 0} #candidate-workspace .diagnostic-stage,#candidate-workspace .diagnostic-input{background:var(--card2);border:1px solid var(--line);border-radius:12px;padding:16px;min-width:0;overflow-wrap:anywhere} #candidate-workspace .diagnostic-stage h4{font-size:16px;color:var(--purple);margin:0 0 10px} #candidate-workspace .identity-diagnostics p,#candidate-workspace .analysis-scope p{font-size:15px;line-height:1.65} #candidate-workspace .diagnostic-input{margin:10px 0} #candidate-workspace .diagnostic-input code,#candidate-workspace .analysis-scope code{display:block;white-space:normal;overflow-wrap:anywhere;font-size:14px;margin:9px 0} #candidate-workspace .analysis-scope{padding:22px;background:var(--card);border:1px solid var(--line);border-radius:16px;margin:18px 0} @media(max-width:1100px){#candidate-workspace .diagnostic-stages{grid-template-columns:1fr}} '
    return ('<style>'+css+'</style><h1>Vulnerability review</h1>'
            '<p class="sub">Upload an SBOM, review the evidence, and export a VEX assessment.</p>'
            '<section id="candidate-workspace">'+content+'</section>'
            '<section id="candidate-vex" class="card" hidden></section>',
            '<script>(()=>{'+script+'\n})();</script>')


BRIDGE_SCRIPT=r'''<script>
window.addEventListener('icsvex:candidates-reset',()=>{
 _item4ReviewId=null;_candidateJobId=null;_lastVex=null;_lastSbom=null;_pidMap=null;_vexFields={};_treeState={};_armResult=null;_srcSession=null;
 const target=document.getElementById('candidate-vex');if(target){target.hidden=true;target.replaceChildren()}
});
window.addEventListener('icsvex:candidates',async event=>{
 const target=document.getElementById('candidate-vex');if(!target)return;
 const id=event.detail.jobId;_candidateJobId=id;target.hidden=false;target.textContent='2단계 VEX 검토를 위한 후보와 근거를 연결하는 중…';
 try{
  const response=await fetch('/api/cve-match/jobs/'+encodeURIComponent(id)+'/vex');
  const data=await response.json();if(!response.ok)throw new Error(data.detail||'후보 연결 실패');if(_candidateJobId!==id)return;
  _lastVex=data;_lastSbom=data.sbom;_pidMap=null;_vexFields={};_treeState={};_armResult=null;_srcSession=null;
  let html='<h2>2단계 · 식별 후보 → VEX 검토</h2><p class="hint">이 단계는 방금 식별한 후보만 전달받습니다. 기존 매처를 다시 실행하거나 SBOM에 들어 있는 취약점 정답을 가져오지 않습니다.</p>';
  if(!data.cves.length){target.innerHTML=html+'<p class="hint">전달할 CVE 후보가 없습니다. 위의 식별 근거와 유보 사유를 확인하세요.</p>';return}
  html+='<p class="hint">고유 CVE '+data.cves.length+'개 · 구성요소 연결 '+data.mapping_count+'건. 후보의 초기 VEX 상태는 모두 under_investigation입니다.</p>';
  html+='<table><thead><tr><th>CVE</th><th>설치 버전 근거</th><th>초기 VEX</th></tr></thead><tbody>';
  for(const row of data.cves)html+='<tr><td>'+esc(row.cve)+'</td><td>'+esc(row.version_decided?'NVD 제품·버전 조건 확인':'미확인 — 추가 근거 필요')+'</td><td>under_investigation</td></tr>';
  html+='</tbody></table>'+_armForkHtml();target.innerHTML=html;
 }catch(error){target.textContent='VEX 연결 실패: '+error.message}
});
// Preserve all identified component mappings when using the existing exporters.
const _candidateOriginalRows=_vexRows;
_vexRows=function(){
 const rows=_candidateOriginalRows();if(!_candidateJobId)return rows;
 return rows.flatMap(row=>{
  const original=(_lastVex.cves||[]).find(r=>r.cve===row.cve)||{};
  const judgment=(_armResult?.statements||[]).find(s=>s.cve===row.cve);
  const updated=judgment?_applyGroundedVex(row):row;
  return (original.mappings||[{component:row.component}]).map(mapping=>{
   const item=Object.assign({},updated,{component:mapping.component,version:mapping.version});
   const vr=judgment?.operational_review?.version_evaluation?.components?.find(r=>r.component_ref===mapping.component_id);
   if(vr){
    const fixed=vr.state==='listed_fixed'&&vr.operator_attested&&vr.operator_evidence;
    item.status=fixed?'fixed':'under_investigation';item.justification='';
    if(item.status!==updated.status)item.impact_statement='Component-specific version review: '+vr.state+'. Product/version: '+vr.product_name+' / '+(vr.installed_version||'unknown')+'. Draft based on operator reports.';
   }
   return item;
  });
 });
};
</script>'''
