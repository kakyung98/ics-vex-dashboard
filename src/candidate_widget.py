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
        r'<div class="notice" role="note"><strong>Experimental identification — review candidates before making a VEX decision.</strong><details><summary>Model limitations</summary><p>Generalization to real SBOMs is unverified. Identification preserves source evidence; candidates require product/version and operational review. An empty result does not establish safety.</p></details></div>',content,count=1,flags=re.S)
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
 const panel=document.getElementById('candidate-vex');if(panel){panel.hidden=true;panel.replaceChildren()}
 window.dispatchEvent(new CustomEvent('icsvex:operational-reset'));
});
window.addEventListener('icsvex:candidates',async event=>{
 const panel=document.getElementById('candidate-vex');if(!panel)return;
 panel.hidden=false;panel.textContent='Loading identified CVEs for operational review...';
 const job=event.detail.jobId;panel.dataset.job=job;
 try{
  const response=await fetch('/api/cve-match/jobs/'+encodeURIComponent(job)+'/vex');
  const data=await response.json();if(!response.ok)throw new Error(data.detail||'Candidate handoff failed');
  if(panel.dataset.job!==job)return;
  panel.replaceChildren();const title=document.createElement('h2');title.textContent='Operational-context assessment';panel.append(title);
  const note=document.createElement('p');note.textContent=data.cves.length+' candidate CVEs. Review source conditions, group profiles, and answer scoped operating questions.';panel.append(note);
  window.dispatchEvent(new CustomEvent('icsvex:operational-handoff',{detail:data}));
 }catch(error){panel.textContent='Unable to prepare operational review: '+error.message}
});
</script>'''
