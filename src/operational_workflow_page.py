"""Prerequisite workflow inside the shared dashboard shell."""
from pathlib import Path
import re

def widget_parts():
    root=Path(__file__).parent
    html=(root/'operational_workflow.html').read_text(encoding='utf-8')
    css=html.split('<style>',1)[1].split('</style>',1)[0]
    content=html.split('<main>',1)[1].split('</main>',1)[0].split('<script>',1)[0]
    for name in re.findall(r'\bid="([^"]+)"',content):
        content=content.replace(f'id="{name}"',f'id="ow-{name}"').replace(f'for="{name}"',f'for="ow-{name}"')
    corpus_panel=re.search(r'<section id="ow-corpusPanel".*?</section>',content,re.S).group()
    content=content.replace(corpus_panel,'',1)
    from .candidate_widget import scope_css
    css=scope_css(css).replace('#candidate-workspace','#operational-workspace')
    colors={'#e5eaf5':'var(--ink)','#0d1422':'var(--bg)','#a7b4cb':'var(--ink2)',
            '#2a3951':'var(--line)','#152136':'var(--card)','#9dbaff':'var(--lime)',
            '#0f1a2e':'var(--card2)','#40516e':'var(--line)','#274372':'#e7e0f7',
            '#91b6ff':'var(--purple)','#b5ccff':'var(--purple)','#c3d8ff':'var(--purple)',
            '#253859':'#e7e0f7','#242437':'#f6f0dd','#bdcae0':'var(--ink2)',
            '#19283f':'#edf4d4','#bdcff3':'var(--purple)','#ffc0c0':'var(--aff)',
            '#9be4c4':'var(--safe)','#8cb6ff':'var(--purple)'}
    for old,new in colors.items():css=css.replace(old,new)
    css+='\n#operational-workspace{--muted:var(--ink2);--panel:var(--card);--accent:var(--purple);font:inherit;color:var(--ink)}#operational-workspace .steps button[aria-selected=true]{color:var(--ink)}#operational-workspace textarea{min-height:100px}#operational-workspace .card{border-radius:20px}#operational-workspace .steps button{border-radius:22px}#operational-workspace .tag{background:#e7e0f7;color:var(--purple)}'
    css+='\n@media(max-width:650px){#operational-workspace .steps{flex-wrap:nowrap;overflow-x:auto;padding-bottom:8px}#operational-workspace .steps button{min-width:170px;max-width:220px;flex:none}}'
    css+='\n#ow-corpusPanel .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}#ow-corpusPanel label input,#ow-corpusPanel label select{width:100%;display:block}#ow-corpusPanel .toolbar{display:flex;flex-wrap:wrap;gap:12px;margin:15px 0}#ow-corpusPanel .tablewrap{overflow:auto}#ow-corpusPanel table{width:100%}#ow-corpusPanel #ow-corpusSummary{padding:15px;background:var(--card2);border-radius:14px;line-height:1.7}'
    script=(root/'operational_workflow_ui.js').read_text(encoding='utf-8')
    script=script.replace('document.getElementById(id)',"(document.getElementById('ow-'+id)||document.getElementById('operational-workspace').querySelector('[id=\"'+id+'\"]'))")
    script=script.replace('document.querySelectorAll(',"document.getElementById('operational-workspace').querySelectorAll(")
    script=script.replace('document.querySelector(',"document.getElementById('operational-workspace').querySelector(")
    return '<style>'+css+'</style>'+corpus_panel+'<section id="operational-workspace">'+content+'</section>','<script>'+script+'</script>'

def render():
    from .api_server import make_page
    return make_page('vex-decision')
