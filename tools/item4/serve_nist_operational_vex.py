"""Run the existing BOM/VEX service with the 54-row / 167-detail input model."""
from pathlib import Path
from html import escape
import importlib.util, json, re, sys, os, hashlib

ROOT = Path(__file__).resolve().parents[2]
HOME = ROOT/'local-service/sbom-vex/vex_operational_logic_20261117'
# Keep shared model downloads off the system drive, including fresh launches
# from desktop processes which have not yet reloaded the user environment.
os.environ.setdefault('HF_HOME',str(ROOT.parent/'ICS-VEX-support/cache/huggingface'))
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(HOME))
port = int(sys.argv[1]) if len(sys.argv)>1 and sys.argv[1].isdigit() else 8100
if port == 8100 and os.environ.get('LOCALAPPDATA'):
    runtime_jobs=Path(os.environ['LOCALAPPDATA'])/'ICS-VEX'/'runtime'/'identification_jobs_active.sqlite3'
    if runtime_jobs.is_file():os.environ['ICSVEX_IDENTIFICATION_JOB_DB']=str(runtime_jobs)
spec = importlib.util.spec_from_file_location('nist_existing_service', HOME/'serve_vex.py')
service = importlib.util.module_from_spec(spec); spec.loader.exec_module(service)
from src.item4.assets import operating_profile_catalog as model
from src.item4.decision import scoped_proof_evaluation as typed # Historical artifact schema only.
from src.item4.decision import evidence_based_vex as automatic
from src.item4.decision import population_condition_rules as population
import operational_vex as V
V.P = model
if port == 8100 and os.environ.get('LOCALAPPDATA'):
    # A validated copy of the existing durable stores can live on the local
    # system drive when the project drive has stalled writes. Keep the original
    # files in place; never create an empty replacement for an absent copy.
    runtime_home=Path(os.environ['LOCALAPPDATA'])/'ICS-VEX'/'runtime'
    jobs=runtime_home/'identification_jobs_active.sqlite3'
    workflows=runtime_home/'workflows.sqlite3'
    reviews=runtime_home/'reviews.sqlite3'
    if any(p.is_file() for p in (jobs,workflows,reviews)) and not all(p.is_file() for p in (jobs,workflows,reviews)):
        raise RuntimeError('Runtime storage is incomplete; restore the missing database before starting.')
    if all(p.is_file() for p in (jobs,workflows,reviews)):
        from src.common.data import analysis_job_store as review_store
        review_store.DB=jobs
        service.bom_vex_workflow.DB=workflows
        service.operational_vex_api.DB=reviews
if port != 8100:
    test_home=ROOT/'results/nist_information_20261118/input_preflight'
    test_home.mkdir(parents=True,exist_ok=True)
    service.operational_vex_api.DB=test_home/'reviews.sqlite3'
    service.bom_vex_workflow.DB=test_home/'workflows.sqlite3'
# One decision path for direct reviews, BOM cases, saved reviews and exports.
# Operator-supplied verdicts and condition truth are never accepted.
V.VERSION=automatic.VERSION
V.plan=automatic.plan
V.evaluate=automatic.evaluate
V.export=automatic.export
service.base.model = model
service.base.templates = model.catalogue
for route in service.app.routes:
    if getattr(route,'path',None) == '/api/asset-vulntology/operating-profiles':
        route.endpoint = model.catalogue
        route.dependant.call = model.catalogue
    if getattr(route,'path',None) == '/api/asset-vulntology/operating-profiles/derivation':
        def derivation():
            c=model.catalogue()
            return dict(version=model.VERSION,source_rows=54,collection_elements=167,rows=c['rows'])
        route.endpoint=derivation
        route.dependant.call=derivation

ui_path = ROOT/'src/item4/assets/operating_profile_catalog_ui.js'
markup_path = ROOT/'src/item4/assets/operating_profile_catalog.html'
original_page = service.make_page
def profile_ui():
    script=ui_path.read_text(encoding='utf-8')
    return script.replace('/* NIST_ENGLISH_PRESENTATION */',(ROOT/'src/item4/assets/operating_profile_translations.json').read_text(encoding='utf-8'))

def client_catalogue():
    data=model.catalogue()
    return {k:data[k] for k in ['version','scope_fields','rows','answer_specs']}|{'profiles':[{'asset':p['asset'],'blank':p['blank']} for p in data['profiles']]}
def page(*args, **kwargs):
    html = original_page(*args, **kwargs)
    if args and args[0] == 'vex-decision':
        html=html.replace((service.EN/'operational_vex.html').read_text(encoding='utf-8'),(ROOT/'src/item4/web/evidence_based_vex_page.html').read_text(encoding='utf-8'),1)
        html=html.replace((service.EN/'operational_vex_ui.js').read_text(encoding='utf-8'),(ROOT/'src/item4/web/evidence_based_vex_ui.js').read_text(encoding='utf-8'),1)
        markup=markup_path.read_text(encoding='utf-8')
        html = html.replace((service.EN/'operating_profiles.html').read_text(encoding='utf-8'),markup,1)
        html = html.replace((service.EN/'operating_profiles_ui.js').read_text(encoding='utf-8'), profile_ui(), 1)
        html, count = re.subn(r'(<div id="op-template-data" hidden>).*?(</div>)',
            lambda m:m[1]+escape(json.dumps(client_catalogue(),ensure_ascii=False),quote=False)+m[2], html, flags=re.S)
        assert count == 1
    return html
service.make_page = page
service.base.api_server.make_page = page
old_bom_page = service.bom_page
def bom_page():
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(old_bom_page(), 'html.parser')
    soup.html['lang']='en'
    soup.html['translate']='no'
    soup.head.append(soup.new_tag('meta',attrs={'name':'google','content':'notranslate'}))
    subtitle=soup.select_one('#bw-panel .bw-subtitle')
    if subtitle:
        subtitle.string='Upload a BOM with identified CVEs to find ICSA evidence, classify the asset and extract exploitation prerequisites. CPE is optional.'
    for link in soup.select('aside a'):
        if (link.get('href') or '').endswith('bom-vex.html'):
            link['href']='/item4.html'
    for code in [profile_ui(),(ROOT/'src/item4/web/evidence_based_vex_ui.js').read_text(encoding='utf-8')]:
        script=soup.new_tag('script');script.string=code
        bom_script=next((s for s in soup.body.find_all('script') if 'let w=null,selected=null' in s.text),None)
        if bom_script:bom_script.insert_before(script)
        else:soup.body.append(script)
    for script in soup.find_all('script'):
        if 'let w=null,selected=null' in script.text:script.string=(ROOT/'src/item4/web/bom_vex_workflow_ui.js').read_text(encoding='utf-8')
    # Keep the underlying controls for the profile editor, but remove the
    # standalone diagnostics and manual asset-type selection from this workflow.
    panel=soup.find(id='op-panel')
    for note in panel.select(':scope > p.op-note, :scope > p.op-muted'):
        note['hidden']=''
    panel.find(id='op-type').find_parent('label')['style']='display:none!important'
    panel.find(id='op-check').find_parent(class_='op-toolbar')['hidden']=''
    panel.find(id='op-result')['hidden']=''
    soup.find(id='bw-type').find_parent('label')['style']='display:none!important'
    classification=soup.new_tag('div',id='bw-classification');classification['class']='bw-note';classification['aria-live']='polite'
    soup.find(id='bw-summary').insert_before(classification)
    # The 167-item catalogue remains available for audit; input is CVE-specific.
    fields=soup.find(id='op-fields')
    if fields:
        details=soup.new_tag('details');summary=soup.new_tag('summary');summary.string='Additional operating questions (optional)'
        fields.insert_before(details);details.append(summary)
        for id in ['op-filter','op-search']:
            label=soup.find(id=id).find_parent('label');details.append(label.extract())
        details.append(soup.find(id='op-counts').extract());details.append(fields.extract())
    return str(soup)
service.bom_page = bom_page
app = service.app
from src.item4.web.asset_vex_questionnaire_api import router as item4_questionnaire_router; from src.item4.web.asset_vex_questionnaire_api import legacy_router as retired_item4_router
app.include_router(item4_questionnaire_router)
app.include_router(retired_item4_router)
# Retire every public entry into the former operating questionnaire. Historical
# stores remain available; the new asset-key workflow uses /api/item4/analyses.
def retired_operating_workflow():
    from fastapi import HTTPException
    raise HTTPException(410,'This questionnaire endpoint is retired. Use /api/item4/analyses for the asset-key input and VEX workflow.')
retired_paths={'/api/operational-vex/plan','/api/operational-vex/assess',
    '/api/operational-vex/batch','/api/operational-vex/reviews/{rid}',
    '/api/operational-vex/reviews/{rid}/input','/api/operational-vex/reviews/{rid}/export/{kind}',
    '/api/bom-vex/from-job','/api/bom-vex/from-json',
    '/api/bom-vex/workflows/{wid}','/api/bom-vex/workflows/{wid}/profiles',
    '/api/bom-vex/workflows/{wid}/cases/{cid}/assess',
    '/api/bom-vex/workflows/{wid}/export/{kind}',
    '/api/bom-vex/workflows/{wid}/cases/{cid}/export/{kind}'}
def is_retired_question_route(path):
    return (path in retired_paths or path in {'/api/oc/questions','/api/oc/answers','/question-mining.html'} or
        path.startswith(('/api/cluster-questions/','/api/question-mining/','/api/operational-workflow/')) or
        (path.startswith('/api/item4/') and not path.startswith(('/api/item4/analyses/','/api/item4/questionnaires/'))))
retired_routes=[r for r in app.routes if is_retired_question_route(getattr(r,'path',''))]
app.router.routes[:]=[r for r in app.routes if r not in retired_routes]
for retired in retired_routes:
    app.add_api_route(retired.path,retired_operating_workflow,methods=list(retired.methods))
from src.item4.web.evaluation_runs_api import router as run_ledger_router
from src.item4.web.scenario_evaluation_api import router as scenario_run_router
app.include_router(scenario_run_router)
app.include_router(run_ledger_router)
from fastapi.responses import FileResponse
from fastapi.responses import HTMLResponse
from src.item4.web.source_evaluation_api import router as source_evaluation_router
app.include_router(source_evaluation_router)
def item4_page():
    """Use the existing Operational VEX shell, brand, sidebar and controls."""
    from bs4 import BeautifulSoup
    # Build the shared chrome without invoking the retired profile editor.
    # Its 167-field catalogue is not part of the active asset-key contract.
    soup=BeautifulSoup(service.make_page('analyzer'),'html.parser')
    soup.html['lang']='en'
    soup.html['translate']='no'
    no_translate=soup.new_tag('meta',attrs={'name':'google','content':'notranslate'})
    soup.head.append(no_translate)
    # Reuse the identification upload card styles in the Operational VEX workspace.
    for shared_style in soup.find_all('style'):
        if '.workflow-panel' in shared_style.text:
            shared_style.string=shared_style.text.replace('#candidate-workspace',':is(#candidate-workspace,#item4-workspace)')
    template=BeautifulSoup((ROOT/'src/item4/web/asset_vex_questionnaire.html').read_text(encoding='utf-8'),'html.parser')
    for script in soup.find_all('script'):script.decompose()
    modal=soup.find(id='ov')
    if modal:modal.decompose()
    main=soup.select_one('main.main')
    # Keep the same workspace chrome as SBOM identification. Replacing the
    # workflow must not remove its brand header or shared footer.
    topbar=main.select_one(':scope > .workspace-topbar')
    footer=main.select_one(':scope > .foot')
    if topbar:topbar.extract()
    if footer:footer.extract()
    main.clear()
    if topbar:main.append(topbar)
    content=template.find('main');content.name='section';content['id']='item4-workspace'
    nav=content.find('nav')
    if nav:nav.decompose()
    classes={'grid':'ov-grid','actions':'ov-toolbar','note':'ov-note','muted':'ov-muted','badge':'ov-pill'}
    for element in content.find_all(class_=True):element['class']=[classes.get(c,c) for c in element['class']]
    heading=content.find('h1',recursive=False)
    if heading:main.append(heading.extract())
    main.append(content)
    if footer:main.append(footer)
    for a in soup.select('aside a'):
        if (a.get('href') or '').endswith('bom-vex.html'):a['href']='/item4.html'
        classes=[c for c in a.get('class',[]) if c not in {'active','on'}]
        a.attrs.pop('aria-current',None)
        if (a.get('href') or '').endswith('item4.html'):
            classes.append('on')
            a['aria-current']='page'
        a['class']=classes
    style=soup.new_tag('style')
    base=BeautifulSoup((service.EN/'operational_vex.html').read_text(encoding='utf-8'),'html.parser').find('style').string
    style.string=base.replace('#ov-panel','#item4-workspace')+'''
#item4-workspace{font-size:16px}#item4-workspace .lead{line-height:1.7}
#item4-workspace .agent-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));align-items:start;gap:14px;margin:20px 0}
#item4-workspace .agent-grid .card{margin:0;padding:18px}#item4-workspace .agent-grid h2{font-size:18px}
#item4-workspace #asset-result details{margin:14px 0 0}
#item4-workspace #asset-result summary{cursor:pointer;font-weight:600}
#item4-workspace .source-list{padding:0;list-style:none;margin:10px 0 0}
#item4-workspace .source-list li{padding:8px 0;border-top:1px solid var(--line);overflow-wrap:anywhere}
#item4-workspace .source-count{display:block;font-size:13px;color:var(--ink2);margin-top:4px}
#item4-workspace progress{width:100%}#item4-workspace [hidden]{display:none!important}#item4-workspace .error{color:#9a2844}
#item4-workspace #bom-loader{margin:0 0 22px}
#item4-workspace #bom-loader .workflow-file-picker{margin:0}
#item4-workspace #bom-loader .workflow-file-picker:focus-within{outline:3px solid #b196e2;outline-offset:3px}
#item4-workspace #message{min-height:0}
#item4-workspace .graph-scroll{overflow:auto;max-height:500px}#item4-workspace .status-tag{font-weight:700;white-space:nowrap}
#item4-workspace .asset-input-group{margin:18px 0;border:1px solid var(--line);border-radius:10px;padding:14px}
#item4-workspace .asset-key-row{padding:16px 0;border-top:1px solid var(--line)}
#item4-workspace .asset-key-row label{display:flex;flex-direction:column;gap:4px}
#item4-workspace .asset-key-row select,#item4-workspace #context-questions select{display:block;width:100%;padding:10px;margin:8px 0;border:1px solid var(--line);border-radius:8px}
#item4-workspace .asset-key-row p{margin:6px 0;font-size:14px}
#item4-workspace #input-message{min-height:24px;overflow-wrap:anywhere}
#item4-workspace .assessment-decision{padding:14px 0;border-top:1px solid var(--line)}
@media(max-width:1100px){#item4-workspace .agent-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:650px){#item4-workspace .agent-grid{grid-template-columns:1fr}}
'''
    style.string += (ROOT/'src/item4/web/operating_questions.css').read_text(encoding='utf-8')
    soup.head.append(style)
    soup.title.string='ICS-VEXForge · Operational VEX'
    for filename, source in (
        ('item4-cluster-diagnostics.js', 'cluster_diagnostics_ui.js'),
        ('item4-question-tree.js', 'operating_question_tree.js'),
        ('item4-questionnaire.js', 'asset_vex_questionnaire_ui.js'),
        ('item4-evaluation.js', 'source_evaluation_ui.js'),
    ):
        version=hashlib.sha256((ROOT/'src/item4/web'/source).read_bytes()).hexdigest()[:12]
        soup.body.append(soup.new_tag('script',src=f'/{filename}?v={version}',defer=''))
    return HTMLResponse(str(soup),headers={'Cache-Control':'no-cache'})
app.add_api_route('/item4.html',item4_page,methods=['GET'])
app.add_api_route('/item4-cvss.html', lambda: FileResponse(ROOT/'site/item4-cvss.html'), methods=['GET'])
from fastapi.staticfiles import StaticFiles
app.mount('/item4-cvss-data', StaticFiles(directory=ROOT/'site/item4-cvss-data', check_dir=False), name='cvss-description-data')

def operational_entry(request:service.operational_vex_api.Request):
    return item4_page()
for route in app.routes:
    if getattr(route,'path',None)=='/bom-vex.html':
        route.endpoint=operational_entry;route.dependant.call=operational_entry
        route.dependant.request_param_name='request'
app.add_api_route('/item4-questionnaire.js',lambda:FileResponse(ROOT/'src/item4/web/asset_vex_questionnaire_ui.js',media_type='application/javascript',headers={'Cache-Control':'no-cache'}),methods=['GET'])
app.add_api_route('/item4-question-tree.js',lambda:FileResponse(ROOT/'src/item4/web/operating_question_tree.js',media_type='application/javascript',headers={'Cache-Control':'no-cache'}),methods=['GET'])
app.add_api_route('/item4-cluster-diagnostics.js',lambda:FileResponse(ROOT/'src/item4/web/cluster_diagnostics_ui.js',media_type='application/javascript',headers={'Cache-Control':'no-cache'}),methods=['GET'])
app.add_api_route('/item4-operating-questions.css',lambda:FileResponse(ROOT/'src/item4/web/operating_questions.css',media_type='text/css',headers={'Cache-Control':'no-cache'}),methods=['GET'])
app.add_api_route('/item4-evaluation.js',lambda:FileResponse(ROOT/'src/item4/web/source_evaluation_ui.js',media_type='application/javascript',headers={'Cache-Control':'no-cache'}),methods=['GET'])
app.add_api_route('/item4-run-ledger.js',lambda:FileResponse(ROOT/'src/item4/web/evaluation_runs_ui.js',media_type='application/javascript',headers={'Cache-Control':'no-cache'}),methods=['GET'])
def shared_operational_page():return item4_page()
def automatic_method_page():
    html=(ROOT/'src/item4/web/attack_graph_methodology.html').read_text(encoding='utf-8')
    return HTMLResponse(html.replace('{{ENGINE_VERSION}}',escape(automatic.VERSION)))
for route in app.routes:
    if getattr(route,'path',None)=='/vex-decision.html':
        route.endpoint=shared_operational_page;route.dependant.call=shared_operational_page
    if getattr(route,'path',None) in ['/bom-vex-method.html','/operational-vex-logic.en.html','/operational-vex-verification.en.html']:
        route.endpoint=automatic_method_page;route.dependant.call=automatic_method_page
app.add_api_route('/nist-answer-design.html',lambda:FileResponse(ROOT/'site/nist-answer-design.html',media_type='text/html'),methods=['GET'])
app.add_api_route('/nist-answer-specs.json',lambda:FileResponse(ROOT/'docs/nist_selectable_answers.v1.json',media_type='application/json'),methods=['GET'])
app.add_api_route('/nist-evidence-registry.schema.json',lambda:FileResponse(ROOT/'schemas/nist-evidence-registry.schema.json',media_type='application/json'),methods=['GET'])
app.add_api_route('/nist-typed-review.schema.json',lambda:typed.REVIEW_SCHEMA,methods=['GET'])
async def validate_typed_review(request:service.operational_vex_api.Request):
    value=await service.operational_vex_api.body(request)
    return service.operational_vex_api.handle(lambda:(typed.validate_bundle(value) or {'valid':True,'adopted_conclusions':False}))
app.add_api_route('/api/operational-vex/validate-typed-review',validate_typed_review,methods=['POST'])
app.add_api_route('/nist-auto-vex-method.html',automatic_method_page,methods=['GET'])
app.add_api_route('/nist-population-vex-method.html',automatic_method_page,methods=['GET'])
def population_registry():
    manifest=population.manifest()
    return automatic.registry()|{'engine_version':automatic.VERSION,'population':{k:manifest[k] for k in ['version','population_count','population_sha256','sha256','counts']},'specializations_are_not_population_limit':True}
app.add_api_route('/nist-auto-vex-rules.json',population_registry,methods=['GET'])
def compiled_source(cve:str):
    from fastapi import HTTPException
    if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cve):raise HTTPException(400,'Invalid CVE ID')
    row=population.get(cve)
    if row is None:raise HTTPException(404,'CVE outside the fixed source population')
    from copy import deepcopy
    result=deepcopy(row)
    result['historical_compilation']=result.pop('compiled',None)
    result['active_extraction_format']='vulnerability-exploitation-prerequisite/1'
    result['historical_compilation_used_for_current_decisions']=False
    result['active_prerequisite_location']='Current component-scoped assessment plan: prerequisite'
    return result
app.add_api_route('/api/operational-vex/compiled-source/{cve}',compiled_source,methods=['GET'])

def population_graph_status():
    from src.item4.decision.batch_attack_graphs import HOME
    path=HOME/'status.json'
    status=json.loads(path.read_text(encoding='utf-8')) if path.exists() else dict(state='not_generated',population=12418,completed=0)
    audit=HOME/'integrity_audit.json'
    status['integrity_audit']=json.loads(audit.read_text(encoding='utf-8')) if audit.exists() else dict(passed=False,state='not_audited')
    return status

def population_graph(cve:str):
    from fastapi import HTTPException
    from src.item4.decision.batch_attack_graphs import get
    if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cve):raise HTTPException(400,'Invalid CVE ID')
    graph=get(cve)
    if graph is None:raise HTTPException(404,'This CVE source graph has not been generated yet; no safety conclusion follows.')
    return graph

app.add_api_route('/api/operational-vex/population-graph-status',population_graph_status,methods=['GET'])
app.add_api_route('/api/operational-vex/population-graphs/{cve}',population_graph,methods=['GET'])
def question_relevance(cve:str,version:str='',product:str=''):
    rule=automatic.rule_for(cve,product)
    state=automatic.version_state(rule,version) if rule and version else 'unknown'
    return dict(conditional_settings_required=state not in ('fixed','unaffected'),version_state=state,not_a_vex_verdict=True)
app.add_api_route('/api/operational-vex/question-relevance',retired_operating_workflow,methods=['GET'])
from src.item4.models import operating_record_review_model as operational_record_llm; from src.item4.analysis import exploitation_prerequisites as vulnerability_exploitation_prerequisite
app.add_api_route('/api/operational-vex/llm-status',operational_record_llm.status,methods=['GET'])
app.add_api_route('/api/operational-vex/prerequisite-schema',lambda:vulnerability_exploitation_prerequisite.SCHEMA,methods=['GET'])
app.add_api_route('/nist-three-axis-method.html',lambda:FileResponse(ROOT/'site/nist-three-axis-method.html',media_type='text/html'),methods=['GET'])
def fixed_artifact(path,media):
    def artifact():return FileResponse(ROOT/'results/nist_three_axis_experiment_20261118'/path,media_type=media)
    return artifact
for filename,path,media in [('nist-three-axis-experiment.json','experiment_report.json','application/json'),('nist-three-axis-cases.csv','case_results.csv','text/csv'),('nist-three-axis-coverage.json','cve_coverage_audit.json','application/json')]:
    app.add_api_route('/'+filename,fixed_artifact(path,media),methods=['GET'])
def auto_artifact(path,media):
    def artifact():return FileResponse(ROOT/'results/nist_auto_vex_20261118'/path,media_type=media)
    return artifact
for filename,path,media in [('nist-auto-vex-experiment.json','experiment/report.json','application/json'),('nist-auto-vex-cases.csv','experiment/cases.csv','text/csv'),('nist-auto-vex-coverage.json','coverage.json','application/json')]:
    app.add_api_route('/'+filename,auto_artifact(path,media),methods=['GET'])
def population_artifact(path,media):
    def artifact():return FileResponse(ROOT/'results/nist_population_vex_20261118/benchmark'/path,media_type=media)
    return artifact
for filename,path,media in [('nist-population-experiment.json','report.json','application/json'),('nist-population-cases.csv','cases.csv','text/csv'),('nist-population-per-cve.json','per_cve.json','application/json'),('nist-population-protocol.json','protocol.json','application/json'),('nist-population-targets.json','population.json','application/json')]:
    app.add_api_route('/'+filename,population_artifact(path,media),methods=['GET'])
if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=port, access_log=False)
