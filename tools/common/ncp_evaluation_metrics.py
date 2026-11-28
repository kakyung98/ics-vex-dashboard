"""Expose the latest isolated H200 run without replacing sealed historical files."""
from pathlib import Path
import json
import sqlite3
ROOT=Path(__file__).resolve().parents[2]
POINTER=ROOT/'results/h200_latest_evaluation.json'


def read(path):return json.loads(path.read_text(encoding='utf-8'))


def current_root():
    if not POINTER.exists():return None
    folder=Path(read(POINTER)['run_root']).resolve()
    if not folder.is_relative_to((ROOT/'results').resolve()):raise ValueError('Invalid evaluation root')
    return folder


def latest():
    folder=current_root()
    if folder is None:return dict(status='not_started')
    return dict(run_root=str(folder),status=read(folder/'status.json'),
                summary=read(folder/'summary.json') if (folder/'summary.json').exists() else None)


def install(app):
    from tools.item3.icsa_cpe_dataset_web import install as install_icsa_dataset
    install_icsa_dataset(app)
    from fastapi.responses import HTMLResponse,JSONResponse
    from src.common import api_server
    if not any(item[0]=='experiments' for _,items in api_server._NAV_GROUPS for item in items):
        entry=('experiments','experiments.html','실험 결과 · H200')
        api_server._NAV_GROUPS.append(('Experiments',[entry]));api_server._NAV.append(entry)
    def experiment_page():return HTMLResponse((ROOT/'site/experiments.html').read_text(encoding='utf-8'))
    def experiment_record():return JSONResponse(read(ROOT/'site/h200-experiment.json'))
    app.add_api_route('/experiments.html',experiment_page,methods=['GET'],response_class=HTMLResponse)
    app.add_api_route('/h200-experiment.json',experiment_record,methods=['GET'])
    for route in app.routes:
        if getattr(route,'path',None)=='/api/precision/metrics':
            original=route.dependant.call
            def metrics():
                data=original();folder=current_root()
                data['h200_full_evaluation']=latest()
                if folder is not None and (folder/'summary.json').exists() and read(folder/'status.json')['status']=='complete':
                    data['population_validation']=read(folder/'item3/validation_report.json')
                    data['item4_source_simulation']=read(folder/'item4/precision_report.json')
                    data['item4_source_progress']=read(folder/'item4/status.json')
                    data['primary_metric_scope']='Fresh H200 inference on the fixed 12418-CVE population; synthetic Gold scopes retained'
                return data
            route.endpoint=metrics;route.dependant.call=metrics
        if getattr(route,'path',None)=='/api/precision/item4/source-simulation/cves/{cve}':
            original_cases=route.dependant.call
            def cases(cve:str):
                data=original_cases(cve);folder=current_root()
                if folder is not None and (folder/'summary.json').exists() and read(folder/'status.json')['status']=='complete':
                    with sqlite3.connect((folder/'item4/predictions.sqlite3').as_uri()+'?mode=ro',uri=True) as db:
                        for row in data['cases']:
                            found=db.execute('select prediction from predictions where id=?',(row['id'],)).fetchone()
                            row['sealed_prediction']=json.loads(found[0]) if found else None
                    data['evaluation_run']=str(folder)
                return data
            route.endpoint=cases;route.dependant.call=cases
    app.add_api_route('/api/precision/h200/full-evaluation',latest,methods=['GET'],tags=['precision-workbench'])
