"""Export current runtime UI for Pages, with opt-in access to the local backend.

Only explicit public assets/UI go into the deployment manifest. No model,
training, upload-session or evaluation-result directories are traversed.
"""
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import sys
import os
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.api_server import make_page,STORE
from src.ui_theme import TOPBAR

SITE=ROOT/'site'
PAGES={'index.html':'analyzer','sbom-to-cve.html':'sbom-to-cve','vex-decision.html':'vex-decision',
       'vex-method.html':'vex-decision','asset-vex.html':'vex-decision','dataset.html':'dataset',
       'corpus.html':'dataset','collectable.html':'dataset','ics-sbom.html':'ics-sbom',
       'source.html':'source','published-vex.html':'published-vex'}
BANNER='''<section class="card" id="pages-backend" style="margin-bottom:22px">
<h2 style="font-size:18px;margin:0 0 8px">Connect local backend</h2>
<p class="hint" id="pages-backend-status">Public data is available. Connect the local backend for analysis.</p>
<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
<label for="pages-backend-url">Backend URL</label><input id="pages-backend-url" type="url" value="http://127.0.0.1:8100" style="flex:1;min-width:220px" autocomplete="off">
<button class="primary" id="pages-backend-connect">Connect</button>
<button id="pages-backend-disconnect" hidden>Disconnect</button>
<a id="pages-open-local" href="http://127.0.0.1:8100" target="_blank" rel="noopener">Open local app ↗</a></div>
<p class="hint" style="margin:8px 0 0">Uploaded files are sent to the connected backend. Your browser may ask for local-network permission.</p></section>'''


def write_asset(path,text):
    """Avoid in-place truncation of watched/compressed Windows public assets."""
    with tempfile.NamedTemporaryFile(dir=path.parent,suffix='.pending',delete=False) as f:
        pending=Path(f.name);f.write(text.encode('utf-8'))
    try:
        for attempt in range(6):
            try:
                os.replace(pending,path)
                return
            except OSError:
                if attempt==5:raise
                time.sleep(.2)
    finally:
        pending.unlink(missing_ok=True)


def build():
    SITE.mkdir(exist_ok=True);files=[]
    bridge=(ROOT/'src/pages_bridge.js').read_text(encoding='utf-8')
    write_asset(SITE/'pages-bridge.js',bridge);files.append('pages-bridge.js')
    for file,page in PAGES.items():
        html=make_page(page)
        html=html.replace('</head>','<script src="pages-bridge.js"></script></head>')
        html=html.replace(TOPBAR,TOPBAR+BANNER,1)
        assert 'id="pages-backend"' in html and 'Test items #3 / #4' not in html
        write_asset(SITE/file,html);files.append(file)
    # Known public corpus snapshots follow the local store. Preserve the existing
    # SBOM archive index when the original local index was removed during cleanup.
    exports={'cve_level.json':STORE.cve_level,'source_available.json':STORE.tier_a,
             'by_year.json':{'total_cves':sum(STORE.by_year.values()),'by_year':STORE.by_year},
             'advisories.json':STORE.advisories,'advisories_list.json':{'count':len(STORE.advisories_list),'advisories':STORE.advisories_list},
             'cve_index.json':list(STORE.cve_index.values()),'verify_results.json':STORE.verify,
             'verify_coverage.json':STORE.verify_coverage}
    if STORE.sbom_index.get('assets'):
        sbom_index=json.loads(json.dumps(STORE.sbom_index))
        from src.dataset_paths import public_sbom_directory
        directory=public_sbom_directory()
        # Compact public documents into bounded bundles; the bridge resolves
        # individual SBOM requests without publishing thousands of Git blobs.
        bundle={};size=0;number=0
        for asset in sbom_index['assets']:
            doc=json.loads((directory/asset['file']).read_text(encoding='utf-8'))
            encoded=json.dumps(doc,ensure_ascii=False,separators=(',',':')).encode('utf-8')
            if bundle and size+len(encoded)>4*1024*1024:
                exports[f'sbom_bundle_{number:03d}.json']=bundle
                bundle={};size=0;number+=1
            asset['public_bundle']=f'sbom_bundle_{number:03d}.json'
            bundle[asset['file']]=doc;size+=len(encoded)
        if bundle:exports[f'sbom_bundle_{number:03d}.json']=bundle
        exports['sbom_index.json']=sbom_index
    # Shard refreshed full advisory details by year, avoiding thousands of stale
    # individual HTML-era detail files and keeping each public blob small.
    details={}
    for aid,record in STORE.adv_detail.items():
        year=aid.split('-')[1]
        details.setdefault('advisory_details_'+year+'.json',{})[aid]=record
    exports.update(details)
    for name,data in exports.items():
        write_asset(SITE/name,json.dumps(data,ensure_ascii=False,separators=(',',':')));files.append(name)
    info={'generated_at':datetime.now(timezone.utc).isoformat(),'ui_source':'src.api_server.make_page',
          'backend':'user-connected; no GPU or FastAPI hosted by Pages','files':{name:hashlib.sha256((SITE/name).read_bytes()).hexdigest() for name in files}}
    write_asset(SITE/'frontend-build.json',json.dumps(info,indent=2));files.append('frontend-build.json')
    manifest={'files':['site/'+name for name in files],'only_explicit_public_frontend_assets':True}
    dest=ROOT/'results/pages_frontend_deployment_manifest.json';dest.parent.mkdir(exist_ok=True)
    dest.write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print('Built',len(PAGES),'current pages and',len(files),'explicit public assets.')


if __name__=='__main__':build()
