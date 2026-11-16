"""Private development-site dataset routes, isolated from sealed classifiers."""
from pathlib import Path
import json,re

def install(app):
    from fastapi.responses import HTMLResponse,FileResponse
    from fastapi.staticfiles import StaticFiles
    from src import api_server
    root=Path(__file__).resolve().parents[1]
    folder=root/'site/icsa-cpe-sbom'
    index=json.loads((folder/'index.json').read_bytes())
    advisory_file=root/'data/cisa_advisories.json'
    advisories=json.loads(advisory_file.read_bytes()) if advisory_file.exists() else {}
    assets=[]
    for row in index['advisories']:
        doc=json.loads((folder/row['file']).read_bytes())
        components=[]
        for c in doc['components']:
            bounds=[p['name'].removeprefix('nvd:')+'='+p['value'] for p in c.get('properties',[]) if p['name'].startswith('nvd:')]
            components.append({'name':c['name'],'version':c.get('version','NOASSERTION'),
                               'description':'; '.join([c['cpe'],*bounds])})
        assets.append({'asset_id':row['advisory_id'],'file':Path(row['file']).name,
            'vendor':advisories.get(row['advisory_id'],{}).get('vendor',''),
            'product':row['title'] or row['advisory_id'],
            'base_platform':'CPE-backed candidate inventory' if components else 'Empty: no eligible CPE-backed CVE',
            'advisories':[row['advisory_id']],'component_count':row['component_count'],
            'components':components,'cves':[{'id':c} for c in dict.fromkeys(row['included_cves'])]})
    api_server.STORE.sbom_index={'generated':len(assets),'assets':assets,'dataset_id':'icsa-cpe-sbom-v1','summary':index['summary']}
    # Reuse the existing sidebar, page, table, search and JSON modal.
    labels={'analyzer':'SBOM → CVE','vex-decision':'Operational VEX','sbom-to-cve':'Method Overview'}
    for _,items in api_server._NAV_GROUPS:
        items[:]=[item for item in items if item[0]!='icsa-cpe-sbom']
        items[:]=[(key,href,labels.get(key,label)) for key,href,label in items]
    api_server._NAV[:]=[item for _,items in api_server._NAV_GROUPS for item in items]
    title,content=api_server.PAGES['ics-sbom']
    content=content.replace('CycloneDX SBOMs reverse-built per ICS device from the CISA ICS-CERT corpus — each keyed to its source advisory.',
                            'CycloneDX SBOMs grouped by CISA ICS advisory, using its listed CVEs and published affected-product CPE conditions.')
    content=content.replace('Synthetic asset inventory reverse-built from the CISA ICS-CERT corpus; components and versions reference real OSS but hashes, serials and contacts are placeholders.',
                            '3,881 advisory records: 3,108 contain CPE-backed components; 773 are empty. Covers 10,847 unique CVEs. Alternative product/version conditions are synthetic candidates, not a verified installation. Existing #3 evaluation data is separate.')
    api_server.PAGES['ics-sbom']=(title,content)
    def page():return HTMLResponse(api_server.make_page('ics-sbom'),headers={'Cache-Control':'no-store'})
    allowed={a['file'] for a in assets}
    def bom_file(name:str):
        from fastapi import HTTPException
        if name not in allowed:raise HTTPException(404,'SBOM not found')
        return FileResponse(folder/'sbom'/name,media_type='application/json',headers={'Cache-Control':'no-store'})
    for route in app.routes:
        if getattr(route,'path',None)=='/ics-sbom.html':
            route.endpoint=page
            route.dependant.call=page
        if getattr(route,'path',None)=='/reverse_sbom/{name}':
            route.endpoint=bom_file
            route.dependant.call=bom_file
    app.add_api_route('/icsa-cpe-sbom.html',page,methods=['GET'],response_class=HTMLResponse)
    app.mount('/icsa-cpe-sbom',StaticFiles(directory=root/'site/icsa-cpe-sbom'),name='icsa-cpe-sbom-data')
