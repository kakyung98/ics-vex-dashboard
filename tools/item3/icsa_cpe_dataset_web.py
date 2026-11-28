"""Link the maintained advisory-product SBOMs to the existing development website."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import argparse, hashlib, json

ROOT=Path(__file__).resolve().parents[2]
FOLDER=ROOT/'benchmark/icsa-cpe-synthetic sbom'

def sha_bytes(wire):return hashlib.sha256(wire).hexdigest()

def build_cache(folder=FOLDER,output=None):
    folder=Path(folder);wire=(folder/'index.json').read_bytes();index=json.loads(wire)
    def asset(row):
        raw=(folder/row['file']).read_bytes()
        assert sha_bytes(raw)==row['sha256'],row['advisory_id']
        doc=json.loads(raw);components=[];vendors=[]
        for c in doc['components']:
            vendor=(c.get('manufacturer') or {}).get('name') or 'unknown'
            if vendor!='unknown' and vendor not in vendors:vendors.append(vendor)
            p={p['name']:p['value'] for p in c.get('properties',[])}
            details=[vendor]
            if c.get('cpe'):details.append(c['cpe'])
            if p.get('dataset:source-kind'):details.append(p['dataset:source-kind'])
            components.append({'bom-ref':c['bom-ref'],'type':c['type'],'name':c['name'],
                'version':c.get('version') or 'unknown','manufacturer':vendor,
                'description':' · '.join(details),'cpe':c.get('cpe'),
                'version_semantics':p.get('dataset:version-semantics','source expression')})
        ids=row.get('declared_cves',row.get('included_cves',[]))
        return {'asset_id':row['advisory_id'],'file':Path(row['file']).name,
            'vendor':', '.join(vendors) or 'unknown','product':row.get('title') or row['advisory_id'],
            'base_platform':'Advisory product/version candidates' if components else 'Source/product information unresolved',
            'advisories':[row['advisory_id']],'component_count':len(components),'components':components,
            'cves':[{'id':c} for c in dict.fromkeys(ids)],'cve_association_scope':'advisory; not a verified installed-product mapping',
            'source_status':row.get('status'),'sbom_sha256':row['sha256']}
    with ThreadPoolExecutor(max_workers=12) as pool:assets=list(pool.map(asset,index['advisories']))
    cache={'dataset_id':index['summary']['dataset_id'],'source_index_sha256':sha_bytes(wire),
           'summary':index['summary'],'generated':len(assets),'assets':assets}
    output=Path(output) if output else folder/'web_index.json'
    temporary=output.with_name(output.name+'.tmp');temporary.write_text(json.dumps(cache,ensure_ascii=False,separators=(',',':')),encoding='utf8');temporary.replace(output)
    return cache

def load_cache(folder=FOLDER):
    folder=Path(folder);wire=(folder/'index.json').read_bytes();index=json.loads(wire)
    for path in [folder/'web_index.json',ROOT/'site/sbom_index.json']:
        if not path.is_file():continue
        cache=json.loads(path.read_bytes());assets=cache.get('assets',[])
        rows={r['advisory_id']:r for r in index['advisories']}
        if (cache.get('dataset_id')==index['summary']['dataset_id']
            and cache.get('source_index_sha256')==sha_bytes(wire)
            and cache.get('summary')==index['summary'] and len(assets)==len(rows)
            and {a['asset_id'] for a in assets}==set(rows)
            and all(a.get('sbom_sha256')==rows[a['asset_id']]['sha256']
                    and len(a.get('components',[]))==rows[a['asset_id']]['component_count'] for a in assets)):
            return cache
    return build_cache(folder)

def install(app):
    from fastapi.responses import HTMLResponse,FileResponse
    from fastapi.staticfiles import StaticFiles
    from src.common import api_server
    folder=FOLDER if FOLDER.exists() else ROOT/'site/icsa-cpe-sbom'
    cache=load_cache(folder);assets=cache['assets'];summary=cache['summary']
    api_server.STORE.sbom_index=cache
    labels={'analyzer':'SBOM → CVE','vex-decision':'Operational VEX','sbom-to-cve':'Method Overview'}
    for _,items in api_server._NAV_GROUPS:
        items[:]=[(key,href,labels.get(key,label)) for key,href,label in items if key!='icsa-cpe-sbom']
    api_server._NAV[:]=[item for _,items in api_server._NAV_GROUPS for item in items]
    title,content=api_server.PAGES['ics-sbom']
    for old in [
        'CycloneDX SBOMs reverse-built per ICS device from the CISA ICS-CERT corpus — each keyed to its source advisory.',
        'CycloneDX SBOMs grouped by CISA ICS advisory, using its listed CVEs and published affected-product CPE conditions.']:
        content=content.replace(old,'CycloneDX 1.7 product and version records linked to their source CISA advisory.')
    for old in [
        'Synthetic asset inventory reverse-built from the CISA ICS-CERT corpus; components and versions reference real OSS but hashes, serials and contacts are placeholders.',
        '3,881 advisory records: 3,108 contain CPE-backed components; 773 are empty. Covers 10,847 unique CVEs. Alternative product/version conditions are synthetic candidates, not a verified installation. Existing #3 evaluation data is separate.']:
        content=content.replace(old,'Products and version expressions are preserved from source advisories. A missing CPE does not remove a product. Unknown authorship and inventory facts remain unknown.')
    archive=next((name for name in ['icsa-advisory-products-sbom-v3.zip','icsa-advisory-products-sbom-v2-reviewed.zip','icsa-advisory-products-sbom-v2.zip'] if (folder/name).is_file()),None)
    if 'id="advisory-sbom-coverage"' not in content:
        content+=('<section class="card" id="advisory-sbom-coverage"><h2>Generation coverage</h2><p>'
            +f"{len(assets):,} advisory records · {summary.get('nonempty_sboms',0):,} with product inventories · {summary.get('empty_sboms',0):,} unresolved."
            +'</p><p>Source version ranges are retained; these collections do not establish one installed configuration.</p>'
            +(('<a href="/icsa-cpe-sbom/'+archive+'">Download SBOM dataset</a> · ') if archive else '')
            +'<a href="/icsa-cpe-sbom/audit.json">View coverage audit</a></section>')
    api_server.PAGES['ics-sbom']=(title,content)
    def page():
        html=api_server.make_page('ics-sbom').replace('Identified CVEs (','Advisory CVEs (')
        return HTMLResponse(html,headers={'Cache-Control':'no-store'})
    allowed={a['file'] for a in assets}
    def bom_file(name:str):
        from fastapi import HTTPException
        if name not in allowed:raise HTTPException(404,'SBOM not found')
        return FileResponse(folder/'sbom'/name,media_type='application/json',headers={'Cache-Control':'no-store'})
    for route in app.routes:
        if getattr(route,'path',None)=='/ics-sbom.html':route.endpoint=page;route.dependant.call=page
        if getattr(route,'path',None)=='/reverse_sbom/{name}':route.endpoint=bom_file;route.dependant.call=bom_file
    app.add_api_route('/icsa-cpe-sbom.html',page,methods=['GET'],response_class=HTMLResponse)
    app.mount('/icsa-cpe-sbom',StaticFiles(directory=folder),name='icsa-cpe-sbom-data')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--folder',type=Path,default=FOLDER)
    args=parser.parse_args();cache=build_cache(args.folder)
    print(json.dumps({'dataset_id':cache['dataset_id'],'assets':len(cache['assets']),'source_index_sha256':cache['source_index_sha256']}))
