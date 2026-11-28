"""CISA snapshot candidate retrieval by anchored, exact affected-product phrases.

No SBOM vulnerability fields or evaluation ground truth are used. An advisory
family/product match supplies candidates, not a confirmed asset-version verdict.
"""
from functools import lru_cache
from copy import deepcopy
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[3]


def words(value):return re.sub('[^a-z0-9]+',' ',str(value or '').lower()).strip()


def vendor_key(value):
    value=re.sub(r'^Organization:\s*','',str(value or ''),flags=re.I)
    value=re.sub(r'\b(incorporated|inc|corporation|corp|limited|ltd|gmbh)\b\.?','',value,flags=re.I)
    return words(value)


def structured_product_match(name, vendor, product):
    """Match a vendor-scoped family with only an explicit version suffix.

    No substring/fuzzy matches, LLM proposals, SBOM advisory IDs or embedded
    vulnerability answers participate in this path.
    """
    text=str(name or '').strip()
    # Keep punctuation until the release/range boundary has been checked.
    key=words(text)
    if key.startswith(vendor+' '):
        # Vendor punctuation may vary; consume its token prefix in the source.
        tokens=list(re.finditer(r'[a-z0-9]+',text.lower()))
        text=text[tokens[len(vendor.split())-1].end():].strip(' -_:')
    expected=words(product).split()
    if not expected or len(words(product))<4:return False
    observed=list(re.finditer(r'[a-z0-9]+',text.lower()))
    if [m.group() for m in observed[:len(expected)]]!=expected:return False
    remainder=text[observed[len(expected)-1].end():].strip(' _-!().')
    return not remainder or bool(re.fullmatch(r'(?:vers:[^\s/]+/[^\s]+|v?\d[\w.+-]*)',remainder,re.I))


def structured_records(component, vendor, aid, row):
    """Pinned CSAF product tree supplies per-CVE family associations."""
    if row.get('source')!='CISA CSAF':return []
    out=[]
    for cve,tree,affected,document_sha in structured_relations(aid):
            hits=[tree[pid] for pid in sorted(affected) if pid in tree
                  and vendor_key(tree[pid]['vendor'])==vendor
                  and structured_product_match(component.get('name'),vendor,tree[pid]['product'])]
            if not hits:continue
            out.append({'cve_id':cve,'match_status':'unknown','patch_status':'not_checked',
                'runtime_exploitability':'not_assessed','evidence':{
                    'source':'CISA advisory snapshot','advisory_id':aid,'url':row['url'],
                    'vendor':row.get('vendor'),'component_vendor_source':'manufacturer' if component.get('manufacturer') else 'supplier',
                    'matched_product_phrase':hits[0]['product'],
                    'basis':'exact vendor-scoped CSAF product family and CVE known-affected product relation',
                    'csaf_product_ids':[p['product_id'] for p in hits],
                    'document_sha256':document_sha,'version_confirmed':False,
                    'scope':'product_family_candidate_not_installed_release'}})
    return out


@lru_cache(maxsize=4096)
def structured_relations(aid):
    """Verify each advisory once; reuse only its source-bound product relations."""
    import hashlib
    from src.item4.assets.installed_version_evidence import products
    row=source_records()[aid]
    if row.get('local_csaf_file'):
        path=(ROOT/row['local_csaf_file']).resolve()
        if not path.is_relative_to(ROOT.resolve()) or not path.is_file():raise RuntimeError('CISA source file unavailable: '+aid)
        raw=path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=row['source_raw_sha256']:raise RuntimeError('CISA source integrity failure: '+aid)
        document=json.loads(raw)
        actual=hashlib.sha256(json.dumps(document,sort_keys=True).encode()).hexdigest()
        if actual!=row['csaf_sha256']:raise RuntimeError('CISA parsed-source integrity failure: '+aid)
        tree=products(document)
        return [(v['cve'],tree,set(v.get('product_status',{}).get('known_affected',[])),actual)
                for v in document.get('vulnerabilities',[]) if re.fullmatch(r'CVE-\d{4}-\d{4,}',v.get('cve',''))]
    from src.common.data.cve_evidence_catalog import documents
    return [(cve,products(d['record']),set(d['vulnerability'].get('product_status',{}).get('known_affected',[])),d['sha256'])
            for cve in row.get('cves',[]) for d in documents(cve) if d['advisory_id']==aid]


@lru_cache(maxsize=1)
def source_records():
    import hashlib
    path=ROOT/'data/cisa_advisories.json'
    if not path.is_file():raise RuntimeError('Server CISA reference snapshot is unavailable.')
    manifest=ROOT/'data/cisa_reference_manifest.json'
    if not manifest.is_file():raise RuntimeError('Server CISA reference integrity manifest is unavailable.')
    raw=path.read_bytes();expected=json.loads(manifest.read_bytes())['index_sha256']
    if hashlib.sha256(raw).hexdigest()!=expected:raise RuntimeError('CISA reference index integrity failure')
    return json.loads(raw)


@lru_cache(maxsize=1)
def advisory_index():
    records=source_records()
    result={}
    for aid,row in records.items():
        vendors={vendor_key(v) for v in row.get('vendors',[]) or [row.get('vendor','')]}
        vendors.discard('')
        if not vendors:continue
        # Never retrieve based on fixed-version instructions or related-advisory footers.
        if row.get('source') == 'CISA CSAF':
            # CSAF product names are structured, not necessarily present before
            # the prose mitigation section. Include known-affected versions;
            # never use fixed/recommended product names as affected evidence.
            affected='\n'.join([row.get('title',''), *row.get('affected_products',[])]) if row.get('affected_products') else ''
        else:
            affected=re.split(r'\b(?:Remediations|Mitigations|Recommended Practices|Related Advisories)\b',
                              row.get('affected_text',''),maxsplit=1,flags=re.I)[0]
        if not affected.strip():continue
        for vendor in vendors:result.setdefault(vendor,[]).append((aid,row,words(affected)))
    return result


@lru_cache(maxsize=1)
def family_index():
    families={};html={}
    for vendor,rows in advisory_index().items():
        for aid,row,affected in rows:
            if row.get('source')!='CISA CSAF':html.setdefault(vendor,[]).append((aid,row,affected))
            for product in row.get('products',[]):
                key=(vendor,tuple(words(product).split()))
                families.setdefault(key,{})[aid]=(aid,row,affected)
    return families,html


def retrieve(component):
    # These are immutable source associations, not asset/version decisions.
    # Different versions of one product must not rescan the same CSAF trees.
    return deepcopy(_retrieve_sources(component.get('name') or '',
                    component.get('manufacturer') or '',component.get('supplier') or ''))


@lru_cache(maxsize=32768)
def _retrieve_sources(name,manufacturer,supplier):
    component=dict(name=name,manufacturer=manufacturer,supplier=supplier)
    vendor_source='manufacturer' if component.get('manufacturer') else 'supplier'
    vendor=vendor_key(component.get(vendor_source,''))
    name=re.sub(r'\s+Vendor\s+Firmware/Application\s*$','',component.get('name',''),flags=re.I)
    phrase=words(name)
    if vendor and phrase.startswith(vendor+' '):phrase=phrase[len(vendor)+1:]
    if not vendor:return []
    results=[]
    families,html=family_index()
    tokens=phrase.split();selected={}
    for length in range(1,len(tokens)+1):
        selected.update(families.get((vendor,tuple(tokens[:length])),{}))
    for aid,row,affected in html.get(vendor,[]):selected[aid]=(aid,row,affected)
    for aid,row,affected in selected.values():
        url=row.get('url','')
        if not url.startswith('https://www.cisa.gov/news-events/ics-advisories/'):continue
        # Only inspect authoritative product trees for an exact scoped family.
        # This prefilter avoids opening CSAF documents for unrelated products.
        if any(structured_product_match(name,vendor,p) for p in row.get('products',[])):
            results.extend(structured_records(component,vendor,aid,row))
            if row.get('source')=='CISA CSAF':continue
        if len(phrase)<10 or len(phrase.split())<2:continue
        if ' '+phrase+' ' not in ' '+affected+' ':continue
        for cve in row.get('cves',[]):
            if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cve):continue
            results.append({'cve_id':cve,'match_status':'unknown',
                'evidence':{'source':'CISA advisory snapshot','advisory_id':aid,'url':url,
                    'matched_product_phrase':phrase,'vendor':row.get('vendor'),
                    'component_vendor_source':vendor_source,
                    'basis':'exact affected-product phrase and vendor match',
                    'version_confirmed':False},
                'patch_status':'not_checked','runtime_exploitability':'not_assessed'})
    return results


def enrich_result(result):
    """Attach source candidates identically for the web and the benchmark runner."""
    from src.item3.web.identification_results import split_findings
    rows=list(result.get('components',[]))+([result['asset_analysis']] if result.get('asset_analysis') else [])
    for row in rows:
        records=retrieve(row['component'])
        row['advisory_evidence']=[r['evidence'] for r in records]
        existing={r['cve_id']:r for r in row.get('cves',[])}
        for record in records:
            if record['cve_id'] in existing:existing[record['cve_id']].setdefault('advisory_evidence',[]).append(record['evidence'])
            else:existing[record['cve_id']]=record
        row['cves']=list(existing.values())
        row['confirmed_cves'],row['review_candidates']=split_findings(row['cves'])
    return result
