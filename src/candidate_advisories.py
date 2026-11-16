"""CISA snapshot candidate retrieval by anchored, exact affected-product phrases.

No SBOM vulnerability fields or evaluation ground truth are used. An advisory
family/product match supplies candidates, not a confirmed asset-version verdict.
"""
from functools import lru_cache
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]


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
    escaped=r'[\s_-]+'.join(re.escape(t) for t in words(product).split())
    if not escaped or len(words(product))<4:return False
    return bool(re.fullmatch(escaped+r'(?:\s+(?:vers:[^\s/]+/[^\s]+|v?\d[\w.+-]*))?',text,re.I))


def structured_records(component, vendor, aid, row):
    """Pinned CSAF product tree supplies per-CVE family associations."""
    if row.get('source')!='CISA CSAF':return []
    from src.cve_evidence import documents
    from src.operational_versions import products
    out=[]
    for cve in row.get('cves',[]):
        if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cve):continue
        for document in documents(cve):
            if document['advisory_id']!=aid:continue
            tree=products(document['record'])
            affected=document['vulnerability'].get('product_status',{}).get('known_affected',[])
            hits=[p for pid,p in tree.items() if pid in affected
                  and vendor_key(p['vendor'])==vendor
                  and structured_product_match(component.get('name'),vendor,p['product'])]
            if not hits:continue
            out.append({'cve_id':cve,'match_status':'unknown','patch_status':'not_checked',
                'runtime_exploitability':'not_assessed','evidence':{
                    'source':'CISA advisory snapshot','advisory_id':aid,'url':row['url'],
                    'vendor':row.get('vendor'),'component_vendor_source':'manufacturer' if component.get('manufacturer') else 'supplier',
                    'matched_product_phrase':hits[0]['product'],
                    'basis':'exact vendor-scoped CSAF product family and CVE known-affected product relation',
                    'csaf_product_ids':[p['product_id'] for p in hits],
                    'document_sha256':document['sha256'],'version_confirmed':False,
                    'scope':'product_family_candidate_not_installed_release'}})
    return out


@lru_cache(maxsize=1)
def advisory_index():
    path=ROOT/'data/cisa_advisories.json'
    if not path.is_file():return {}
    records=json.loads(path.read_text(encoding='utf-8'))
    result={}
    for aid,row in records.items():
        vendor=vendor_key(row.get('vendor',''))
        if not vendor:continue
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
        result.setdefault(vendor,[]).append((aid,row,words(affected)))
    return result


def retrieve(component):
    vendor_source='manufacturer' if component.get('manufacturer') else 'supplier'
    vendor=vendor_key(component.get(vendor_source,''))
    name=re.sub(r'\s+Vendor\s+Firmware/Application\s*$','',component.get('name',''),flags=re.I)
    phrase=words(name)
    if vendor and phrase.startswith(vendor+' '):phrase=phrase[len(vendor)+1:]
    if not vendor:return []
    results=[]
    for aid,row,affected in advisory_index().get(vendor,[]):
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
