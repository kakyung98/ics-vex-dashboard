"""Prove input-product origin from pinned CISA known-affected product records.

No fuzzy product matching, model inference, or NVD-description text is used.
Unproven links are review items, never silently accepted as advisory products.
"""
from collections import defaultdict,Counter
from pathlib import Path
import hashlib,json,re,unicodedata,fnmatch
from tools.item3.item3_truth_oracle import parts,identity,literal


def normalized(value):
    value=unicodedata.normalize('NFKD',str(value or '')).casefold()
    return re.sub('[^a-z0-9]','',value)


def vendor_key(value):
    value=re.sub(r'\b(?:incorporated|inc|corporation|corp|limited|ltd|llc|gmbh|ag)\b\.?','',str(value or ''),flags=re.I)
    return normalized(value)


def product_key(value,vendor=''):
    value=normalized(value);prefix=vendor_key(vendor)
    if prefix and value.startswith(prefix):value=value[len(prefix):]
    return value


def product_forms(value,vendor=''):
    base=product_key(value,vendor);forms={base}
    if base.endswith('firmware'):forms.add(base[:-8])
    return forms-{''}


def product_tree(document):
    products={}
    def visit(branches,vendor='',name='',release='',family=''):
        for branch in branches:
            category=branch.get('category');text=branch.get('name','')
            ve=text if category=='vendor' else vendor
            na=text if category=='product_name' else name
            vr=text if category in ('product_version','product_version_range') else release
            fa=text if category=='product_family' else family
            obj=branch.get('product')
            if obj:
                products[obj['product_id']]={'vendor':ve,'name':na or fa,'release':vr,'family':fa,'record':obj}
            visit(branch.get('branches',[]),ve,na,vr,fa)
    visit(document.get('product_tree',{}).get('branches',[]))
    # Relationship products describe combinations. Retain the explicit component
    # product references; their use here proves product origin, not independent
    # affected status outside that combination.
    relations={r['full_product_name']['product_id']:r for r in document.get('product_tree',{}).get('relationships',[])}
    def resolve(pid,seen=None):
        seen=set() if seen is None else seen
        if pid in seen:return []
        if pid in products:return [(pid,products[pid])]
        if pid not in relations:return []
        seen=seen|{pid};rel=relations[pid]
        return resolve(rel.get('product_reference'),seen)+resolve(rel.get('relates_to_product_reference'),seen)
    return products,resolve


class ScopeCatalog:
    def __init__(self,root):
        self.root=Path(root);self.by_cve=defaultdict(list);self.documents={};self.counts=Counter();self.issues=[]
        advisories=json.loads((self.root/'data/cisa_advisories.json').read_text(encoding='utf-8'))
        folder=sorted((self.root/'data/public_sbom').glob('*/csaf'))[-1]
        self.folder=folder
        for aid,row in sorted(advisories.items()):
            if row.get('source')!='CISA CSAF':self.counts['legacy_without_structured_proof']+=1;continue
            path=folder/(aid+'.json')
            if not path.exists():raise ValueError('Missing pinned CISA document: '+aid)
            raw=path.read_bytes();doc=json.loads(raw)
            canonical=hashlib.sha256(json.dumps(doc,sort_keys=True).encode()).hexdigest()
            if canonical!=row.get('csaf_sha256'):raise ValueError('CISA hash mismatch: '+aid)
            self.documents[aid]={'path':str(path.relative_to(self.root)), 'canonical_sha256':canonical,
                                 'raw_sha256':hashlib.sha256(raw).hexdigest(),'url':row.get('url')}
            self.counts['verified_documents']+=1
            tree,resolve=product_tree(doc)
            for vi,vuln in enumerate(doc.get('vulnerabilities',[])):
                cve=vuln.get('cve')
                if not cve or cve not in row.get('cves',[]):continue
                for affected in vuln.get('product_status',{}).get('known_affected',[]):
                    resolved=resolve(affected)
                    if not resolved:self.issues.append({'advisory_id':aid,'cve':cve,'product_id':affected,'reason':'unresolved_product_reference'})
                    for leaf,product in resolved:
                        if not product['vendor'] or not product['name']:continue
                        self.by_cve[cve].append({'advisory_id':aid,'cve':cve,'affected_product_id':affected,'leaf_product_id':leaf,
                            'relationship_context_required':affected!=leaf,'vendor':product['vendor'],'product':product['name'],
                            'release':product['release'],'identification_helper':product['record'].get('product_identification_helper',{}),
                            'document_ref':aid,'vulnerability_index':vi})
                        self.counts['known_affected_product_relations']+=1
        self.title_forms=defaultdict(set);self.cache={}

    def load_dictionary_titles(self,wanted):
        catalog=defaultdict(set)
        with (self.root/'data/cpe_dictionary.jsonl').open(encoding='utf-8') as handle:
            for line in handle:
                row=json.loads(line);fields=parts(row.get('cpe'))
                if not fields or row.get('deprecated'):continue
                ident=identity(fields)
                if ident not in wanted:continue
                if fields[3] not in ('*','-'):catalog[ident].add(fields[3])
                # An exact dictionary display title may bridge namespace spelling.
                # Only the explicitly recorded release/update suffix is removed.
                title=str(row.get('title') or '')
                for suffix in (literal(fields[4]),literal(fields[3])):
                    if suffix and suffix not in ('*','-'):
                        title=re.sub(r'(?:\s|\(|\[|:)+v?'+re.escape(suffix)+r'[\s)\]]*$', '',title,flags=re.I)
                self.title_forms[ident].add(normalized(title))
        return {k:sorted(v) for k,v in catalog.items()}

    def classify(self,row):
        relations=self.by_cve.get(row['cve'],[])
        if not relations:return [],'no_verified_known_affected_product'
        ident=identity(row['fields']);part,vendor,product=ident;proofs=[]
        cache_key=(row['cve'],ident)
        if cache_key in self.cache:return self.cache[cache_key]
        for declared in relations:
            helper=declared['identification_helper'];method=None
            helper_fields=parts(helper.get('cpe'))
            if helper_fields and identity(helper_fields)==ident:method='explicit_csaf_cpe_identity'
            elif vendor_key(vendor)==vendor_key(declared['vendor']):
                expected=product_forms(declared['product'],declared['vendor'])
                if expected & product_forms(product,vendor):method='exact_vendor_product_spelling'
                elif any(vendor_key(declared['vendor'])+name in self.title_forms.get(ident,set()) for name in expected):method='exact_official_dictionary_title'
                else:
                    for model in helper.get('model_numbers',[]):
                        pattern=''.join(c for c in unicodedata.normalize('NFKD',model).casefold() if c.isalnum() or c in '*?')
                        if pattern and len(pattern.replace('*','').replace('?',''))>=4 and any(fnmatch.fnmatchcase(p,pattern) for p in product_forms(product,vendor)):
                            method='explicit_csaf_model_number';break
            if method:proofs.append({**declared,'match_method':method})
        result=(proofs,'verified_advisory_product' if proofs else 'product_link_unproven_needs_review')
        self.cache[cache_key]=result
        return result
