"""CISA-native product cases for EVERY CPE-bearing CVE; never a name-join gate."""
from pathlib import Path
from collections import defaultdict
import re,json,hashlib
from bs4 import BeautifulSoup
from tools.item3_advisory_scope import ScopeCatalog,product_tree,normalized,vendor_key,product_key
from tools.item3_truth_oracle import key,version_compare


def family(vendor,name):return vendor_key(vendor),product_key(name,vendor)


def version_state(installed,release):
    """Conservative numeric VERS intervals plus literal release points.

    Pipes separate signposts, not a blanket AND. Unsupported ordering stays None.
    """
    release=str(release or '').strip()
    if release.casefold() in ('*','vers:all/*','vers:generic/*','all versions','all firmware versions'):return True
    if installed in (None,'NOASSERTION','-','*') or not release:return None
    installed=re.sub(r'^[vV](?=\d)','',installed).casefold()
    if release.startswith('vers:'):
        if '/' not in release:return None
        release=release.split('/',1)[1]
    tokens=[]
    for part in release.split('|'):
        m=re.fullmatch(r'\s*(>=|<=|>|<|!=|=)?\s*[vV]?(\S+)\s*',part)
        if not m:return None
        op,value=m.groups();tokens.append((op or '=',value.casefold()))
    if all(op=='=' for op,v in tokens):return any(installed==v for op,v in tokens)
    if any(op=='!=' and installed==v for op,v in tokens):return False
    points=[v for op,v in tokens if op=='='];bounds=[(op,v) for op,v in tokens if op not in ('=','!=')]
    if installed in points:return True
    if any(version_compare(a[1],b[1]) not in (-1,) for a,b in zip(bounds,bounds[1:])):return None
    if any((a[0] in ('>','>='))==(b[0] in ('>','>=')) for a,b in zip(bounds,bounds[1:])):return None
    intervals=[];lower=None
    for op,value in bounds:
        if op in ('>','>='):
            if lower is not None:return None
            lower=(op,value)
        else:
            intervals.append((lower,(op,value)));lower=None
    if lower is not None:intervals.append((lower,None))
    states=[]
    for lo,hi in intervals:
        checks=[]
        for endpoint in (lo,hi):
            if endpoint is None:continue
            op,value=endpoint;compared=version_compare(installed,value)
            if compared is None:checks.append(None)
            else:checks.append({'>':compared>0,'>=':compared>=0,'<':compared<0,'<=':compared<=0}[op])
        states.append(False if False in checks else None if None in checks else True)
    return True if True in states else None if None in states else False


def installed_witness(release):
    release=str(release or '').strip();body=release.split('/',1)[1] if release.startswith('vers:') and '/' in release else release
    candidates=[]
    for op,value in re.findall(r'(>=|<=|>|<|!=|=)?\s*([vV]?\d+(?:\.\d+)*)(?=\||$)',body):
        value=re.sub(r'^[vV]','',value)
        if op in ('','=', '>=','<='):candidates.append((value,'source_exact_or_inclusive_release'))
        elif op=='>':candidates.append((value+'.0.1','synthetic_numeric_range_witness'))
        elif op=='<':
            nums=list(map(int,value.split('.')))
            for i in range(len(nums)-1,-1,-1):
                if nums[i]>0:
                    candidates.append(('.'.join(map(str,nums[:i]+[nums[i]-1]+[0]*(len(nums)-i-1))),'synthetic_numeric_range_witness'));break
    if body and not re.search(r'[<>|!*\s]',body):candidates.insert(0,(re.sub(r'^=','',body),'source_literal_release'))
    for value,basis in candidates:
        if version_state(value,release) is True:return value,basis
    return None,'installed_version_unconfirmed'


VENDORS={'icsa-12-018-02':'Certec','icsa-15-335-01':'Saia Burgess Controls','icsa-16-175-02':'Unitronics',
 'icsa-16-196-01':'Schneider Electric','icsa-16-287-05a':'Moxa','icsa-16-308-03':'Schneider Electric',
 'icsa-16-336-05b':'GE','icsa-16-336-06':'Rockwell Automation','icsa-16-343-04':'INTERSCHALT',
 'icsa-16-343-05':'Rockwell Automation','icsa-17-094-04':'Rockwell Automation','icsa-18-095-01':'Rockwell Automation'}
OVERRIDES={
 'icsa-12-018-02':['Atvise'],
 'icsa-15-335-01':['Saia PCD Controllers'],
 'icsa-16-175-02':['VisiLogic'],
 'icsa-16-196-01':['Pelco Digital Sentry Video Management System'],
 'icsa-16-336-06':['MicroLogix 1100','MicroLogix 1400'],
 'icsa-16-343-04':['VDR G4e'],
 'icsa-16-343-05':['Logix5000 Controller'],
}
GLEG={
 'CVE-2001-1340':[('BECK GMBH','IPC@CHIP')],'CVE-2001-1341':[('BECK GMBH','IPC@CHIP')],
 'CVE-2006-6488':[('ICONICS','Dialog Wrapper Module ActiveX control')],
 'CVE-2008-0175':[('GE Fanuc','Real Time Information Portal')],
 'CVE-2008-0760':[('SafeNet','Sentinel Protection Server'),('SafeNet','Sentinel Keys Server'),('NOASSERTION','DATARATE SCADA')],
 'CVE-2008-2639':[('Citect','SCADA ODBC')],
 'CVE-2010-2974':[('Invensys','Wonderware InFusion SCADA')],
 'CVE-2010-4142':[('DATAC','RealWin SCADA')],'CVE-2010-4598':[('Ecava','IntegraXor')],
 'CVE-2010-4709':[('Automated Solutions','Modbus/TCP OPC Server')],
 'CVE-2010-4740':[('SCADA Engine','BACnet OPC client')],'CVE-2010-4741':[('MOXA','Device Manager Tool')],
 'CVE-2011-0488':[('Indusoft','SCADA web studio'),('Advantech','Studio')],
}


def legacy_products(root,aid,cve):
    folder=root/'data/item3_full_advisory_sources_v3';index=json.loads((folder/'index.json').read_text(encoding='utf-8'));meta=index[aid]
    raw=(folder/(aid+'.html')).read_bytes();assert hashlib.sha256(raw).hexdigest()==meta['sha256']
    soup=BeautifulSoup(raw,'html.parser');text=soup.get_text(' ',strip=True);lines=[]
    if aid=='icsa-11-096-01':items=GLEG[cve]
    elif aid in OVERRIDES:items=[(VENDORS.get(aid,'Siemens'),p) for p in OVERRIDES[aid]]
    else:
        for heading in soup.find_all(re.compile('^h[1-6]$')):
            if not re.search(r'(?i)affected\s+products',heading.get_text(' ',strip=True)):continue
            for node in heading.next_elements:
                name=getattr(node,'name',None)
                if name and re.fullmatch('h[1-6]',name) and not re.search(r'(?i)begin update|end update',node.get_text(' ',strip=True)):break
                if name=='li':lines.append(node.get_text(' ',strip=True))
        items=[]
        for line in lines:
            if re.search(r'(?i)begin update|end update',line):continue
            name=re.split(r':|,\s*firmware|\s+(?:all\s+)?(?:firmware\s+)?versions?\b|\s+prior to\b|\s+before\b',line,maxsplit=1,flags=re.I)[0]
            name=re.sub(r'\s*\(only affected by.*$', '',name,flags=re.I).strip(' ,;.')
            name=re.sub(r',?\s+and$','',name,flags=re.I).strip()
            if name and not re.search(r'CVE-',name):items.append((VENDORS.get(aid,'Siemens'),name))
    if not items:raise ValueError('No source product found for '+aid+' '+cve)
    result=[]
    for vendor,name in items:
        if normalized(name) not in normalized(text):raise ValueError('Product not present in CISA source: '+aid+' '+name)
        result.append({'cve':cve,'advisory_id':aid,'vendor':vendor,'product':name,'release':'',
            'relation_kind':'legacy_context_unadjudicated','relationship_context_required':True,
            'affected_product_id':None,'leaf_product_id':None,'identification_helper':{},
            'source_path':str((folder/(aid+'.html')).relative_to(root)),'source_sha256':meta['sha256'],
            'source_url':meta['url'],'normalized_source_product_text_evidence':name})
    return result


class FullCatalog:
    def __init__(self,root,universe):
        self.root=Path(root);self.scope=ScopeCatalog(root);self.by_cve=defaultdict(list);self.by_family=defaultdict(list)
        self.advisories=json.loads((self.root/'data/cisa_advisories.json').read_text(encoding='utf-8'));self.target=set(universe)
        advisory_links=defaultdict(list)
        for aid,r in self.advisories.items():
            for cve in r.get('cves',[]):advisory_links[cve].append((aid,r))
        for cve in sorted(self.target):
            if self.scope.by_cve.get(cve):
                self.by_cve[cve]=[{**r,'relation_kind':'csaf_known_affected','source_path':self.scope.documents[r['advisory_id']]['path'],
                    'source_sha256':self.scope.documents[r['advisory_id']]['raw_sha256'],
                    'source_url':self.scope.documents[r['advisory_id']]['url']} for r in self.scope.by_cve[cve]]
            else:
                for aid,r in advisory_links[cve]:
                    if r.get('csaf_path'):
                        path=self.scope.folder/(aid+'.json');doc=json.loads(path.read_text(encoding='utf-8'));tree,_=product_tree(doc)
                        for pid,p in tree.items():
                            if not p['name'] or not p['vendor']:continue
                            self.by_cve[cve].append({'cve':cve,'advisory_id':aid,'vendor':p['vendor'],'product':p['name'],'release':p['release'],
                                'relation_kind':'csaf_advisory_context_unadjudicated','relationship_context_required':True,
                                'affected_product_id':None,'leaf_product_id':pid,'identification_helper':p['record'].get('product_identification_helper',{}),
                                'source_path':self.scope.documents[aid]['path'],'source_sha256':self.scope.documents[aid]['raw_sha256'],
                                'source_url':self.scope.documents[aid]['url']})
                    else:self.by_cve[cve].extend(legacy_products(self.root,aid,cve))
            if not self.by_cve[cve]:raise ValueError('CPE-bearing CVE has no input-product source: '+cve)
            for r in self.by_cve[cve]:
                r['id']='ORIGIN-'+key(r)[:24];self.by_family[family(r['vendor'],r['product'])].append(r)
        assert set(self.by_cve)==self.target
        self.cache={}

    def labels(self,vendor,product,version,rejected=()):
        cachekey=(family(vendor,product),version,frozenset(rejected))
        if cachekey in self.cache:return self.cache[cachekey]
        states=defaultdict(list);support=defaultdict(list)
        for r in self.by_family[cachekey[0]]:
            cid=r['cve'];state=None
            if (r['relation_kind']=='csaf_known_affected' and not r['relationship_context_required'] and cid not in rejected
                and not r['identification_helper'].get('model_numbers') and cachekey[0][1]
                and vendor_key(vendor) not in ('noassertion','unknown','other')):
                state=version_state(version,r['release'])
            states[cid].append(state)
            if state is True:support[cid].append(r['id'])
        positives=sorted(c for c,v in states.items() if True in v)
        unknown=sorted(c for c,v in states.items() if True not in v and None in v)
        value={'expected_cves':positives,'unknown_cves':unknown,'positive_origin_refs':{c:sorted(set(v)) for c,v in support.items()},
            'complete_within_scored_universe':not unknown}
        self.cache[cachekey]=value;return value
