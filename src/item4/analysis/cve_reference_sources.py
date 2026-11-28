"""Generic, CVE-scoped primary-source collection. No CVE/product allowlist.

Collection proposes source text, never conditions, scores, questions or verdicts.
Raw bytes, selected source spans and failures remain available for audit.
"""
from copy import deepcopy
from datetime import datetime, timezone
from functools import lru_cache
from io import BytesIO
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import threading
import uuid
from urllib.parse import urlparse, urljoin

ROOT=Path(__file__).resolve().parents[3]
CACHE=ROOT/'data/cve_reference_sources'
VERSION='cve-reference-sources/2'
CACHE_LOCK=threading.RLock()
CVE=re.compile(r'\bCVE-\d{4}-\d{4,}\b',re.I)
STOP=re.compile(r'(?im)^\s*(?:Classification of Vulnerability|Temporary Fix|Mitigation|Remediation|Acknowledg\w*|Revision History|References)\s*[:/\w ]*$')


def sha(value):return hashlib.sha256(value).hexdigest()


def public_url(url):
    parsed=urlparse(url)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.port not in (None,443):
        raise ValueError('Only public HTTPS references without credentials are allowed')
    host=parsed.hostname
    if host.casefold() in {'localhost','localhost.localdomain'}:raise ValueError('Private reference host')
    for address in socket.getaddrinfo(host,443,type=socket.SOCK_STREAM):
        if not ipaddress.ip_address(address[4][0]).is_global:raise ValueError('Private reference address')
    return url


def download(url):
    import requests
    session=requests.Session();session.trust_env=False
    for _ in range(5):
        public_url(url)
        response=session.get(url,timeout=(8,18),allow_redirects=False,stream=True)
        if response.is_redirect:
            url=urljoin(url,response.headers['Location']);response.close();continue
        response.raise_for_status();parts=[];size=0
        for part in response.iter_content(65536):
            size+=len(part)
            if size>8*1024*1024:raise ValueError('Reference document exceeds 8 MiB')
            parts.append(part)
        return b''.join(parts),response.headers.get('Content-Type',''),url
    raise ValueError('Too many reference redirects')


def _source(cve,text,url,raw_path,raw_sha,locator):
    text=text.strip()
    return dict(id='reference:'+sha((url+json.dumps(locator,sort_keys=True)+cve).encode())[:24],
        text=text,text_sha256=sha(text.encode()),url=url,product_keys=[],scope_binding='unresolved',
        cve_binding=cve,source_type='primary_cve_reference',
        provenance=dict(raw_path=raw_path,document_sha256=raw_sha,locator=locator))


def csaf_sources(cve,document,url,path,document_sha):
    rows=[];vulns=document.get('vulnerabilities',[])
    matched=[(i,v) for i,v in enumerate(vulns) if v.get('cve')==cve]
    for i,v in matched:
        for n,note in enumerate(v.get('notes',[])):
            if note.get('category') not in {'summary','description','details'}:continue
            if re.search(r'mitigat|remediat|workaround|fix',note.get('title',''),re.I):continue
            if note.get('text'):rows.append(_source(cve,note['text'],url,path,document_sha,dict(pointer=f'/vulnerabilities/{i}/notes/{n}/text')))
    # Document-wide narrative is attributable only for a single-CVE advisory.
    if len(vulns)==1 and matched:
        for n,note in enumerate(document.get('document',{}).get('notes',[])):
            if note.get('category')=='summary' and note.get('text'):
                rows.insert(0,_source(cve,note['text'],url,path,document_sha,dict(pointer=f'/document/notes/{n}/text')))
    return rows


def document_sources(cve,raw,media,url,path,document_sha):
    if 'json' in media or raw.lstrip().startswith(b'{'):
        doc=json.loads(raw)
        if doc.get('csaf_version')=='2.0' or doc.get('document',{}).get('csaf_version')=='2.0':
            return csaf_sources(cve,doc,url,path,document_sha)
        if doc.get('cveMetadata',{}).get('cveId')!=cve or doc.get('cveMetadata',{}).get('state')=='REJECTED':return []
        return [_source(cve,x['value'],url,path,document_sha,dict(pointer=f'/containers/cna/descriptions/{i}/value'))
            for i,x in enumerate(doc.get('containers',{}).get('cna',{}).get('descriptions',[])) if x.get('lang','').startswith('en')]
    if raw.startswith(b'%PDF'):
        from pypdf import PdfReader
        pages=PdfReader(BytesIO(raw)).pages;rows=[]
        if len(pages)>80:raise ValueError('Reference PDF exceeds bounded page budget')
        for index,page in enumerate(pages):
            text=page.extract_text() or ''
            if {x.upper() for x in CVE.findall(text)}!={cve}:continue
            start=re.search(r'(?im)^\s*(?:Vulnerability Description|Description|Summary)\s*$',text)
            if not start:continue
            begin=start.end();stop=STOP.search(text,begin);end=stop.start() if stop else len(text)
            rows.append(_source(cve,text[begin:end],url,path,document_sha,dict(page=index+1,span=[begin,end])))
        return rows
    from bs4 import BeautifulSoup
    soup=BeautifulSoup(raw,'html.parser')
    for tag in soup(['script','style','nav','footer','header']):tag.decompose()
    main=soup.find('main') or soup.find('article') or soup
    ids={x.upper() for x in CVE.findall(main.get_text(' ',strip=True))}
    if cve not in ids:return []
    rows=[]
    for heading in main.find_all(re.compile('^h[1-6]$')):
        label=heading.get_text(' ',strip=True)
        # Multi-CVE pages require a heading identifying this exact CVE.
        if len(ids)>1 and cve not in label:continue
        if len(ids)==1 and not re.search(r'summary|description|details|vulnerability',label,re.I):continue
        if re.search(r'mitigat|remediat|fix|references',label,re.I):continue
        chunks=[]
        for sibling in heading.next_siblings:
            if getattr(sibling,'name','') and re.match(r'^h[1-6]$',sibling.name):break
            text=sibling.get_text(' ',strip=True) if hasattr(sibling,'get_text') else str(sibling).strip()
            if text:chunks.append(text)
        text='\n\n'.join(chunks)
        if text:rows.append(_source(cve,text,url,path,document_sha,dict(heading=label)))
    return rows


def _ingest(url,raw,media,*,cache=None):
    cache=Path(cache or CACHE);cache.mkdir(parents=True,exist_ok=True)
    key=sha(url.encode());raw_sha=sha(raw);path=cache/(raw_sha+'.raw')
    if not path.is_file() or sha(path.read_bytes())!=raw_sha:
        raw_tmp=cache/(raw_sha+'.'+uuid.uuid4().hex+'.tmp')
        raw_tmp.write_bytes(raw);raw_tmp.replace(path)
    if raw.startswith(b'%PDF'):
        from pypdf import PdfReader
        searchable='\n'.join(p.extract_text() or '' for p in PdfReader(BytesIO(raw)).pages)
    else:searchable=raw.decode('utf-8',errors='replace')
    info=dict(url=url,cves=sorted({x.upper() for x in CVE.findall(searchable)}),
        raw_path=str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path),
        document_sha256=raw_sha,media=media,retrieved_at=datetime.now(timezone.utc).isoformat())
    tmp=cache/(key+'.'+uuid.uuid4().hex+'.tmp');tmp.write_text(json.dumps(info,ensure_ascii=False,indent=2),encoding='utf-8');tmp.replace(cache/(key+'.json'))
    return info


def ingest(url,raw,media,*,cache=None):
    # Windows can deny replace/open while another thread holds the same file.
    # Serialize publication and metadata reads, keeping downloads outside it.
    with CACHE_LOCK:return _ingest(url,raw,media,cache=cache)


def _metadata(path):
    with CACHE_LOCK:return json.loads(path.read_bytes())


def _raw(info):
    path=ROOT/info['raw_path']
    with CACHE_LOCK:data=path.read_bytes()
    if sha(data)!=info['document_sha256']:raise ValueError('Reference raw bytes changed')
    return data


def verify(source):
    if source.get('source_type')!='primary_cve_reference':return
    info=source['provenance'];data=_raw(info)
    media='application/json' if data.lstrip().startswith(b'{') else 'application/pdf' if data.startswith(b'%PDF') else 'text/html'
    expected=document_sources(source['cve_binding'],data,media,source['url'],info['raw_path'],info['document_sha256'])
    if not any(s['id']==source['id'] and s['text_sha256']==source['text_sha256'] and s['text']==source['text'] for s in expected):
        raise ValueError('Reference passage no longer matches its pinned document and CVE scope')


def collect(cve,advisory_ids=(),*,fetcher=None,cache=None,network=None):
    if not CVE.fullmatch(cve):raise ValueError('Invalid CVE ID')
    cache=Path(cache or CACHE);cache.mkdir(parents=True,exist_ok=True)
    network=os.getenv('ICSVEX_REFERENCE_NETWORK','1')=='1' if network is None else network
    fetcher=fetcher or download
    rows=[];attempts=[];seen=set();links=[];rejected_record=False;network_attempts=[]
    api='https://cveawg.mitre.org/api/cve/'+cve
    def fetch(url):
        for index in range(3):
            entry=dict(url=url,attempt=index+1);network_attempts.append(entry)
            try:
                value=fetcher(url);entry['status']='retrieved';return value
            except Exception as exc:
                code=getattr(getattr(exc,'response',None),'status_code',None)
                transient=isinstance(exc,OSError) and (code is None or code in (408,429) or code>=500)
                entry.update(status='failed',reason=type(exc).__name__+': '+str(exc)[:300],retryable=transient)
                if not transient or index==2:raise
    def add(info):
        nonlocal rejected_record
        try:
            raw=_raw(info)
            if info['url']==api:
                metadata=json.loads(raw).get('cveMetadata',{})
                if metadata.get('cveId')==cve and metadata.get('state')=='REJECTED':rejected_record=True
            extracted=document_sources(cve,raw,info['media'],info['url'],info['raw_path'],info['document_sha256'])
            rows.extend(extracted);attempts.append(dict(url=info['url'],status='scoped' if extracted else 'no_unambiguous_cve_passage',document_sha256=info['document_sha256']))
        except Exception as exc:attempts.append(dict(url=info['url'],status='failed',reason=type(exc).__name__+': '+str(exc)[:300]))
    for aid in advisory_ids:
        if not re.fullmatch(r'icsa-\d{2}-\d{3}-\d{2}',aid,re.I):continue
        path=ROOT/'data/cisa_identification_csaf'/(aid.lower()+'.json')
        if path.is_file():
            raw=path.read_bytes();doc=json.loads(raw)
            refs=doc.get('document',{}).get('references',[])
            url=next((r['url'] for r in refs if 'cisa.gov/news-events/ics-advisories/' in r.get('url','')),'https://www.cisa.gov/news-events/ics-advisories/'+aid)
            add(dict(url=url,raw_path=str(path.relative_to(ROOT)),document_sha256=sha(raw),media='application/json'))
    for entry in sorted(cache.glob('*.json')):
        try:
            info=_metadata(entry);raw=_raw(info)
            if cve in info.get('cves',[]) or ('cves' not in info and (cve.encode() in raw or raw.startswith(b'%PDF'))):
                add(info);seen.add(info['url'])
        except Exception as exc:attempts.append(dict(url=str(entry),status='failed',reason=type(exc).__name__))
    # Public CVE records remove the historical fixed-population lookup limit.
    if network:
        try:
            cached=cache/(sha(api.encode())+'.json')
            if cached.exists():info=_metadata(cached);raw=_raw(info)
            else:
                raw,media,final=fetch(api);info=ingest(api,raw,'application/json',cache=cache)
            if api not in seen:add(info)
            doc=json.loads(raw)
            containers=[] if rejected_record else [doc.get('containers',{}).get('cna',{}),*doc.get('containers',{}).get('adp',[])]
            for container in containers:
                for ref in container.get('references',[]):
                    url=ref.get('url','');host=urlparse(url).hostname or '';tags=ref.get('tags',[])
                    if ('vendor-advisory' in tags or 'x_refsource_CONFIRM' in tags
                            or host in {'cisa.gov','www.cisa.gov','ics-cert.us-cert.gov','cert.vde.com','certvde.com'}
                            or host.endswith(('.cisa.gov','.certvde.com')) or 'csaf' in host):
                        links.append(url)
        except Exception as exc:attempts.append(dict(url=api,status='failed',reason=type(exc).__name__+': '+str(exc)[:300]))
        queue=list(dict.fromkeys(links));processed=0
        while queue and processed<8:
            url=queue.pop(0);processed+=1
            if url in seen:continue
            try:
                cached=cache/(sha(url.encode())+'.json')
                if cached.exists():info=_metadata(cached)
                else:
                    raw,media,final=fetch(url);info=ingest(url,raw,media,cache=cache)
                add(info);seen.add(url)
                # Follow official page links to structured advisories or PDFs;
                # parsing them does not import a page's instructions as policy.
                raw=_raw(info)
                if 'html' in info['media']:
                    from bs4 import BeautifulSoup
                    soup=BeautifulSoup(raw,'html.parser')
                    for a in soup.find_all('a',href=True):
                        target=urljoin(url,a['href'])
                        if '.pdf' in target.lower() or ('csaf' in target.lower() and '.json' in target.lower()):
                            if target not in seen and target not in queue:queue.append(target)
            except Exception as exc:attempts.append(dict(url=url,status='failed',reason=type(exc).__name__+': '+str(exc)[:300]))
        for url in queue:attempts.append(dict(url=url,status='deferred_reference_budget'))
    accepted=[];size=0;hashes=set()
    for row in ([] if rejected_record else rows):
        if row['text_sha256'] in hashes:continue
        if len(row['text'])>3000 or len(accepted)>=6 or size+len(row['text'])>6000:
            attempts.append(dict(url=row['url'],status='deferred_context_budget',source_id=row['id']));continue
        accepted.append(row);hashes.add(row['text_sha256']);size+=len(row['text'])
    return accepted,dict(version=VERSION,cve=cve,attempts=attempts,network_attempts=network_attempts,source_count=len(accepted),network_enabled=network,
        complete=False,cve_record_state='REJECTED' if rejected_record else 'unverified',
        interpretation='Retrieved text only; no prerequisite or exploitability is inferred by collection')
