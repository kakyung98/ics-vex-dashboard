"""Fetch official search hits and locally index normalized text; preserve URL and locator."""
import concurrent.futures as cf
import hashlib,json,re,sys,tempfile
from pathlib import Path
from urllib.parse import urlparse, unquote
import requests, pymupdf
from bs4 import BeautifulSoup
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/"results/item4_asset_key_provenance"
CACHE=Path(tempfile.gettempdir())/"icsvex_asset_key_docs_v1"
CACHE.mkdir(exist_ok=True)
DOMAINS="""dell.com net-snmp.org kernel.org docs.aws.amazon.com siemens.com siemens-energy.com rockwellautomation.com se.com schneider-electric.com abb.com hitachienergy.com selinc.com beckhoff.com moxa.com emerson.com opto22.com cisco.com mikrotik.com fortinet.com openvpn.net microsoft.com tomcat.apache.org httpd.apache.org wildfly.org redhat.com inductiveautomation.com osisoft.com aveva.com automationdirect.com phoenixcontact.com unitronicsplc.com wago.com rfc-editor.org openbsd.org docs.ansible.com postgresql.org eclipse.dev ignitionmanual.com kepware.com ptc.com gevernova.com schneider-electric.us download.phoenixcontact.com learn.microsoft.com bsi.bund.de""".split()
def valid(url):
    h=urlparse(url).hostname or ""
    return any(h==d or h.endswith("."+d) for d in DOMAINS)
def norm(s):return " ".join(s.split())
def fetch(item):
    url=item["url"]; ident=hashlib.sha256(url.encode()).hexdigest()[:20];save=CACHE/(ident+".json")
    if save.exists():return json.loads(save.read_bytes())|item
    result=dict(id=ident); pages=[]
    try:
        with requests.get(url,stream=True,timeout=(6,15),headers={"User-Agent":"Mozilla/5.0 (research document retrieval)"}) as resp:
            resp.raise_for_status()
            if not valid(resp.url):raise ValueError("off-domain redirect")
            buf=bytearray()
            for chunk in resp.iter_content(131072):
                buf.extend(chunk)
                if len(buf)>32_000_000:raise ValueError("size limit")
            raw=bytes(buf);result["final_url"]=resp.url
        result["sha256"]=hashlib.sha256(raw).hexdigest()
        if raw.startswith(b"%PDF"):
            with pymupdf.open(stream=raw,filetype="pdf") as doc:
                result["format"]="pdf"
                result["title"]=norm(doc.metadata.get("title","") or item["title"])
                for i,p in enumerate(doc):
                    t=norm(p.get_text())
                    if t:pages.append([f"PDF p.{i+1}",t])
        else:
            soup=BeautifulSoup(raw,"html.parser")
            result["format"]="html";result["title"]=norm(soup.title.get_text(" ",strip=True) if soup.title else item["title"])
            block=soup.find("main") or soup.find("article") or soup.body
            if not block:raise ValueError("no article")
            for n in block.select("script,style,nav,footer,header,aside,noscript"):n.decompose()
            # Ordered segments with context; exact quotes verified against canonical normalized page.
            text=norm(block.get_text(" ",strip=True))
            if re.search("access denied|just a moment|page not found|request rejected",result["title"],re.I):raise ValueError("unavailable")
            if len(text)<120:raise ValueError("no article text")
            pages=[["HTML",text]]
        if not pages:raise ValueError("no extractable text")
        result["pages"]=pages
    except Exception as e:result.update(error=str(e)[:220],pages=[])
    save.write_text(json.dumps(result,ensure_ascii=False),encoding="utf8")
    return result|item
def collect(filename):
    entries=json.loads((OUT/filename).read_bytes()); urls={}
    for g in entries:
        used=0
        for title,url in g["urls"]:
            if not valid(url):continue
            url=url.split("#")[0]
            if "x-sign=" in url:url=url.split("?")[0]
            obj=urls.setdefault(url,dict(url=url,search_title=title,title=title,hints=[],keys=[]))
            if g["id"] not in obj["hints"]:obj["hints"].append(g["id"])
            if g.get("key") and g["key"] not in obj["keys"]:obj["keys"].append(g["key"])
            used+=1
            if used>=(3 if "key" in g else 4):break
    with cf.ThreadPoolExecutor(max_workers=20) as pool:results=list(pool.map(fetch,urls.values()))
    manifest=[]
    for x in results:
        cached=json.loads((CACHE/(x["id"]+".json")).read_bytes())
        x["title"]=cached.get("title") or x["title"]
        manifest.append({k:v for k,v in x.items() if k!="pages"}|{"pages":len(cached["pages"])})
    (OUT/("sources_"+filename)).write_text(json.dumps(manifest,indent=1,ensure_ascii=False),encoding="utf8")
    print(len(manifest),sum(bool(x["pages"]) for x in manifest),flush=True)
if __name__=="__main__":collect(sys.argv[1])
