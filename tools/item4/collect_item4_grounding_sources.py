"""Preserve the official vendor role evidence used by the product Gold."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from html.parser import HTMLParser
import hashlib,json,re,sys
from pathlib import Path
from urllib.request import Request,urlopen

ROOT=Path(__file__).resolve().parents[2]
URL='https://cert-portal.siemens.com/productcert/html/ssa-763427.html'

class Text(HTMLParser):
    def __init__(self):super().__init__();self.parts=[]
    def handle_data(self,data):
        if data.strip():self.parts.append(data.strip())

def collect(output):
    with urlopen(Request(URL,headers={'User-Agent':'ICS-VEX source evidence audit'}),timeout=30) as response:
        raw=response.read()
    parser=Text();parser.feed(raw.decode('utf-8'))
    text=re.sub(r'\s+',' ',' '.join(parser.parts))
    match=re.search(r'SIMATIC CPs \(Communications Processors\) are specialized interface modules[^.]+\.',text)
    if not match:raise ValueError('Official communication-processor description not found')
    document=dict(url=URL,document_sha256=hashlib.sha256(raw).hexdigest(),
        raw_html=raw.decode('utf-8'),text=text,communication_processor_description=match.group(),
        collection_method='Official vendor HTTPS response; HTML text extraction',
        independent_semantic_accuracy_verified=False)
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True)
    output.with_suffix('.json.tmp').write_bytes(json.dumps(document,ensure_ascii=False,indent=2).encode('utf-8'))
    output.with_suffix('.json.tmp').replace(output)
    print(json.dumps({'output':str(output),'document_sha256':document['document_sha256'],'role_quote':match.group()}))

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=ROOT/'data/item4_grounding_v1/siemens_ssa_763427.json')
    collect(p.parse_args().output)
