"""Extract native HWP content and check preservation of the operator catalogue."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
import hashlib
import json
import struct
import zlib
import olefile

ROOT=Path(__file__).resolve().parents[2]


def hwp_text(path):
    result=[]
    with olefile.OleFileIO(path) as o:
        flags=struct.unpack_from('<I',o.openstream('FileHeader').read(),36)[0]
        for name in o.listdir():
            if name[0]!='BodyText':continue
            data=o.openstream(name).read()
            if flags&1:data=zlib.decompress(data,-15)
            pos=0
            while pos+4<=len(data):
                h=struct.unpack_from('<I',data,pos)[0];pos+=4;tag=h&1023;n=h>>20
                if n==4095:n=struct.unpack_from('<I',data,pos)[0];pos+=4
                body=data[pos:pos+n];pos+=n
                if tag==67:result.append(body.decode('utf-16le',errors='replace'))
    return '\n'.join(result).replace('\u200b','')


def main():
    import csv,gzip,io
    keys=list(csv.DictReader(io.StringIO(gzip.open(ROOT/'data/operator_asset_keys.csv.gz','rt',encoding='utf-8-sig').read())))
    report={}
    for kind,name in [('design','설계서'),('manual','사용 매뉴얼')]:
        p=ROOT/'outputs/item4_csaf_v2'/(kind+'_final.hwp');text=hwp_text(p)
        missing=[r['key'] for r in keys if r['key'] not in text]
        for token in ['86,926','12,418','28,630','1,164','2,717','Cohen','TP/(TP+FP)']:
            if token not in text:missing.append(token)
        assert not missing,(kind,missing)
        report[kind]=dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
            bytes=p.stat().st_size,catalogue_rows_preserved=len(keys),current_evaluation_contract_present=True)
    target=ROOT/'outputs/item4_csaf_v2/document_audit.json'
    target.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
