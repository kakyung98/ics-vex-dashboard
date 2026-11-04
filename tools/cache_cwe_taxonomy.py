"""Pin the official CWE catalog for offline Pillar ancestry (not routing policy)."""
from pathlib import Path
import hashlib,json,zipfile,io,sys
import requests
from defusedxml import ElementTree as ET
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.training_io import atomic_json


def main():
    url='https://cwe.mitre.org/data/xml/cwec_latest.xml.zip'
    response=requests.get(url,timeout=90);response.raise_for_status();blob=response.content
    archive=zipfile.ZipFile(io.BytesIO(blob))
    names=[x for x in archive.namelist() if x.endswith('.xml')]
    if len(names)!=1:raise ValueError('Expected one CWE catalog XML.')
    info=archive.getinfo(names[0])
    if info.file_size>100*1024*1024:raise ValueError('CWE catalog exceeds configured size bound.')
    xml=archive.read(names[0]);root=ET.fromstring(xml)
    namespace=root.tag.split('}')[0].lstrip('{')
    if not namespace.startswith('http://cwe.mitre.org/cwe-'):raise ValueError('Unexpected CWE XML namespace.')
    ns={'c':namespace}
    records={}
    for e in root.findall('./c:Weaknesses/c:Weakness',ns):
        cid='CWE-'+e.attrib['ID']
        parents=sorted({'CWE-'+r.attrib['CWE_ID'] for r in e.findall('./c:Related_Weaknesses/c:Related_Weakness',ns)
                        if r.attrib.get('Nature')=='ChildOf' and r.attrib.get('View_ID')=='1000'})
        description=' '.join(' '.join(e.find('c:Description',ns).itertext()).split()) if e.find('c:Description',ns) is not None else ''
        records[cid]={'id':cid,'name':e.attrib['Name'],'abstraction':e.attrib.get('Abstraction'),
            'status':e.attrib.get('Status'),'parents_view_1000':parents,'description':description,
            'url':'https://cwe.mitre.org/data/definitions/'+e.attrib['ID']+'.html'}
    if len(records)<100 or not any(r['abstraction']=='Pillar' for r in records.values()):raise ValueError('Incomplete CWE taxonomy parse.')
    version=root.attrib.get('Version');directory=ROOT/'data/cwe_taxonomy'/('v'+str(version));directory.mkdir(parents=True,exist_ok=True)
    manifest={'schema':'ics-vex-cwe-taxonomy/1','version':version,'release_date':root.attrib.get('Date'),
        'source':url,'zip_sha256':hashlib.sha256(blob).hexdigest(),'xml_sha256':hashlib.sha256(xml).hexdigest(),
        'view':'CWE-1000','records':records,'routing_policy_included':False}
    target=directory/'catalog.json'
    if target.exists() and target.read_text(encoding='utf-8')!=json.dumps(manifest,ensure_ascii=False,indent=2):
        previous=json.loads(target.read_text(encoding='utf-8'))
        if previous['xml_sha256']!=manifest['xml_sha256']:raise FileExistsError('Pinned version changed; create a new snapshot.')
    atomic_json(target,manifest)
    atomic_json(ROOT/'data/cwe_taxonomy/current.json',{'path':str(target.relative_to(ROOT)).replace('\\','/'),
        'version':version,'sha256':hashlib.sha256(target.read_bytes()).hexdigest()})
    print(json.dumps({'version':version,'weaknesses':len(records),'pillars':[r['id'] for r in records.values() if r['abstraction']=='Pillar']},indent=2))


if __name__=='__main__':main()
