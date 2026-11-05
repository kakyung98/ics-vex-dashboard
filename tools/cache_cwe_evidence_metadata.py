"""Pin official platform/detection metadata to the existing exact CWE XML hash."""
from pathlib import Path
import argparse,hashlib,io,json,sys,zipfile
import requests
from defusedxml import ElementTree as ET
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.cwe_taxonomy import load


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--xml',type=Path);args=parser.parse_args()
    pinned=load();url=f'https://cwe.mitre.org/data/xml/cwec_v{pinned["version"]}.xml.zip'
    if args.xml:xml=args.xml.read_bytes()
    else:
        response=requests.get(url,timeout=90);response.raise_for_status()
        archive=zipfile.ZipFile(io.BytesIO(response.content));names=[n for n in archive.namelist() if n.endswith('.xml')]
        if len(names)!=1 or archive.getinfo(names[0]).file_size>100*1024*1024:raise ValueError('Unexpected XML archive')
        xml=archive.read(names[0])
    if hashlib.sha256(xml).hexdigest()!=pinned['xml_sha256']:raise ValueError('Metadata XML does not match pinned taxonomy')
    root=ET.fromstring(xml);ns={'c':root.tag.split('}')[0][1:]};records={}
    def text(node):return ' '.join(' '.join(node.itertext()).split()) if node is not None else ''
    for e in root.findall('./c:Weaknesses/c:Weakness',ns):
        cid='CWE-'+e.attrib['ID'];platforms=e.find('c:Applicable_Platforms',ns)
        records[cid]={'platforms':[{'kind':p.tag.split('}')[-1],**p.attrib} for p in platforms] if platforms is not None else [],
            'detection_methods':[{'method':text(d.find('c:Method',ns)),
                'description':text(d.find('c:Description',ns)),
                'effectiveness':text(d.find('c:Effectiveness',ns))}
                for d in e.findall('./c:Detection_Methods/c:Detection_Method',ns)],
            'mapping_usage':text(e.find('./c:Mapping_Notes/c:Usage',ns)),
            'mapping_rationale':text(e.find('./c:Mapping_Notes/c:Rationale',ns))}
    out={'schema':'ics-vex-cwe-evidence-metadata/1','taxonomy_version':pinned['version'],
        'taxonomy_xml_sha256':pinned['xml_sha256'],'source':url,'records':records,
        'detection_methods_are_not_mandatory_analysis_requirements':True}
    dest=ROOT/'data/cwe_taxonomy'/('v'+pinned['version'])/'evidence_metadata.json'
    dest.write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'records':len(records),'bytes':dest.stat().st_size,'same_xml_hash':True}))


if __name__=='__main__':main()
