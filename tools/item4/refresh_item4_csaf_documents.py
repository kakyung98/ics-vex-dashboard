"""Preserve native HWPML formatting and append the current benchmark contract.

Original HWP files are backed up first. HWPML inputs are exported from the
current documents in Hancom; the revised HWPML is opened and saved as native
HWP/PDF for pagination and visual verification.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from lxml import etree as E

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'outputs/item4_csaf_v2'


def paragraph(template,text,page_break=False):
    p=E.Element('P',**{k:v for k,v in template.attrib.items() if k not in
        {'InstId','PageBreak','ColumnBreak'}})
    if page_break:p.set('PageBreak','true')
    run=E.SubElement(p,'TEXT',CharShape=template.find('TEXT').get('CharShape'))
    E.SubElement(run,'CHAR').text=text
    return p


def main():
    changes=[]
    for kind,doc in [('design','ITEM4_CSAF_EXPERT_DESIGN.md'),('manual','ITEM4_CSAF_EXPERT_MANUAL.md')]:
        src=OUT/(kind+'_original.hml');tree=E.parse(str(src));root=tree.getroot()
        section=root.find('./BODY/SECTION');ps=section.findall('P')
        texts=[''.join(p.itertext()) for p in ps]
        # Use native styles already present in the latest document.
        heading=next(p for p,t in zip(ps,texts) if t.startswith('1. '))
        subheading=next(p for p,t in zip(ps,texts) if t.startswith('1.1 '))
        body=next(p for p,t in zip(ps,texts) if t.startswith('- '))
        original_tables=[E.tostring(t) for t in root.findall('.//TABLE')]
        cover=ps[3]
        cs=cover.findall('.//CHAR')
        cs[0].text=('제품 식별·자산 운영 정보 값·VEX 흐름을 설명한다. 시험 항목 #4의 전체 CVE 시나리오와 '
                     'ICSA 70:30 분할·전문가 κ 검증은 문서 끝의 추가 개정 절을 적용한다.')
        for c in cs[1:]:c.text=''
        first=True
        for raw in (ROOT/'docs'/doc).read_text(encoding='utf-8').splitlines():
            if not raw.strip():continue
            if raw.startswith('# '):
                p=paragraph(heading,'추가 개정  '+raw[2:],True)
            elif raw.startswith('## '):
                p=paragraph(subheading,raw[3:])
            else:
                text=raw if raw.startswith('- ') else '- '+raw
                # Permit wrapping in long command paths without changing XML IDs.
                text=text.replace('_','_\u200b').replace('/','/\u200b')
                p=paragraph(body,text)
            section.append(p)
            first=False
        assert original_tables==[E.tostring(t) for t in root.findall('.//TABLE')]
        output=OUT/(kind+'_revised.hml')
        tree.write(str(output),xml_declaration=True,encoding='UTF-8',pretty_print=False)
        changes.append(dict(kind=kind,source_sha256=hashlib.sha256(src.read_bytes()).hexdigest(),
            output=str(output),output_sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
            preserved_tables=len(original_tables),appended_contract=doc))
    (OUT/'hml_changes.json').write_text(json.dumps(changes,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(changes,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
