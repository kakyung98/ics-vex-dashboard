"""Update current native HWP documents and regenerate their PDF counterparts."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from lxml import etree as E
import base64
import hashlib
import json
import re
import runpy
import zlib
from tools.item3.rename_identification_agents import rename_text

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'outputs/c_agent_rename_20261120'
LABELS = {
    'I1 제품 후보 분석': 'I1 컴포넌트명 분석',
    'I1 후보 분석': 'I1 컴포넌트명 분석',
    'I1: 제품 후보 순위 결정': 'I1: 컴포넌트명 분석과 후보 순위 결정',
    'I3 최종 제품 식별': 'I3 CPE·purl 식별자 확인',
    'I3 최종 제품 후보 선택': 'I3 CPE·purl 식별자 확인',
    'I3: 최종 제품 후보 선택': 'I3: CPE·purl 식별자 확인',
    'I3 최종 식별': 'I3 식별자 확인',
    'I3는 제품 식별 상태': 'I3는 CPE·purl 식별자 확인 상태',
    '제품 식별 단계는 I1·I2·I3': '제품 식별 단계는 I1(컴포넌트명)·I2(버전)·I3(CPE 및 purl 식별자)',
}


def revise(kind):
    tree = E.parse(str(OUT / (kind + '_native_current.hml')))
    original = tree.getroot()
    styles = [E.tostring(x) for x in original.findall('.//CHARSHAPELIST') + original.findall('.//PARASHAPELIST')]
    geometry = [E.tostring(x.find('SHAPEOBJECT/SIZE')) for x in original.findall('.//PICTURE')]
    changes = 0
    for element in original.iter():
        if element.tag not in {'CHAR', 'SHAPECOMMENT'} or not element.text:
            continue
        text = rename_text(element.text)
        for old, new in LABELS.items():
            text = text.replace(old, new)
        if text != element.text:
            changes += 1
            element.text = text
    replacements = {'2': ROOT / 'outputs/diagrams/agent_sequences/01_identification_sequence.png'} if kind == 'design' else {
        '1': OUT / 'images/sbom_initial.jpg',
        '3': OUT / 'images/sbom_results.jpg',
        '4': OUT / 'images/sbom_evidence.jpg',
    }
    for identifier, image in replacements.items():
        raw = image.read_bytes()
        compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        packed = compressor.compress(raw) + compressor.flush()
        item = original.find(f'.//BINITEM[@BinData="{identifier}"]')
        item.set('Format', image.suffix[1:].upper())
        data = original.find(f'.//BINDATASTORAGE/BINDATA[@Id="{identifier}"]')
        data.set('Compress', 'true')
        data.set('Encoding', 'Base64')
        data.set('Size', str(len(packed)))
        data.text = base64.b64encode(packed).decode('ascii')
    assert styles == [E.tostring(x) for x in original.findall('.//CHARSHAPELIST') + original.findall('.//PARASHAPELIST')]
    assert geometry == [E.tostring(x.find('SHAPEOBJECT/SIZE')) for x in original.findall('.//PICTURE')]
    text = ''.join(original.itertext()).replace('\u200b', '')
    # Search editable text only, never base64-encoded pictures.
    chars = ''.join(x.text or '' for x in original.findall('.//CHAR')).replace('\u200b', '')
    assert not re.search(r'(?<![A-Za-z0-9])P[234](?=$|[^A-Za-z0-9])', chars)
    path = OUT / (kind + '_I123.hml')
    tree.write(str(path), xml_declaration=True, encoding='UTF-8', pretty_print=False)
    return path, dict(text_nodes_updated=changes, pictures_updated=len(replacements),
                      picture_geometry_preserved=True, font_and_paragraph_styles_preserved=True)


def main():
    helper = runpy.run_path(str(ROOT / '.tools/replace_manual_with_form.py'))
    hwp = helper['via_pywin32']()
    audit = {}
    for kind in ['design', 'manual']:
        path, entry = revise(kind)
        assert hwp.Open(str(path), 'HWPML2X', 'forceopen:true')
        hwp_path = OUT / (kind + '_I123.hwp')
        pdf_path = OUT / (kind + '_I123.pdf')
        assert hwp.SaveAs(str(hwp_path), 'HWP', '')
        entry['pages'] = hwp.PageCount
        assert hwp.SaveAs(str(pdf_path), 'PDF', '')
        entry['hwp_sha256'] = hashlib.sha256(hwp_path.read_bytes()).hexdigest()
        audit[kind] = entry
        print(kind, entry, flush=True)
    (OUT / 'document_build_audit.json').write_text(json.dumps(audit, ensure_ascii=False, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
