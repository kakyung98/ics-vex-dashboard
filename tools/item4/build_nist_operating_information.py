"""Render NIST Rev.4 IPD tables 12–17 without changing assessment templates.

The 167-element project mapping is deliberately not reconstructed from a count.
Pass --mapping only with the original reviewed mapping JSON, containing one
entry per source row and its collection elements with exact source excerpts.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import argparse
from collections import Counter
from hashlib import sha256
from html import escape
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PDF_SHA256 = '66e00d5c8dbbfaf0342890e75d2492f72e1ef34da81df5c6a94cc339bd91f683'
URL = 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r4.ipd.pdf'
TABLES = {
    12: ('Architecture and design', 11),
    13: ('Configuration and maintenance', 21),
    14: ('Physical', 5),
    15: ('Software development', 3),
    16: ('Communication and network', 11),
    17: ('Sensors, final elements, and asset management', 3),
}


def normalize(text):
    return ' '.join(text.split())


def extract(pdf):
    import pymupdf
    if sha256(pdf.read_bytes()).hexdigest() != PDF_SHA256:
        raise ValueError('PDF differs from the pinned September 2026 Rev.4 IPD')
    doc = pymupdf.open(pdf)
    page_tables = {187: [12], 188: [12], 189: [13], 190: [13],
                   191: [13, 14], 192: [15, 16], 193: [16, 17]}
    rows = []
    for page_index, numbers in page_tables.items():
        tables = doc[page_index].find_tables().tables
        assert len(tables) == len(numbers)
        for number, table in zip(numbers, tables):
            cells = table.extract()
            assert cells[0] == ['Vulnerability', 'Description']
            for title, description in cells[1:]:
                row_no = 1 + sum(r['table'] == number for r in rows)
                row = dict(id=f'T{number}-{row_no:02}', table=number,
                           title=normalize(title), description=normalize(description),
                           printed_page=page_index + 1 - 18, pdf_page=page_index + 1,
                           url=f'{URL}#page={page_index + 1}', collection_elements=[])
                # Verify both cells against the page text independently of table extraction.
                page_text = normalize(doc[page_index].get_text())
                assert row['title'] in page_text, row['id']
                assert row['description'] in page_text, row['id']
                row['quote_sha256'] = sha256(row['description'].encode()).hexdigest()
                rows.append(row)
    assert Counter(r['table'] for r in rows) == Counter({k: v[1] for k, v in TABLES.items()})
    return rows


def load_mapping(rows, path):
    mapping = json.loads(path.read_text(encoding='utf-8'))
    apply_mapping(rows, mapping)


def parse_markdown(path):
    """Read the supplied v0.4 content as data, preserving every traceability ID."""
    text = path.read_text(encoding='utf-8-sig')
    content = text.split('## 3. ', 1)[1].split('\n## 4.', 1)[0]
    mapping = {}
    for match in re.finditer(r'^### (C\d{2}-\d{2}) · ([^\n]+)\n(.*?)(?=^### |\Z)', content, re.M | re.S):
        identity, label, body = match.groups()
        quotes = re.findall(r'^> (.+)$', body, re.M)
        assert len(quotes) == 2, identity
        location = re.search(r'Table (\d+), 인쇄 p\.(\d+), PDF p\.(\d+)', body)
        assert location, identity
        category = re.search(r'^- 활용 구분\(연구자 분류\): (.+)$', body, re.M)
        assert category, identity
        elements = []
        for line in body.splitlines():
            if not line.startswith('| ' + identity + '.'):
                continue
            cells = [cell.strip() for cell in line.strip().strip('|').split('|')]
            assert len(cells) == 5, (identity, cells)
            detail_id, detail_label, excerpt, column, note = cells
            assert excerpt.startswith('“') and excerpt.endswith('”'), detail_id
            assert column in {'Vulnerability', 'Description'}, detail_id
            elements.append(dict(id=detail_id, label=detail_label, quote=excerpt[1:-1],
                                 source_column=column, interpretation_note=note))
        key = 'T' + identity[1:]
        assert key not in mapping
        mapping[key] = dict(source_id=identity, label=label.strip(),
                            title=quotes[0], description=quotes[1],
                            table=int(location[1]), printed_page=int(location[2]),
                            pdf_page=int(location[3]), category=category[1], elements=elements)
    return mapping


def apply_mapping(rows, mapping):
    assert set(mapping) == {r['id'] for r in rows}
    assert sum(len(m['elements']) for m in mapping.values()) == 167
    identities = []
    for row in rows:
        item = mapping[row['id']]
        for key in ['title', 'description', 'table', 'printed_page', 'pdf_page']:
            assert item[key] == row[key], (row['id'], key)
        row['label'] = item['label']
        row['source_id'] = item['source_id']
        row['category'] = item['category']
        for index, element in enumerate(item['elements'], 1):
            assert element['label'] and element['quote']
            assert element['id'] == f'{item["source_id"]}.{index:02}', element['id']
            identities.append(element['id'])
            source = row['title'] if element['source_column'] == 'Vulnerability' else row['description']
            assert normalize(element['quote']) in source, element['id']
            assert element['interpretation_note'], element['id']
        row['collection_elements'] = item['elements']
    assert len(identities) == len(set(identities)) == 167


def render(rows):
    e = escape
    elements = sum(len(r['collection_elements']) for r in rows)
    parts = ['''<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NIST asset operational information · Source evidence</title>
<style>
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#f6f5f9;color:#292138;font:16px/1.65 system-ui,sans-serif}main{max-width:1180px;margin:auto;padding:32px 24px 80px}a{color:#634398}header,section{background:#fff;border:1px solid #e5dfed;border-radius:16px;padding:24px;margin:18px 0}h1{font-size:clamp(26px,4vw,40px);line-height:1.2}h2{font-size:23px}h3{font-size:19px;line-height:1.5}.muted{color:#625b70}.notice{padding:16px;background:#f7f1de;border-left:4px solid #ac791d}.counts,.toolbar,nav{display:flex;gap:12px;flex-wrap:wrap;align-items:center}.counts span{padding:10px 18px;border-radius:10px;background:#f0ebf8}.source-row{padding:24px 0;border-top:1px solid #e4dfec;scroll-margin-top:20px}blockquote{margin:12px 0;padding:16px 20px;border-left:3px solid #a695cd;background:#f6f4fa;overflow-wrap:anywhere}label{display:block}input,select,button{font:inherit;padding:10px;border:1px solid #c6bdd4;border-radius:8px;background:#fff;color:inherit}input{width:min(450px,100%)}button{cursor:pointer}code{overflow-wrap:anywhere}table{border-collapse:collapse;width:100%}td,th{padding:12px;text-align:left;border-bottom:1px solid #ddd;vertical-align:top}.table-wrap{overflow:auto}[hidden]{display:none!important}li{margin-bottom:12px}@media(max-width:600px){main{padding:16px 12px}section,header{padding:16px}.source-row{padding:18px 0}.toolbar{align-items:stretch;flex-direction:column}input,select{width:100%}}@media print{.toolbar,.back{display:none}body{background:#fff}section,header{border:0;padding:0}blockquote{break-inside:avoid}}
</style></head><body><main><header>
<nav class="back"><a href="/bom-vex.html">← Operational VEX</a><a href="/operating-profile-derivation.en.html#profile-derivation">Asset profile derivation</a></nav>
<p class="muted">NIST SP 800-82 Rev.4 · September 2026 Initial Public Draft</p>
<h1>NIST asset operational information and English source evidence</h1>
<p>Tables 12–17: every original vulnerability/predisposing-condition row, with its full English description, table number, and printed/PDF page. All source rows, collection information, and quotations are expanded by default.</p>
''', f'<div class="counts"><span><strong>{len(rows)}</strong> original source rows</span><span><strong>{elements}</strong> collection elements loaded</span><span><strong>6</strong> source tables</span></div>']
    if not elements:
        parts.append('<p class="notice"><strong>167-element project mapping: original document required.</strong> The referenced ICS_OT_profiles_v0_1.md (v0.4) is not present in the supplied project path. Its 167 collection elements are not prescribed by NIST and cannot be recovered from the number alone. The complete 54-row English source catalogue is available below; the project mapping is pending.</p>')
    if elements:
        parts.append('<p class="notice"><strong>54개 원문 항목 · 167개 세부 수집정보 · 영어 원문 근거 전체</strong><br>첨부 명세 v0.4의 C항목·세부 ID, 한국어 수집정보, 영어 발췌, 원문 열, 해석상 주의를 모두 보존했습니다. 한국어 수집정보는 연구자의 재서술이며 NIST 공식 필드가 아닙니다. 원문과 발췌의 일치는 확인했으나 도출 타당성에 대한 독립 전문가 검증은 별도입니다.</p>')
    parts.append(f'<p>One original table row counts as one item. Collection elements are project interpretations and may overlap; they are not 167 independent mandatory answers. This catalogue does not establish a CVE prerequisite or VEX verdict.</p><p><a href="{URL}" target="_blank" rel="noopener">Open the NIST source PDF ↗</a></p></header>')
    parts.append('<section aria-labelledby="catalog-summary"><h2 id="catalog-summary">Source table inventory</h2><div class="table-wrap"><table><thead><tr><th>Table</th><th>Subject</th><th>Source rows</th><th>Collection elements loaded</th></tr></thead><tbody>')
    for number, (title, count) in TABLES.items():
        total = sum(len(r['collection_elements']) for r in rows if r['table'] == number)
        parts.append(f'<tr><td><a href="#table-{number}">Table {number}</a></td><td>{e(title)}</td><td>{count}</td><td>{total}</td></tr>')
    parts.append('''</tbody></table></div></section><section><h2>Browse all source rows</h2>
<div class="toolbar"><label>Search titles, English evidence, and collection information<br><input id="catalog-search" type="search" placeholder="e.g. firewall, password, cloud"></label><label>Source table<br><select id="catalog-table"><option value="all">All six tables</option>''')
    for number, (title, _) in TABLES.items():
        parts.append(f'<option value="{number}">Table {number} · {e(title)}</option>')
    parts.append('</select></label><button id="catalog-reset" type="button">Show all</button></div><p id="catalog-results" role="status" aria-live="polite">54 of 54 source rows displayed.</p></section><div id="catalog-rows">')
    for number, (title, _) in TABLES.items():
        parts.append(f'<section class="source-table" id="table-{number}" data-table="{number}"><h2>Table {number} · {e(title)}</h2>')
        for row in (r for r in rows if r['table'] == number):
            source_id = row.get('source_id', row['id'])
            parts.append(f'<article class="source-row" id="{row["id"]}"><span id="{source_id}"></span><p class="muted">{source_id} · Table {number} · Printed p. {row["printed_page"]} / PDF p. {row["pdf_page"]}</p><h3>{e(row.get("label", row["title"]))}</h3>')
            if row.get('category'):
                parts.append(f'<p class="muted">활용 구분(연구자 분류): {e(row["category"])}</p>')
            if row.get('label'):
                parts.append(f'<p lang="en"><strong>English source title:</strong> {e(row["title"])}</p>')
            parts.append(f'<p><a href="{row["url"]}" target="_blank" rel="noopener">NIST original · Table {number} · PDF p. {row["pdf_page"]} ↗</a> · <a href="#{row["id"]}">Permanent row link</a></p><h4>Full English source description</h4><blockquote lang="en">{e(row["description"])}</blockquote>')
            if row['collection_elements']:
                parts.append(f'<h4>세부 수집정보와 영어 근거 · {len(row["collection_elements"])}개</h4><ol>')
                for element in row['collection_elements']:
                    parts.append(f'<li class="collection-element" id="{e(element["id"])}"><p><a href="#{e(element["id"])}"><code>{e(element["id"])}</code></a> · <strong>{e(element["label"])}</strong></p><p class="muted">원문 열: {e(element["source_column"])} · <a href="{row["url"]}" target="_blank" rel="noopener">Table {number} · 인쇄 p.{row["printed_page"]} / PDF p.{row["pdf_page"]} ↗</a></p><blockquote lang="en">{e(element["quote"])}</blockquote><p class="interpretation-note">해석상 주의: {e(element["interpretation_note"])}</p></li>')
                parts.append('</ol>')
            parts.append('</article>')
        parts.append('</section>')
    parts.append('''</div><p class="muted">Source: NIST SP 800-82 Rev.4 IPD. Line wrapping is normalized; English wording is preserved. The original PDF remains authoritative.</p></main>
<script>(()=>{'use strict';const q=document.getElementById('catalog-search'),t=document.getElementById('catalog-table'),rows=[...document.querySelectorAll('.source-row')];function filter(){const s=q.value.trim().toLocaleLowerCase();let count=0,details=0;for(const r of rows){r.hidden=!((t.value==='all'||r.closest('.source-table').dataset.table===t.value)&&(!s||r.textContent.toLocaleLowerCase().includes(s)));if(!r.hidden){count++;details+=r.querySelectorAll('.collection-element').length}}for(const section of document.querySelectorAll('.source-table'))section.hidden=![...section.querySelectorAll('.source-row')].some(r=>!r.hidden);document.getElementById('catalog-results').textContent=count+' of '+rows.length+' source rows displayed · '+details+' collection elements.'+(count?'':' No matching source rows.')}q.addEventListener('input',filter);t.addEventListener('change',filter);document.getElementById('catalog-reset').onclick=()=>{q.value='';t.value='all';filter()};filter();})();</script></body></html>''')
    return ''.join(parts)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pdf', type=Path, required=True)
    parser.add_argument('--mapping', type=Path)
    parser.add_argument('--markdown', type=Path)
    parser.add_argument('--output', type=Path, default=ROOT/'site/nist-operating-information.html')
    args = parser.parse_args()
    rows = extract(args.pdf)
    if args.mapping:
        load_mapping(rows, args.mapping)
    if args.markdown:
        if args.mapping:
            raise ValueError('Choose either --mapping or --markdown')
        apply_mapping(rows, parse_markdown(args.markdown))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(rows), encoding='utf-8')
    args.output.with_suffix('.json').write_text(json.dumps(dict(
        source_document='NIST SP 800-82 Rev.4 IPD (September 2026)',
        source_url=URL, pdf_sha256=PDF_SHA256, source_rows=len(rows),
        mapping_status='loaded' if args.mapping or args.markdown else 'original_document_missing',
        mapping_document_sha256=sha256(args.markdown.read_bytes()).hexdigest() if args.markdown else None,
        collection_elements=sum(len(r['collection_elements']) for r in rows), rows=rows),
        ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(dict(source_rows=len(rows), collection_elements=sum(len(r['collection_elements']) for r in rows), output=str(args.output))))


if __name__ == '__main__':
    main()
