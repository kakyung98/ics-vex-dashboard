"""Append the versioned rule-evaluation/schema chapter to a backed-up design PDF."""
from pathlib import Path
import hashlib
import json
import shutil
import re
import markdown
import pymupdf as fitz

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'artifacts/item4_rule_evaluation_v1'
ARCHIVE=ROOT/'docs/archive/item4_rule_evaluation_20261123'
CSS='''
@font-face {font-family: Malgun; src: url(malgun.ttf);}
body {font-family:Malgun; font-size:10pt; line-height:1.5; color:#17202a;}
h1 {font-size:18pt;line-height:1.4;color:#000;margin-bottom:18pt;}
h2 {font-size:15pt;line-height:1.4;color:#000;margin:0 0 14pt;}
h3 {font-size:11.5pt;color:#000;margin-top:16pt;}
p {margin:0 0 10pt;}
table {width:100%;border-collapse:collapse;margin:9pt 0 13pt;font-size:9pt;}
td,th {border:0.6pt solid #cbd1d8;padding:6pt 6pt;vertical-align:middle;}
th {background:#e6edf5;color:#000;}
code {font-family:Malgun;font-size:9pt;}
'''


def main():
    OUT.mkdir(parents=True,exist_ok=True);ARCHIVE.mkdir(parents=True,exist_ok=True)
    original=next(ROOT.glob('*시스템 설계서.pdf'))
    backup=ARCHIVE/'design_before_rule_evaluation.pdf'
    if not backup.exists():shutil.copy2(original,backup)
    text=(ROOT/'docs/ITEM4_RULE_EVALUATION_DESIGN.md').read_text(encoding='utf-8')
    # One major section per starting page; long sections flow onto continuation pages.
    sections=re.split(r'(?m)(?=^## [0-9]|^### 6\.1)',text)
    sections=[sections[0]+sections[1],*sections[2:]]
    appendix=OUT/'Item4_Rules_and_Data_Schemas.pdf'
    writer=fitz.DocumentWriter(str(appendix))
    for section in sections:
        html=markdown.markdown(section,extensions=['tables'])
        # Break long identifiers at semantic separators while preserving readable words.
        html=html.replace('_','_\u200b').replace('scope_id','scope_\u200bid')
        story=fitz.Story(html=html,user_css=CSS,archive=fitz.Archive('C:/Windows/Fonts'))
        more=1
        while more:
            device=writer.begin_page(fitz.Rect(0,0,595,842))
            more,_=story.place(fitz.Rect(44,46,551,790));story.draw(device);writer.end_page()
    writer.close()
    doc=fitz.open(appendix)
    for i,page in enumerate(doc):
        page.insert_text((44,819),f'ICS-VEX | #4 rule evaluation v1 | appendix {i+1}/{len(doc)}',fontsize=8,color=(.35,.35,.35))
    paginated=OUT/'appendix_paginated.pdf';doc.save(paginated);doc.close()
    shutil.move(str(paginated),appendix)
    merged=fitz.open(backup);before=len(merged);addition=fitz.open(appendix);merged.insert_pdf(addition)
    toc=merged.get_toc();toc.append([1,'#4 독립 규칙 엔진 및 데이터 스키마 개정',before+1]);merged.set_toc(toc)
    revised=OUT/'ICS_VEX_Design_Revised.pdf';merged.save(revised,garbage=4,deflate=True);merged.close();addition.close()
    # Verify before replacing the user's PDF, and retain native HWP unchanged.
    check=fitz.open(revised)
    assert len(check)>before and 'item4-rule-evaluation' in ''.join(p.get_text() for p in list(check)[before:])
    for i in range(before,len(check)):
        check[i].get_pixmap(matrix=fitz.Matrix(1.3,1.3)).save(OUT/f'qa-appendix-{i-before+1:02}.png')
    manifest=dict(original_pages=before,appendix_pages=len(check)-before,revised_pages=len(check),
        original_sha256=hashlib.sha256(backup.read_bytes()).hexdigest(),
        revised_sha256=hashlib.sha256(revised.read_bytes()).hexdigest(),
        native_hwp_updated=False,native_hwp_reason='Hancom automation object unavailable in this execution session',
        editable_schema_source='docs/ITEM4_RULE_EVALUATION_DESIGN.md')
    check.close();shutil.copy2(revised,original)
    (OUT/'document_build.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(manifest,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
