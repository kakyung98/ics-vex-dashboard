#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the 1-page Word (.docx) test-procedure doc for 시험항목 #3.

Four sections only: 시험도구 / 절차 / 전제조건 / 검증 데이터셋. Fits one A4 page.
"""
import os
from docx import Document
from docx.shared import Pt, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "docs", "시험절차서_시험항목3_SBOM식별정밀도.docx")
KFONT, MONO, HDR_FILL = "Malgun Gothic", "Consolas", "1F4E79"
HDR_TXT = RGBColor(0xFF, 0xFF, 0xFF)


def _kf(run, size=None, bold=None, color=None, mono=False):
    fn = MONO if mono else KFONT
    run.font.name = fn
    rpr = run._element.get_or_add_rPr()
    rf = rpr.find(qn('w:rFonts'))
    if rf is None:
        rf = OxmlElement('w:rFonts'); rpr.append(rf)
    for aa in ('w:ascii', 'w:hAnsi', 'w:eastAsia', 'w:cs'):
        rf.set(qn(aa), fn)
    if size is not None:
        run.font.size = Pt(size)
    if bold is not None:
        run.font.bold = bold
    if color is not None:
        run.font.color.rgb = color


def _shade(cell, fill):
    tcpr = cell._tc.get_or_add_tcPr()
    sh = OxmlElement('w:shd')
    sh.set(qn('w:val'), 'clear'); sh.set(qn('w:color'), 'auto'); sh.set(qn('w:fill'), fill)
    tcpr.append(sh)


def _tight(p, before=0, after=2):
    pf = p.paragraph_format
    pf.space_before = Pt(before); pf.space_after = Pt(after); pf.line_spacing = 1.0


def h(doc, t):
    p = doc.add_paragraph(); _tight(p, before=4, after=2)
    _kf(p.add_run(t), size=10.5, bold=True, color=RGBColor(0x1F, 0x4E, 0x79))


def para(doc, t, size=9, bold=False):
    p = doc.add_paragraph(); _tight(p); _kf(p.add_run(t), size=size, bold=bold)


def code(doc, t):
    p = doc.add_paragraph(); _tight(p, before=1, after=3)
    p.paragraph_format.left_indent = Cm(0.3)
    for i, line in enumerate(t.split("\n")):
        if i:
            p.add_run().add_break()
        _kf(p.add_run(line), size=8.5, mono=True)
    ppr = p._p.get_or_add_pPr()
    sh = OxmlElement('w:shd'); sh.set(qn('w:val'), 'clear'); sh.set(qn('w:color'), 'auto'); sh.set(qn('w:fill'), 'F2F2F2')
    ppr.append(sh)


def table(doc, rows, widths):
    t = doc.add_table(rows=0, cols=len(rows[0])); t.style = 'Table Grid'
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for ri, row in enumerate(rows):
        cells = t.add_row().cells
        for ci, val in enumerate(row):
            cells[ci].width = Cm(widths[ci]); cells[ci].text = ""
            p = cells[ci].paragraphs[0]; _tight(p)
            hd = ri == 0
            _kf(p.add_run(str(val)), size=8.5, bold=hd, color=(HDR_TXT if hd else None))
            if hd:
                _shade(cells[ci], HDR_FILL)


def main():
    doc = Document()
    s = doc.sections[0]
    s.top_margin = s.bottom_margin = Cm(1.6); s.left_margin = s.right_margin = Cm(1.8)
    st = doc.styles['Normal']; st.font.name = KFONT; st.font.size = Pt(9)
    st.element.rPr.rFonts.set(qn('w:eastAsia'), KFONT)

    tp = doc.add_paragraph(); tp.alignment = WD_ALIGN_PARAGRAPH.CENTER; _tight(tp, after=1)
    _kf(tp.add_run("시험절차서 — 시험항목 #3: SBOM 기반 공개 취약점 정보 식별 정밀도"),
        size=14, bold=True, color=RGBColor(0x1F, 0x4E, 0x79))
    mp = doc.add_paragraph(); mp.alignment = WD_ALIGN_PARAGRAPH.CENTER; _tight(mp, after=3)
    _kf(mp.add_run("대상: ICS-VEX(ICS-VEXForge) · 알고리즘 Ratcliff–Obershelp 문자열 유사도(difflib) · 정밀도 = TP/(TP+FP)×100 · 합격기준 ≥ 95%"),
        size=8.5, color=RGBColor(0x50, 0x50, 0x50))

    # 1. 시험도구
    h(doc, "1. 시험 도구")
    table(doc, [
        ["도구", "역할"],
        ["SUT 매칭 엔진",
         "api_server.vex_compare_sbom / _ro_best_match — SBOM 컴포넌트명을 KB에 Ratcliff–Obershelp 유사도(difflib SequenceMatcher.ratio, 임계값 0.7)로 정규화하고 매칭된 CPE에서 CVE를 재식별."],
        ["tools/eval_cpe_match_precision.py",
         "위 매칭을 구동해 식별 CVE를 라벨(정답)과 대조, precision=TP/(TP+FP)×100 산출·기록(결과 results/cpe_match_precision.json). 알고리즘은 결정적(난수 없음)."],
        ["참고", "대시보드 'CPE normalization — exact vs Ratcliff–Obershelp' 화면 및 tools/compare_cisa_csaf.py(ICSA 단위 대조)."],
    ], [4.4, 12.6])
    para(doc, "· TP: 매칭된 CPE 제품이 정답과 일치하고 식별 CVE가 정답 CVE와 완전 일치.  · FP: 버전/에디션 불일치 또는 잘못된 제품 매핑.")

    # 2. 절차
    h(doc, "2. 시험 절차")
    para(doc, "① 전제조건(제3항) 확인 → ② 라벨 데이터셋 준비(제4항) → ③ 아래 명령 실행 → ④ 결과 JSON 수집 → ⑤ precision ≥ 95% 이면 합격(PASS).")
    code(doc, "python tools/eval_cpe_match_precision.py --data data/cpe_match_eval.jsonl --threshold 0.7")
    para(doc, "· --threshold: Ratcliff–Obershelp 정규화 임계값(기본 0.7).  · 결과: results/cpe_match_precision.json(TP·FP·precision_pct·pass).")

    # 3. 전제조건
    h(doc, "3. 시험을 위한 전제조건")
    para(doc, "① 컴포넌트 지식베이스(KB, results/cve_kb.json — CPE 제품·버전·CVE) 적재. SUT는 이 KB에 대해 매칭·재식별을 수행.")
    para(doc, "② 라벨 데이터셋(제4항)이 준비되어 있음. '영향 있음(affected)' 여부는 고려하지 않으며, 식별 CVE가 항목과 정확히 일치하는지만 판정.")
    para(doc, "③ 결정성: Ratcliff–Obershelp(difflib)는 난수가 없고 임계값(0.7)이 고정되어, 동일 입력에 항상 동일 결과.")
    para(doc, "④ 버전/에디션 비교 가능: 정답 CVE는 CPE 제품·버전 기준으로 라벨링되어 버전/에디션 불일치를 FP로 판별 가능.")

    # 4. 검증 데이터셋
    h(doc, "4. 성능평가결과 검증을 위한 데이터셋")
    para(doc, "라벨(정답)은 실제 SBOM에 나타나는 컴포넌트 표기와 그에 대한 권위 있는 CPE 제품·CVE 매핑이다. 권위 출처는 CISA CSAF(cisagov/CSAF)의 제품↔CVE 정보로, tools/compare_cisa_csaf.py가 사용하는 것과 동일하다.")
    para(doc, "형식(JSONL, data/cpe_match_eval.jsonl):", bold=True)
    code(doc, '{"component":"OpenSSL","version":"1.0.2","correct_cpe_product":"openssl",\n "correct_cves":["CVE-2016-2107", "..."]}')
    table(doc, [
        ["구분", "값"],
        ["항목(레코드)", "실제 SBOM 컴포넌트 표기 + 정답 CPE 제품 + 정답 CVE 목록(버전/에디션 포함)"],
        ["정답 출처", "CISA CSAF 제품↔CVE 권위 매핑(cisagov/CSAF), NVD CPE 사전"],
        ["TP 판정", "매칭된 CPE 제품 = 정답 제품 AND 식별 CVE ∈ 정답 CVE"],
        ["FP 판정", "매칭된 CPE 제품/버전 ≠ 정답(버전·에디션 불일치 또는 잘못된 제품 매핑)"],
    ], [3.4, 13.6])
    para(doc, "※ 데이터셋은 대상 컴포넌트 군을 대표하도록 구성한다. 임계값 0.7은 SUT 기본값이며, 필요 시 절차의 --threshold 로 명시한다.", size=8)

    doc.save(OUT)
    print("saved:", OUT)


if __name__ == "__main__":
    main()
