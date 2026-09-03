#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the 1-page Word (.docx) test-procedure doc for 시험항목 #4.

Only four sections, per request: 시험도구 / 절차 / 전제조건 / 검증 데이터셋.
Compact layout to fit within a single A4 page. python-docx (no pandoc/soffice).
"""
import os
from docx import Document
from docx.shared import Pt, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "docs", "시험절차서_시험항목4_VEX정밀도.docx")
KFONT, MONO, HDR_FILL = "Malgun Gothic", "Consolas", "1F4E79"
HDR_TXT = RGBColor(0xFF, 0xFF, 0xFF)


def _kf(run, name=KFONT, size=None, bold=None, color=None, mono=False):
    fn = MONO if mono else name
    run.font.name = fn
    rpr = run._element.get_or_add_rPr()
    rf = rpr.find(qn('w:rFonts'))
    if rf is None:
        rf = OxmlElement('w:rFonts'); rpr.append(rf)
    for a in ('w:ascii', 'w:hAnsi', 'w:eastAsia', 'w:cs'):
        rf.set(qn(a), fn)
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


def h(doc, text):
    p = doc.add_paragraph(); _tight(p, before=4, after=2)
    _kf(p.add_run(text), size=10.5, bold=True, color=RGBColor(0x1F, 0x4E, 0x79))
    return p


def para(doc, text, size=9, bold=False, mono=False):
    p = doc.add_paragraph(); _tight(p)
    _kf(p.add_run(text), size=size, bold=bold, mono=mono)
    return p


def code(doc, text):
    p = doc.add_paragraph(); _tight(p, before=1, after=3)
    p.paragraph_format.left_indent = Cm(0.3)
    for i, line in enumerate(text.split("\n")):
        if i:
            p.add_run().add_break()
        _kf(p.add_run(line), size=8.5, mono=True)
    ppr = p._p.get_or_add_pPr()
    sh = OxmlElement('w:shd'); sh.set(qn('w:val'), 'clear'); sh.set(qn('w:color'), 'auto'); sh.set(qn('w:fill'), 'F2F2F2')
    ppr.append(sh)
    return p


def table(doc, rows, widths):
    t = doc.add_table(rows=0, cols=len(rows[0]))
    t.style = 'Table Grid'; t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for ri, row in enumerate(rows):
        cells = t.add_row().cells
        for ci, val in enumerate(row):
            cells[ci].width = Cm(widths[ci])
            cells[ci].text = ""
            p = cells[ci].paragraphs[0]; _tight(p)
            ishdr = ri == 0
            _kf(p.add_run(str(val)), size=8.5, bold=ishdr, color=(HDR_TXT if ishdr else None))
            if ishdr:
                _shade(cells[ci], HDR_FILL)
    return t


def main():
    doc = Document()
    sec = doc.sections[0]
    sec.top_margin = sec.bottom_margin = Cm(1.6)
    sec.left_margin = sec.right_margin = Cm(1.8)
    st = doc.styles['Normal']; st.font.name = KFONT; st.font.size = Pt(9)
    st.element.rPr.rFonts.set(qn('w:eastAsia'), KFONT)

    # header
    tp = doc.add_paragraph(); tp.alignment = WD_ALIGN_PARAGRAPH.CENTER; _tight(tp, after=1)
    _kf(tp.add_run("시험절차서 — 시험항목 #4: VEX 기반 식별된 취약점 영향 판단 정밀도"),
        size=14, bold=True, color=RGBColor(0x1F, 0x4E, 0x79))
    mp = doc.add_paragraph(); mp.alignment = WD_ALIGN_PARAGRAPH.CENTER; _tight(mp, after=3)
    _kf(mp.add_run("대상: ICS-VEX(ICS-VEXForge) · 성능지표 정밀도(Precision) = TP/(TP+FP)×100 · 합격기준 ≥ 95%"),
        size=8.5, color=RGBColor(0x50, 0x50, 0x50))

    # 1. 시험도구
    h(doc, "1. 시험 도구")
    table(doc, [
        ["도구", "역할"],
        ["tools/eval_affected_precision.py",
         "affected 자동분류에 대해 TP/FP를 집계하고 precision=TP/(TP+FP)×100 산출·기록(결정적 greedy 디코딩, 시드 고정). 결과는 results/affected_precision.json."],
        ["평가 대상 모델",
         "취약 코드 존재 판단 모델(sLLM): Qwen2.5-Coder-7B-Instruct + QLoRA(models/vex-justifier-lora/, commit 2f729d03)."],
    ], [4.6, 12.4])
    para(doc, "· TP: affected로 분류했고 정답(취약 버전=미패치)에서도 영향받음.  · FP: affected로 분류했으나 정답(패치/안전)에서 영향 없음.")
    para(doc, "· 파싱 불가·not_affected는 분모(TP+FP)에서 제외. 재현율·F1은 합격 판정 대상이 아니다.")

    # 2. 절차
    h(doc, "2. 시험 절차")
    para(doc, "① 전제조건(제3항) 충족 확인 → ② 아래 명령 실행 → ③ 표준출력·결과 JSON 수집 → ④ precision 산출 → ⑤ ≥95% 이면 합격(PASS).")
    code(doc, 'POC_BASE_MODEL="Qwen/Qwen2.5-Coder-7B-Instruct" SEED=20260416 SUBSAMPLE=12000 \\\n  python tools/eval_affected_precision.py --clean --n 1200')
    para(doc, "· --clean: fix-commit 뒷받침 패치쌍 정답만 사용.  · --n: 평가 표본 수(전수 평가는 --n 3471).")
    para(doc, "· (옵션) --abstain: 5회 샘플 만장일치일 때만 affected 발행, 애매하면 보류 → 정밀도 보강.")

    # 3. 전제조건
    h(doc, "3. 시험을 위한 전제조건")
    para(doc, "① 학습된 QLoRA 어댑터(models/vex-justifier-lora/) 존재 — 본 시험은 추론만 수행(재학습 없음).")
    para(doc, "② 데이터 누출 방지: 평가는 학습에 쓰이지 않은 held-out 행만 사용. 학습·평가가 동일 셔플 시드(SEED=20260416)와 동일 학습 표본 크기(SUBSAMPLE=12000)를 써 학습 rows[:12000]과 평가 rows[12000:]이 서로소임을 보장.")
    para(doc, "③ 결정성: greedy 디코딩(do_sample=False) + 표본추출 시드 고정(random.Random(7)) → 동일 입력에 동일 결과.")
    para(doc, "④ 데이터셋 data/vex_train_full.jsonl이 제4항 형상(행 수·출처·클래스 분포)과 일치.")

    # 4. 검증 데이터셋
    h(doc, "4. 성능평가결과 검증을 위한 데이터셋")
    para(doc, "정답(그라운드 트루스)은 fix-commit(패치 커밋)으로 뒷받침되는 취약/패치 코드 쌍 — 취약 버전 함수→affected, 패치 버전 함수→not_affected. 시험 기준의 TP 정의('소스코드 패치 여부가 CVE 영향 조건과 일치')에 직접 부합.")
    table(doc, [
        ["구분", "값"],
        ["평가 표본", "data/vex_train_full.jsonl의 held-out(rows[12000:]) 중 패치쌍 출처만(--clean)"],
        ["규모", "held-out ∩ 패치쌍 = 3,471행 (affected 2,124 / not_affected 1,347)"],
        ["출처", "CVEfixes(PROMISE'21) 2,119 · BigVul(MSR'20) 1,352 · project seed 소수"],
        ["누출 없음", "정답은 학습 표본과 서로소인 held-out에서만 취함. 모델 입력(함수 코드)과 분리된 필드로 사후 대조(모델에 정답 미제공)"],
    ], [3.2, 13.8])
    para(doc, "※ 원 코드 표본은 각 출처 라이선스를 따름. 재구성 스크립트: tools/build_vexc_dataset.py, tools/collect_vulnfix_dataset.py.", size=8)

    doc.save(OUT)
    print("saved:", OUT)


if __name__ == "__main__":
    main()
