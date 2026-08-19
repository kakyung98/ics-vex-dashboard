#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Self-contained CVE ground-truth analysis page (SVG charts, no external deps).

Reads data/findings.csv (+ data/vex_dataset.jsonl for evidence tiers) and writes
cve_analysis.html at the repo root -- deploys straight to GitHub Pages at
  https://kakyung98.github.io/ics-vex-dashboard/cve_analysis.html
Run:  python tools/build_cve_analysis.py
"""
import csv, json, os, collections, html

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
FIND = os.path.join(BASE, "data", "findings.csv")
DATASET = os.path.join(BASE, "data", "vex_dataset.jsonl")
OUT = os.path.join(BASE, "cve_analysis.html")

# Official CISA KEV count for this CVE set (findings.csv flags are incomplete).
KEV_LISTED = 149

# validated dark categorical palette (dataviz skill, dark column) ------------
BLUE, ORANGE, AQUA, YELLOW, MAGENTA, GREEN, VIOLET, RED = (
    "#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767")
SURFACE, INK, INK2, INK3, LINE = "#1a1a19", "#ffffff", "#c3c2b7", "#8b8a80", "#333330"

# ---------------------------------------------------------------------------
# Load + aggregate
# ---------------------------------------------------------------------------
rows = list(csv.DictReader(open(FIND, encoding="utf-8-sig")))
by_cve = {}
for r in rows:
    c = (r.get("cve") or "").strip()
    if c and c not in by_cve:
        by_cve[c] = r
U = list(by_cve.values())

n_cve = len(U)
n_dev = len({r["device"] for r in rows if r.get("device")})
n_vendor = len({r["vendor"] for r in rows if r.get("vendor")})
n_adv = len({r["source_advisory"] for r in rows if r.get("source_advisory")})

def count(key, src=U):
    return collections.Counter((r.get(key) or "").strip() for r in src)

# source availability (tier)
tier_c = count("tier")
SRC_AVAIL = [
    ("Closed vendor firmware", tier_c.get("E", 0), INK3),
    ("OSS, no source", tier_c.get("C", 0), BLUE),
    ("OSS, source available", tier_c.get("A", 0), AQUA),
]

# evidence tiers from pipeline (pair level)
ev = collections.Counter()
if os.path.exists(DATASET):
    for line in open(DATASET, encoding="utf-8"):
        try:
            ev[json.loads(line).get("evidence_tier")] += 1
        except Exception:
            pass
EVIDENCE = [
    ("execution-verified", ev.get("execution-verified", 0), AQUA),
    ("source-available-unverified", ev.get("source-available-unverified", 0), BLUE),
    ("source-pending", ev.get("source-pending", 0), VIOLET),
    ("source-unavailable", ev.get("source-unavailable", 0), INK3),
]
ev_total = sum(v for _, v, _ in EVIDENCE) or 1

# by year
yr = collections.Counter()
for c in by_cve:
    p = c.split("-")
    if len(p) == 3 and p[1].isdigit():
        yr[int(p[1])] += 1
YEARS = [(str(y), yr[y]) for y in sorted(yr) if y >= 2011]

# top CWE
cwe = count("cwe")
cwe.pop("", None)
CWE = cwe.most_common(12)

# attack vector
AV_LABEL = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
avc = count("av")
AV = [(AV_LABEL.get(k, k or "Unknown"), v) for k, v in avc.most_common() if k]

# severity (only scored)
sev = count("severity")
SEV = [("Critical", sev.get("critical", 0), RED), ("High", sev.get("high", 0), ORANGE),
       ("Medium", sev.get("medium", 0), YELLOW), ("Low", sev.get("low", 0), BLUE)]

# ---------------------------------------------------------------------------
# SVG helpers
# ---------------------------------------------------------------------------
def esc(s):
    return html.escape(str(s))

def hbars(data, unit="", w=440, rowh=30, pad_l=150, color=None):
    """data: list of (label, value[, color]). Horizontal bars."""
    mx = max((d[1] for d in data), default=1) or 1
    h = rowh * len(data) + 10
    bw = w - pad_l - 62
    out = [f'<svg viewBox="0 0 {w} {h}" width="100%" role="img">']
    for i, d in enumerate(data):
        lab, val = d[0], d[1]
        col = d[2] if len(d) > 2 else (color or BLUE)
        y = i * rowh + 6
        ln = max(2, bw * val / mx)
        out.append(f'<text x="{pad_l-8}" y="{y+13}" text-anchor="end" '
                   f'font-size="12" fill="{INK2}" font-family="monospace">{esc(lab)}</text>')
        out.append(f'<rect x="{pad_l}" y="{y+3}" width="{ln:.1f}" height="15" rx="4" fill="{col}">'
                   f'<title>{esc(lab)}: {val:,}{unit}</title></rect>')
        out.append(f'<text x="{pad_l+ln+6:.1f}" y="{y+15}" font-size="11.5" '
                   f'fill="{INK}" font-family="monospace">{val:,}</text>')
    out.append("</svg>")
    return "".join(out)

def vbars(data, w=560, h=210, color=BLUE):
    """data: list of (label, value). Vertical bars with baseline."""
    mx = max((v for _, v in data), default=1) or 1
    n = len(data)
    pad_b, pad_t = 26, 10
    bw = w / n
    barw = bw * 0.64
    ch = h - pad_b - pad_t
    out = [f'<svg viewBox="0 0 {w} {h}" width="100%" role="img">']
    for i, (lab, v) in enumerate(data):
        bh = max(1.5, ch * v / mx)
        x = i * bw + (bw - barw) / 2
        y = pad_t + ch - bh
        out.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{barw:.1f}" height="{bh:.1f}" rx="3" fill="{color}">'
                   f'<title>{esc(lab)}: {v:,}</title></rect>')
        if n <= 20 or i % 2 == 0:
            out.append(f'<text x="{x+barw/2:.1f}" y="{h-9}" text-anchor="middle" '
                       f'font-size="10" fill="{INK3}" font-family="monospace">{esc(lab)}</text>')
    out.append(f'<line x1="0" y1="{pad_t+ch:.1f}" x2="{w}" y2="{pad_t+ch:.1f}" stroke="{LINE}"/>')
    out.append("</svg>")
    return "".join(out)

def donut(data, size=200, thick=34):
    """data: list of (label, value, color). Returns (svg, legend_html)."""
    total = sum(d[1] for d in data) or 1
    r = (size - thick) / 2
    cx = cy = size / 2
    import math
    out = [f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" role="img">']
    ang = -math.pi / 2
    for lab, val, col in data:
        frac = val / total
        a2 = ang + frac * 2 * math.pi
        large = 1 if frac > 0.5 else 0
        x1, y1 = cx + r * math.cos(ang), cy + r * math.sin(ang)
        x2, y2 = cx + r * math.cos(a2), cy + r * math.sin(a2)
        out.append(f'<path d="M {x1:.2f} {y1:.2f} A {r:.2f} {r:.2f} 0 {large} 1 {x2:.2f} {y2:.2f}" '
                   f'fill="none" stroke="{col}" stroke-width="{thick}">'
                   f'<title>{esc(lab)}: {val:,} ({frac*100:.1f}%)</title></path>')
        ang = a2
    out.append(f'<text x="{cx}" y="{cy-4}" text-anchor="middle" font-size="22" '
               f'font-weight="700" fill="{INK}" font-family="monospace">{total:,}</text>')
    out.append(f'<text x="{cx}" y="{cy+15}" text-anchor="middle" font-size="11" fill="{INK3}">CVE</text>')
    out.append("</svg>")
    legend = ['<div class="legend">']
    for lab, val, col in data:
        legend.append(f'<div class="lg"><span class="sw" style="background:{col}"></span>'
                      f'<span>{esc(lab)}</span><b>{val:,}</b>'
                      f'<span class="pct">{val/total*100:.1f}%</span></div>')
    legend.append("</div>")
    return "".join(out), "".join(legend)

src_svg, src_leg = donut(SRC_AVAIL)
av_svg, av_leg = donut([(l, v, c) for (l, v), c in zip(AV, [BLUE, AQUA, YELLOW, MAGENTA])])

# evidence stacked bar
ev_seg = []
for lab, v, col in EVIDENCE:
    frac = v / ev_total
    ev_seg.append(f'<div class="evseg" style="width:{frac*100:.3f}%;background:{col}" '
                  f'title="{esc(lab)}: {v:,}"></div>')
ev_leg = "".join(
    f'<div class="lg"><span class="sw" style="background:{c}"></span><span>{esc(l)}</span>'
    f'<b>{v:,}</b></div>' for l, v, c in EVIDENCE)

kpis = [
    (f"{n_cve:,}", "Unique CVEs", "after dedup"),
    (f"{n_adv:,}", "CISA advisories", ""),
    (f"{n_dev:,}", "ICS assets", f"{n_vendor} vendors"),
    (f"{SRC_AVAIL[2][1]:,}", "Source available", "PoC-triggerable"),
    (f"{ev.get('execution-verified',0):,}", "Execution-verified", "true ground truth"),
    (f"{KEV_LISTED:,}", "KEV-listed", "known exploited"),
]
kpi_html = "".join(
    f'<div class="kpi"><div class="kv">{v}</div><div class="kl">{esc(l)}</div>'
    f'<div class="ks">{esc(s)}</div></div>' for v, l, s in kpis)

# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------
HTML = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ICS-VEX &middot; CVE Ground Truth Analysis</title>
<style>
 :root{{--bg:{SURFACE};--card:#232320;--ink:{INK};--ink2:{INK2};--ink3:{INK3};--line:{LINE};--acc:{BLUE}}}
 *{{box-sizing:border-box}}
 body{{margin:0;background:var(--bg);color:var(--ink);
   font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;line-height:1.55}}
 .wrap{{max-width:1080px;margin:0 auto;padding:34px 26px 80px}}
 h1{{font-size:24px;margin:0 0 22px}}
 .bar-accent{{width:4px;height:22px;background:var(--acc);display:inline-block;vertical-align:-4px;margin-right:10px;border-radius:2px}}
 .kpis{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:26px}}
 @media(max-width:820px){{.kpis{{grid-template-columns:repeat(3,1fr)}}}}
 @media(max-width:520px){{.kpis{{grid-template-columns:repeat(2,1fr)}}}}
 .kpi{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 14px 12px}}
 .kv{{font-size:24px;font-weight:750;font-family:monospace}} .kl{{font-size:12px;margin-top:3px}}
 .ks{{font-size:10.5px;color:var(--ink3);margin-top:1px}}
 .grid2{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}
 @media(max-width:820px){{.grid2{{grid-template-columns:1fr}}}}
 .card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin-bottom:18px}}
 .card h2{{font-size:14px;margin:0 0 4px}} .card .sub{{font-size:11.5px;color:var(--ink3);margin:0 0 14px}}
 .donut-wrap{{display:flex;gap:18px;align-items:center;flex-wrap:wrap}}
 .legend{{display:flex;flex-direction:column;gap:7px;font-size:12.5px}}
 .lg{{display:flex;align-items:center;gap:8px}} .lg .sw{{width:11px;height:11px;border-radius:3px;flex:0 0 auto}}
 .lg b{{font-family:monospace}} .lg .pct{{color:var(--ink3);font-family:monospace;font-size:11px}}
 .evbar{{display:flex;height:30px;border-radius:8px;overflow:hidden;border:1px solid var(--line);gap:2px;background:var(--bg)}}
 .evseg{{height:100%}} .evleg{{display:flex;flex-wrap:wrap;gap:16px;margin-top:12px;font-size:12px}}
 .note{{font-size:12px;color:var(--ink3);margin-top:12px;border-left:2px solid var(--acc);padding-left:10px}}
 footer{{margin-top:30px;color:var(--ink3);font-size:11.5px;text-align:center}}
 a{{color:{BLUE}}}
</style></head><body>
<div class="wrap">
  <h1><span class="bar-accent"></span>ICS-VEX &middot; CVE Ground Truth Dataset</h1>

  <div class="kpis">{kpi_html}</div>

  <div class="grid2">
    <div class="card">
      <h2>Asset VEX type &mdash; source availability</h2>
      <p class="sub">All {n_cve:,} CVEs &middot; source is required for execution verification</p>
      <div class="donut-wrap">{src_svg}<div>{src_leg}</div></div>
    </div>
    <div class="card">
      <h2>Attack vector (CVSS AV)</h2>
      <p class="sub">Primary signal for the exposure estimate</p>
      <div class="donut-wrap">{av_svg}<div>{av_leg}</div></div>
    </div>
  </div>

  <div class="card">
    <h2>CVEs by year</h2>
    <p class="sub">By CVE-ID year &middot; 2011&ndash;present</p>
    {vbars(YEARS)}
  </div>

  <div class="grid2">
    <div class="card">
      <h2>Top CWE types (Top 12)</h2>
      <p class="sub">Weakness-type distribution</p>
      {hbars([(k, v) for k, v in CWE], color=BLUE)}
    </div>
    <div class="card">
      <h2>Severity (CVSS v3)</h2>
      <p class="sub">CVEs with a recorded score</p>
      {hbars(SEV, pad_l=90)}
    </div>
  </div>

  <div class="card">
    <h2>Evidence tiers &mdash; pipeline adjudication</h2>
    <p class="sub">By device&middot;CVE pair ({ev_total:,}) &middot; only execution-verified is true ground truth</p>
    <div class="evbar">{''.join(ev_seg)}</div>
    <div class="evleg">{ev_leg}</div>
    <p class="note">Execution-verified: {ev.get('execution-verified',0)} ({ev.get('execution-verified',0)/ev_total*100:.2f}%).
       The rest are CVSS-AV-based secondary estimates, being expanded via CVE-Genie reproduction.</p>
  </div>

  <footer>Generated by tools/build_cve_analysis.py &middot; ICS-VEX &middot;
    Data: CISA ICS-CERT &middot; KEV &middot; findings.csv</footer>
</div></body></html>
"""

open(OUT, "w", encoding="utf-8").write(HTML)
print(f"wrote {OUT}  ({len(HTML):,} bytes)")
print(f"  CVE={n_cve:,}  assets={n_dev:,}  advisories={n_adv:,}  "
      f"code-available={SRC_AVAIL[2][1]}  exec-verified={ev.get('execution-verified',0)}  KEV={KEV_LISTED}")
