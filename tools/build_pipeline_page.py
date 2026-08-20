#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate pipeline.html — a live web view of the hybrid VEX pipeline.

Data-driven from results/vex_batch_summary.json + results/genie_candidates.json,
so it always reflects the current corpus. Self-contained (inline CSS), theme-aware,
matching the ICS-VEXForge dashboard palette. Linked from index.html.

Sections:
  1. what it is + KPI row
  2. flow: static triage -> source routing -> execution reproduction
  3. static VEX distribution (by verdict / tier / reachability)
  4. source-availability routing (which findings can ever be reproduced)
  5. reproduction candidates (ready / needs-code, top ready targets)

Run:  python tools/build_pipeline_page.py
"""
import os, json, html

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SUM = json.load(open(os.path.join(BASE, "results", "vex_batch_summary.json"), encoding="utf-8"))
CAND = json.load(open(os.path.join(BASE, "results", "genie_candidates.json"), encoding="utf-8"))
OUT = os.path.join(BASE, "pipeline.html")

VEX = SUM["by_vex"]
TIER = SUM["by_tier"]
REACH = SUM["by_reachability"]
SC = SUM["by_source_class"]
TOTAL = SUM["total_findings"]

VEX_COLOR = {"LIKELY_AFFECTED": "var(--affected)", "LIKELY_NOT_AFFECTED": "var(--safe)",
             "UNDER_INVESTIGATION": "var(--under)"}
VEX_LABEL = {"LIKELY_AFFECTED": "Affected", "LIKELY_NOT_AFFECTED": "Not affected",
             "UNDER_INVESTIGATION": "Under investigation"}


def esc(s):
    return html.escape(str(s))


def pct(n, d):
    return (100.0 * n / d) if d else 0.0


def stacked_bar(counts, order, colormap, labelmap, total=None):
    total = total or sum(counts.values())
    segs = []
    for k in order:
        v = counts.get(k, 0)
        if not v:
            continue
        w = pct(v, total)
        segs.append(
            f'<div class="seg" style="width:{w:.2f}%;background:{colormap.get(k,"var(--ink-3)")}" '
            f'title="{esc(labelmap.get(k,k))}: {v:,} ({w:.1f}%)"></div>')
    leg = "".join(
        f'<span class="lg"><i style="background:{colormap.get(k,"var(--ink-3)")}"></i>'
        f'{esc(labelmap.get(k,k))} <b>{counts.get(k,0):,}</b> '
        f'<span class="mut">{pct(counts.get(k,0),total):.1f}%</span></span>'
        for k in order if counts.get(k, 0))
    return f'<div class="bar">{"".join(segs)}</div><div class="legend">{leg}</div>'


def kpi(v, l, s=""):
    return (f'<div class="kpi"><div class="kv">{esc(v)}</div><div class="kl">{esc(l)}</div>'
            f'<div class="ks">{esc(s)}</div></div>')


REACH_COLOR = {"yes": "var(--affected)", "no": "var(--safe)",
               "conditional": "var(--under)", "unknown": "var(--ink-3)"}
REACH_LABEL = {"yes": "Reachable", "no": "Unreachable",
               "conditional": "Conditional", "unknown": "Unknown AV"}
TIER_COLOR = {"static-reasoned": "var(--accent)", "under-investigation": "var(--under)",
              "static-analysis-verified": "var(--safe)"}
TIER_LABEL = {"static-reasoned": "static-reasoned", "under-investigation": "under-investigation",
              "static-analysis-verified": "static-analysis-verified"}

SC_META = {
    "code-available": ("Code available", "vuln/patched pair collected — CodeBERT diff + "
                       "reproduction-eligible", "var(--safe)"),
    "oss-attributed": ("OSS, no code yet", "open-source but code not collected yet — "
                       "promotable once code is collected", "var(--under)"),
    "vendor-proprietary": ("Vendor firmware", "closed source — never reproducible, static "
                           "verdict only", "var(--ink-3)"),
}


def sc_rows():
    rows = []
    for key in ("code-available", "oss-attributed", "vendor-proprietary"):
        d = SC.get(key, {})
        n = d.get("n", 0)
        name, desc, col = SC_META[key]
        split = stacked_bar({k: d.get(k, 0) for k in VEX_COLOR}, list(VEX_COLOR),
                            VEX_COLOR, VEX_LABEL, total=n or 1)
        rows.append(
            f'<div class="scrow"><div class="scmeta"><div class="scn" style="color:{col}">'
            f'{esc(name)}</div><div class="scd">{esc(desc)}</div>'
            f'<div class="scc">{n:,} findings · {pct(n,TOTAL):.1f}%</div></div>'
            f'<div class="scbar">{split}</div></div>')
    return "".join(rows)


def cand_rows():
    ready = [c for c in CAND["candidates"] if c["status"] == "ready"]
    rows = []
    for c in ready[:15]:
        kev = '<span class="tag kev">KEV</span>' if c.get("kev") else ""
        rc = c.get("reachability", "")
        rcs = f'<span class="tag" style="color:{REACH_COLOR.get(rc,"var(--ink-3)")}">{esc(rc)}</span>'
        repo = c.get("repo_url") or ""
        repo_l = (f'<a href="{esc(repo)}" target="_blank" rel="noopener">{esc(repo.replace("https://github.com/",""))}</a>'
                  if repo else "")
        rows.append(
            f'<tr><td class="mono">{esc(c["cve"])}</td><td>{esc(c.get("severity") or "—")}</td>'
            f'<td>{kev}</td><td>{rcs}</td><td class="mono sm">{repo_l}</td></tr>')
    return "".join(rows)


PAGE = f"""<title>ICS-VEX Pipeline</title>
<style>
  :root{{
    --ground:#e9edf1;--surface:#fff;--surface-2:#f1f5f8;--ink:#111a20;--ink-2:#4b5a64;
    --ink-3:#7c8b95;--line:#d4dde4;--accent:#0c7c8a;
    --affected:#bd3b2c;--safe:#1c8551;--under:#b07d16;
    --shadow:0 1px 2px rgba(16,26,32,.06),0 6px 20px rgba(16,26,32,.05);
    --mono:ui-monospace,"Cascadia Code","JetBrains Mono",Consolas,monospace;
    --sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  }}
  @media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{
    --ground:#0b1116;--surface:#111a20;--surface-2:#16222a;--ink:#e6edf2;--ink-2:#93a3ad;
    --ink-3:#657580;--line:#25333c;--accent:#38ccd9;
    --affected:#e5675c;--safe:#43be7c;--under:#e0b24c;
    --shadow:0 1px 2px rgba(0,0,0,.3),0 8px 26px rgba(0,0,0,.35);
  }}}}
  :root[data-theme="dark"]{{
    --ground:#0b1116;--surface:#111a20;--surface-2:#16222a;--ink:#e6edf2;--ink-2:#93a3ad;
    --ink-3:#657580;--line:#25333c;--accent:#38ccd9;
    --affected:#e5675c;--safe:#43be7c;--under:#e0b24c;
    --shadow:0 1px 2px rgba(0,0,0,.3),0 8px 26px rgba(0,0,0,.35);
  }}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--ground);color:var(--ink);font-family:var(--sans);line-height:1.5;-webkit-font-smoothing:antialiased}}
  .wrap{{max-width:1080px;margin:0 auto;padding:32px 22px 64px}}
  .eyebrow{{font-family:var(--mono);font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--accent);font-weight:600}}
  h1{{font-size:clamp(24px,4vw,34px);margin:.28em 0 .1em;letter-spacing:-.02em;font-weight:680}}
  .sub{{color:var(--ink-2);max-width:70ch;font-size:14.5px}}
  a{{color:var(--accent)}}
  .back{{display:inline-block;font-family:var(--mono);font-size:12px;margin-bottom:8px;text-decoration:none;color:var(--ink-2)}}
  section{{margin-top:34px}}
  .sec-h{{display:flex;align-items:baseline;gap:12px;margin-bottom:14px;flex-wrap:wrap}}
  .sec-h h2{{font-size:16px;margin:0;font-weight:640}}
  .sec-h .n{{font-family:var(--mono);font-size:11px;color:var(--ink-3)}}
  .card{{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:18px;box-shadow:var(--shadow)}}
  .kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}}
  .kpi{{background:var(--surface);border:1px solid var(--line);border-radius:11px;padding:14px 16px;box-shadow:var(--shadow)}}
  .kpi .kv{{font-size:24px;font-weight:700;letter-spacing:-.02em}}
  .kpi .kl{{font-size:13px;font-weight:600;margin-top:2px}}
  .kpi .ks{{font-size:11px;color:var(--ink-3);font-family:var(--mono);margin-top:2px}}
  .flow{{display:flex;gap:10px;align-items:stretch;flex-wrap:wrap}}
  .step{{flex:1;min-width:150px;background:var(--surface-2);border:1px solid var(--line);border-radius:10px;padding:13px 14px}}
  .step .t{{font-weight:640;font-size:13.5px}}
  .step .d{{font-size:12px;color:var(--ink-2);margin-top:4px}}
  .step .m{{font-family:var(--mono);font-size:10.5px;color:var(--ink-3);margin-top:6px;word-break:break-all}}
  .arrow{{align-self:center;color:var(--ink-3);font-size:18px}}
  .bar{{display:flex;height:22px;border-radius:6px;overflow:hidden;border:1px solid var(--line)}}
  .bar .seg{{height:100%}}
  .legend{{display:flex;flex-wrap:wrap;gap:14px;margin-top:10px;font-size:12.5px}}
  .legend .lg{{display:flex;align-items:center;gap:6px}}
  .legend i{{width:11px;height:11px;border-radius:3px;display:inline-block}}
  .legend .mut{{color:var(--ink-3);font-family:var(--mono);font-size:11px}}
  .grid2{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
  @media(max-width:720px){{.grid2{{grid-template-columns:1fr}}}}
  h3{{margin:0 0 3px;font-size:13.5px;font-weight:620}}.hint{{font-size:12px;color:var(--ink-3);margin:0 0 14px}}
  .scrow{{display:grid;grid-template-columns:minmax(180px,1fr) 2fr;gap:16px;padding:13px 0;border-bottom:1px dashed var(--line);align-items:center}}
  .scrow:last-child{{border-bottom:none}}
  .scn{{font-weight:640;font-size:13.5px}}.scd{{font-size:12px;color:var(--ink-2)}}
  .scc{{font-family:var(--mono);font-size:11px;color:var(--ink-3);margin-top:3px}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th,td{{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line)}}
  th{{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--ink-3);font-weight:600}}
  .mono{{font-family:var(--mono)}}.sm{{font-size:11.5px}}
  .tag{{font-family:var(--mono);font-size:10.5px;font-weight:700}}
  .tag.kev{{color:#fff;background:var(--affected);padding:1px 6px;border-radius:5px}}
  .note{{font-size:12.5px;color:var(--ink-2);margin-top:12px}}
  .foot{{margin-top:40px;font-size:11.5px;color:var(--ink-3);text-align:center}}
</style>

<div class="wrap">
  <a class="back" href="index.html">&larr; ICS-VEXForge dashboard</a>
  <div class="eyebrow">Hybrid VEX &middot; static triage → execution reproduction</div>
  <h1>ICS-VEX Pipeline</h1>
  <p class="sub">Every finding is triaged by <b>static analysis</b> (no PoC generated or executed).
  Only the small source-available subset can ever be <b>execution-verified</b>; static triage selects
  exactly those and hands them to an isolated CVE-Genie run. This page is generated from the live
  corpus sweep ({TOTAL:,} findings).</p>

  <section>
    <div class="kpis">
      {kpi(f"{TOTAL:,}", "Findings triaged", "static, no execution")}
      {kpi(f"{VEX.get('LIKELY_AFFECTED',0):,}", "Affected", f"{pct(VEX.get('LIKELY_AFFECTED',0),TOTAL):.1f}% reachable")}
      {kpi(f"{VEX.get('LIKELY_NOT_AFFECTED',0):,}", "Not affected", f"{pct(VEX.get('LIKELY_NOT_AFFECTED',0),TOTAL):.1f}% unreachable")}
      {kpi(f"{CAND['ready']}", "Reproduction-ready", "code pair + repo")}
      {kpi(f"{CAND['needs_code']:,}", "Promotable", "OSS, collect code")}
    </div>
  </section>

  <section>
    <div class="sec-h"><h2>How it flows</h2><span class="n">static primary · execution for ground truth</span></div>
    <div class="card"><div class="flow">
      <div class="step"><div class="t">1 · Static triage</div><div class="d">SecureBERT context + CVSS AV×exposure reachability → VEX for all findings. Nothing executed.</div><div class="m">src/vex_batch.py</div></div>
      <div class="arrow">→</div>
      <div class="step"><div class="t">2 · Source routing</div><div class="d">Split by code availability; only code-available / OSS can be reproduced.</div><div class="m">source_class</div></div>
      <div class="arrow">→</div>
      <div class="step"><div class="t">3 · Candidate export</div><div class="d">Pick reproduction targets, ranked by KEV, reachability, severity.</div><div class="m">tools/export_genie_candidates.py</div></div>
      <div class="arrow">→</div>
      <div class="step"><div class="t">4 · Isolated reproduction</div><div class="d">CVE-Genie in Docker; Exploiter routed to a local non-refusing model.</div><div class="m">serve_poc_llm.py · model_routing</div></div>
    </div></div>
  </section>

  <section>
    <div class="sec-h"><h2>Static VEX distribution</h2><span class="n">all {TOTAL:,} findings</span></div>
    <div class="grid2">
      <div class="card"><h3>By verdict</h3><p class="hint">Reachable → affected, unreachable → not affected, conditional/local → under investigation.</p>
        {stacked_bar(VEX, ["LIKELY_AFFECTED","LIKELY_NOT_AFFECTED","UNDER_INVESTIGATION"], VEX_COLOR, VEX_LABEL, TOTAL)}</div>
      <div class="card"><h3>By reachability</h3><p class="hint">CVSS Attack Vector × deployment exposure (exposure is synthetic).</p>
        {stacked_bar(REACH, ["yes","conditional","no","unknown"], REACH_COLOR, REACH_LABEL, TOTAL)}</div>
    </div>
    <div class="card" style="margin-top:16px"><h3>By evidence tier</h3>
      <p class="hint">Decisive reachability → <b>static-reasoned</b>; conditional/unknown → <b>under-investigation</b>.
      A confirmed <b>static-analysis-verified</b> tier needs a separable code diff (code-available subset).</p>
      {stacked_bar(TIER, ["static-reasoned","under-investigation","static-analysis-verified"], TIER_COLOR, TIER_LABEL, TOTAL)}</div>
  </section>

  <section>
    <div class="sec-h"><h2>Source-availability routing</h2><span class="n">who can ever be execution-verified</span></div>
    <div class="card">{sc_rows()}
      <p class="note">Only <b>code-available</b> findings reach CodeBERT patch-diff and execution reproduction;
      <b>vendor-proprietary</b> firmware ({pct(SC.get("vendor-proprietary",{}).get("n",0),TOTAL):.0f}% of the corpus)
      is decided by static reachability alone.</p></div>
  </section>

  <section>
    <div class="sec-h"><h2>Reproduction candidates</h2><span class="n">{CAND['ready']} ready · {CAND['needs_code']:,} need code</span></div>
    <div class="card"><h3>Top ready targets</h3>
      <p class="hint">Vuln/patched pair collected (repo + commit) — ready for an isolated CVE-Genie run,
      ranked by KEV → reachability → severity.</p>
      <div style="overflow-x:auto"><table>
        <thead><tr><th>CVE</th><th>Severity</th><th>KEV</th><th>Reach</th><th>Repository</th></tr></thead>
        <tbody>{cand_rows()}</tbody>
      </table></div>
      <p class="note">Execution reproduction promotes a CVE to <b>execution-verified</b> ground truth. The
      refusal that blocked the exploit step is bypassed by routing only the Exploiter to a local model
      (<span class="mono">EXPLOITER_MODEL=local-poc</span>); a 7B local model proved the routing but a
      capable (cloud) model is needed to satisfy the exploit critic.</p></div>
  </section>

  <div class="foot">Generated from results/vex_batch_summary.json + results/genie_candidates.json ·
  static analysis only, no PoC executed in this view.</div>
</div>
"""

open(OUT, "w", encoding="utf-8").write(PAGE)
print("wrote", os.path.relpath(OUT, BASE), "(%.1f KB)" % (len(PAGE) / 1024))
