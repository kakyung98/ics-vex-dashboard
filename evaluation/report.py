#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Render the scored results as a self-contained HTML report.

No CDN, no build step, no JS framework: one file that opens from the filesystem and
keeps working years from now, which matters because this report is the thing a
reviewer is handed. Charts are inline SVG for the same reason.

Chart choices, and why each is the form it is:

  * The two headline precisions are **stat tiles with a threshold bar**, not a bar
    chart. Each is one number against one acceptance line; a two-bar chart comparing
    item #3 to item #4 would invite reading them as competitors when they measure
    different stages over different populations.
  * The per-vendor view is **two single-series charts side by side**, precision and
    abstention, sharing one vendor order. They are two different measures, so putting
    them on one pair of axes would be a dual-axis chart - the single worst charting
    mistake. But they have to be read together (a vendor the matcher mostly declines
    scores well on the little it answers), so they are adjacent and the order is
    locked to corpus share rather than to either score.
  * Evidence tiers use an **ordinal one-hue ramp**, because tier strength is ordered
    (verified > reachable > present > component). Five categorical hues would imply
    five unrelated categories.

Colour comes from the project's validated reference palette, used in the roles that
palette documents: categorical slot 1 (blue) and slot 2 (orange) for the two measures,
the blue sequential ramp for the ordinal tiers, and the reserved status palette for
PASS/FAIL - which always ships with a text label, never colour alone.
"""
import datetime
import html
import json

# --- palette ------------------------------------------------------------------
# Documented-as-passing values in their documented roles. The ordinal ramp respects
# the documented contrast floors: on light start no lighter than step 250, on dark go
# no darker than step 600, so the step nearest each surface still clears 2:1.
SERIES_1 = "#2a78d6"   # categorical slot 1, light
SERIES_2 = "#eb6834"   # categorical slot 2, light
RAMP_LIGHT = ["#104281", "#1c5cab", "#2a78d6", "#5598e7", "#86b6ef"]
RAMP_DARK = ["#b7d3f6", "#86b6ef", "#3987e5", "#256abf", "#184f95"]

CSS = """
:root{
  --surface-1:#fcfcfb; --plane:#f9f9f7;
  --ink-1:#0b0b0b; --ink-2:#52514e; --ink-3:#898781;
  --grid:#e1e0d9; --axis:#c3c2b7; --ring:rgba(11,11,11,0.10);
  --series-1:#2a78d6; --series-2:#eb6834;
  --good:#0ca30c; --critical:#d03b3b; --warning:#fab219;
  color-scheme:light;
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]){
    --surface-1:#1a1a19; --plane:#0d0d0d;
    --ink-1:#ffffff; --ink-2:#c3c2b7; --ink-3:#898781;
    --grid:#2c2c2a; --axis:#383835; --ring:rgba(255,255,255,0.10);
    --series-1:#3987e5; --series-2:#d95926;
    color-scheme:dark;
  }
}
:root[data-theme="dark"]{
  --surface-1:#1a1a19; --plane:#0d0d0d;
  --ink-1:#ffffff; --ink-2:#c3c2b7; --ink-3:#898781;
  --grid:#2c2c2a; --axis:#383835; --ring:rgba(255,255,255,0.10);
  --series-1:#3987e5; --series-2:#d95926;
  color-scheme:dark;
}
*{box-sizing:border-box}
body{margin:0;background:var(--plane);color:var(--ink-1);
  font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:1060px;margin:0 auto;padding:32px 16px 72px}
h1{font-size:25px;margin:0 0 6px;letter-spacing:-.02em}
h2{font-size:18px;margin:38px 0 4px;letter-spacing:-.01em}
h3{font-size:14px;margin:22px 0 8px;color:var(--ink-2);font-weight:600}
.sub{color:var(--ink-2);margin:0 0 4px}
.muted{color:var(--ink-3);font-size:13px}
.card{background:var(--surface-1);border:1px solid var(--ring);border-radius:12px;
  padding:18px 20px;margin:14px 0}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(248px,1fr));gap:14px;margin:14px 0}
.tile{background:var(--surface-1);border:1px solid var(--ring);border-radius:12px;padding:18px 20px}
.tile .lab{font-size:12.5px;color:var(--ink-2);text-transform:uppercase;letter-spacing:.06em}
.tile .val{font-size:40px;line-height:1.05;margin:8px 0 2px;letter-spacing:-.03em}
.tile .meta{font-size:13px;color:var(--ink-2)}
.pill{display:inline-flex;align-items:center;gap:5px;font-size:12px;font-weight:650;
  padding:3px 9px;border-radius:999px;border:1px solid}
.pill-pass{color:var(--good);border-color:var(--good);background:color-mix(in srgb,var(--good) 12%,transparent)}
.pill-fail{color:var(--critical);border-color:var(--critical);background:color-mix(in srgb,var(--critical) 12%,transparent)}
.pill-warn{color:var(--warning);border-color:var(--warning);background:color-mix(in srgb,var(--warning) 14%,transparent)}
/* A 7-column table cannot fit 375px without shrinking the type past legibility, so
   it scrolls sideways inside its own box instead of pushing the whole page wide.
   `tbl-scroll` is applied by _tbl(); the min-width keeps columns from collapsing
   into unreadable slivers before the scroll kicks in. */
.tbl-scroll{overflow-x:auto;-webkit-overflow-scrolling:touch;margin:2px 0}
.tbl-scroll table{min-width:460px}
table{border-collapse:collapse;width:100%;font-size:13.5px;
  font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--grid)}
th{color:var(--ink-2);font-weight:600;font-size:12.5px}
td.n,th.n{text-align:right}
.twoup{display:grid;grid-template-columns:1fr 1fr;gap:20px}
@media (max-width:760px){.twoup{grid-template-columns:1fr}}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:12.5px;color:var(--ink-2);margin:2px 0 10px}
.legend i{width:10px;height:10px;border-radius:2px;display:inline-block;margin-right:6px;
  vertical-align:-1px}
svg{display:block;overflow:visible;max-width:100%}
svg text{font:12px system-ui,-apple-system,"Segoe UI",sans-serif}
details{margin:10px 0}summary{cursor:pointer;color:var(--ink-2);font-size:13.5px}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace;
  background:color-mix(in srgb,var(--ink-1) 7%,transparent);padding:1px 5px;border-radius:4px}
.note{border-left:3px solid var(--axis);padding:2px 0 2px 13px;margin:12px 0;
  color:var(--ink-2);font-size:13.5px}
"""


def _e(s):
    return html.escape(str(s), quote=True)


def _fmt(v, nd=4):
    return "—" if v is None else ("%.*f" % (nd, v))


def _n(v):
    return "—" if v is None else "{:,}".format(v)


# --- charts -------------------------------------------------------------------
def hbars(rows, value_key, label_key, color, max_value=None, width=460,
          row_h=26, pct=False, rule=None, rule_label=None):
    """Horizontal bars: one series, labels on the left, value direct-labelled.

    Horizontal because the categories are vendor names - rotated tick labels are a
    readability tax paid for no reason when the bars can simply run the other way.
    Every bar is direct-labelled here rather than selectively, because there are at
    most a dozen rows and the value IS the finding; the "never label every point"
    rule is about dense series, which this is not.
    """
    if not rows:
        return "<p class='muted'>no rows</p>"
    lab_w, pad_r = 148, 54
    plot_w = width - lab_w - pad_r
    top = 0 if rule is None else 16
    height = top + len(rows) * row_h + 16
    vmax = max_value if max_value is not None else max(
        (r.get(value_key) or 0) for r in rows) or 1
    out = ['<svg viewBox="0 0 %d %d" width="%d" height="%d" role="img">'
           % (width, height, width, height)]
    # gridlines at 0/25/50/75/100% of the scale, recessive
    for frac in (0.25, 0.5, 0.75, 1.0):
        x = lab_w + plot_w * frac
        out.append('<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="var(--grid)" '
                   'stroke-width="1"/>' % (x, top, x, top + len(rows) * row_h))
    if rule is not None:
        x = lab_w + plot_w * (rule / vmax)
        out.append('<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="var(--ink-3)" '
                   'stroke-width="1" stroke-dasharray="3 3"/>'
                   % (x, top - 4, x, top + len(rows) * row_h))
        if rule_label:
            out.append('<text x="%.1f" y="%d" fill="var(--ink-3)" font-size="11" '
                       'text-anchor="middle">%s</text>' % (x, top - 8, _e(rule_label)))
    for i, r in enumerate(rows):
        v = r.get(value_key)
        y = top + i * row_h
        out.append('<text x="%d" y="%.1f" fill="var(--ink-2)" text-anchor="end">%s</text>'
                   % (lab_w - 10, y + row_h / 2 + 4, _e(r[label_key])))
        if v is None:
            out.append('<text x="%d" y="%.1f" fill="var(--ink-3)" font-size="11">n/a</text>'
                       % (lab_w + 4, y + row_h / 2 + 4))
            continue
        bw = max(2.0, plot_w * (v / vmax))
        out.append('<rect x="%d" y="%.1f" width="%.1f" height="12" rx="4" fill="%s"/>'
                   % (lab_w, y + row_h / 2 - 6, bw, color))
        txt = ("%.1f%%" % (v * 100)) if pct else ("%.4f" % v)
        out.append('<text x="%.1f" y="%.1f" fill="var(--ink-2)" font-size="11.5">%s</text>'
                   % (lab_w + bw + 7, y + row_h / 2 + 4, txt))
    out.append("</svg>")
    return "".join(out)


def tier_bar(tiers, order, labels):
    """One stacked bar for the evidence-tier mix, with a 2px surface gap per segment.

    A stacked single bar rather than a pie: the question is "how is the population
    split", and segment length on a common baseline is read far more accurately than
    angle. The ramp is ordinal, strongest tier darkest.
    """
    total = sum(tiers.get(k, 0) for k in order) or 1
    width, h = 1000, 44
    x = 0.0
    segs, legend = [], []
    for i, k in enumerate(order):
        n = tiers.get(k, 0)
        if not n:
            continue
        w = width * n / total
        segs.append(
            '<rect x="%.2f" y="0" width="%.2f" height="%d" fill="%s" '
            'class="seg-%d"><title>%s: %d of %d (%.1f%%)</title></rect>'
            % (x, max(1.0, w - 2), h, RAMP_LIGHT[i % len(RAMP_LIGHT)], i,
               labels.get(k, k), n, total, 100.0 * n / total))
        if w > 58:
            segs.append('<text x="%.2f" y="%d" fill="#fff" font-size="13" '
                        'text-anchor="middle" font-weight="600">%d</text>'
                        % (x + (w - 2) / 2, h // 2 + 5, n))
        legend.append("<span><i style='background:%s'></i>%s <b>%d</b></span>"
                      % (RAMP_LIGHT[i % len(RAMP_LIGHT)], _e(labels.get(k, k)), n))
        x += w
    # The ramp has to re-step for the dark surface; a flip would put the darkest
    # segment against the darkest background.
    dark = "".join(
        ":root:not([data-theme='light']) .seg-%d{fill:%s}" % (i, RAMP_DARK[i % len(RAMP_DARK)])
        for i in range(len(order)))
    # The segments are laid out edge to edge across the full viewBox, so the clip has
    # to come from the wrapper: `overflow:visible` is set globally for the bar charts,
    # whose direct labels sit outside the plot, and without a clip here the final
    # segment bleeds past the card edge.
    return ("<style>@media (prefers-color-scheme:dark){%s}"
            ":root[data-theme='dark'] %s</style>"
            "<div class='legend'>%s</div>"
            "<div style='overflow:hidden;border-radius:6px;line-height:0'>"
            '<svg viewBox="0 0 %d %d" width="%d" height="%d" preserveAspectRatio="none" '
            'style="width:100%%;height:%dpx;overflow:hidden" role="img">%s</svg></div>'
            % (dark,
               "".join(".seg-%d{fill:%s}" % (i, RAMP_DARK[i % len(RAMP_DARK)])
                       for i in range(len(order))),
               "".join(legend), width, h, width, h, h, "".join(segs)))


def gauge(value, threshold, width=300):
    """A single measure against its acceptance line. One number, one rule."""
    if value is None:
        return ""
    h, bar_y, bar_h = 40, 14, 12
    vx = width * min(1.0, max(0.0, value))
    tx = width * min(1.0, max(0.0, threshold))
    ok = value >= threshold
    col = "var(--good)" if ok else "var(--critical)"
    return (
        '<svg viewBox="0 0 %d %d" width="%d" height="%d" role="img">'
        '<rect x="0" y="%d" width="%d" height="%d" rx="4" fill="var(--grid)"/>'
        '<rect x="0" y="%d" width="%.1f" height="%d" rx="4" fill="%s"/>'
        '<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="var(--ink-1)" stroke-width="2"/>'
        '<text x="%.1f" y="%d" fill="var(--ink-2)" font-size="11" text-anchor="middle">'
        'acceptance %.2f</text></svg>'
        % (width, h, width, h, bar_y, width, bar_h, bar_y, vx, bar_h, col,
           tx, bar_y - 5, tx, bar_y + bar_h + 5, tx, h - 1, threshold))


# --- sections -----------------------------------------------------------------
_TIER_LABELS = {
    "verified": "verified (present + reachable + controllable)",
    "reachable": "reachable (present + reachable)",
    "present": "present (reachability not confirmable)",
    "component": "component (function not located)",
    "patch-verified": "patch-verified → fixed",
}
_TIER_ORDER = ["verified", "reachable", "present", "component", "patch-verified"]


def _tile(item):
    """One headline stat tile. PASS/FAIL carries a text label, never colour alone."""
    res, meta = item["result"], item["meta"]
    prec = res.get("precision")
    acc = meta.get("acceptance")
    if acc is None:
        contradictions = sum((q or {}).get("contradictions", 0)
                             for q in (res.get("per_question") or {}).values())
        ok = contradictions == 0
        pill = ("<span class='pill %s'>%s contradictions %d</span>"
                % ("pill-pass" if ok else "pill-fail",
                   "PASS" if ok else "FAIL", contradictions))
        val = str(contradictions)
        meta_line = _e(meta.get("acceptance_label") or "")
    else:
        ok = prec is not None and prec >= acc
        pill = ("<span class='pill %s'>%s</span>"
                % ("pill-pass" if ok else "pill-fail", "PASS" if ok else "FAIL"))
        val = _fmt(prec)
        meta_line = ("TP %s &middot; FP %s &nbsp;|&nbsp; acceptance &ge; %.2f"
                     % (_n(res.get("TP")), _n(res.get("FP")), acc))
    return ("<div class='tile'><div class='lab'>%s</div>"
            "<div class='val'>%s</div><div style='margin:6px 0 9px'>%s</div>"
            "<div class='meta'>%s</div>%s</div>"
            % (_e(meta.get("title") or ("item #" + item["item"])), val, pill,
               meta_line,
               gauge(prec, acc) if acc is not None else ""))


#: How many vendors the per-vendor charts draw before folding the rest into one row.
#: The scorer emits 532 vendors, 271 of them with something scored, and charting all
#: of them buries the finding: the tail is overwhelmingly 1.0000 over a handful of
#: predictions, so 40 full-length bars say "near perfect" where the real result is
#: Rockwell at 0.4739. Ten matches the published table, and the remainder is shown as
#: an aggregate rather than dropped, so nothing leaves the chart silently.
TOP_VENDORS = 10


def _item3_section(item):
    res = item["result"]
    # Every vendor, including those with nothing scored. Filtering them out would
    # drop exactly the vendors the matcher declined on entirely, which is the
    # abstention column's whole subject - the aggregate would then report a lower
    # abstention rate precisely because the full abstainers were removed from it.
    by_vendor = list(res.get("by_vendor") or [])
    by_vendor.sort(key=lambda v: -(v.get("components") or 0))
    head, tail = by_vendor[:TOP_VENDORS], by_vendor[TOP_VENDORS:]
    rows = [{"vendor": v["vendor"], "precision": v.get("precision"),
             "abst": (v.get("abstention_pct") or 0) / 100.0,
             "components": v.get("components"), "scored": v.get("scored"),
             "TP": v.get("TP"), "FP": v.get("FP")} for v in head]
    if tail:
        # Recomputed from the tail's own TP/FP rather than averaged: a mean of
        # per-vendor precisions would weight a 2-prediction vendor like a
        # 2,000-prediction one.
        tp = sum(v.get("TP") or 0 for v in tail)
        fp = sum(v.get("FP") or 0 for v in tail)
        comps = sum(v.get("components") or 0 for v in tail)
        abst = sum(v.get("abstained") or 0 for v in tail)
        rows.append({"vendor": "(other %d vendors)" % len(tail),
                     "precision": (tp / (tp + fp)) if (tp + fp) else None,
                     "abst": (abst / comps) if comps else 0.0,
                     "components": comps, "scored": tp + fp, "TP": tp, "FP": fp})
    tbl = "".join(
        "<tr><td>%s</td><td class='n'>%s</td><td class='n'>%s</td><td class='n'>%.1f%%</td>"
        "<td class='n'>%s</td><td class='n'>%s</td><td class='n'><b>%s</b></td></tr>"
        % (_e(r["vendor"]), _n(r["components"]), _n(r["scored"]), r["abst"] * 100,
           _n(r["TP"]), _n(r["FP"]), _fmt(r["precision"]))
        for r in rows)
    fp_axis = res.get("fp_by_axis") or {}
    axis_rows = "".join("<tr><td>%s</td><td class='n'>%s</td></tr>" % (_e(k), _n(v))
                        for k, v in sorted(fp_axis.items(), key=lambda kv: -kv[1]))
    return """
<h2>Item #3 &mdash; per vendor</h2>
<p class="sub">The ten largest vendors by corpus share, with the remaining %d folded
into one aggregate row. Ordered by share and <b>not</b> by score: a chart sorted by
precision invites reading its top row as the result.</p>
<div class="note"><b>Read the two charts together.</b> A vendor the matcher mostly
declines to identify scores well on the little it does answer &mdash; Honeywell reads
1.0000 over 6 scored predictions having abstained on 83%% of its components. Precision
and abstention are one result, which is why they sit side by side rather than on one
pair of axes.</div>
<div class="twoup">
  <div><h3>Precision (higher is better)</h3>%s</div>
  <div><h3>Abstention rate (lower is more answered)</h3>%s</div>
</div>
<details><summary>The same ten rows as a table, and where the false positives come from &mdash; all 532 vendors are in <code>results.json</code></summary>
<table><thead><tr><th>vendor</th><th class="n">components</th><th class="n">scored</th>
<th class="n">abstained</th><th class="n">TP</th><th class="n">FP</th>
<th class="n">precision</th></tr></thead><tbody>%s</tbody></table>
<h3>False positives by axis</h3>
<table><thead><tr><th>axis</th><th class="n">FP</th></tr></thead><tbody>%s</tbody></table>
<p class="muted">Coverage: %s of %s components answered, %s abstentions.
%s labelled predictions scored (%s%% of what the matcher emits); %s unlabelled and
%s unadjudicable are held out rather than charged as errors.</p>
</details>""" % (
        len(tail),
        hbars(rows, "precision", "vendor", "var(--series-1)", max_value=1.0,
              rule=0.80, rule_label="0.80"),
        hbars(rows, "abst", "vendor", "var(--series-2)", max_value=1.0, pct=True),
        tbl, axis_rows,
        _n((res.get("sut_runs") or 0) - (res.get("sut_abstained") or 0)),
        _n(res.get("sut_runs")), _n(res.get("sut_abstained")), _n(res.get("scored")),
        res.get("labelled_share_pct"), _n(res.get("unlabelled_predictions")),
        _n(res.get("unadjudicable_predictions")))


def _item4_section(item, tiers):
    res = item["result"]
    fps = res.get("fp_cases") or []
    fp_rows = "".join(
        "<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (_e(f.get("cve")), _e(f.get("build")), _e(f.get("evidence_type")),
           _e(f.get("gt_detail")))
        for f in fps)
    tier_html = (tier_bar(tiers, _TIER_ORDER, _TIER_LABELS) if tiers
                 else "<p class='muted'>results/vex_v2_summary.json not found</p>")
    circ = ("<span class='pill pill-warn'>CIRCULAR</span> "
            if res.get("patch_gate_live") else "")
    return """
<h2>Item #4 &mdash; evidence behind the verdicts</h2>
<p class="sub">Every CVE in the population receives a verdict; what narrows is the
answer key, not the judging. %s%s of %s (CVE, build) cases are scored.</p>
<h3>Evidence tier over the %d collected-source CVEs</h3>
<p class="muted">Presence decides the verdict; reachability (Q3) and controllability
(Q4) only grade how much source evidence backs it. The ramp is ordinal &mdash;
strongest tier darkest.</p>
%s
<h3>The %d false positive(s)</h3>
<p class="muted">Each is a build the ground truth independently labels not-affected
that the pre-gate SUT still calls affected. They are exactly the cases the patch
pre-gate clears, which is why turning the gate on raises the figure and why that rise
proves nothing.</p>
<table><thead><tr><th>CVE</th><th>build</th><th>GT evidence</th>
<th>why the GT says not-affected</th></tr></thead><tbody>%s</tbody></table>""" % (
        circ, _n((res.get("TP") or 0) + (res.get("FP") or 0)),
        _n(res.get("gt_cases_total")), sum(tiers.values()) if tiers else 0,
        tier_html, len(fps), fp_rows or "<tr><td colspan='4'>none</td></tr>")


def _q34_section(item):
    res = item["result"]
    pq = res.get("per_question") or {}
    rows = "".join(
        "<tr><td>%s</td><td class='n'>%s</td><td class='n'>%s</td><td class='n'>%s</td>"
        "<td class='n'>%s</td><td class='n'><b>%s</b></td><td>%s</td></tr>"
        % (_e(q), _n(d.get("labels")), _n(d.get("answered")), _n(d.get("abstained")),
           _fmt(d.get("recall")), d.get("contradictions"),
           "<span class='pill %s'>%s</span>" % (
               "pill-pass" if d.get("contradictions") == 0 else "pill-fail",
               "PASS" if d.get("contradictions") == 0 else "FAIL"))
        for q, d in sorted(pq.items()))
    return """
<h2>Q3 / Q4 &mdash; do the solvers agree with outside authorities?</h2>
<p class="sub">A supplementary disclosure, <b>not</b> a certification item. Its bar is
this repository's own.</p>
<div class="note"><b>Why the bar is contradictions, not precision or recall.</b> The
answer key is one-sided by construction: a shipped public header cannot say an
internal function is <i>un</i>reachable, and CVSS cannot say an input is <i>not</i>
attacker-chosen. So precision reads 1.0000 by construction, and a recall threshold is
passed outright by a solver that answers "yes" to everything. The harm here is
one-directional &mdash; an over-positive solver clears nothing and is safe, an
over-refuting one produces false clearances &mdash; so the bar sits there.</div>
<table><thead><tr><th>question</th><th class="n">labels</th><th class="n">scored</th>
<th class="n">abstained</th><th class="n">recall</th><th class="n">contradictions</th>
<th>verdict</th></tr></thead><tbody>%s</tbody></table>
<p class="muted">Precision is withheld on purpose, with its reason recorded in the
result JSON &mdash; a figure describing the answer key rather than the solver is worse
than no figure.</p>""" % rows


def _components_section(components):
    """The learned components inside each item, measured on their own.

    Deliberately placed after both items and labelled as decomposition: these are not
    certification figures and must never be read beside 0.9490 / 0.9718 as if they
    competed with them. What they answer is the question the headlines cannot - how
    much of each figure is the learned part, and how often that part is wrong.
    """
    live = [c for c in components if c.get("result") and not c.get("error")]
    if not live:
        return ""
    blocks = []
    for c in live:
        res = c["result"]
        if c["key"] == "encoder":
            v, m = res["variants"], res["retrieval_marginal"]
            rows = "".join(
                "<tr><td>%s</td><td class='n'>%s</td><td class='n'>%s</td>"
                "<td class='n'>%s</td><td class='n'><b>%s</b></td></tr>"
                % (lab, _n(d["TP"]), _n(d["FP"]), _n(d["abstained"]),
                   _fmt(d["precision"]))
                for lab, d in (("string cascade only (ablation)", v["cascade_only"]),
                               ("cascade + retrieval (shipped SUT)",
                                v["cascade_plus_retrieval"])))
            rows += ("<tr><td><b>&rarr; the encoder's marginal effect</b></td>"
                     "<td class='n'>+%s</td><td class='n'>+%s</td>"
                     "<td class='n'>&minus;%s</td><td class='n'><b>%s</b></td></tr>"
                     % (_n(m["TP_added"]), _n(m["FP_added"]),
                        _n(m["components_recovered_from_abstention"]),
                        _fmt(m["precision_on_what_it_recovered"])))
            metrics = "".join(
                "<tr><td>%s</td><td><code>%s</code></td><td>%s</td></tr>"
                % (_e(x["measures"]),
                   _e(", ".join("%s=%s" % (k, val) for k, val in x["values"].items())),
                   _e(x["evidence_for"]))
                for x in res.get("component_metrics", []))
            sweep = res.get("ungated_sweep") or {}
            blocks.append("""
<h3>%s</h3>
<p class="muted">%s</p>
<table><thead><tr><th>variant</th><th class="n">TP</th><th class="n">FP</th>
<th class="n">abstained</th><th class="n">precision</th></tr></thead>
<tbody>%s</tbody></table>
<div class="note"><b>The headline is the string cascade's.</b> %s</div>
<h3>The encoder's own metrics, as already measured</h3>
<table><thead><tr><th>measures</th><th>values</th><th>evidence for</th></tr></thead>
<tbody>%s</tbody></table>
<p class="muted">%s</p>""" % (
                _e(c["title"]),
                "Subtraction, not adjective: the two runs differ only in whether the "
                "retrieval stage is enabled.",
                rows, _e(res.get("reading", "")), metrics,
                _e(sweep.get("note", ""))))
        else:
            dis = "".join(
                "<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td>"
                "<td>%s</td></tr>"
                % (_e(r["cve"]), _e(r.get("component") or ""),
                   _e(", ".join(r["named_by_llm"])[:52]),
                   _e(", ".join(r["edited_by_fix"][:4])
                      + (" (+%d)" % (r["edited_count"] - 4)
                         if r["edited_count"] > 4 else "")),
                   "<span class='pill pill-warn'>same file</span>"
                   if r.get("same_file_as_fix") else "")
                for r in res.get("disagreements", []))
            held = "".join("<tr><td>%s</td><td class='n'>%s</td></tr>"
                           % (_e(k), _n(v)) for k, v in
                           sorted((res.get("held_out") or {}).items(),
                                  key=lambda kv: -kv[1]))
            blocks.append("""
<h3>%s</h3>
<div class="tiles">
  <div class="tile"><div class="lab">exact function match</div>
    <div class="val">%s</div>
    <div class="meta">%d of %d scored CVEs &mdash; the model named a function the fix
    actually edits</div></div>
  <div class="tile"><div class="lab">file-level</div>
    <div class="val">%s</div>
    <div class="meta">%d near-misses added: named a function defined in a file the fix
    touches, but not the edited one</div></div>
</div>
<div class="note"><b>Agreement with the fix, not ground truth about vulnerability.</b>
A fix sometimes lands in the caller or a helper while the function the advisory
describes is untouched &mdash; OpenSSL's CVE-2020-1967 is exactly that, the model named
<code>SSL_check_chain</code> and the fix edits its helper <code>tls1_check_sig_alg</code>.
Those count as disagreements here, which is why all %d are listed rather than averaged
away. Unlike the Q3/Q4 axis this key IS two-sided, so the figure describes the model
rather than the key.</div>
<table><thead><tr><th>CVE</th><th>component</th><th>named by the model</th>
<th>edited by the fix</th><th></th></tr></thead><tbody>%s</tbody></table>
<h3>Held out</h3>
<table><thead><tr><th>reason</th><th class="n">n</th></tr></thead><tbody>%s</tbody></table>""" % (
                _e(c["title"]), _fmt(res.get("agreement")), res.get("agree", 0),
                res.get("scored", 0), _fmt(res.get("file_level_agreement")),
                res.get("near_miss_same_file", 0), res.get("disagree", 0), dis, held))

    return ("""
<h2>Component axes &mdash; what is inside each figure</h2>
<p class="sub">Each headline above contains a learned component whose own error rate the
headline does not show. These measure those components. <b>Neither is a certification
figure</b>, and neither should be read beside 0.9490 / 0.9718 as if it competed with
them.</p>""" + "".join(blocks))


def _wrap_tables(html_text):
    """Put every table in a horizontal-scroll box.

    Applied to the finished document rather than at each call site: a table added
    later would otherwise silently miss the wrapper and reintroduce the page-wide
    overflow this fixes.
    """
    return (html_text.replace("<table>", "<div class='tbl-scroll'><table>")
                     .replace("</table>", "</table></div>"))


def render(run):
    """Build the whole report from a run record produced by run_eval.py."""
    items = run["items"]
    tiles = "".join(_tile(it) for it in items if it.get("result"))
    body = [tiles and "<div class='tiles'>%s</div>" % tiles]
    for it in items:
        if not it.get("result"):
            body.append("<div class='card'><b>item #%s did not run</b>"
                        "<p class='muted'>%s</p></div>"
                        % (_e(it["item"]), _e(it.get("error") or "")))
            continue
        if it["item"] == "3":
            body.append(_item3_section(it))
        elif it["item"] == "4":
            body.append(_item4_section(it, run.get("evidence_tier") or {}))
        elif it["item"] == "q34":
            body.append(_q34_section(it))

    body.append(_components_section(run.get("components") or []))

    ds_rows = "".join(
        "<tr><td>#%s</td><td><code>%s</code></td><td class='n'>%s</td>"
        "<td class='n'>%s</td><td>%s</td></tr>"
        % (_e(d["item"]), _e(d["gt"]), _n(d.get("records")), _n(d.get("expected")),
           "<span class='pill pill-pass'>matches manifest</span>"
           if d.get("expected") is None or d.get("records") == d.get("expected")
           else "<span class='pill pill-fail'>disagrees</span>")
        for d in run.get("datasets", []))
    repro = "".join(
        "<tr><td>#%s</td><td class='n'>%s</td><td class='n'>%s</td><td>%s</td></tr>"
        % (_e(it["item"]), _fmt((it.get("result") or {}).get("precision")),
           _fmt(it.get("reference")),
           {True: "<span class='pill pill-pass'>reproduces</span>",
            False: "<span class='pill pill-fail'>differs</span>",
            None: "<span class='muted'>no recorded figure</span>"}[it.get("reproduces")])
        for it in items if it.get("result"))

    doc = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ICS-VEX Certification Evaluation</title>
<style>%s</style></head><body><div class="wrap">
<h1>ICS-VEX &mdash; certification test items #3 / #4</h1>
<p class="sub">Generated %s by <code>evaluation/run_eval.py</code>. Every figure below
was produced by this run, through the same <code>score()</code> functions the CLI and
the web console call &mdash; nothing here is transcribed.</p>
%s
<h2>Dataset integrity</h2>
<p class="sub">Each answer key is checked against the record count its own manifest
records, before anything is scored.</p>
<table><thead><tr><th>item</th><th>ground truth</th><th class="n">records</th>
<th class="n">manifest says</th><th>state</th></tr></thead><tbody>%s</tbody></table>
<h2>Does this run reproduce the recorded figures?</h2>
<table><thead><tr><th>item</th><th class="n">this run</th><th class="n">recorded</th>
<th>state</th></tr></thead><tbody>%s</tbody></table>
<div class="note"><b>What these numbers do not cover.</b> Neither item scores its whole
population, because both answer keys are earned from evidence and evidence does not
reach every member. Forcing the remainder in would mean counting undecidable as a false
positive (charging the system for a gap in the key) or assuming the unlabelled are
positives &mdash; and for #4 the pre-gate SUT answers <code>affected</code> for nearly
all of them, so FP would become structurally 0 and precision the identity 1.0. The
claim is "precision over the evidence-labelled subset", never "precision over the
population".</div>
<p class="muted">Raw result records for every item are written beside this file as
<code>results.json</code>.</p>
</div></body></html>""" % (CSS, _e(run.get("generated", "")),
                           "\n".join(x for x in body if x), ds_rows, repro)
    return _wrap_tables(doc)
