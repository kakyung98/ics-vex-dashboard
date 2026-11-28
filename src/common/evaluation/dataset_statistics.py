"""Render corpus metadata statistics from a dated, reproducible snapshot."""
from html import escape
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def render(snapshot=None):
    path = ROOT / 'site/dataset_statistics.json'
    if snapshot is None:
        if not path.exists():
            return ''
        snapshot = json.loads(path.read_text(encoding='utf-8'))
    s = snapshot
    total = s['total_cves']

    def rows(items, scale=None):
        maximum = scale or max((r['count'] for r in items), default=1) or 1
        return '<div class="ds-bars">' + ''.join(
            '<div class="ds-row"><span title="' + escape(r['label'], quote=True) + '">' +
            escape(r['label']) + '</span><span class="ds-track" role="meter" aria-label="' +
            escape(r['label'], quote=True) + '" aria-valuemin="0" aria-valuemax="' + str(total) +
            '" aria-valuenow="' + str(r['count']) + '"><i style="width:' +
            str(round(100*r['count']/maximum, 3)) + '%;background:' +
            r.get('color', 'var(--lavender,#b8aceb)') + '"></i></span><b>' +
            f"{r['count']:,}" + '</b><small>' + f"{100*r['count']/total:.1f}%" +
            '</small></div>' for r in items) + '</div>'

    def average(value, percent=False):
        return '—' if value is None else (f'{value*100:.2f}%' if percent else f'{value:.2f}')

    def coverage(stat):
        return f"{stat['available']:,} / {total:,} CVEs · {stat['missing']:,} unavailable"

    cwe, cvss, epss = s['cwe'], s['cvss'], s['epss']
    cwe_rows = cwe['counts']
    html = '''<section id="dataset-metadata-statistics" aria-label="CWE, CVSS and EPSS statistics">
<style>
#dataset-metadata-statistics .ds-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px}
#dataset-metadata-statistics .ds-grid>.card{min-width:0}
#dataset-metadata-statistics .ds-bars{display:grid;gap:12px;margin:20px 0}
#dataset-metadata-statistics .ds-row{display:grid;grid-template-columns:minmax(100px,1.3fr) minmax(50px,2fr) 52px 48px;gap:12px;align-items:center;font-size:13px}
#dataset-metadata-statistics .ds-row>span:first-child{overflow-wrap:anywhere}
#dataset-metadata-statistics .ds-track{height:12px;background:var(--card2);border-radius:5px;overflow:hidden}
#dataset-metadata-statistics .ds-track i{display:block;height:100%;border-radius:5px}
#dataset-metadata-statistics .ds-row b,#dataset-metadata-statistics .ds-row small{text-align:right;font-variant-numeric:tabular-nums}
#dataset-metadata-statistics .ds-row small{color:var(--ink2)}
#dataset-metadata-statistics .ds-cwe .ds-row{grid-template-columns:minmax(160px,1.3fr) minmax(70px,2fr) 52px 48px}
#dataset-metadata-statistics .ds-summary{display:flex;gap:24px;flex-wrap:wrap;margin:16px 0}
#dataset-metadata-statistics .ds-summary b{display:block;font-size:26px;font-weight:600}
#dataset-metadata-statistics .ds-summary span{font-size:12px;color:var(--ink2)}
#dataset-metadata-statistics summary{cursor:pointer;color:var(--purple);font-size:13px}
@media(max-width:900px){#dataset-metadata-statistics .ds-grid{grid-template-columns:1fr;gap:0}}
@media(max-width:540px){#dataset-metadata-statistics .ds-row,#dataset-metadata-statistics .ds-cwe .ds-row{grid-template-columns:minmax(90px,1.2fr) minmax(30px,1fr) 44px 42px;gap:7px;font-size:12px}}
</style>'''
    html += '<div class="card ds-cwe"><h3>CWE · reported weakness types</h3><p class="hint">' + coverage(cwe) + \
        f" · {len(cwe_rows):,} distinct CWE IDs</p>" + rows(cwe_rows[:12])
    if len(cwe_rows) > 12:
        html += '<details><summary>Show all ' + str(len(cwe_rows)) + ' reported CWE types</summary>' + rows(cwe_rows[12:], cwe_rows[0]['count']) + '</details>'
    html += '<p class="hint">Top 12 shown. Counts use the reported CWE field in the corpus snapshot; no new CWE is assigned. A CVE with multiple reported IDs can appear in multiple rows. Percentages use all ' + f'{total:,}' + ' CVEs. Missing or unspecified CWE: ' + f"{cwe['missing']:,}" + '.</p></div>'
    html += '<div class="ds-grid"><div class="card"><h3>CVSS · base score severity</h3><p class="hint">' + coverage(cvss) + '</p>'
    html += '<div class="ds-summary"><div><b>' + average(cvss['mean']) + '</b><span>Mean base score</span></div><div><b>' + average(cvss['median']) + '</b><span>Median base score</span></div></div>' + rows(cvss['bins'])
    html += '<p class="hint">Severity is derived from each stored base score (0–10), using the displayed ranges. Scores retain their source versions. Mean and median exclude unavailable values; percentages include all CVEs.</p></div>'
    html += '<div class="card"><h3>EPSS · exploitation probability</h3><p class="hint">' + coverage(epss) + '</p>'
    html += '<div class="ds-summary"><div><b>' + average(epss['mean'], True) + '</b><span>Mean probability</span></div><div><b>' + average(epss['median'], True) + '</b><span>Median probability</span></div></div>' + rows(epss['bins'])
    html += '<p class="hint">Score date: <b>' + escape(epss['score_date'] or 'unavailable') + '</b> · <a href="https://www.first.org/epss/" target="_blank" rel="noopener">FIRST EPSS</a> estimates exploitation in the next 30 days. Probability is shown, not percentile. Unavailable scores remain unknown; mean and median use available scores only.</p></div></div></section>'
    return html
