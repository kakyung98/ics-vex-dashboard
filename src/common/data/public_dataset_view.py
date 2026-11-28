"""Project refreshed advisory relationships into the UI without inventing analyses."""
from collections import defaultdict


def current_findings(previous, advisories, nvd):
    rows = defaultdict(list)
    present = set()
    for cid, findings in previous.items():
        for original in findings:
            aid = original.get('device')
            if aid in advisories and cid not in advisories[aid].get('cves', []):
                continue  # An official correction removed this advisory/CVE relation.
            r = dict(original)
            rows[cid].append(r)
            present.add((aid, cid))
    for aid, advisory in advisories.items():
        if advisory.get('error'):
            continue
        vulns = {v['cve']: v for v in advisory.get('vulns', []) if v.get('cve')}
        for cid in advisory.get('cves', []):
            if (aid, cid) in present:
                continue
            v = vulns.get(cid, {})
            rows[cid].append({'cve': cid, 'device': aid,
                             'vendor': advisory.get('vendor', ''), 'product': advisory.get('title', ''),
                             'cwe': v.get('cwe', ''), 'sev': 'unrated',
                             'final_vex': 'UNDER_INVESTIGATION', 'justification': None,
                             'tier': 'B', 'source_class': 'vendor-proprietary',
                             'route': 'refreshed-advisory-unassessed', 'analysis_performed': False,
                             'source_url': advisory.get('url')})
    for cid, findings in rows.items():
        rec = nvd.get(cid) or {}
        metric = rec.get('metric') or {}
        for r in findings:
            if metric.get('severity'):
                r['sev'] = metric['severity']
            if rec.get('cwes'):
                r['cwe'] = rec['cwes'][0]
    return rows
