"""Join the corpus snapshot to the official daily EPSS CSV, then render statistics."""
import csv
import gzip
import hashlib
import io
import json
import math
from pathlib import Path
import re
import statistics
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.common.data.weakness_taxonomy import display_names
from src.common.dataset_statistics import render


def number(value, maximum):
    if value is None or isinstance(value, bool) or not str(value).strip():
        return None
    try:
        value = float(value)
    except (ValueError, TypeError):
        return None
    return value if math.isfinite(value) and 0 <= value <= maximum else None


def build(records, epss_rows, score_date, names=None):
    from collections import Counter
    names = names or {}
    records = {r['cve']: r for r in records}
    cwes = Counter()
    cwe_available = 0
    scores, probabilities = [], []
    cvss_bins = [0]*6
    epss_bins = [0]*5
    for cid, record in records.items():
        reported = set(re.findall(r'\bCWE-\d+\b', str(record.get('cwe') or '')))
        cwes.update(reported)
        cwe_available += bool(reported)
        score = number(record.get('cvss'), 10)
        if score is None:
            cvss_bins[5] += 1
        else:
            scores.append(score)
            cvss_bins[0 if score == 0 else 1 if score < 4 else 2 if score < 7 else 3 if score < 9 else 4] += 1
        probability = number((epss_rows.get(cid) or {}).get('epss'), 1)
        if probability is None:
            epss_bins[4] += 1
        else:
            probabilities.append(probability)
            epss_bins[0 if probability < .01 else 1 if probability < .1 else 2 if probability < .5 else 3] += 1

    def distribution(values, bins, labels, colors):
        return dict(available=len(values), missing=len(records)-len(values),
                    mean=statistics.mean(values) if values else None,
                    median=statistics.median(values) if values else None,
                    bins=[dict(label=label, count=count, color=color) for label, count, color in zip(labels, bins, colors)])

    return dict(total_cves=len(records),
        cwe=dict(available=cwe_available, missing=len(records)-cwe_available,
                 counts=[dict(id=key, label=key + (' · ' + names[key] if key in names else ''), count=count)
                         for key, count in sorted(cwes.items(), key=lambda item: (-item[1], item[0]))]),
        cvss=distribution(scores, cvss_bins, ['None · 0', 'Low · >0–<4', 'Medium · 4–<7', 'High · 7–<9', 'Critical · 9–10', 'Unavailable'],
                          ['#94a08a', '#86b79d', '#d9bd73', '#d79472', '#bd7176', '#b8bac3']),
        epss=dict(distribution(probabilities, epss_bins, ['0–<1%', '1–<10%', '10–<50%', '50–100%', 'Unavailable'],
                               ['#c8bee9', '#ab98db', '#8870bf', '#6246a4', '#b8bac3']), score_date=score_date))


def main():
    out = ROOT/'results/dataset_statistics'
    raw = (out/'epss_scores.csv.gz').read_bytes()
    text = gzip.decompress(raw).decode('utf-8-sig')
    lines = text.splitlines()
    comment = '\n'.join(line for line in lines if line.startswith('#'))
    date = re.search(r'score_date\s*:\s*(\d{4}-\d{2}-\d{2})', comment)
    assert date, 'Official daily score date is required'
    epss_rows = {r['cve']: r for r in csv.DictReader(io.StringIO('\n'.join(line for line in lines if not line.startswith('#'))))}
    source = ROOT/'site/cve_index.json'
    records = json.loads(source.read_text(encoding='utf-8'))
    snapshot = build(records, epss_rows, date[1], display_names())
    snapshot['sources'] = dict(corpus='cve_index.json', corpus_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        epss_url='https://epss.empiricalsecurity.com/epss_scores-current.csv.gz',
        epss_sha256=hashlib.sha256(raw).hexdigest(), epss_header=comment)
    assert snapshot['total_cves'] == 12418
    for key in ['cvss', 'epss']:
        assert sum(b['count'] for b in snapshot[key]['bins']) == snapshot['total_cves']
    (ROOT/'site/dataset_statistics.json').write_text(json.dumps(snapshot, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    (ROOT/'site/dataset_statistics.html').write_text(render(snapshot), encoding='utf-8')
    print(json.dumps({k: ({a:b for a,b in v.items() if a not in {'counts', 'bins'}} if isinstance(v,dict) else v)
                      for k,v in snapshot.items() if k != 'sources'}))


if __name__ == '__main__':
    main()
