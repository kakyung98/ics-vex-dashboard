"""Reproducible 944-row policy export from the pinned official hierarchy."""
from pathlib import Path
import csv,json,sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.cwe_evidence_policy import catalog


def main():
    data=catalog();assert data['summary']['detailed_cwes']==944
    folder=ROOT/'data/cwe_routing/v2';folder.mkdir(parents=True,exist_ok=True)
    (folder/'profiles.json').write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    (folder/'summary.json').write_text(json.dumps(data['summary'],ensure_ascii=False,indent=2),encoding='utf-8')
    with (folder/'profiles.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.writer(f);w.writerow(['cwe','name','pillars','source_requirement_baseline','operational_requirement_baseline','resolution','rules','facts','rationale','definition_url','official_mapping_usage','mapping_review_needed','official_detection_suggestions','policy_sha256'])
        for cid,r in sorted(data['profiles'].items(),key=lambda kv:int(kv[0][4:])):
            w.writerow([cid,r['name'],','.join(r['pillars']),r['source_requirement'],r['operational_requirement'],r['resolution'],
                ','.join(m['rule_id'] for m in r['matched_rules']),','.join(f['id'] for f in r['required_facts']),r['rationale'],r['definition_url'],
                r['cve_mapping_gate']['usage'],r['cve_mapping_gate']['requires_mapping_review'],
                ','.join(d['method'] for d in r['official_metadata'].get('detection_methods',[])),r['policy_sha256']])
    lines=['# Detailed CWE evidence requirements','',
        'Project policy derived from explicit evidence rules and the pinned CWE v5.0 View 1000. Taxonomy membership is official; routing requirements are project hypotheses, not independently adjudicated ground truth. No VEX verdict follows from this table.','',
        'Every mapped active non-Pillar CWE has one row. Ancestor rules apply only through explicit detailed anchors, selecting the nearest match; equally specific requirements are combined. No Pillar-wide source default exists. Hardware/design and unspecified mechanisms remain unresolved.','',
        'Baseline summary: `'+json.dumps(data['summary']['by_source_requirement'])+'`. Actual CVE routes apply explicit mechanism refinements; mapping usage is advisory only and does not block analysis. See [the detailed criteria](CWE_ROUTING_CRITERIA.md).','',
        '| CWE | Name | Pillars | Source baseline | Operating baseline | Rule / resolution | CVE mapping usage |',
        '| --- | --- | --- | --- | --- | --- | --- |']
    for cid,r in sorted(data['profiles'].items(),key=lambda kv:int(kv[0][4:])):
        lines.append('| '+ ' | '.join([f'[{cid}]({r["definition_url"]})',r['name'].replace('|','/'),', '.join(r['pillars']),r['source_requirement'],r['operational_requirement'],', '.join(m['rule_id'] for m in r['matched_rules'])+' / '+r['resolution'],r['cve_mapping_gate']['usage']])+' |')
    (ROOT/'docs/CWE_EVIDENCE_POLICY_V2.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    from build_cwe_routing_results import write_results
    write_results(data=data)
    print(json.dumps(data['summary'],ensure_ascii=False))


if __name__=='__main__':main()
