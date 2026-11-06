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
        w=csv.writer(f);w.writerow(['cwe','name','pillars','source_requirement_baseline','operational_requirement_baseline','resolution','rules','facts','rationale','definition_url','official_detection_suggestions','policy_sha256','recommended_evidence_routes','plan_basis','claim_to_examine','next_action'])
        for cid,r in sorted(data['profiles'].items(),key=lambda kv:int(kv[0][4:])):
            w.writerow([cid,r['name'],','.join(r['pillars']),r['source_requirement'],r['operational_requirement'],r['resolution'],
                ','.join(m['rule_id'] for m in r['matched_rules']),','.join(f['id'] for f in r['required_facts']),r['rationale'],r['definition_url'],
                ','.join(d['method'] for d in r['official_metadata'].get('detection_methods',[])),r['policy_sha256'],
                ','.join(r['evidence_plan']['recommended_routes']),r['evidence_plan']['basis'],
                r['evidence_plan']['claim_to_examine']['text'],r['evidence_plan']['next_action']])
    lines=['# Detailed CWE evidence requirements','',
        'Each of the 944 official CWE entries has an evidence collection plan. Directly listed detection methods are artifact-collection alternatives, not mandatory source requirements or VEX decisions. Entries without methods start with CVE/vendor mechanism evidence.','',
        'Every mapped active non-Pillar CWE has one row. Official ancestry does not assign an analysis method. No source/operational defaults, method inheritance or keyword refinements are active.','',
        'Baseline summary: `'+json.dumps(data['summary']['by_source_requirement'])+'`. Automatic routing is disabled. Only reported CWE IDs are used. See [the detailed criteria](CWE_ROUTING_CRITERIA.md).','',
        '| CWE | Name | Pillars | Source baseline | Operating baseline | Evidence collection plan |',
        '| --- | --- | --- | --- | --- | --- |']
    for cid,r in sorted(data['profiles'].items(),key=lambda kv:int(kv[0][4:])):
        lines.append('| '+ ' | '.join([f'[{cid}]({r["definition_url"]})',r['name'].replace('|','/'),', '.join(r['pillars']),r['source_requirement'],r['operational_requirement'],'; '.join(r['evidence_plan']['route_labels_ko'])])+' |')
    (ROOT/'docs/CWE_EVIDENCE_POLICY_V2.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    from build_cwe_routing_results import write_results
    write_results(data=data)
    print(json.dumps(data['summary'],ensure_ascii=False))


if __name__=='__main__':main()
