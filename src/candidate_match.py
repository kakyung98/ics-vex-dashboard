"""HTTP integration for the isolated LangGraph candidate retrieval pipeline."""
from ics_agent_matcher_full.ics_agent_matcher.matcher import NVD, extract, run


def match_candidates(sbom, offline=False, nvd=None, agent_mode='unified',lookup_mode=None,progress=None):
    if not isinstance(sbom, dict):
        raise ValueError('SBOM must be a JSON object')
    from src.project_input_contract import to_analysis_input
    sbom=to_analysis_input(sbom)
    components = extract(sbom)
    if len(components) > 100:
        raise ValueError('At most 100 components per candidate lookup')
    if agent_mode not in {'unified','rules','base','tuned','evidence','evidence_llm'}:
        raise ValueError('Unsupported agent_mode')
    lookup_mode=lookup_mode or ('none' if offline else 'live')
    if lookup_mode not in {'live','local','none'}:raise ValueError('lookup_mode must be live, local or none')
    if nvd is None:
        if lookup_mode=='local':
            from src.candidate_snapshot import SnapshotNVD
            nvd=SnapshotNVD()
        else:nvd=NVD(offline=lookup_mode=='none')
    requested_mode=agent_mode
    from src.unified_identification import run_unified
    result=run_unified(sbom,nvd,progress=progress,mode='rules' if agent_mode=='rules' else None)
    result['requested_agent_mode']=requested_mode
    result['identity_notice']=('Local P2/P3/P4 agents review supplied evidence; source, dictionary and version checks guard every accepted output. Agent failures remain visible and unresolved.'
        if result['identification_mode']=='agents' else 'Deterministic product/version/identifier checks; no identification model runs.')
    asset=(sbom.get('metadata') or {}).get('component') or {}
    if sbom.get('bomFormat')=='CycloneDX' and asset.get('cpe'):
        from copy import deepcopy
        from src.identity_evidence import run_evidence
        asset_input=deepcopy(asset)
        asset_input.setdefault('bom-ref','metadata:component')
        if any(c['component']['id']==asset_input['bom-ref'] for c in result['components']):
            result['asset_analysis_note']='The representative asset shares a component reference and is already included in the component analysis.'
        else:
            envelope={'bomFormat':'CycloneDX','components':[asset_input],
                      'metadata':deepcopy(sbom.get('metadata',{})),'properties':deepcopy(sbom.get('properties',[]))}
            asset_result=run_unified(envelope,nvd,mode=result['identification_mode'],progress=progress)
            result['asset_analysis']=asset_result['components'][0]
            result['llm_used']=result['llm_used'] or asset_result['llm_used']
            result['asset_analysis']['analysis_role']='representative_asset'
            result['asset_analysis']['architecture']=result['architecture']
    analyzed_rows=list(result['components'])+([result['asset_analysis']] if result.get('asset_analysis') else [])
    if lookup_mode!='none':
        from src.candidate_advisories import retrieve
        for row in analyzed_rows:
            advisory_records=retrieve(row['component'])
            row['advisory_evidence']=[r['evidence'] for r in advisory_records]
            existing={r['cve_id']:r for r in row.get('cves',[])}
            for record in advisory_records:
                if record['cve_id'] in existing:
                    existing[record['cve_id']].setdefault('advisory_evidence',[]).append(record['evidence'])
                else:existing[record['cve_id']]=record
            row['cves']=list(existing.values())
    from src.identification_output import split_findings
    for row in analyzed_rows:
        row['confirmed_cves'],row['review_candidates']=split_findings(row.get('cves',[]))
    result['agent_mode']='llm_agents' if result['identification_mode']=='agents' else 'deterministic'
    result['lookup_mode']=lookup_mode
    asset=sbom.get('metadata',{}).get('component',{})
    result['asset']={k:asset[k] for k in ('name','bom-ref','purl','version','type') if k in asset}
    result['asset_summary']={'analyzed':bool(result.get('asset_analysis')),
        'identity_accepted':result.get('asset_analysis',{}).get('validation',{}).get('status')=='validated',
        'unique_cves':len({v['cve_id'] for v in result.get('asset_analysis',{}).get('cves',[]) if v.get('match_status')!='no_match'})}
    result['candidate_sources']=['NVD','CISA advisory snapshot'] if lookup_mode!='none' else []
    properties=sbom.get('metadata',{}).get('component',{}).get('properties',[])
    if any(p.get('name')=='dataset:synthetic-inventory' and str(p.get('value')).lower()=='true' for p in properties):
        result['input_notice']='This input is marked as an advisory-derived synthetic SBOM. Retrieving the same advisory corpus is not an independent model-performance test.'
    if lookup_mode=='local':
        result['lookup_notice']='Declared SBOM versions and ranges are compared with local product/version conditions. Full platform and AND/OR configuration applicability remains separate.'
    result['summary'] = {
        'components': len(result['components']),
        'validated': sum(c.get('validation', {}).get('status') == 'validated'
                         for c in result['components']),
        'candidate_records': sum(len(c.get('cves', [])) for c in result['components']),
        'unique_cves':len({v['cve_id'] for c in result['components'] for v in c.get('cves',[])}),
        'errors':sum('error' in c for c in result['components']),
        'optional_ranking_errors':sum((c.get('l2',{}).get('agent') or {}).get('status') in {'unavailable','rejected'} for c in result['components']) if agent_mode=='evidence_llm' else 0,
        'model_stage_errors':sum((c.get(key,{}).get('agent') or {}).get('status') in {'unavailable','rejected'}
                                 for c in analyzed_rows for key in ('l2','l3','l4')),
        'advisory_linked':sum(bool(c.get('advisory_evidence')) for c in result['components']),
        'unknown_records':sum(v.get('match_status')=='unknown' for c in result['components'] for v in c.get('cves',[])),
        'matched_records':sum(v.get('match_status')=='match' for c in result['components'] for v in c.get('cves',[])),
        'confirmed_mapping_records':sum(len(c['confirmed_cves']) for c in result['components']),
        'review_candidate_records':sum(len(c['review_candidates']) for c in result['components']),
    }
    from src.identification_diagnostics import explain_identification
    return explain_identification(result,sbom)
