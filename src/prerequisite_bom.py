"""Preserve the uploaded BOM and bind context decisions to exact inventory refs."""
from copy import deepcopy
import json
from .cluster_question_pipeline import digest


def identification_snapshot(job_id, reviewed_cves):
    from .candidate_web import get_job
    job=get_job(job_id)
    if not job or job.get('status')!='completed':raise ValueError('Identification job is missing or incomplete')
    if not job.get('input_sbom'):raise ValueError('Identification job has no original BOM')
    mappings={}
    result=job['result']
    for row in list(result['components'])+([result['asset_analysis']] if result.get('asset_analysis') else []):
        component=row['component']
        for finding in row.get('cves',[]):
            if finding.get('match_status')=='no_match' or not finding.get('cve_id'):continue
            mappings.setdefault(finding['cve_id'],[]).append(dict(component_ref=str(component['id']),
                name=component.get('name',''),version=component.get('version',''),match_status=finding.get('match_status')))
    if not set(reviewed_cves)<=set(mappings):raise ValueError('Reviewed CVE is outside this identification job')
    return dict(job_id=job_id,input_bom=deepcopy(job['input_sbom']),input_digest=digest(job['input_sbom']),
                cve_mappings=mappings,architecture=result.get('architecture'),simulation=bool(result.get('input_notice')))


def context_bom(saved,evaluation):
    snapshot=saved.get('identification')
    if not snapshot:return None
    if digest(snapshot['input_bom'])!=snapshot['input_digest']:raise ValueError('Original BOM snapshot changed')
    decisions={d['binding']['cve']:d for d in evaluation['decisions']}
    rows=[]
    for cve,mappings in sorted(snapshot['cve_mappings'].items()):
        decision=decisions.get(cve)
        for mapping in mappings:
            scoped=bool(decision and decision['binding']['asset_ref']==mapping['component_ref'] and
                        decision['binding']['build']==mapping['version'])
            rows.append(dict(cve=cve,**mapping,status=decision['status'] if scoped else 'under_investigation',
                reason=decision.get('reason') if scoped else 'No reviewed assessment for this exact component and installed build',
                scope=deepcopy(decision['binding']) if scoped else None,
                condition_values=deepcopy(decision.get('condition_values',{})) if scoped else {}))
    result=dict(schema='ics-vex-context-bom/1',classification='Research-defined context BOM envelope',
        identification_job_id=snapshot['job_id'],input_bom_digest=snapshot['input_digest'],
        input_bom=deepcopy(snapshot['input_bom']),simulation=snapshot['simulation'],
        plan_id=saved['plan']['plan_id'],clustering=deepcopy(saved.get('clustering')),
        condition_question_templates=deepcopy(saved.get('template_catalog',[])),
        source_reviews=deepcopy(saved['plan']['reviews']),asset_cases=deepcopy(saved.get('last_cases',[])),
        component_assessments=rows,decisions=deepcopy(evaluation['decisions']),
        unreviewed_cves=sorted(set(snapshot['cve_mappings'])-set(decisions)),
        coverage=dict(candidate_cves=len(snapshot['cve_mappings']),reviewed_cves=len(decisions),
                      component_links=len(rows),assessed_component_links=sum(r['scope'] is not None for r in rows)))
    if result['input_bom'].get('bomFormat')=='CycloneDX':
        from .sbom_vex import STATE,JUST,normalize_input_copy
        bom=deepcopy(result['input_bom']);bom.pop('signature',None)
        bom['version']=int(bom.get('version',1))+1
        refs=set()
        def walk(items):
            for c in items:
                if c.get('bom-ref'):refs.add(str(c['bom-ref']))
                walk(c.get('components',[]))
        walk(bom.get('components',[]))
        root=bom.get('metadata',{}).get('component',{})
        if root.get('bom-ref'):refs.add(str(root['bom-ref']))
        vulnerabilities=[v for v in bom.get('vulnerabilities',[]) if v.get('id') not in snapshot['cve_mappings']]
        bound=0
        for row in rows:
            ref=row['component_ref']
            # Matcher's positional IDs are resolved against the original top-level inventory.
            if ref not in refs and ref.isdecimal() and int(ref)<len(bom.get('components',[])):
                c=bom['components'][int(ref)]
                if not c.get('bom-ref'):c['bom-ref']='ics-vex-component-'+ref
                ref=str(c['bom-ref']);refs.add(ref)
            if ref not in refs:continue
            bound+=1
            analysis=dict(state=STATE[row['status']],detail=row['reason'] or 'Evidence incomplete')
            if row['status']=='not_affected':
                just=decisions[row['cve']].get('justification')
                if just in JUST:analysis['justification']=JUST[just]
            vulnerabilities.append(dict(id=row['cve'],**{'bom-ref':'vex-'+digest([row['cve'],ref])[:24]},
                source=dict(name='NVD',url='https://nvd.nist.gov/vuln/detail/'+row['cve']),
                affects=[dict(ref=ref)],analysis=analysis,
                properties=[dict(name='ics-vex:context',value=json.dumps(row,ensure_ascii=False)),
                            dict(name='ics-vex:plan-id',value=saved['plan']['plan_id'])]))
        bom['vulnerabilities']=vulnerabilities
        bom.setdefault('properties',[]).append(dict(name='ics-vex:context-bom',value=json.dumps(
            {k:result[k] for k in ('schema','plan_id','coverage','unreviewed_cves')},ensure_ascii=False)))
        changes=normalize_input_copy(bom)
        if changes:bom['properties'].append(dict(name='ics-vex:input-normalizations',value=json.dumps(changes)))
        from .sbom_schema import validate
        result['cyclonedx']=bom;result['cyclonedx_validation']=validate(bom)
        result['unbound_component_links']=len(rows)-bound
    return result
