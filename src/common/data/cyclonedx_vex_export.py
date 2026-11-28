"""Merge reviewed decisions into a copy of the original CycloneDX inventory."""
from copy import deepcopy
from datetime import datetime,timezone
import hashlib,json

STATE={'under_investigation':'in_triage','affected':'exploitable','not_affected':'not_affected','fixed':'resolved'}
JUST={'vulnerable_code_not_present':'code_not_present','vulnerable_code_not_in_execute_path':'code_not_reachable',
      'vulnerable_code_cannot_be_controlled_by_adversary':'protected_at_runtime','inline_mitigations_already_exist':'protected_by_mitigating_control'}

def normalize_input_copy(document):
    changes=[]
    def walk(obj,path):
        if isinstance(obj,dict):
            for entry in obj.get('licenses',[]) if isinstance(obj.get('licenses'),list) else []:
                license=entry.get('license') if isinstance(entry,dict) else None
                if isinstance(license,dict) and license.get('id') in {'NOASSERTION','NONE'}:
                    old=license.pop('id');license.setdefault('name',old)
                    changes.append({'path':path+['licenses'],'change':'unknown SPDX marker represented as a license name, not an SPDX identifier','original':old})
            refs=obj.get('externalReferences')
            if isinstance(refs,list):
                rebuilt=[]
                for r in refs:
                    if not isinstance(r,dict):rebuilt.append(r);continue
                    if r.get('type')=='advisory':r['type']='advisories';changes.append({'path':path+['externalReferences'],'change':'advisory -> advisories'})
                    if isinstance(r.get('url'),list) and r['url'] and all(isinstance(u,str) for u in r['url']):
                        changes.append({'path':path+['externalReferences'],'change':'URL array expanded into separate string-valued references','original':r['url']})
                        rebuilt.extend({**r,'url':u} for u in r['url'])
                    else:rebuilt.append(r)
                obj['externalReferences']=rebuilt
            for k,v in list(obj.items()):walk(v,path+[k])
        elif isinstance(obj,list):
            for i,v in enumerate(obj):walk(v,path+[i])
    walk(document,[])
    return changes

def merge(sbom,review,cases):
    if sbom.get('bomFormat')!='CycloneDX':raise ValueError('Embedded VEX export currently requires CycloneDX; use OpenVEX/CSAF for SPDX input.')
    out=deepcopy(sbom);out['version']=int(out.get('version',1))+1
    signature=out.pop('signature',None)
    if signature:out.setdefault('properties',[]).append({'name':'ics-vex:input-signature','value':'Removed because this is a modified document; original input is preserved separately.'})
    refs={};position_refs={}
    def inventory(items):
        for i,c in enumerate(items):
            if 'bom-ref' not in c:c['bom-ref']='component-'+hashlib.sha256((json.dumps(c,sort_keys=True)+'|'+str(len(refs))).encode()).hexdigest()[:20]
            if str(c['bom-ref']) in refs:raise ValueError('Duplicate component bom-ref.')
            refs[str(c['bom-ref'])]=c
            inventory(c.get('components',[]))
    inventory(out.get('components',[]))
    position_refs={str(i):str(c['bom-ref']) for i,c in enumerate(out.get('components',[]))}
    for ref,f in review.get('component_facts',{}).items():
        target=ref if ref in refs else position_refs.get(ref)
        if not target or f.get('present')!='yes' or not f.get('attested') or not f.get('evidence') or not f.get('installed_version'):continue
        c=refs[target];old=c.get('version')
        c.setdefault('properties',[]).extend([{'name':'ics-vex:original-version','value':str(old or '')},
            {'name':'ics-vex:operator-product','value':f.get('product_name','')},
            {'name':'ics-vex:version-record','value':f['evidence']},
            {'name':'ics-vex:version-provenance','value':'operator-attested; not independently verified'}])
        c['version']=f['installed_version']
    by_cve={c['cve']:c for c in cases};old=out.get('vulnerabilities',[])
    existing={v.get('id'):v for v in old};reviewed={s['cve'] for s in review['statements']}
    vulnerabilities=[deepcopy(v) for v in old if v.get('id') not in reviewed]
    for s in review['statements']:
        case=by_cve[s['cve']];mappings=case.get('mappings') or []
        targets=sorted({str(m.get('component_id')) if str(m.get('component_id')) in refs else position_refs[str(m.get('component_id'))] for m in mappings if str(m.get('component_id')) in refs or str(m.get('component_id')) in position_refs})
        if not targets:
            names={case.get('component')}
            targets=[ref for ref,c in refs.items() if c.get('name') in names]
        if not targets and len(refs)==1:targets=list(refs)
        if not targets:raise ValueError('Cannot bind reviewed CVE to a component bom-ref: '+s['cve'])
        version_rows={r['component_ref'] if r['component_ref'] in refs else position_refs.get(r['component_ref']):r
                      for r in s.get('operational_review',{}).get('version_evaluation',{}).get('components',[])}
        for ref in targets:
            record=deepcopy(existing.get(s['cve'],{}));record.pop('analysis',None)
            record['id']=s['cve'];record['bom-ref']='vex-'+hashlib.sha256((s['cve']+'|'+ref).encode()).hexdigest()[:24]
            record.setdefault('source',{'name':'NVD','url':'https://nvd.nist.gov/vuln/detail/'+s['cve']})
            r=version_rows.get(ref);status=s['status'];just=s.get('justification')
            scoped = next((e for e in s.get('evidence_decision', {}).get('components', [])
                           if e['asset_ref'] == ref or position_refs.get(e['asset_ref']) == ref), None)
            if s.get('evidence_decision'):
                status = scoped['status'] if scoped else 'under_investigation'
                just = scoped.get('justification') if scoped else None
                if scoped and status != 'under_investigation' and scoped.get('binding', {}).get('build') != refs[ref].get('version'):
                    raw_case = review.get('evidence_reviews', {}).get(s['cve'], {}).get(scoped['asset_ref'], {}).get('case', {})
                    valid_ids = {e['id'] for e in scoped.get('evidence_validation', []) if e['valid']}
                    installed = any(e['kind']=='installation_record' and e['id'] in valid_ids for e in raw_case.get('evidence', []))
                    if installed:
                        c=refs[ref]
                        c.setdefault('properties', []).append({'name':'ics-vex:original-version','value':str(c.get('version',''))})
                        c['version']=scoped['binding']['build']
                        c['properties'].append({'name':'ics-vex:version-provenance','value':'Scoped reviewed installation record; human declaration'})
                    else:
                        status='under_investigation';just=None
            elif r and s.get('evidence_progress',{}).get('ready_for_authoring',True) and not s.get('branch_evidence',{}).get('source'):
                if r['state']=='listed_fixed' and r['operator_attested'] and r['operator_evidence']:status='fixed';just=None
                else:status='under_investigation';just=None
            draft=s.get('document_draft');text=draft.get('impact_statement') if draft else s.get('reason','Evidence incomplete.')
            if scoped:text=(scoped.get('impact_statement') or scoped['reason'])+' Scope: '+json.dumps(scoped.get('binding', {}),ensure_ascii=False)
            elif s.get('evidence_decision'):text='No current scoped evidence assessment for this component.'
            elif status!=s['status']:text='Component-specific version review: '+str(r.get('state') if r else 'unknown')+'. Operator report requires review.'
            if scoped and status != scoped['status']:text+=' Input SBOM build differs; a valid installation record is required before binding this result to its inventory component.'
            if scoped and scoped.get('action_statement'):text+=' Action: '+scoped['action_statement']
            if case.get('simulation') and 'simulat' not in text.lower():text='Simulated inventory review. '+text
            if r:text+=' Product/version: '+str(r['product_name'])+' / '+str(r['installed_version'])+'.'
            text+=' Draft for review; independent deployment verification has not been performed.'
            analysis={'state':STATE.get(status,'in_triage'),'detail':text}
            if status=='not_affected' and just in JUST:analysis['justification']=JUST[just]
            record['analysis']=analysis;record['affects']=[{'ref':ref}]
            props=[p for p in record.get('properties',[]) if not p.get('name','').startswith('ics-vex:')]
            props.extend([{'name':'ics-vex:case-id','value':s['case_id']},
                {'name':'ics-vex:standard-status','value':status},{'name':'ics-vex:review-required','value':'true'},
                {'name':'ics-vex:explanation-origin','value':'reviewed_evidence_rule_summary' if scoped else 'validated_model_draft' if draft and status==s['status'] else 'component_or_rule_summary'},
                {'name':'ics-vex:authoring-status','value':s.get('authoring',{}).get('status','unavailable')}])
            if scoped:props.append({'name':'ics-vex:evidence-refs','value':json.dumps(scoped.get('accepted_evidence_ids',[]))})
            elif draft:props.append({'name':'ics-vex:evidence-refs','value':json.dumps(draft.get('evidence_refs',[]))})
            record['properties']=props;vulnerabilities.append(record)
    out['vulnerabilities']=vulnerabilities
    out.setdefault('properties',[]).append({'name':'ics-vex:review-required','value':'true'})
    changes=normalize_input_copy(out)
    if changes:out['properties'].append({'name':'ics-vex:input-normalizations','value':json.dumps(changes,ensure_ascii=False)})
    out.setdefault('metadata',{})['timestamp']=datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
    return out
