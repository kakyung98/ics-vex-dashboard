"""CSAF 2.0 VEX with the operational-evidence output schema v2.0."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

from .cluster_question_pipeline import digest, SCOPE
from .operational_evidence_judge import instant

ROOT=Path(__file__).resolve().parents[1]
SCHEMAS=ROOT/'data/export_schemas/csaf_2_0'
STATUS={'affected':'known_affected','not_affected':'known_not_affected','fixed':'fixed',
        'under_investigation':'under_investigation'}
ESTIMATES={'likely_affected','likely_not_affected','likely_mitigated','likely_cannot_determine'}
POLICIES={'evidence'}


def validate_csaf(document):
    """Offline official-schema validation plus product/status reference checks."""
    from jsonschema import Draft202012Validator, FormatChecker
    from referencing import Registry, Resource
    manifest=json.loads((SCHEMAS/'manifest.json').read_text(encoding='utf-8'))
    registry=Registry()
    for name,spec in manifest.items():
        raw=(SCHEMAS/name).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=spec['sha256']:
            raise ValueError('Cached official schema hash mismatch')
        schema=json.loads(raw)
        resource=Resource.from_contents(schema)
        registry=registry.with_resource(spec['url'],resource)
        if schema.get('$id'):registry=registry.with_resource(schema['$id'],resource)
    schema=json.loads((SCHEMAS/'csaf_json_schema.json').read_text(encoding='utf-8'))
    errors=sorted(Draft202012Validator(schema,registry=registry,format_checker=FormatChecker()).iter_errors(document),key=lambda e:str(e.path))
    if errors:
        raise ValueError('CSAF schema: '+'; '.join('/'.join(map(str,e.path))+': '+e.message for e in errors[:5]))
    tree=document.get('product_tree',{})
    products=[p['product_id'] for p in tree.get('full_product_names',[])]
    products += [r['full_product_name']['product_id'] for r in tree.get('relationships',[])]
    if len(products)!=len(set(products)):raise ValueError('Duplicate product IDs')
    known=set(products)
    for relation in tree.get('relationships',[]):
        if not {relation['product_reference'],relation['relates_to_product_reference']}<=known:
            raise ValueError('Undefined product relationship reference')
    for vulnerability in document.get('vulnerabilities',[]):
        assigned=[]
        for ids in vulnerability.get('product_status',{}).values():assigned.extend(ids)
        if len(assigned)!=len(set(assigned)) or not set(assigned)<=known:
            raise ValueError('Conflicting or undefined product status reference')
        not_affected=set(vulnerability.get('product_status',{}).get('known_not_affected',[]))
        affected=set(vulnerability.get('product_status',{}).get('known_affected',[]))
        explained=set()
        for flag in vulnerability.get('flags',[]):
            if not set(flag.get('product_ids',[]))<=not_affected:
                raise ValueError('Non-impact flags must reference known_not_affected products')
            explained.update(flag.get('product_ids',[]))
        explained.update(pid for threat in vulnerability.get('threats',[]) if threat['category']=='impact'
                         for pid in threat.get('product_ids',[]))
        if not not_affected<=explained:
            raise ValueError('Known-not-affected products need a scoped flag or impact explanation')
        remediated={pid for remediation in vulnerability.get('remediations',[]) for pid in remediation.get('product_ids',[])}
        if not affected<=remediated:
            raise ValueError('Known-affected products need a scoped remediation')
        for key in ('flags','threats','remediations'):
            for row in vulnerability.get(key,[]):
                if not set(row.get('product_ids',[]))<=known:
                    raise ValueError('Undefined product reference in '+key)
        analysis=vulnerability.get('analysis')
        if analysis:
            estimate=analysis['semantic_estimation']
            if analysis['source_code_available'] is not None and type(analysis['source_code_available']) is not bool or estimate['status'] not in ESTIMATES:
                raise ValueError('Invalid operational analysis extension')
            for evidence in estimate['evidence']:
                if not {'signal','value','supports','source'}<=set(evidence) or evidence['supports'] not in ESTIMATES:
                    raise ValueError('Invalid semantic evidence signal')
    if any('analysis' in v for v in document.get('vulnerabilities',[])):
        project=json.loads((ROOT/'docs/cluster_vex_output_schema_v2.json').read_text(encoding='utf-8'))
        project_errors=list(Draft202012Validator(project,registry=registry,format_checker=FormatChecker()).iter_errors(document))
        if project_errors:
            raise ValueError('Operational output schema v2: '+project_errors[0].message)
        for vulnerability in document['vulnerabilities']:
            for analysis in vulnerability['analysis']['product_analyses']:
                pid=analysis['product_id']
                if pid not in vulnerability['product_status'].get(STATUS[analysis['formal_status']],[]):
                    raise ValueError('Analysis formal_status differs from CSAF product_status')
    tracking=document['document']['tracking']
    if instant(tracking['initial_release_date'])>instant(tracking['current_release_date']):
        raise ValueError('Initial release follows current release')
    return dict(valid=True,csaf_version='2.0',schema_validation=True,
                product_references_verified=True,operational_schema_version='2.0')


def _helper(metadata):
    result={k:deepcopy(metadata[k]) for k in ('cpe','purl','sbom_urls') if metadata.get(k)}
    return {'product_identification_helper':result} if result else {}


def _estimate(metadata):
    estimate=deepcopy(metadata.get('semantic_estimation') or {})
    status=estimate.get('status',estimate.get('assessment','likely_cannot_determine'))
    if status not in ESTIMATES:raise ValueError('Unknown semantic estimation label')
    return dict(status=status,rationale=estimate.get('rationale') or
                'No separate source-grounded semantic estimation was supplied; missing facts remain unresolved.',
                evidence=estimate.get('evidence',[]))


def export_csaf(evaluation,author,timestamp,*,metadata=None,source_policy='evidence',include_extensions=True):
    """Serialize evidence decisions; source-code availability never overrides status."""
    if not isinstance(author,str) or not author.strip() or instant(timestamp) is None:
        raise ValueError('Publisher and timezone-aware timestamp required')
    if source_policy not in POLICIES:raise ValueError('Schema v2 requires evidence policy; the legacy workbook policy has been retired')
    if type(include_extensions) is not bool:raise ValueError('include_extensions must be boolean')
    metadata=metadata or {}
    publisher=dict(category='other',name=author,namespace='urn:ics-vex:publisher:'+digest(author))
    publisher.update(metadata.get('publisher',{}))
    initial=metadata.get('initial_release_date',timestamp)
    if instant(initial) is None or instant(initial)>instant(timestamp):
        raise ValueError('Invalid initial release date')
    version=str(metadata.get('version','1'))
    history=deepcopy(metadata.get('revision_history') or [])
    if version!='1' and not history:
        raise ValueError('Revised documents require the original revision history')
    if not history or history[-1]['number']!=version:
        history.append(dict(number=version,date=timestamp,summary='Scoped cluster-question VEX export'))
    elif history[-1]['date']!=timestamp:
        raise ValueError('Current revision date must match the document release date')
    document=dict(document=dict(category='csaf_vex',csaf_version='2.0',lang='ko-KR',
        title=metadata.get('title','ICS-VEX cluster-question asset assessment'),publisher=publisher,
        tracking=dict(id=metadata.get('document_id','ics-vex:'+digest({'plan':evaluation.get('plan_id'),'decisions':evaluation['decisions']})),
            status=metadata.get('tracking_status','draft'),version=version,
            initial_release_date=initial,current_release_date=timestamp,revision_history=history)))
    names={};relationships={};vulnerabilities={};analyses={}
    for decision in evaluation['decisions']:
        binding=decision['binding'];cve=decision['cve']
        if any(not isinstance(binding.get(k),str) or not binding[k].strip() for k in SCOPE):
            raise ValueError('A complete asset/product/build/configuration/mode/time scope is required')
        scope={k:binding[k] for k in SCOPE if k!='evaluated_at'}
        scope_id='urn:ics-vex:scope:'+digest(scope)
        product=deepcopy(metadata.get('products',{}).get(binding['asset_ref'],{}))
        component=deepcopy(metadata.get('components',{}).get(cve) or product.pop('component',None))
        pid=scope_id
        display=product.get('name',binding['product'])+' '+binding['build']+' ['+binding['asset_ref']+']'
        if component:
            host_id=scope_id+':host'
            names[host_id]=dict(product_id=host_id,name=display,**_helper(product))
            component_id='urn:ics-vex:component:'+digest(dict(scope=scope,component=component))
            component_name=component['name']+' '+str(component.get('version',binding['build']))
            names[component_id]=dict(product_id=component_id,name=component_name,**_helper(component))
            pid='urn:ics-vex:relationship:'+digest([component_id,host_id])
            relationships[pid]=dict(category='default_component_of',product_reference=component_id,
                relates_to_product_reference=host_id,full_product_name=dict(product_id=pid,name=component_name+' in '+display))
        else:
            names[pid]=dict(product_id=pid,name=display,**_helper(product))
        context=deepcopy(metadata.get('vulnerabilities',{}).get(cve,{}))
        context.update((component or {}).get('analysis',{}))
        source_available=context.get('source_code_available')
        if source_available is not None and type(source_available) is not bool:raise ValueError('source_code_available must be boolean or null')
        status=decision['status']
        vulnerability=vulnerabilities.setdefault(cve,dict(product_status={},notes=[]))
        if re.fullmatch(r'CVE-\d{4}-\d{4,}',cve):vulnerability['cve']=cve
        else:vulnerability['ids']=[dict(system_name='ICS-VEX internal synthetic demonstration',text=cve)]
        if context.get('title'):vulnerability['title']=context['title']
        bucket=vulnerability['product_status'].setdefault(STATUS[status],[])
        if pid in bucket:raise ValueError('Duplicate vulnerability/product assessment')
        bucket.append(pid)
        trace=dict(scope=binding,product_id=pid,engine_status=decision['status'],exported_status=status,
                   source_policy=source_policy,source_availability_is_informational=True,
                   evidence_ids=decision.get('accepted_evidence_ids',[]),plan_id=evaluation.get('plan_id'),
                   condition_values=decision.get('condition_values',{}),
                   question_answers=decision.get('question_answer_trace',[]))
        vulnerability['notes'].extend([
            dict(category='description',title=binding['asset_ref'],text=decision['reason']),
            dict(category='details',title='Scoped decision and export-policy trace',text=json.dumps(trace,ensure_ascii=False))])
        if status=='not_affected':
            if decision.get('justification'):
                vulnerability.setdefault('flags',[]).append(dict(label=decision['justification'],product_ids=[pid]))
            vulnerability.setdefault('threats',[]).append(dict(category='impact',
                details=decision.get('impact_statement') or decision['reason'],product_ids=[pid]))
        if status=='affected':
            if not decision.get('action_statement'):raise ValueError('Affected exports require the reviewed action statement')
            vulnerability.setdefault('remediations',[]).append(dict(category='mitigation',
                details=decision['action_statement'],product_ids=[pid]))
        for remediation in context.get('remediations',[]):
            vulnerability.setdefault('remediations',[]).append(dict(deepcopy(remediation),product_ids=[pid]))
        for threat in context.get('threats',[]):
            vulnerability.setdefault('threats',[]).append(dict(deepcopy(threat),product_ids=[pid]))
        cvss=context.get('cvss')
        if cvss:
            key='cvss_v2' if cvss.get('version')=='2.0' else 'cvss_v3'
            score=dict(products=[pid],**{key:deepcopy(cvss)})
            vulnerability.setdefault('scores',[]).append(score)
        if context.get('references'):
            refs=deepcopy(context['references'])
            vulnerability['references']=list({json.dumps(r,sort_keys=True):r for r in vulnerability.get('references',[])+refs}.values())
        estimate=_estimate(context)
        answers=deepcopy(decision.get('question_answer_trace',[]))
        for answer in answers:
            answer.setdefault('question_text',None)
            answer.setdefault('target',None)
            answer.setdefault('condition_ids',[])
        analysis=dict(source_code_available=source_available,semantic_estimation=estimate,
            scope=deepcopy(binding),formal_status=status,
            condition_values=deepcopy(decision.get('condition_values',{})),
            condition_definitions=deepcopy(decision.get('condition_definitions',[])),
            formula=deepcopy(decision.get('formula_definition')),
            formula_value=decision.get('formula_value','unknown'),
            formula_complete=bool(decision.get('formula_complete',False)),
            answer_conflicts=deepcopy(decision.get('answer_conflicts',[])),
            question_plan=dict(plan_id=evaluation.get('plan_id'),
                common_answers=[a for a in answers if a.get('common_question_id')],
                specific_answers=[a for a in answers if not a.get('common_question_id')],
                remaining_condition_ids=deepcopy(decision.get('remaining_logical_condition_ids',[])),
                next_common_question_ids=deepcopy(decision.get('next_common_question_ids',[])),
                next_specific_question_ids=[q['id'] for q in decision.get('next_specific_questions',[])]),
            evidence=dict(accepted_ids=deepcopy(decision.get('accepted_evidence_ids',[])),
                          proofs=deepcopy(decision.get('proofs',[])),decision_trace=deepcopy(decision.get('decision_trace',[]))),
            decision_reason=decision['reason'],missing_evidence=deepcopy(decision.get('missing_evidence',[])))
        if context.get('epss') is not None:
            probability=float(context['epss'])
            if not 0<=probability<=1:raise ValueError('EPSS must be between 0 and 1')
            analysis['epss']=str(context['epss'])
        if context.get('hbom_evidence') is not None:analysis['hbom_evidence']=deepcopy(context['hbom_evidence'])
        analyses.setdefault(cve,[]).append(dict(product_id=pid,**analysis))
    if not vulnerabilities:raise ValueError('At least one bound asset decision is required; do not export an empty VEX')
    document['product_tree']=dict(full_product_names=list(names.values()))
    if relationships:document['product_tree']['relationships']=list(relationships.values())
    for cve,vulnerability in vulnerabilities.items():
        per_product=analyses[cve]
        if include_extensions:
            availability={p['source_code_available'] for p in per_product}
            analysis=dict(schema_version='2.0',method='operational_evidence',
                source_code_available=per_product[0]['source_code_available'] if len(availability)==1 else None,
                semantic_estimation=deepcopy(per_product[0]['semantic_estimation']) if len({digest(p['semantic_estimation']) for p in per_product})==1 else _estimate({}),
                product_analyses=per_product)
            vulnerability['analysis']=analysis
        else:
            vulnerability['notes'].append(dict(category='details',title='Operational analysis v2 fields',
                text=json.dumps(per_product,ensure_ascii=False)))
    document['vulnerabilities']=list(vulnerabilities.values())
    validate_csaf(document)
    return document
