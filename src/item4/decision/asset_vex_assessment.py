"""Fourth role: source logic + attributed operator choices -> scoped VEX.

No language inference or manufactured inventory/configuration evidence.
Blocked modeled paths do not establish a product not_affected statement.
"""
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import json
import re
import uuid
from src.item4.decision import assessment_evidence_chain as CHAIN

from src.item4.decision import attack_graph_builder as G
from src.item4.decision import evidence_based_vex as E
from src.item4.decision import population_condition_rules as P
from src.item4.analysis import exploitation_prerequisites as V
from src.item4.decision import scoped_vex_review as A
from src.item4.decision.inventory_evidence_policy import absence_hold_reason; from src.item4.decision.inventory_evidence_policy import MISSING_COMPLETENESS

VERSION='item4-source-prerequisite-vex/3-information-requirements'
CONTROLS_VERSION='item4-shared-runtime-controls/5'
CHOICES={'o':'true','x':'false','holds':'true','absent':'false','mixed':'unknown','unknown':'unknown','not_applicable':'unknown'}
STATE={'affected':'exploitable','not_affected':'not_affected','fixed':'resolved','under_investigation':'in_triage'}
digest=G.digest


def supplier_registry():
    """The historical hand-curated registry is optional for the active flow.

    Absence means no extra supplier claims, never a safe version. An existing
    but invalid registry must still fail its integrity checks.
    """
    if (E.ROOT/'data/nist_auto_vex/rules.json').is_file():
        return E.registry()
    value=dict(version='absent-supplier-registry/1',rules={},sources={})
    return dict(value,sha256=digest(value))


def case_questions(job,case):
    return [q for q in job.get('asset_questions',[]) if q['cve']==case['cve'] and q.get('component_ref')==case['declared_ref']]


def concrete(version):
    from src.common.source_version_parser import concrete as concrete_build
    return (concrete_build(version) and not version_range(version) and not re.search(
        r'\b(?:all|before|prior to|through|earlier|later|versions)\b', version, re.I))


def version_range(version):
    if not isinstance(version,str) or not version.strip():
        return False
    predicate=P.version_predicate(version)
    def supported(node):
        return node['op']!='unknown' and all(supported(a) for a in node.get('args',[]))
    return predicate['op'] not in {'=', 'unknown', 'none'} and supported(predicate)


def controls(job):
    """Context choices are separate from source exploitation prerequisites."""
    def question(qid,label,options):
        return dict(id=qid,label=label,options=[dict(code=k,label=v) for k,v in options.items()],
                    answer_type='single_choice',default='unknown',kind='assessment_context')
    questions=[
        question('scope','Assessment scope and observation time',{'current_single':'Current operating state confirmed for the same asset and configuration','mixed':'Multiple assets, configurations or historical records are mixed','unknown':'Unknown'}),
        question('mode','Operating mode for this assessment',{'normal':'Normal operation','maintenance':'Maintenance','startup_shutdown':'Startup or shutdown','unknown':'Unknown'})]
    questions[-1]['description']='Select one operating mode. Assess other modes separately if their configuration or access paths differ. Leave Unknown if the mode has not been confirmed.'
    questions[-1]['optional']=True
    components=deepcopy(job.get('components',[]))
    if not components:
        components=list({c['ref']:c for d in job.get('declared_cves',[]) for c in d.get('components',[])}.values())
    cases=[];seen_contexts=set()
    for declaration in job['declared_cves']:
        for ref in declaration.get('component_refs') or [None]:
            case_id='case-'+digest([declaration['cve'],ref])[:20]
            prefix=('component-'+digest(ref)[:20]+':' if ref is not None else case_id+':')
            component=next((c for c in components if c['ref']==ref),None)
            if component is None:
                options={'unknown':'Product association unknown'}
                options.update({'component:'+c['ref']:c['name']+' / '+str(c.get('version') or 'Version unknown') for c in components if c.get('type')!='data'})
                questions.append(question(prefix+'target',declaration['cve']+' · BOM component to assess',options))
            case=dict(id=case_id,cve=declaration['cve'],component=component,prefix=prefix,
                      declared_ref=ref,component_candidates=components if component is None else [])
            cases.append(case)
            if prefix in seen_contexts:continue
            seen_contexts.add(prefix)
            title=component['name'] if component else declaration['cve']+' · Selected component'
            questions.append(question(prefix+'deployment',title+' · Is this component installed or deployed?',{
                'running':'Installed or deployed on the assessed asset','not_deployed':'Reported not deployed','mixed':'Deployment varies across instances','unknown':'Unknown'}))
            questions.append(question(prefix+'inventory_coverage',title+' · Coverage of the deployment inventory record',{
                'unknown':'Coverage is unknown or undocumented',
                'partial':'The record covers part of the assessed deployment',
                'complete':'The record explicitly covers all deployed components of this asset and configuration at the assessment time'}))
            questions[-1]['visible_when']=dict(question_id=prefix+'deployment',value='not_deployed')
            options={'unknown':'Running version unknown','different':'Running version differs from the BOM','mixed':'Running version records conflict'}
            declared_version=component.get('version') if component else None
            if version_range(declared_version):
                options={'bom_range':'Running version is within the range declared in the BOM',**options}
                options['different']='Running version is outside the range declared in the BOM'
            elif component is not None and concrete(declared_version):
                options={'bom':'Running version matches the exact BOM component version',**options}
            elif component is None:
                if any(concrete(c.get('version')) for c in components):
                    options={'bom':'Running version matches the exact BOM version of the selected component',**options}
                if any(version_range(c.get('version')) for c in components):
                    options={'bom_range':'Running version is within the selected component BOM range',**options}
            runtime_question=question(prefix+'runtime',title+' · Running version confirmation'+(' · BOM: '+declared_version if declared_version else ''),options)
            runtime_question['visible_when']=dict(question_id=prefix+'deployment',value='running')
            runtime_question['description']='Check the installed version on the device or in a current management record. The BOM alone does not confirm the installed version.'
            if 'bom_range' in options:
                runtime_question['description']='The BOM declares a version range. Range membership is recorded separately from an exact running version and does not alone establish a final VEX decision.'
            questions.append(runtime_question)
    return questions,cases


def version_binding(cve,component,result):
    """Use supplier/CSAF version membership, never an LLM fix prediction."""
    out=dict(state='unknown',product_bound=False,condition_product_bound=False,sources=[])
    try:
        if A.detail(cve).get('original_nvd_status')=='Rejected':return out
    except KeyError:pass
    if not component or not concrete(component.get('version')):
        return out
    from src.item4.analysis.product_advisory_evidence import scenarios_for
    matches = [m for m in result.get('advisory_context', {}).get('matches', [])
               if m['component_ref'] == component['ref']]
    if matches or result.get('source_kind') == 'Product-scoped ICSA':
        out['sources'] = deepcopy(matches)
        current = {m.get('status') for m in matches if m['version_membership'] == 'true'}
        if len(current) > 1:
            out.update(state='conflicting', product_bound=True)
        elif current and all(m['version_membership'] != 'unknown' for m in matches):
            state = {'known_affected':'vulnerable', 'fixed':'fixed',
                     'known_not_affected':'unaffected', 'under_investigation':'unknown'}.get(current.pop(), 'unknown')
            out.update(state=state, product_bound=True, condition_product_bound=(
                state == 'vulnerable' and bool(scenarios_for(result, component['ref']))))
        return out
    rule=supplier_registry()['rules'].get(cve)
    if rule and E.supported_product(rule,component['name']):
        return dict(state=E.version_state(rule,component['version']),product_bound=True,
                    condition_product_bound=False,sources=[rule['source']]+rule['fix_sources'])
    record=P.get(cve)
    matched=P.choose(record,component['name']) if record else []
    if matched:
        out.update(state=P.status(dict(source_product_rows=matched),component['version']),product_bound=True,
                   sources=[{k:p[k] for k in ('key','status','version_text','source_file','status_pointer','product_pointer','document_sha256') if k in p} for p in matched])
    return out


def source_gaps(draft):
    """Untyped legacy uncertainty has no evidence that limits it to one route."""
    details = {gap['reason']: gap for gap in draft.get('uncertainty_details', [])}
    gaps = []
    for reason in dict.fromkeys(draft.get('unknowns', [])):
        gap = details.get(reason, dict(reason=reason, kind='unclassified', scenario_ids=[], source_refs=[]))
        gaps.append(dict(gap, id='source-gap:' + digest(gap)[:24]))
    used = set()
    for scenario in draft.get('scenarios', []):
        used.update(V.leaves(scenario['expression']))
    for item in draft.get('prerequisites', []):
        if item['id'] in used or item.get('necessity', 'required') not in ('required', 'alternative'):
            continue
        gaps.append(dict(id='source-gap:unplaced:' + item['id'], kind='required_condition',
                         reason='No scenario binds the extracted condition: ' + item['statement'],
                         scenario_ids=[], source_refs=item['source_refs']))
    return gaps


def build_graph(job,case,result,component):
    artifact=result.get('prerequisite');draft=(artifact or {}).get('draft',{})
    mapping={q['condition_id']:q for q in case_questions(job,case)}
    items={p['id']:p for p in draft.get('prerequisites',[])}
    def convert(expression):
        if 'condition' in expression:
            cid=expression['condition'];item=items.get(cid,{})
            from src.item4.analysis.operator_verifiable_conditions import positive_leaf
            return positive_leaf(mapping[cid]['id'] if cid in mapping else 'unobserved:'+cid,item)
        return dict(op=expression['op'],args=[convert(a) for a in expression['args']])
    from src.item4.analysis.product_advisory_evidence import scenarios_for
    scenarios = scenarios_for(result, component['ref'] if component else case['declared_ref'])
    scenario_ids = {s['id'] for s in scenarios}
    gaps = [g for g in source_gaps(draft)
            if not g['scenario_ids'] or scenario_ids.intersection(g['scenario_ids'])]
    expressions = []
    for scenario in scenarios:
        route = convert(scenario['expression'])
        blockers = [dict(condition=g['id']) for g in gaps if g['kind'] != 'context_only'
                    and (not g['scenario_ids'] or scenario['id'] in g['scenario_ids'])]
        expressions.append(dict(op='and', args=[route, *blockers]) if blockers else route)
    expression=expressions[0] if len(expressions)==1 else dict(op='or',args=expressions) if expressions else {'condition':'unresolved-source-rule'}
    by_source={s['id']:s for s in result.get('sources',[])}
    questions=[]
    for q in mapping.values():
        ref=q['source_refs'][0];source=by_source.get(ref['source_id'],{})
        questions.append(dict(id=q['id'],label=q['label'],nist_fields=[],
                              operating_field_ids=['asset-key:'+q['key']],
                              source=dict(ref,url=source.get('url'),source_sha256=source.get('text_sha256'))))
    context=job.get('context_answers',{})
    return G.build(case['cve'],expression,questions,
        dict(component_ref=component['ref'] if component else 'unbound',
             product=component['name'] if component else 'unknown',build=component.get('version') if component else None,
             mode=context.get('mode','unknown'),origin='observed per-CVE access paths; no attacker location assumed',basis='operator-confirmed current configuration and scoped access observations'),
        (job.get('asset_classification') or {}).get('asset_type_id'),False,
        (artifact or {}).get('sha256',digest(result)),gaps,
        [r for p in draft.get('prerequisites',[]) for r in p['source_refs']])


def verify_source(result):
    artifact=result.get('prerequisite')
    csaf_packet = None
    if 'advisory_context' in result and 'source_components' in result:
        from src.item4.analysis.product_advisory_evidence import packet as source_packet
        csaf_packet, context = source_packet(result['cve'],result['source_components'])
        if context != result['advisory_context']:
            raise ValueError('CSAF product status or evidence changed. Generate the analysis again.')
    elif result.get('advisory_context', {}).get('matches'):
        raise ValueError('CSAF component evidence is missing. Generate the analysis again.')
    if not artifact:return
    if artifact.get('sha256') != V.digest({k:v for k,v in artifact.items() if k!='sha256'}):
        raise ValueError('Extraction integrity changed. Generate the questions again.')
    from src.item4.workflow.source_analysis_jobs import description_packet
    if result.get('evidence_packet'):
        from src.item4.analysis.cve_reference_sources import verify
        packet=result['evidence_packet']
        for source in packet.get('sources',[]):verify(source)
        if packet.get('cve')!=result['cve'] or packet.get('sources')!=result.get('sources'):
            raise ValueError('CVE evidence packet identity or source list changed.')
    elif result.get('source_kind') == 'Product-scoped ICSA':
        packet=csaf_packet
    else:
        packet=description_packet(result['cve'])
    if not packet or packet.get('status')=='unresolved' or V.digest(packet)!=artifact['source_record_sha256']:
        raise ValueError('CVE source evidence changed. Generate the questions again.')
    V.validate(artifact['draft'],packet)


def evaluate(job):
    # Revalidate V3 artifact and both confidence gates, including direct callers.
    from src.item4.assets.asset_observations import build
    from src.item4.workflow.source_analysis_jobs import digest as plan_digest
    refreshed=build(job,plan_digest)
    job=dict(job,**refreshed)
    evaluated_at=datetime.now(timezone.utc).isoformat();run_id=uuid.uuid4().hex
    context=job.get('context_answers',{})
    complete=context.get('scope')=='current_single'
    from src.item4.assets.asset_observations import classifications
    classified_components=classifications(job)
    results={r['cve']:r for r in job['conditions']}
    for result in results.values():verify_source(result)
    rows=[]
    for case in job['assessment_cases']:
        result=results.get(case['cve'],{});artifact=result.get('prerequisite')
        component=case.get('component')
        if component is None:
            selected=context.get(case['prefix']+'target','unknown')
            component=next((c for c in case['component_candidates'] if 'component:'+c['ref']==selected),None)
        classified=bool(component and component['ref'] in classified_components)
        binding=version_binding(case['cve'],component,result)
        deployment=context.get(case['prefix']+'deployment','unknown');runtime=context.get(case['prefix']+'runtime','unknown')
        coverage_key = case['prefix'] + 'inventory_coverage'
        observation = dict(scope=context.get('scope', 'unknown'), deployment=deployment,
                           inventory_coverage=context.get(coverage_key, 'unknown'),
                           component_ref=component and component.get('ref'))
        absence_hold = absence_hold_reason(observation, observation['component_ref'])
        confirmed_absence = deployment == 'not_deployed' and absence_hold is None
        selected_questions=case_questions(job,case)
        facts={q['id']:CHOICES.get(job['answers'].get(q['id'],'unknown'),'unknown') for q in selected_questions}
        facts.update(deployment='true' if deployment=='running' else 'false' if confirmed_absence else 'unknown',
                     affected_version='true' if binding['state']=='vulnerable' and runtime=='bom' else 'false' if binding['state'] in ('fixed','unaffected') and runtime=='bom' else 'unknown')
        build_confirmed = (context.get('scope') == 'current_single' and bool(component) and
                           runtime == 'bom' and concrete(component.get('version')) and deployment == 'running')
        product_ready = build_confirmed and binding['product_bound']
        if confirmed_absence or (product_ready and binding['state'] in {'fixed', 'unaffected'}):
            graph = dict(cve=case['cve'], component_ref=component['ref'], generation_status='not_required',
                         reason=('The scoped deployment inventory establishes component absence.' if confirmed_absence
                                 else 'Supplier evidence establishes the status of the confirmed running build.'),
                         nodes=[], edges=[], coverage_complete=False)
            graph['sha256'] = digest(graph)
            evaluated = dict(generation_status='not_required', value='unknown', path_found=False,
                             no_path_proven=False, node_states={}, witness_nodes=[], inference_steps=[],
                             unresolved_questions=[], graph_sha256=graph['sha256'])
            formula = 'unknown'
        else:
            graph = build_graph(job, case, result, component)
            evaluated = G.evaluate(graph, facts)
            formula = evaluated['node_states'].get(graph['operating_root'], 'unknown')
        mixed_answers = any(job['answers'].get(q['id']) == 'mixed' for q in selected_questions)
        graph_ready = graph.get('generation_status') == 'complete'
        current_source=(result.get('source_kind')=='CVE description' and result.get('source_policy')=='cve-description-special/1')
        path_ready = (current_source and product_ready and binding['state'] == 'vulnerable' and binding['condition_product_bound']
                      and complete and classified and graph_ready and not mixed_answers)
        applicability = 'unknown'
        if product_ready:
            applicability = {'vulnerable':'applicable','fixed':'not_applicable','unaffected':'not_applicable'}.get(binding['state'],'unknown')
        status = 'under_investigation'
        reason = 'Product identity, running version or operating scope remains unresolved.'
        if confirmed_absence:
            status, reason = 'not_affected', 'The operator reports this component absent from an explicitly complete deployment inventory for the current asset and configuration.'
        elif product_ready and binding['state'] == 'fixed':
            status, reason = 'fixed', 'The operator-confirmed running version meets the supplier fix criteria for this CVE.'
        elif product_ready and binding['state'] == 'unaffected':
            status, reason = 'not_affected', 'The supplier explicitly lists this running version as unaffected.'
        elif path_ready and artifact and evaluated['path_found']:
            status, reason = 'affected', 'Supplier evidence identifies a vulnerable version and operator responses satisfy a source-supported path.'
        elif deployment == 'not_deployed':
            reason = ('The operator reported non-deployment. The deployment inventory lacks explicit evidence of complete coverage.'
                      if absence_hold == MISSING_COMPLETENESS else 'The inventory record does not resolve a single current asset and component.')
        elif binding['state'] == 'conflicting':
            reason = 'Supplier product status records conflict for the same version.'
        elif deployment == 'mixed' or runtime == 'mixed' or mixed_answers:
            reason = 'Mixed or conflicting responses prevent a final decision.'
        elif not graph_ready:
            reason = 'The MulVAL graph is incomplete. The decision remains under investigation.'
        elif not classified:
            reason = 'Asset classification remains unresolved.'
        elif not current_source:
            reason = 'Saved source extraction uses an earlier policy. Refresh the CVE-description-specific conditions.'
        elif path_ready and formula == 'false':
            reason = 'Known prerequisite paths are blocked. This alone does not establish that the product is unaffected.'
        elif path_ready and formula == 'unknown' and any(q.startswith('source-gap:') for q in evaluated['unresolved_questions']):
            reason = 'A source requirement remains unresolved for the assessed path.'
        elif product_ready and not binding['condition_product_bound']:
            reason = 'The source binding between the confirmed running version and the prerequisite path is unresolved.'
        rows.append(dict(case_id=case['id'],cve=case['cve'],component=component,status=status,reason=reason,
            product_applicability=applicability,prerequisite_status={'true':'satisfied','false':'unsatisfied','unknown':'unknown'}[formula],
            deployment_exploitability='not_applicable' if confirmed_absence or applicability=='not_applicable' else 'conditions_satisfied' if path_ready and formula=='true' else 'known_paths_blocked' if path_ready and formula=='false' else 'under_investigation',
            version_binding=binding,attack_graph=graph,graph_evaluation=evaluated,condition_values=facts,
            answers={q['id']:job['answers'].get(q['id'],'unknown') for q in selected_questions},
            product_vex_status=status,path_coverage_complete=False,
            accepted_question_confidences={q['id']:q['llm_confidence'] for q in job.get('asset_questions',[]) if q.get('case_id')==case['id']},
            special_question_ids=[q['id'] for q in job.get('special_questions',[]) if q.get('case_id')==case['id']]))
        if deployment == 'not_deployed':
            rows[-1]['inventory_observation'] = dict(observation, answer_id=coverage_key,
                basis='operator_context_answer', completeness_explicit=observation['inventory_coverage']=='complete',
                hold_reason=absence_hold)
        # Preserve the checkpoint actually used for this extraction, including
        # the evaluation decision in effect then. Reading today's config would
        # misattribute historical analyses after a model change.
        model = (artifact or {}).get('model')
        adapter = model.get('adapter') if isinstance(model, dict) else None
        if isinstance(adapter, dict):
            rows[-1]['extraction_adapter'] = {
                key: adapter.get(key) for key in (
                    'role', 'sha256', 'training_completed', 'evaluation_passed',
                    'evaluation_gate_override', 'experimental_use_approved', 'evaluation_sha256')
            }
        from src.item4.assets.condition_coverage import coverage
        case_coverage=coverage(job,[case],job['asset_questions'],job.get('extraction_confidence_rejections',[]),job.get('question_confidence_rejections',[]))[0]
        rows[-1]['condition_coverage']=case_coverage
        from src.item4.analysis.product_advisory_evidence import scenarios_for
        scenarios=scenarios_for(result,component['ref'] if component else case['declared_ref'])
        rows[-1]['evidence_chain']=CHAIN.evidence_chain(job,case,result,rows[-1],case_coverage,scenarios,source_gaps((artifact or {}).get('draft',{})),run_id,evaluated_at)
    report=dict(version=VERSION,evaluated_at=evaluated_at,run_id=run_id,evidence_input_sha256=CHAIN.input_digest(job),
        job_id=job['id'],input_revision=job['revision'],plan_sha256=job['plan_sha256'],
        answer_digest=digest(dict(answers=job['answers'],context=context)),bom_sha256=job['bom_sha256'],
        rule_registry_sha256=supplier_registry()['sha256'],decisions=rows,counts=dict(Counter(r['status'] for r in rows)),
        provenance='Exact-source-quote/structure checks and attributed operator choices; no independent operating-record verification',
        catalogue_sha256=job.get('catalogue_sha256'),answer_provenance=deepcopy(job.get('answer_provenance',{})),
        asset_values=deepcopy(job.get('answers',{})),
        independent_semantic_accuracy_verified=False,agent='exploitability_vex_generation')
    report['sha256']=digest(report)
    return report


def export(job,kind):
    report=job.get('assessment')
    if not report or report.get('version') != VERSION or report['input_revision']!=job['revision'] or report['plan_sha256']!=job['plan_sha256']:
        raise ValueError('Run the VEX assessment with the latest responses first.')
    if report['sha256']!=digest({k:v for k,v in report.items() if k!='sha256'}):raise ValueError('Assessment result integrity changed.')
    if report['answer_digest']!=digest(dict(answers=job['answers'],context=job.get('context_answers',{}))):raise ValueError('Answers changed. Run the assessment again.')
    if report.get('evidence_input_sha256')!=CHAIN.input_digest(job):raise ValueError('Agent records or answer evidence changed. Run the assessment again.')
    if report['rule_registry_sha256']!=supplier_registry()['sha256']:raise ValueError('Supplier rules changed. Run the assessment again.')
    for result in job['conditions']:verify_source(result)
    if kind=='review':return deepcopy(report)
    if kind in {'openvex','cyclonedx'} and any(not row.get('component') for row in report['decisions']):
        raise ValueError('Select a BOM component for every CVE before exporting VEX. The assessment review remains available.')
    if kind=='openvex':
        document={'@context':'https://openvex.dev/ns/v0.2.0','@id':'urn:sha256:'+report['sha256'],
                  'author':'ICS-VEX · operator questionnaire assessment','timestamp':report['evaluated_at'],'version':job['revision'],'statements':[]}
        for row in report['decisions']:
            ref=row['component']['ref'] if row['component'] else 'unbound:'+row['case_id']
            notes=dict(reason=row['reason'],component_ref=ref,assessment_sha256=report['sha256'],
                evidence_chain=row['evidence_chain'],
                provenance=report['provenance'],prerequisite_status=row['prerequisite_status'],deployment_exploitability=row['deployment_exploitability'])
            if row.get('extraction_adapter'):
                notes['extraction_adapter']=row['extraction_adapter']
            if 'inventory_observation' in row:
                notes['inventory_observation']=row['inventory_observation']
            statement=dict(vulnerability=dict(name=row['cve']),products=[{'@id':'urn:ics-vex:component:'+digest([job['bom_sha256'],ref])}],
                status=row['status'],status_notes=json.dumps(notes,ensure_ascii=False))
            if row['status']=='affected':statement['action_statement']='Apply the supplier guidance and verify the actual running version.'
            if row['status']=='not_affected':statement['impact_statement']=row['reason']
            document['statements'].append(statement)
        from jsonschema import Draft202012Validator,FormatChecker
        from pathlib import Path
        Draft202012Validator(json.loads((Path(__file__).resolve().parents[3]/'data/standards/openvex-schema.json').read_bytes()),format_checker=FormatChecker()).validate(document)
        return document
    if kind!='cyclonedx':raise ValueError('Supported formats: review, openvex and cyclonedx.')
    original=job.get('input_bom')
    if not original:raise ValueError('This older job has no original BOM. Upload the BOM again.')
    import bom_vex_workflow as W
    document=deepcopy(original) if original.get('bomFormat')=='CycloneDX' else W.spdx_cyclonedx_inventory(dict(bom=original,input_sha256=job['bom_sha256'],revision=job['revision']))
    if original.get('bomFormat')=='CycloneDX':
        # CycloneDX refs are optional on input. Preserve the pointer identities
        # used by V1/V2 when assigning refs in this exported copy only.
        def bind_refs(items,path):
            for i,item in enumerate(items):
                pointer=path+'/'+str(i);item.setdefault('bom-ref',pointer)
                bind_refs(item.get('components',[]),pointer+'/components')
        top=document.get('metadata',{}).get('component')
        if top:
            top.setdefault('bom-ref','/metadata/component')
            bind_refs(top.get('components',[]),'/metadata/component/components')
        bind_refs(document.get('components',[]),'/components')
    merge_component_decisions(document,report['decisions'],job['id'])
    W.prop(document,'assessment-sha256',report['sha256'])
    W.validate_bom(document,target_refs=set(inventory_target_refs(document)))
    return document


def inventory_target_refs(document):
    """Collect component and service identities from the actual exported inventory."""
    pending=list(document.get('components',[])) + list(document.get('services',[]))
    root=document.get('metadata',{}).get('component')
    if root:
        pending.append(root)
    while pending:
        target=pending.pop()
        if 'bom-ref' in target:
            yield target['bom-ref']
        pending.extend(target.get('components',[]))
        pending.extend(target.get('services',[]))


def bom_refs(node):
    if isinstance(node,dict):
        if isinstance(node.get('bom-ref'),str):
            yield node['bom-ref']
        for child in node.values():
            yield from bom_refs(child)
    elif isinstance(node,list):
        for child in node:
            yield from bom_refs(child)


def merge_component_decisions(document,rows,job_id):
    """Update only the original records whose scope equals the assessed component."""
    from collections import defaultdict
    vulnerabilities=document.setdefault('vulnerabilities',[])
    used_refs=set(bom_refs(document))
    by_cve=defaultdict(list)
    for index,entry in enumerate(vulnerabilities):
        by_cve[str(entry.get('id','')).upper()].append((index,entry))
    for row in rows:
        cve,ref=row['cve'],row['component']['ref']
        targets=[{'ref':ref}]
        entries=by_cve[cve]
        exact=[entry for _,entry in entries if entry.get('affects')==targets]
        broader=[entry.get('bom-ref') or '/vulnerabilities/'+str(index)
                 for index,entry in entries if entry.get('affects')!=targets
                 and (not entry.get('affects') or any(a['ref']==ref for a in entry['affects']))]
        if not exact:
            # Do not assign a single component's result to a multi-target or
            # version-qualified source assertion. Keep that assertion verbatim.
            entry={'id':cve,'affects':targets}
            vulnerabilities.append(entry)
            exact=[entry]
        analysis={'state':STATE[row['status']],'detail':row['reason']}
        decision=dict(component_ref=ref,status=row['status'],reason=row['reason'])
        if row.get('evidence_chain'):
            decision['evidence_chain']=row['evidence_chain']
        if 'inventory_observation' in row:
            decision['inventory_observation']=row['inventory_observation']
        if row.get('extraction_adapter'):
            decision['extraction_adapter']=row['extraction_adapter']
        if broader:
            decision['source_vulnerabilities']=broader
        for entry in exact:
            if 'bom-ref' not in entry:
                base='item4-vex:'+job_id+':'+row['case_id']
                new_ref=base
                suffix=1
                while new_ref in used_refs:
                    new_ref=f'{base}:{suffix}'
                    suffix+=1
                used_refs.add(new_ref)
                entry['bom-ref']=new_ref
            properties=entry.setdefault('properties',[])
            if 'analysis' in entry and entry['analysis']!=analysis:
                # Older reasons, justifications and response actions belong to
                # the original verdict. Retain them together for audit.
                properties.append(dict(name='ics-vex:prior-analysis',value=json.dumps(entry['analysis'],ensure_ascii=False)))
            entry['analysis']=dict(analysis)
            properties.append(dict(name='ics-vex:component-decision',value=json.dumps(decision,ensure_ascii=False)))
