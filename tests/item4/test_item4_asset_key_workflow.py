"""V3/V4 contracts. Synthetic sources; graph fixture is not a live MulVAL run."""
from copy import deepcopy
import hashlib
import tempfile
from pathlib import Path
from unittest.mock import patch
import unittest

from fastapi.testclient import TestClient
from src.item4.workflow import source_analysis_jobs as Q; from src.item4.assets import asset_observations as I
from src.item4.decision import asset_vex_assessment as E; from src.item4.decision import attack_graph_builder as G
from src.item4.analysis import exploitation_prerequisites as V
from tools.item4 import serve_nist_operational_vex as S


def fixture_job(expression=None):
    cve='CVE-2099-12345';text='Exploitation requires HTTP enabled.'
    ref=dict(source_id='fixture:source',quote=text)
    packet=dict(cve=cve,products=[dict(key='p')],sources=[dict(id='fixture:source',text=text,
        text_sha256=hashlib.sha256(text.encode()).hexdigest(),product_keys=['p'],url='https://example.invalid/advisory')])
    atom=dict(id='http',predicate='feature_enabled',target='HTTP',value='enabled',
        category='OTHER',extraction_confidence=0.95,
        statement='HTTP is enabled',operator_observable=True,operator='eq',expected=True,
        operational_quote=text,observation=dict(kind='configuration',record_type='configuration_export',check='Read the applied HTTP service setting.'),source_refs=[ref])
    draft=dict(format=V.VERSION,cve=cve,prerequisites=[atom],scenarios=[dict(id='path',
        product_keys=['p'],expression=expression or dict(condition='http'),source_refs=[ref])],
        nonrequirements=[],unknowns=[],excluded_facts=[])
    V.validate(draft,packet)
    artifact=dict(draft=draft,source_record_sha256=V.digest(packet));artifact['sha256']=V.digest(artifact)
    bom=dict(bomFormat='CycloneDX',specVersion='1.6',version=1,
        metadata=dict(component={'bom-ref':'asset','type':'device','name':'Fixture HMI','version':'1.0'}),
        vulnerabilities=[dict(id=cve,affects=[dict(ref='asset')])])
    components,declared=Q.inventory(bom)
    job=dict(id='fixture-job',status='completed',bom_sha256=Q.digest(bom),input_bom=bom,
        components=[dict(ref='asset',name='Fixture HMI',version='1.0',type='device')],
        declared_cves=declared,representative=dict(ref='asset',name='Fixture HMI'),revision=1,
        extraction_identity='fixture',conditions=[dict(cve=cve,status='extracted',prerequisite=artifact,
        source_kind='CVE description',source_policy='cve-description-special/1',sources=packet['sources'],cvss_assessments=[dict(id='fixture-cvss',
            vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            source=dict(id='fixture-cvss',quote='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'))])],asset_state='completed',condition_state='completed',
        cves_total=1,cves_done=1,asset_classification=dict(status='classified',asset_type_id='A0002',asset=dict(name='HMI'),classification_version=Q.asset_model.VERSION))
    generate_fixture_questions(job)
    Q._prepare_analysis(job)
    return job,packet


def generate_fixture_questions(job):
    from src.item4.analysis import asset_operating_question_generation as V3
    def fixture_runner(system,payload,**kwargs):
        return dict(prediction=dict(questions={k:dict(positive_fact=a['positive_fact'],
            question=payload['schema']['properties']['questions']['properties'][k]['properties']['question'].get('const','Is the following true: '+a['positive_fact']+'?'),
            check=a['observation']['check'],record_type=a['observation']['record_type'],confidence=95)
            for k,a in payload['atoms'].items()}),model={'model':'fixture'},llm_used=False)
    def sealed_fixture(system,payload,**kwargs):
        # Unit-test response only; never included in measured model reports.
        value=fixture_runner(system,payload,**kwargs);value['llm_used']=True;return value
    job['question_generations']=V3.run_job(job,runner=sealed_fixture)


def graph_fixture(*args,**kwargs):
    graph=G.source_contract(*args,**kwargs)
    graph['generation_status']='complete'
    graph['sha256']=G.digest(graph)
    return graph


class AssetKeyWorkflow(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        patches=[patch.object(Q.store,'DB',Path(folder.name)/'jobs.sqlite3'),
            patch.object(Q,'JOBS',{}),patch.object(Q,'extraction_identity',return_value='fixture'),
            patch.object(E.G,'build',side_effect=graph_fixture),
            patch.object(E,'version_binding',return_value=dict(state='vulnerable',product_bound=True,condition_product_bound=True,sources=[]))]
        for p in patches:p.start();self.addCleanup(p.stop)
        self.job,self.packet=fixture_job()
        p=patch.object(Q,'description_packet',return_value=self.packet);p.start();self.addCleanup(p.stop)
        Q.JOBS[self.job['id']]=deepcopy(self.job);Q._save(self.job)
        self.client=TestClient(S.app);self.url='/api/item4/analyses/jobs/'+self.job['id']

    def token(self,job):return dict(revision=job['revision'],plan_sha256=job['plan_sha256'])
    def save(self,value,context=True):
        job=Q.get(self.job['id']);q=job['questions'][0]
        scope=dict(scope='current_single',mode='normal') if context else {}
        if context:
            for case in job['assessment_cases']:
                scope[case['prefix']+'runtime']='bom';scope[case['prefix']+'deployment']='running'
        answers={q['id']:value}
        r=self.client.post(self.url+'/answers',json=dict(self.token(job),answers=answers,context_answers=scope))
        self.assertEqual(r.status_code,200,r.text);return r.json()
    def assess(self,job):
        r=self.client.post(self.url+'/assess',json=self.token(job));self.assertEqual(r.status_code,200,r.text);return r.json()

    def test_catalogue_preserves_all_keys_without_equal_count_quota(self):
        cat=I.catalogue();self.assertEqual(len(cat['asset_types']),18);self.assertEqual(cat['question_count'],505)
        self.assertEqual(len(cat['asset_types']['A0013']),19)
        self.assertEqual(len(cat['asset_types']['A0008']),33)
        q=self.job['questions'][0];self.assertEqual(q['key'],'http_listener_enabled')
        self.assertEqual(q['binding'],'exact_positive_feature_target')
        self.assertEqual(len(self.job['asset_questions']),1)
        self.assertNotIn('common_questions',self.job)
        self.assertEqual(len(self.job['special_questions']),1)
        self.assertEqual([a['number'] for a in self.job['agents']],[1,2,3,4])
        self.assertEqual([a['code'] for a in self.job['agents']],['V1','V2','V3','V4'])

    def test_source_scoped_yes_produces_affected_and_valid_vex_exports(self):
        saved=self.save('o');result=self.assess(saved);row=result['assessment']['decisions'][0]
        self.assertEqual(row['deployment_exploitability'],'conditions_satisfied')
        self.assertEqual(row['product_vex_status'],'affected')
        self.assertEqual(set(row['attack_graph']['operational_field_ids']),{'asset-key:http_listener_enabled'})
        for kind in ('openvex','cyclonedx','review'):
            response=self.client.get(self.url+'/export/'+kind);self.assertEqual(response.status_code,200,response.text)
        vex=self.client.get(self.url+'/export/openvex').json()
        self.assertEqual(vex['statements'][0]['status'],'affected')
        self.assertIn('action_statement',vex['statements'][0])
        self.assertFalse(next(iter(result['assessment']['answer_provenance'].values()))['independent_evidence_verified'])

    def test_false_blocks_known_path_without_claiming_product_nonimpact(self):
        result=self.assess(self.save('x'));row=result['assessment']['decisions'][0]
        self.assertEqual(row['prerequisite_status'],'unsatisfied')
        self.assertEqual(row['deployment_exploitability'],'known_paths_blocked')
        self.assertEqual(row['status'],'under_investigation')

    def test_unknown_not_applicable_and_mixed_never_turn_into_false(self):
        for value in ('unknown','not_applicable','mixed'):
            result=self.assess(self.save(value));row=result['assessment']['decisions'][0]
            self.assertEqual(row['prerequisite_status'],'unknown');self.assertEqual(row['status'],'under_investigation')

    def test_source_uncertainty_blocks_only_the_affected_routes(self):
        reason = 'Unresolved site-specific operating condition.'
        for kind, scoped, alternate, expected in [
            (None, False, True, 'under_investigation'),
            ('required_condition', True, False, 'under_investigation'),
            ('product_binding', True, False, 'under_investigation'),
            ('required_condition', True, True, 'affected'),
            ('context_only', False, False, 'affected'),
        ]:
            with self.subTest(kind=kind, scoped=scoped, alternate=alternate):
                job = deepcopy(self.job)
                artifact = job['conditions'][0]['prerequisite']
                draft = artifact['draft']
                draft['unknowns'] = [reason]
                if kind:
                    draft['uncertainty_details'] = [dict(kind=kind, reason=reason,
                        scenario_ids=['path'] if scoped else [], source_refs=draft['scenarios'][0]['source_refs'])]
                if alternate:
                    draft['scenarios'].append(dict(deepcopy(draft['scenarios'][0]), id='other-route'))
                artifact['sha256'] = V.digest({k: v for k, v in artifact.items() if k != 'sha256'})
                generate_fixture_questions(job)
                Q._prepare_analysis(job)
                Q.JOBS[job['id']] = job
                row = self.assess(self.save('o'))['assessment']['decisions'][0]
                self.assertEqual(row['status'], expected)
                self.assertEqual(row['attack_graph']['gaps'][0]['reason'], reason)
                if expected == 'under_investigation':
                    self.assertEqual(row['prerequisite_status'], 'unknown')
                    self.assertEqual(row['deployment_exploitability'], 'under_investigation')
                    self.assertFalse(row['graph_evaluation']['path_found'])
                exported = self.client.get(self.url + '/export/openvex')
                self.assertEqual(exported.status_code, 200, exported.text)
                self.assertEqual(exported.json()['statements'][0]['status'], expected)

    def test_old_policy_result_requires_reassessment_with_existing_answers(self):
        old = self.assess(self.save('o'))
        old['assessment']['version'] = 'item4-answer-vex/2'
        Q.JOBS[old['id']] = old
        self.assertEqual(self.client.get(self.url + '/export/openvex').status_code, 422)
        current = self.client.get(self.url).json()
        self.assertIsNone(current['assessment'])
        self.assertEqual(current['answers'], old['answers'])
        self.assertEqual(self.assess(current)['assessment']['version'], E.VERSION)

    def test_inventory_coverage_is_scoped_and_evidenced_in_assessment_and_exports(self):
        job = self.save('o')
        prefix = job['assessment_cases'][0]['prefix']
        coverage_key = prefix+'inventory_coverage'
        def submit(changes):
            current = Q.get(job['id'])
            response = self.client.post(self.url+'/answers', json=dict(self.token(current), context_answers=changes))
            self.assertEqual(response.status_code, 200, response.text)
            return self.assess(response.json())['assessment']['decisions'][0]
        for changes, expected in [
                ({prefix+'deployment':'not_deployed'}, 'under_investigation'),
                ({coverage_key:'partial'}, 'under_investigation'),
                ({coverage_key:'complete'}, 'not_affected'),
                ({'scope':'mixed'}, 'under_investigation'),
                ({'scope':'current_single'}, 'under_investigation')]:
            row = submit(changes)
            self.assertEqual(row['status'], expected)
            self.assertEqual(row['deployment_exploitability'], 'not_applicable' if expected=='not_affected' else 'under_investigation')
            self.assertEqual(row['condition_values']['deployment'], 'false' if expected=='not_affected' else 'unknown')
            exported = self.client.get(self.url+'/export/openvex').json()['statements'][0]
            self.assertEqual(exported['status'], expected)
            from json import loads
            self.assertEqual(loads(exported['status_notes'])['inventory_observation'], row['inventory_observation'])
            self.assertEqual(row['inventory_observation']['completeness_explicit'], expected=='not_affected')

    def test_older_control_migration_preserves_answers_and_retires_absence_decision(self):
        job = self.assess(self.save('o'))
        job.pop('context_controls_version')
        prefix = job['assessment_cases'][0]['prefix']
        job['context_answers'][prefix+'inventory_coverage'] = 'complete'
        prior = deepcopy(job['answers'])
        self.assertTrue(I.prepare(job, Q.digest))
        self.assertIsNone(job['assessment'])
        self.assertEqual(job['answers'], prior)
        self.assertNotIn(prefix+'inventory_coverage', job['context_answers'])
        self.assertFalse(I.prepare(job, Q.digest))

    def test_edit_invalidates_exports_and_stale_revision_is_rejected(self):
        result=self.assess(self.save('o'));old=self.token(result)
        saved=self.save('x');self.assertIsNone(saved['assessment'])
        self.assertEqual(self.client.get(self.url+'/export/openvex').status_code,422)
        self.assertEqual(self.client.post(self.url+'/answers',json=dict(old,answers={})).status_code,409)
        self.assertEqual(self.client.post(self.url+'/assess',json=old).status_code,409)

    def test_verdicts_unknown_ids_and_non_enum_values_are_rejected(self):
        for payload in [dict(answers={'not-a-key':'o'}),dict(answers={self.job['questions'][0]['id']:'yes'}),dict(status='not_affected'),dict(answers=[]),dict(context_answers={'scope':'trust-me'})]:
            response=self.client.post(self.url+'/answers',json=dict(self.token(Q.get(self.job['id'])),**payload))
            self.assertEqual(response.status_code,422,response.text)

    def test_persistence_and_plan_migration_preserve_only_current_answers(self):
        saved=self.save('o');Q.JOBS.clear();loaded=Q.get(self.job['id'])
        self.assertEqual(loaded['answers'],saved['answers'])
        loaded['asset_classification']['asset_type_id']='A0003';Q.JOBS[loaded['id']]=loaded
        migrated=Q.get(loaded['id']);self.assertEqual(migrated['answers'],{})
        self.assertGreater(migrated['revision'],saved['revision'])

    def test_unknown_source_fact_stays_unknown_without_cvss_inputs(self):
        job=self.save('unknown')
        self.assertNotIn('cvss_plans',job)
        row=self.assess(job)['assessment']['decisions'][0]
        self.assertEqual(row['prerequisite_status'],'unknown')

    def test_product_version_mismatch_and_missing_scope_stay_unknown(self):
        job=self.save('o',context=False)
        self.assertEqual(self.assess(job)['assessment']['decisions'][0]['status'],'under_investigation')
        job=self.save('o');case=job['assessment_cases'][0]
        job=Q.save_answers(job['id'],dict(self.token(job),context_answers={case['prefix']+'runtime':'different'}))
        self.assertEqual(self.assess(job)['assessment']['decisions'][0]['status'],'under_investigation')

    def test_changed_source_and_modified_answer_digest_block_export(self):
        job=self.assess(self.save('o'))
        with patch.object(Q,'description_packet',return_value=dict(self.packet,sources=[])):
            self.assertEqual(self.client.get(self.url+'/export/openvex').status_code,422)
        changed=deepcopy(job);changed['answers'][job['questions'][0]['id']]='x'
        with self.assertRaisesRegex(ValueError,'Answers changed'):E.export(changed,'openvex')

    def test_source_target_qualifier_does_not_get_keyword_matched(self):
        job=deepcopy(self.job)
        job['conditions'][0]['prerequisite']['draft']['prerequisites'][0]['target']='HTTP on TCP 8080'
        built=I.build(job,Q.digest)
        self.assertEqual(built['questions'][0]['binding'],'direct_source_condition')
        self.assertTrue(built['questions'][0]['key'].startswith('cve_fact_'))

    def test_missing_mulval_does_not_generate_a_final_verdict(self):
        from src.item4.decision import mulval_attack_graphs as M
        with patch.object(E.G,'build',wraps=lambda *a,**kw:M.build(G.source_contract(*a,**kw))),patch.object(M,'generate',side_effect=RuntimeError('test offline')):
            row=self.assess(self.save('o'))['assessment']['decisions'][0]
        self.assertEqual(row['status'],'under_investigation')
        self.assertEqual(row['attack_graph']['generation_status'],'unavailable')

    def test_unclassified_component_never_inherits_another_components_type(self):
        job=deepcopy(self.job);job['declared_cves'][0]['component_refs'].append('other')
        job['components'].append(dict(ref='other',name='Other Library',version='1.0',type='library'))
        generate_fixture_questions(job)
        Q._prepare_analysis(job)
        extra=[q for q in job['asset_questions'] if q['component_ref']=='other']
        self.assertTrue(extra);self.assertTrue(all(q.get('asset_type_id') is None for q in extra))
        self.assertTrue(all(q['binding']=='direct_source_condition' for q in extra if q['question_group']=='cve_special'))

    def test_invalid_payload_and_legacy_routes_stay_closed(self):
        self.assertEqual(self.client.post(self.url+'/answers',content='[]',headers={'Content-Type':'application/json'}).status_code,422)
        self.assertEqual(self.client.post('/api/item4/questionnaires/start',json={}).status_code,410)

    def install_logic(self,op):
        job=deepcopy(self.job);draft=job['conditions'][0]['prerequisite']['draft']
        if op=='not':
            text='Exploitation requires HTTP disabled.'
            draft['scenarios'][0]['expression']=dict(op='not',args=[dict(condition='http')])
        else:
            text='Exploitation requires HTTP enabled '+('and' if op=='and' else 'or')+' SSH enabled.'
            ssh=deepcopy(draft['prerequisites'][0]);ssh.update(id='ssh',target='SSH',statement='SSH is enabled')
            draft['prerequisites'].append(ssh)
            draft['scenarios'][0]['expression']=dict(op=op,args=[dict(condition='http'),dict(condition='ssh')])
        self.packet['sources'][0].update(text=text,text_sha256=hashlib.sha256(text.encode()).hexdigest())
        for p in draft['prerequisites']:
            p['operational_quote']=text;p['source_refs'][0]['quote']=text
        draft['scenarios'][0]['source_refs'][0]['quote']=text
        V.validate(draft,self.packet)
        artifact=job['conditions'][0]['prerequisite'];artifact['source_record_sha256']=V.digest(self.packet)
        artifact['sha256']=V.digest({k:v for k,v in artifact.items() if k!='sha256'})
        job['conditions'][0]['sources']=deepcopy(self.packet['sources'])
        generate_fixture_questions(job);Q._prepare_analysis(job);Q.JOBS[job['id']]=job
        return job

    def test_source_and_or_not_logic_preserves_unknown_and_polarity(self):
        for op,values,expected in [('and',('o','unknown'),'unknown'),('and',('o','x'),'unsatisfied'),
                                   ('or',('o','unknown'),'satisfied'),('not',('x',),'satisfied')]:
            self.install_logic(op);job=self.save(values[0])
            if len(values)>1:
                q=next(q for q in job['questions'] if q['condition_id']=='ssh')
                job=Q.save_answers(job['id'],dict(self.token(job),answers={q['id']:values[1]}))
            row=self.assess(job)['assessment']['decisions'][0]
            self.assertEqual(row['prerequisite_status'],expected,(op,values))

    def test_concurrent_edit_cannot_publish_an_outdated_assessment(self):
        job=self.save('o')
        def concurrent_edit(snapshot):
            Q.save_answers(job['id'],dict(self.token(job),answers={job['questions'][0]['id']:'x'}))
            return {}
        with patch.object(E,'evaluate',side_effect=concurrent_edit):
            response=self.client.post(self.url+'/assess',json=self.token(job))
        self.assertEqual(response.status_code,409)
        self.assertIsNone(Q.get(job['id'])['assessment'])

    def test_supplier_fixed_and_unaffected_are_separate_from_blocked_paths(self):
        for state,status in [('fixed','fixed'),('unaffected','not_affected')]:
            with patch.object(E,'version_binding',return_value=dict(state=state,product_bound=True,condition_product_bound=False,sources=[])):
                row=self.assess(self.save('unknown'))['assessment']['decisions'][0]
                self.assertEqual(row['status'],status)
                response=self.client.get(self.url+'/export/openvex');self.assertEqual(response.status_code,200,response.text)

    def test_scope_change_without_new_attestation_clears_old_operating_values(self):
        job=self.save('o');self.assertTrue(job['answers'])
        changed=Q.save_answers(job['id'],dict(self.token(job),context_answers={'mode':'maintenance'}))
        self.assertEqual(changed['answers'],{});self.assertEqual(changed['answer_provenance'],{})
        row=self.assess(changed)['assessment']['decisions'][0]
        self.assertEqual(row['prerequisite_status'],'unknown')

    def test_cvss_common_answers_are_not_registered(self):
        job=self.save('o')
        response=self.client.post(self.url+'/answers',json=dict(self.token(job),answers={'common-network':'o'}))
        self.assertEqual(response.status_code,422)
        row=self.assess(job)['assessment']['decisions'][0]
        self.assertNotIn('cvss_common_evaluation',row)

    def test_confidence_80_question_cannot_be_submitted_or_assumed_false(self):
        from src.item4.analysis import asset_operating_question_generation as V3
        job=Q.get(self.job['id']);qid=job['questions'][0]['id']
        for artifact in job['question_generations'].values():
            for row in artifact['prediction']['questions'].values():row['confidence']=80
            artifact['sha256']=V3.digest({k:v for k,v in artifact.items() if k!='sha256'})
        I.prepare(job,Q.digest);Q.JOBS[job['id']]=job;Q._save(job)
        response=self.client.post(self.url+'/answers',json=dict(self.token(job),answers={qid:'x'}))
        self.assertEqual(response.status_code,422)
        prefix=job['assessment_cases'][0]['prefix']
        saved=Q.save_answers(job['id'],dict(self.token(job),context_answers={'scope':'current_single',prefix+'deployment':'running',prefix+'runtime':'bom'}))
        row=self.assess(saved)['assessment']['decisions'][0]
        self.assertEqual(row['prerequisite_status'],'unknown')
        self.assertEqual(row['status'],'under_investigation')

    def test_removed_origin_and_mixed_mode_are_rejected_and_hidden_version_is_cleared(self):
        job=self.save('o');prefix=job['assessment_cases'][0]['prefix']
        for context in [dict(origin='internet'),dict(mode='mixed')]:
            response=self.client.post(self.url+'/answers',json=dict(self.token(job),context_answers=context))
            self.assertEqual(response.status_code,422)
        job=Q.save_answers(job['id'],dict(self.token(job),context_answers={prefix+'deployment':'not_deployed',prefix+'runtime':'bom'}))
        self.assertEqual(job['context_answers'][prefix+'runtime'],'unknown')
        row=self.assess(job)['assessment']['decisions'][0]
        self.assertEqual(row['product_applicability'],'unknown')

    def test_legacy_origin_is_archived_without_becoming_observed_access(self):
        job=self.save('o');prior=deepcopy(job['answers'])
        job['asset_input_contract']='item4-cvss-operational-input/3'
        job['context_answers']['origin']='internet';job['context_answers']['mode']='mixed'
        I.prepare(job,Q.digest)
        self.assertEqual(job['answers'],{});self.assertEqual(job['context_answers'],{})
        self.assertIsNone(job['assessment'])
        archived=job['operating_input_history'][-1]
        self.assertEqual(archived['answers'],prior)
        self.assertEqual(archived['context_answers']['origin'],'internet')

    def test_spdx_packages_export_to_valid_cyclonedx_with_original_refs(self):
        job=deepcopy(self.job)
        job['input_bom']=dict(spdxVersion='SPDX-2.3',SPDXID='SPDXRef-DOCUMENT',name='Fixture',
            documentNamespace='https://example.invalid/spdx/fixture',documentDescribes=['SPDXRef-asset'],
            packages=[dict(SPDXID='SPDXRef-asset',name='Fixture HMI',versionInfo='1.0')],
            vulnerabilities=[dict(id='CVE-2099-12345',affects=[dict(ref='SPDXRef-asset')])])
        job['components'][0]['ref']='SPDXRef-asset';job['representative']['ref']='SPDXRef-asset'
        job['declared_cves'][0]['component_refs']=['SPDXRef-asset']
        job['bom_sha256']=Q.digest(job['input_bom']);generate_fixture_questions(job);Q._prepare_analysis(job);Q.JOBS[job['id']]=job
        saved=self.assess(self.save('o'))
        response=self.client.get(self.url+'/export/cyclonedx');self.assertEqual(response.status_code,200,response.text)
        doc=response.json();self.assertEqual(doc['bomFormat'],'CycloneDX')
        self.assertEqual(doc['vulnerabilities'][0]['affects'],[dict(ref='SPDXRef-asset')])

    def test_cyclonedx_optional_component_refs_are_assigned_without_changing_input(self):
        job=deepcopy(self.job);job['input_bom']['metadata']['component'].pop('bom-ref')
        job['input_bom']['vulnerabilities'][0]['affects']=[dict(ref='/metadata/component')]
        job['components'][0]['ref']='/metadata/component';job['representative']['ref']='/metadata/component'
        job['declared_cves'][0]['component_refs']=['/metadata/component']
        job['bom_sha256']=Q.digest(job['input_bom']);generate_fixture_questions(job);Q._prepare_analysis(job);Q.JOBS[job['id']]=job
        self.assess(self.save('o'))
        response=self.client.get(self.url+'/export/cyclonedx');self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()['metadata']['component']['bom-ref'],'/metadata/component')
        self.assertNotIn('bom-ref',Q.get(job['id'])['input_bom']['metadata']['component'])

    def test_unlinked_cve_requires_explicit_target_and_can_confirm_its_bom_version(self):
        job=deepcopy(self.job);job['declared_cves'][0]['component_refs']=[]
        generate_fixture_questions(job);Q._prepare_analysis(job);Q.JOBS[job['id']]=job
        case=job['assessment_cases'][0];prefix=case['prefix']
        runtime=next(q for q in job['context_questions'] if q['id']==prefix+'runtime')
        self.assertIn('bom',{o['code'] for o in runtime['options']})
        answers={job['questions'][0]['id']:'o',**{}}
        saved=Q.save_answers(job['id'],dict(self.token(job),answers=answers,
            context_answers=dict(scope='current_single',mode='normal',
                **{prefix+'target':'component:asset',prefix+'runtime':'bom',prefix+'deployment':'running'})))
        row=self.assess(saved)['assessment']['decisions'][0]
        self.assertEqual(row['component']['ref'],'asset');self.assertEqual(row['status'],'affected')

    def test_standard_vex_needs_product_identity_but_unresolved_review_is_available(self):
        job=deepcopy(self.job);job['declared_cves'][0]['component_refs']=[]
        generate_fixture_questions(job);Q._prepare_analysis(job);Q.JOBS[job['id']]=job
        result=self.assess(job)
        self.assertIsNone(result['assessment']['decisions'][0]['component'])
        self.assertEqual(self.client.get(self.url+'/export/review').status_code,200)
        for kind in ('openvex','cyclonedx'):
            response=self.client.get(self.url+'/export/'+kind)
            self.assertEqual(response.status_code,422)
            self.assertIn('Select a BOM component',response.json()['detail'])

if __name__=='__main__':unittest.main()
