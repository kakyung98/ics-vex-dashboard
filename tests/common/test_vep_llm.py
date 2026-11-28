"""Contract/regression tests with synthetic LLM responses, not accuracy claims."""
from copy import deepcopy
import hashlib
import json
import tempfile
import unittest
import sys
from pathlib import Path
from unittest.mock import patch
from src.item4.analysis import exploitation_prerequisites as V
from src.item4.models import operating_record_review_model as O
from src.item4.decision import population_condition_rules as P
from src.item4.decision import evidence_based_vex as E
from src.item4.models import json_inference_client as L
from src.common.data.prerequisite_research_schema import enrich


def fixture():
    text='For Product A, exploitation requires FTP enabled and network access to TCP port 21.'
    source=dict(id='s1',text=text,text_sha256=hashlib.sha256(text.encode()).hexdigest(),
                url='https://example.invalid/fixture',product_keys=['p1'])
    record=dict(cve='CVE-2026-12345',sources=[source],products=[dict(key='p1',aliases=['Product A'])])
    ref=dict(source_id='s1',quote=text)
    draft=dict(format=V.VERSION,cve=record['cve'],prerequisites=[
        dict(id='ftp',predicate='feature_enabled',target='FTP',value='',statement='FTP must be enabled',operator_observable=True,source_refs=[ref]),
        dict(id='net',predicate='network_reachable',target='TCP port 21',value='',statement='TCP port 21 must be reachable',operator_observable=True,source_refs=[ref])],
        scenarios=[dict(id='route1',product_keys=['p1'],expression=dict(op='and',args=[dict(condition='ftp'),dict(condition='net')]),source_refs=[ref])],
        nonrequirements=[],unknowns=[])
    for item in draft['prerequisites']:
        item.update(operator='eq',expected=True,operational_quote='FTP enabled' if item['id']=='ftp' else 'network access to TCP port 21',
            observation=dict(kind='configuration' if item['id']=='ftp' else 'network_access',
                record_type='configuration_export' if item['id']=='ftp' else 'firewall_acl',check='Verify the source-specified state'))
    return record,enrich(draft)


class VEP(unittest.TestCase):
    def artifact(self):
        record,draft=fixture()
        return record,V.extract(record,runner=lambda *a,**k:dict(prediction=draft,model={'name':'synthetic'},llm_used=True))

    def test_llm_extraction_compiles_source_bound_and_or_not(self):
        record,artifact=self.artifact()
        self.assertFalse(artifact['nli_used']);self.assertFalse(artifact['coverage_complete'])
        compiled=V.compile_artifact(artifact,record)
        self.assertEqual(len(compiled['questions']),2)
        self.assertEqual(compiled['paths'][0]['expression']['op'],'and')
        self.assertEqual(compiled['paths'][0]['product_keys'],['p1'])

    def test_hallucinated_quotes_wrong_cve_scope_and_dangling_ids_rejected(self):
        for change in ('quote','cve','product','dangling','duplicate','nonrequirement'):
            record,draft=fixture()
            if change=='quote':draft['prerequisites'][0]['source_refs']=[dict(source_id='s1',quote='invented')]
            if change=='cve':draft['cve']='CVE-2026-99999'
            if change=='product':draft['scenarios'][0]['product_keys']=['p2']
            if change=='dangling':draft['scenarios'][0]['expression']={'condition':'missing'}
            if change=='duplicate':draft['prerequisites'][1]['id']='ftp'
            if change=='nonrequirement':draft['scenarios'][0]['expression']={'condition':'ftp'}
            with self.subTest(change=change),self.assertRaises(ValueError):V.validate(draft,record)

    def test_unknown_attacker_possession_never_becomes_an_operator_question(self):
        record,draft=fixture();draft['prerequisites'][0]['predicate']='attacker_authenticated'
        with self.assertRaises(ValueError):
            V.extract(record,runner=lambda *a,**k:dict(prediction=draft,model={},llm_used=True))

    def test_source_hash_and_relation_product_scope_are_checked(self):
        record,draft=fixture();record['sources'][0]['text']='changed'
        with self.assertRaisesRegex(ValueError,'hash'):V.validate(draft,record)
        record,draft=fixture();record['sources'][0]['product_keys']=['another']
        with self.assertRaisesRegex(ValueError,'scope'):V.validate(draft,record)

    def test_uncertainty_metadata_requires_recorded_reason_scope_and_exact_citation(self):
        record, draft = fixture()
        draft['unknowns'] = ['The required mode is unspecified.']
        gap = dict(reason=draft['unknowns'][0], kind='required_condition', scenario_ids=['route1'],
                   source_refs=[dict(evidence_id='e1')])
        draft['uncertainty_details'] = [gap]
        result = V.extract(record, runner=lambda *a, **k: dict(prediction=draft, model={}, llm_used=True))
        self.assertEqual(result['draft']['uncertainty_details'][0]['source_refs'][0]['quote'], record['sources'][0]['text'])
        for change in [dict(reason='different issue'), dict(scenario_ids=['missing']),
                       dict(source_refs=[dict(source_id='s1', quote='invented')])]:
            bad = deepcopy(result['draft'])
            bad['uncertainty_details'][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                V.validate(bad, record)

    def test_evidence_id_transport_preserves_exact_original_newlines(self):
        record,draft=fixture();source=record['sources'][0]
        source['text']=source['text'].replace(' and ','\nand ')
        source['text_sha256']=hashlib.sha256(source['text'].encode()).hexdigest()
        packet=V.extraction_packet(record)
        for item in draft['prerequisites']+draft['scenarios']:
            item['source_refs']=[dict(evidence_id=packet['evidence'][0]['evidence_id'])]
        result=V.extract(record,runner=lambda *a,**k:dict(prediction=draft,model={},llm_used=True))
        self.assertEqual(result['draft']['prerequisites'][0]['source_refs'][0]['quote'],source['text'])
        draft['prerequisites'][0]['source_refs']=[dict(evidence_id='invented')]
        with self.assertRaisesRegex(ValueError,'evidence ID'):V.resolve_references(draft,packet)

    def test_llm_relation_review_is_bounded_to_the_quoted_prerequisite_ids(self):
        record,draft=fixture();bad=deepcopy(draft)
        bad['scenarios'][0]['expression']={'condition':'invented'}
        calls=[]
        def generate(system,packet,**kwargs):
            calls.append(packet)
            if len(calls)==1:return dict(prediction=bad,model={},llm_used=True)
            self.assertEqual(set(packet['schema']['properties']),{'scenarios','unknowns'})
            self.assertEqual(packet['prerequisites'],bad['prerequisites'])
            self.assertEqual(packet['schema']['$defs']['expression']['oneOf'][0]['properties']['condition']['enum'],['ftp','net'])
            return dict(prediction={k:draft[k] for k in ('scenarios','unknowns')},model={},llm_used=True)
        result=V.extract(record,runner=generate)
        self.assertEqual(len(calls),2);self.assertTrue(result['relation_review'])
        self.assertFalse(result['relation_review']['nli_used'])
        bad['scenarios']=[];calls.clear()
        self.assertTrue(V.extract(record,runner=generate)['relation_review'])
        self.assertEqual(len(calls),2)

    def test_inference_failure_never_falls_back_to_regex_or_nli(self):
        record,_=fixture()
        with patch.object(V,'resolve',side_effect=RuntimeError('unavailable')),patch.dict(sys.modules,{'src.operational_nli':None}),patch.object(P,'compile_paths',side_effect=AssertionError('regex forbidden')):
            output,artifact,error=V.compiled(record)
        self.assertFalse(output['paths']);self.assertIsNone(artifact);self.assertTrue(error)

    def test_cache_reuses_valid_output_and_invalidates_changed_sources(self):
        record,draft=fixture();calls=[]
        def generate(*args,**kwargs):
            calls.append(1);return dict(prediction=draft,model={},llm_used=True)
        with tempfile.TemporaryDirectory() as directory,patch.dict(V.os.environ,ICSVEX_VEP_CACHE=directory),patch.object(L,'generate',side_effect=generate):
            a=V.resolve(record);self.assertEqual(V.resolve(record),a);self.assertEqual(len(calls),1)
            record['sources'][0]['url']='https://example.invalid/new';V.resolve(record)
            self.assertEqual(len(calls),2)
            for path in Path(directory).glob('*.json'):
                data=json.loads(path.read_text());data['draft']['unknowns']=['tampered'];path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,'integrity'):V.resolve(record)

    def test_failed_extraction_preserves_unresolved_plan_during_backoff(self):
        record,_=fixture()
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(V.os.environ,ICSVEX_VEP_CACHE=directory), \
                patch.object(V,'FAILURES',{}), \
                patch.object(L,'generate',side_effect=ValueError('Invalid source relation')) as infer:
            first=V.compiled(record)
            repeated=V.compiled(record)
        self.assertEqual(first,repeated)
        self.assertIsNone(first[1])
        self.assertTrue(first[0]['gaps'])
        self.assertEqual(infer.call_count,1)

    def test_population_rule_uses_vep_instead_of_stored_regex_compilation(self):
        record,artifact=self.artifact()
        record.update(sha256='a'*64,source_backing='synthetic',compiled={'gaps':[], 'paths':[], 'questions':[]})
        with patch.object(P,'get',return_value=record),patch.object(V,'compiled',return_value=(V.compile_artifact(artifact,record),artifact,None)),patch.dict(sys.modules,{'src.llm_source_rules':None}):
            rule=P.make_rule(record['cve'],'Product A')
        self.assertEqual(rule['extraction_provider'],'generative_llm_vep')
        self.assertEqual(len(rule['questions']),2);self.assertEqual(len(rule['source_path_scopes']),1)


class OperatingRecords(unittest.TestCase):
    def fixture(self,value='true'):
        q=dict(id='vep-ftp',label='Is FTP enabled?',nist_fields=['C13-02.02'],source={},options={})
        O.annotate(q,dict(origin='workstation'))
        evidence=[dict(id='r1',excerpt='FTP is enabled on this component now.')]
        row=dict(evidence_id='r1',value=value,quote=evidence[0]['excerpt'],current_applied_state=True,scope_matches=True,reason='Synthetic judgement')
        return q,evidence,row

    def run_review(self,q,evidence,rows,coverage='complete'):
        with patch.dict(sys.modules,{'src.operational_nli':None}):
            return O.compare(q,evidence,coverage,runner=lambda *a,**k:dict(prediction={'records':rows},model={},llm_used=True))

    def test_record_review_is_generative_and_has_no_nli_scores(self):
        q,e,row=self.fixture();result=self.run_review(q,e,[row])
        self.assertEqual(result['value'],'true');self.assertFalse(result['nli_used'])
        self.assertNotIn('nli',q);self.assertNotIn('minimum_score',result['policy'])
        row['quote_evidence_id']=row.pop('evidence_id');row['evidence_id']=row['quote_evidence_id'];row.pop('quote')
        self.assertEqual(self.run_review(q,e,[row])['value'],'true')

    def test_partial_negatives_conflicts_unapplied_and_wrong_quotes_stay_unknown(self):
        q,e,row=self.fixture('false');self.assertEqual(self.run_review(q,e,[row],'partial')['value'],'unknown')
        for field,value in [('current_applied_state',False),('scope_matches',False),('quote','invented'),('evidence_id','missing')]:
            with self.subTest(field=field):
                bad=dict(row,**{field:value});self.assertEqual(self.run_review(q,e,[bad])['value'],'unknown')
        e.append(dict(id='r2',excerpt='FTP is disabled now.'))
        other=dict(row,evidence_id='r2',value='true',quote=e[1]['excerpt'])
        self.assertEqual(self.run_review(q,e,[row,other])['value'],'unknown')

    def test_historical_records_and_model_failure_stay_unknown(self):
        q,e,row=self.fixture();e[0]['excerpt']='Historical record: FTP is enabled.'
        with patch.object(L,'generate',side_effect=AssertionError('Historical input must abstain')):
            self.assertEqual(O.compare(q,e,'complete')['value'],'unknown')
        q,e,row=self.fixture()
        with patch.object(L,'generate',side_effect=RuntimeError('offline')):
            self.assertEqual(O.compare(q,e,'complete')['value'],'unknown')


class Integration(unittest.TestCase):
    def test_default_plan_evaluation_and_export_never_call_nli(self):
        from tools.item4.auto_vex_fixture_support import profile,request
        from src.item4.decision import attack_graph_builder as G
        from src.item4.decision import mulval_attack_graphs as MV
        original=deepcopy(E.registry()['rules']['CVE-2014-0198'])
        # Synthetic model output grounded in the actual supplier snapshot.
        def infer(record):
            source=record['sources'][0]
            quote=original['questions'][0]['source']['quote']
            ref=dict(source_id=source['id'],quote=quote)
            draft=dict(format=V.VERSION,cve=record['cve'],prerequisites=[dict(id='buffers',predicate='feature_enabled',target='SSL_MODE_RELEASE_BUFFERS',value='',statement='SSL_MODE_RELEASE_BUFFERS must be enabled',operator_observable=True,source_refs=[ref],operator='eq',expected=True,operational_quote='SSL_MODE_RELEASE_BUFFERS is\nenabled',observation=dict(kind='configuration',record_type='configuration_export',check='Check the running SSL_MODE_RELEASE_BUFFERS configuration'))],scenarios=[dict(id='route',product_keys=[record['products'][0]['key']],expression=dict(condition='buffers'),source_refs=[ref])],nonrequirements=[],unknowns=[])
            return V.extract(record,runner=lambda *a,**k:dict(prediction=draft,model={'name':'synthetic'},llm_used=True))
        # Validate production graph wiring without depending on an external MulVAL host.
        def graph(*args):
            result=G.source_contract(*args)
            result['generation_status']='complete';result['sha256']=G.digest({k:v for k,v in result.items() if k!='sha256'})
            return result
        with patch.object(V,'resolve',side_effect=infer),patch.object(G,'build',side_effect=graph),patch.dict(sys.modules,{'src.operational_nli':None,'src.llm_source_rules':None}):
            p=profile();plan=E.plan(original['cve'],p)
            q=next(q for q in plan['questions'] if q['id'].startswith('vep-'))
            req=request(original['cve'],p,{q['id']:'observed'})
            result=E.evaluate(req)
            self.assertEqual(result['decision']['status'],'affected')
            self.assertTrue(result['llm_used']);self.assertFalse(result['nli_used'])
            self.assertNotIn('operational_nli',result)
            self.assertNotIn('nli_analysis',result['workflow_contract']['stages'])
            req['auto_observations'][q['id']]['value']='absent'
            self.assertEqual(E.evaluate(req)['decision']['status'],'under_investigation')
            exported=E.export(req)
            self.assertIn('prerequisite_sha256',exported['statements'][0]['status_notes'])
            self.assertNotIn('operational_nli_sha256',exported['statements'][0]['status_notes'])
            # Exercise record review, persisted BOM evaluation and both API exports.
            from tools.item4 import serve_nist_operational_vex as S
            from fastapi.testclient import TestClient
            p['evidence']['configuration']['excerpt']='SSL_MODE_RELEASE_BUFFERS is enabled in the current applied configuration.'
            req=request(original['cve'],p,{q['id']:'from_evidence'})
            def review(system,packet,**kwargs):
                self.assertEqual(kwargs['role'],'operating-record-review')
                return dict(llm_used=True,model={'name':'synthetic'},prediction=dict(records=[dict(
                    evidence_id=e['id'],value='true',quote=e['excerpt'],current_applied_state=True,
                    scope_matches=True,reason='Synthetic model response') for e in packet['records']]))
            with tempfile.TemporaryDirectory() as directory,patch.object(L,'generate',side_effect=review),patch.object(S.service.bom_vex_workflow,'DB',Path(directory)/'workflows.db'),patch.object(S.service.operational_vex_api,'DB',Path(directory)/'reviews.db'):
                w=S.service.bom_vex_workflow;client=TestClient(S.app)
                self.assertEqual(client.get('/api/operational-vex/nli-status').status_code,404)
                self.assertEqual(client.get('/api/operational-vex/prerequisite-schema').json()['title'],V.TITLE)
                bom=dict(bomFormat='CycloneDX',specVersion='1.6',version=1,components=[{
                    'bom-ref':'openssl','type':'library','name':'OpenSSL','version':'1.0.1g'}])
                workflow=w.create(dict(id='synthetic-vep-integration',status='completed',input_sbom=bom,result={'components':[{
                    'component':{'id':'openssl','name':'OpenSSL'},'validation':{'status':'validated'},
                    'cves':[{'cve_id':original['cve'],'match_status':'match'}]}]}))
                workflow=w.save_profile(workflow['id'],dict(revision=workflow['revision'],bom_sha256=workflow['bom_sha256'],
                    component_ref='openssl',profile=p,component_binding=dict(review_confirmed=True,source='Synthetic inventory',quote='Synthetic component deployment.')))
                cid=workflow['cases'][0]['id']
                result=w.assess(workflow['id'],cid,dict(revision=workflow['revision'],bom_sha256=workflow['bom_sha256'],assessment=req,mapping_review={}))
                self.assertEqual(result['decision']['status'],'affected')
                self.assertEqual(result['operational_record_review']['executed'],1)
                prefix='/api/bom-vex/workflows/'+workflow['id']+'/cases/'+cid+'/export/'
                ov=client.get(prefix+'openvex');cdx=client.get(prefix+'cyclonedx')
                self.assertEqual(ov.status_code,410,ov.text);self.assertEqual(cdx.status_code,410,cdx.text)
                # Retained engine exports are tested above; the retired public
                # workflow must not expose decisions from old questionnaires.



if __name__=='__main__':unittest.main()
