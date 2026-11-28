"""Semantic boundary and three-valued polarity regressions."""
from copy import deepcopy
import hashlib,json
from pathlib import Path
import unittest
from src.item4.analysis import exploitation_prerequisites as V; from src.item4.analysis import operator_verifiable_conditions as O; from src.item4.decision import attack_graph_builder as G
from tools.item4.build_operator_vep_curriculum import case

class OperatorPrerequisites(unittest.TestCase):
    def test_directory_write_access_cannot_become_file_writability_by_any_user(self):
        quote='The attacker must have write access to the directory containing the TD project file.'
        item=dict(predicate='configuration_required',operator_observable=True,operator='eq',expected=True,
            target='TD project file',value='writable',statement='TD project file is writable',
            operational_quote=quote,source_refs=[dict(source_id='s',quote=quote)],
            observation=dict(kind='access_policy',record_type='access_control_record',check='Inspect the directory write permissions for the assessed principal.'))
        with self.assertRaisesRegex(ValueError,'same assessed attacker'):O.validate_condition(item,{'s':dict(text=quote)})
        item['statement']='The directory containing the TD project file is writable'
        with self.assertRaisesRegex(ValueError,'same assessed attacker'):O.validate_condition(item,{'s':dict(text=quote)})
        item.update(target='TD project directory',statement='The assessed actor has write access to the directory containing the TD project file')
        O.validate_condition(item,{'s':dict(text=quote)})
    def test_default_state_does_not_reverse_explicit_exploitation_condition(self):
        item=dict(predicate='feature_enabled',target='SOCKS Proxy',
            operational_quote='Exploitation requires SOCKS Proxy enabled. SOCKS Proxy is disabled by default.')
        self.assertIs(O.source_polarity(item),True)
        item.update(target='HTTP',operational_quote='The flaw is triggered over HTTP when enabled. HTTP is disabled by default.')
        self.assertIs(O.source_polarity(item),True)
        item['operational_quote']='HTTP is disabled by default.'
        with self.assertRaises(O.OperationalPrerequisiteError):O.source_polarity(item)
    def test_uncertainty_link_accepts_only_unique_terminal_punctuation_difference(self):
        raw=dict(unknowns=['The operating requirement is unresolved.'],
            uncertainty_details=[dict(reason='The operating requirement is unresolved',source_refs=[])])
        linked=V.resolve_references(raw,dict(evidence=[]))
        self.assertEqual(linked['uncertainty_details'][0]['reason'],raw['unknowns'][0])
        self.assertNotEqual(raw['uncertainty_details'][0]['reason'],raw['unknowns'][0])
        raw['unknowns']=['A different fact is unresolved.']
        self.assertEqual(V.resolve_references(raw,dict(evidence=[]))['uncertainty_details'][0]['reason'],raw['uncertainty_details'][0]['reason'])
    def test_action_retains_same_user_privilege_qualification(self):
        quote='A legitimate user with higher privileges than the attacker must open the TD project.'
        item=dict(predicate='user_performs_action',operator_observable=True,operator='eq',expected=True,
            target='TD project',value='opened',statement='A legitimate user opens the TD project.',
            operational_quote=quote,source_refs=[dict(source_id='s',quote=quote)],
            observation=dict(kind='operating_workflow',record_type='operating_procedure',check='Inspect the TD project handling procedure.'))
        with self.assertRaisesRegex(ValueError,'same source actor'):
            O.validate_condition(item,{'s':dict(text=quote)})
        item['statement']='A legitimate user with higher privileges than the attacker opens the TD project.'
        O.validate_condition(item,{'s':dict(text=quote)})
    def test_configuration_predicate_cannot_bypass_positive_atom_convention(self):
        _,record,draft=self.fixture(1)
        item=draft['prerequisites'][0]
        item.update(predicate='configuration_required',value='disabled',statement='FTP is disabled.')
        with self.assertRaisesRegex(ValueError,'positive state'):
            O.validate_condition(item,{s['id']:s for s in record['sources']})
    def test_remote_delivery_does_not_establish_absent_authentication_or_interaction(self):
        for statement in ['No authentication is required.','No user interaction is required.','No privileges are required.']:
            item=dict(statement=statement,source_refs=[dict(quote='Remote attackers execute code via crafted packets.')])
            with self.assertRaises(O.OperationalPrerequisiteError):O.validate_nonrequirement(item)
        O.validate_nonrequirement(dict(statement='No authentication is required.',
            source_refs=[dict(quote='An unauthenticated attacker can exploit the vulnerability.')]))
    def fixture(self,index):
        row=case('test',index);packet=row['packet']
        record={k:packet[k] for k in ('cve','sources','products')}
        return row,record,V.resolve_references(row['target'],packet)

    def compile(self,index):
        row,record,draft=self.fixture(index)
        artifact=V.extract(record,runner=lambda *a,**k:dict(prediction=row['target'],model={},llm_used=True))
        return V.compile_artifact(artifact,record)

    def test_canonical_negative_is_not_inverted_twice_and_unknown_stays_unknown(self):
        compiled=self.compile(1);expression=compiled['paths'][0]['expression'];qid=compiled['questions'][0]['id']
        self.assertEqual(expression,dict(op='not',args=[dict(condition=qid)]))
        graph=G.source_contract('CVE-2096-50001',expression,compiled['questions'],{},None,False,'a'*64)
        graph['sha256']=G.digest(graph)
        for supplied,expected in [('true','false'),('false','true'),('unknown','unknown')]:
            result=G.evaluate(graph,{qid:supplied,'deployment':'true','affected_version':'true'})
            self.assertEqual(result['value'],expected);self.assertFalse(result['no_path_proven'])

    def test_supported_and_or_and_not_structure_survives_compilation(self):
        for index,op in [(4,'and'),(5,'or'),(11,'and')]:
            value=self.compile(index)['paths'][0]['expression'];self.assertEqual(value['op'],op)
            if index==11:self.assertEqual(value['args'][1]['op'],'not')

    def test_defects_and_architecture_are_excluded_and_not_safety_evidence(self):
        for index in (7,8,9):
            row,record,draft=self.fixture(index)
            self.assertFalse(draft['prerequisites']);self.assertFalse(draft['scenarios'])
            self.assertTrue(draft['unknowns']);self.assertTrue(draft['excluded_facts'])
            injected=deepcopy(self.fixture(0)[2]['prerequisites'][0])
            injected.update(target='software',operational_quote=record['sources'][0]['text'].split('\n\n')[-1],source_refs=[dict(source_id=record['sources'][0]['id'],quote=record['sources'][0]['text'])])
            with self.assertRaisesRegex(ValueError,'defect|architecture'):
                O.validate_condition(injected,{s['id']:s for s in record['sources']})

    def test_ambiguous_legacy_encoding_and_contradictory_not_are_rejected(self):
        _,record,draft=self.fixture(0)
        for key,value in [('operator','neq'),('expected',False)]:
            changed=deepcopy(draft);changed['prerequisites'][0][key]=value
            with self.assertRaises(ValueError):V.validate(changed,record)
        changed=deepcopy(draft);changed['scenarios'][0]['expression']=dict(op='not',args=[{'condition':'service'}])
        with self.assertRaisesRegex(ValueError,'polarity'):V.validate(changed,record)

    def test_authentication_nonrequirement_does_not_mean_authentication_disabled(self):
        _,record,draft=self.fixture(10)
        self.assertFalse(draft['prerequisites']);self.assertTrue(draft['nonrequirements'])
        item=deepcopy(self.fixture(0)[2]['prerequisites'][0]);source=record['sources'][0]
        item.update(operational_quote='Exploitation does not require authentication.',source_refs=[dict(source_id=source['id'],quote=source['text'])])
        with self.assertRaisesRegex(ValueError,'nonrequirement'):O.validate_condition(item,{source['id']:source})

    def test_real_annotations_preserve_quantified_negative_and_grouped_split(self):
        root=Path(__file__).resolve().parents[2]/'results/operator_vep_adapter_v2/real_dataset'
        rows={split:[json.loads(l) for l in (root/(split+'.jsonl')).read_text(encoding='utf-8').splitlines()] for split in ('train','test')}
        groups={split:{r['source_group'] for r in data if not r['synthetic']} for split,data in rows.items()}
        self.assertFalse(groups['train']&groups['test'])
        rejected={}
        for split,items in rows.items():
            for row in items:
                record={k:row['packet'][k] for k in ('cve','sources','products')}
                draft=V.resolve_references(row['target'],row['packet'])
                try:V.validate(draft,record)
                except O.OperationalPrerequisiteError as exc:
                    rejected[row.get('cve',row['id'])]=str(exc)
                    continue
                if row.get('cve')=='CVE-2024-2617':
                    atom=draft['prerequisites'][0]
                    self.assertEqual(atom['observation']['quantifier'],'all')
                    self.assertEqual(draft['scenarios'][0]['expression']['op'],'not')
        self.assertEqual(sum(not r['synthetic'] for r in rows['train']),42)
        self.assertEqual(sum(not r['synthetic'] for r in rows['test']),18)
        self.assertEqual(set(rejected),{'CVE-2023-0345'})

if __name__=='__main__':unittest.main()
