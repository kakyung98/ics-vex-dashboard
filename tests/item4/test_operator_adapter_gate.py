"""Reject failed/incomplete evaluation, and keep JSON Boolean generation legal."""
from copy import deepcopy
import unittest
from tools.item4.install_operator_vep_adapter import validate_gate,validate_evaluation
from src.common.runtime.json_output_constraints import generation_schema

class ActivationGate(unittest.TestCase):
    def test_explicit_override_preserves_failure_and_never_bypasses_fingerprints(self):
        report=dict(state='complete',passed=False,adapter_sha256='weights',counts=dict(total=82))
        logic=dict(state='complete',passed=False,total_heldout_cases=82,adapter_sha256='weights',predictions_sha256='predictions')
        with self.assertRaises(ValueError):validate_evaluation(report,logic,'predictions')
        self.assertFalse(validate_evaluation(report,logic,'predictions',True))
        with self.assertRaises(ValueError):validate_evaluation(report,logic,'changed',True)
        incomplete=deepcopy(logic);incomplete['state']='running'
        with self.assertRaises(ValueError):validate_evaluation(report,incomplete,'predictions',True)

    def test_failed_or_incomplete_or_negative_incorrect_cannot_activate(self):
        report=dict(state='complete',passed=True,counts=dict(total=82,valid=82,positive_cases=50,
            positive_cases_recovered=50,admitted_defect_cases=0,negative_cases=8,valid_negative_cases=8))
        validate_gate(report)
        for key,value in [('valid',73),('positive_cases_recovered',39),('admitted_defect_cases',1),('valid_negative_cases',7),('negative_cases',0)]:
            bad=deepcopy(report);bad['counts'][key]=value
            with self.assertRaises(ValueError):validate_gate(bad)
        bad=deepcopy(report);bad['passed']=False
        with self.assertRaises(ValueError):validate_gate(bad)

    def test_boolean_constants_only_relaxed_for_generation_never_original_validator(self):
        schema={'type':'object','properties':{'observed':{'const':True},'value':{'enum':[False]},'kind':{'const':'eq'}}}
        result=generation_schema(schema)
        self.assertEqual(result['properties']['observed'],{'type':'boolean'})
        self.assertEqual(result['properties']['value'],{'type':'boolean'})
        self.assertEqual(result['properties']['kind'],{'const':'eq'})
        self.assertEqual(schema['properties']['observed'],{'const':True})
        from lmformatenforcer import JsonSchemaParser
        for value in ('true','false'):
            p=JsonSchemaParser(result['properties']['observed'])
            for char in value:
                self.assertIn(char,p.get_allowed_characters());p=p.add_character(char)
            self.assertTrue(p.can_end())

if __name__=='__main__':unittest.main()
