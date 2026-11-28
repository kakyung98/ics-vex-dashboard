from copy import deepcopy
import unittest
from tools.item4.audit_operator_vep_logic import equivalent
from tools.item4.build_operator_vep_curriculum import case

class SignedLogicAudit(unittest.TestCase):
    def test_missing_negative_atom_cannot_pass_as_a_valid_negative_case(self):
        target=case('test',11)['target'];bad=deepcopy(target)
        bad['prerequisites']=bad['prerequisites'][:1]
        bad['scenarios'][0]['expression']={'condition':bad['prerequisites'][0]['id']}
        self.assertFalse(equivalent(target,bad))
        self.assertTrue(equivalent(target,target))

    def test_negation_flip_fails_and_commutative_order_does_not(self):
        target=case('test',11)['target'];actual=deepcopy(target)
        actual['scenarios'][0]['expression']['args'].reverse()
        self.assertTrue(equivalent(target,actual))
        actual['scenarios'][0]['expression']['args'][0]={'condition':'diagnostic'}
        self.assertFalse(equivalent(target,actual))

if __name__=='__main__':unittest.main()
