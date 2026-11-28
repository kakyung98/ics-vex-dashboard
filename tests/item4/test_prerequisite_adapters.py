"""Routing tests using dummy bytes; these fixtures are not trained model weights."""
from contextlib import contextmanager
import hashlib,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from src.item4.models import review_adapter_config as A


class AdapterRouting(unittest.TestCase):
    def fixture(self,root):
        rows={}
        for i,role in enumerate(sorted(A.ROLES)):
            folder=root/'models'/role;folder.mkdir(parents=True)
            weights=('dummy-routing-test-'+str(i)).encode()
            (folder/'adapter_model.safetensors').write_bytes(weights)
            (folder/'adapter_config.json').write_text(json.dumps({'base_model_name_or_path':str(root/'base')}))
            marker=dict(role=role,base=str(root/'base'),optimizer_updates=1,
                adapter_sha256=hashlib.sha256(weights).hexdigest(),train_manifest_sha256='a'*64)
            (folder/'training_complete.json').write_text(json.dumps(marker))
            rows[role]=dict(enabled=True,alias=role.replace('-','_'),path='models/'+role)
        config=root/'roles.json';config.write_text(json.dumps({'roles':rows}))
        return config,rows

    def test_two_distinct_roles_are_verified_and_selected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);config,_=self.fixture(root)
            with patch.object(A,'ROOT',root),patch.object(A,'CONFIG',config):
                roles=A.active_roles();a,b=roles.values()
                self.assertNotEqual(a['sha256'],b['sha256']);self.assertNotEqual(a['alias'],b['alias'])
                self.assertEqual({r['state'] for r in A.status()},{'trained_adapter_configured'})

    def test_role_weights_mismatch_or_untrained_marker_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);config,rows=self.fixture(root);role=next(iter(rows))
            with patch.object(A,'ROOT',root),patch.object(A,'CONFIG',config):
                path=root/rows[role]['path']/'adapter_model.safetensors';path.write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError,'fingerprint'):A.selected(role)
                marker=root/rows[role]['path']/'training_complete.json'
                value=json.loads(marker.read_text());value['optimizer_updates']=0;marker.write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError,'separately trained'):A.selected(role)

    def test_failed_checkpoint_records_experimental_approval_and_checks_evaluation(self):
        from src.item4.models.operating_record_review_model import status
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, rows = self.fixture(root)
            role = 'exploitation-prerequisites'
            row = rows[role]
            folder = root / row['path']
            weights_sha = hashlib.sha256((folder / 'adapter_model.safetensors').read_bytes()).hexdigest()
            report = folder / 'evaluation.json'
            report.write_text(json.dumps(dict(state='complete', passed=False, adapter_sha256=weights_sha)))
            receipt = dict(adapter_sha256=weights_sha, evaluation_passed=False,
                           evaluation_sha256=hashlib.sha256(report.read_bytes()).hexdigest(),
                           user_requested_failed_evaluation_activation=True)
            (folder / 'import_receipt.json').write_text(json.dumps(receipt))
            row.update(evaluation_passed=False, evaluation_gate_override='explicit_user_request')
            config.write_text(json.dumps(dict(roles=rows)))
            with patch.object(A,'ROOT',root), patch.object(A,'CONFIG',config):
                selected = A.selected(role)
                self.assertTrue(selected['training_completed'])
                self.assertIs(selected['evaluation_passed'], False)
                self.assertTrue(selected['experimental_use_approved'])
                self.assertEqual(selected['evaluation_sha256'], receipt['evaluation_sha256'])
                details = next(r for r in A.status() if r['role']==role)
                self.assertTrue(details['enabled'])
                self.assertEqual(details['state'], 'enabled_by_user_request_evaluation_failed')

                row['evaluation_gate_override'] = None
                config.write_text(json.dumps(dict(roles=rows)))
                with self.assertRaisesRegex(ValueError, 'approval'):
                    A.selected(role)
                row['evaluation_passed'] = True
                config.write_text(json.dumps(dict(roles=rows)))
                with self.assertRaisesRegex(ValueError, 'differs'):
                    A.selected(role)

                row.update(evaluation_passed=False, evaluation_gate_override='explicit_user_request')
                config.write_text(json.dumps(dict(roles=rows)))
                report.write_text(report.read_text()+' ')
                with self.assertRaisesRegex(ValueError, 'fingerprint'):
                    A.selected(role)
                api_status = status()
                self.assertFalse(api_status['enabled'])
                self.assertEqual(next(r['state'] for r in api_status['role_adapters']
                                      if r['role']==role), 'invalid_adapter')

                report.write_text(json.dumps(dict(state='complete', passed=True, adapter_sha256=weights_sha)))
                receipt.update(evaluation_passed=True, user_requested_failed_evaluation_activation=False,
                               evaluation_sha256=hashlib.sha256(report.read_bytes()).hexdigest())
                (folder / 'import_receipt.json').write_text(json.dumps(receipt))
                row.update(evaluation_passed=True, evaluation_gate_override=None)
                config.write_text(json.dumps(dict(roles=rows)))
                selected = A.selected(role)
                self.assertIs(selected['evaluation_passed'], True)
                self.assertFalse(selected['experimental_use_approved'])

    def test_active_role_is_restored_after_failure(self):
        model=SimpleNamespace(peft_config={'default':SimpleNamespace(base_model_name_or_path='base')},active_adapter='default')
        events=[]
        def load(folder,adapter_name,is_trainable):
            events.append(('load',adapter_name));model.peft_config[adapter_name]=SimpleNamespace()
        def select(alias):events.append(('select',alias));model.active_adapter=alias
        model.load_adapter=load;model.set_adapter=select;model.eval=lambda:events.append(('eval',model.active_adapter))
        runtime=SimpleNamespace(model=model)
        spec=dict(alias='vep_extraction',base='base',folder='dummy',sha256='a'*64)
        with patch.object(A,'active_roles',return_value={'exploitation-prerequisites':spec}):
            with self.assertRaisesRegex(RuntimeError,'generation failure'):
                with A.inference_context(runtime,'exploitation-prerequisites'):
                    self.assertEqual(model.active_adapter,'vep_extraction');raise RuntimeError('generation failure')
        self.assertEqual(model.active_adapter,'default')
        self.assertEqual(events[-1],('select','default'))

    def test_pending_training_uses_explicit_base_context(self):
        events=[]
        @contextmanager
        def disabled():
            events.append('disabled');yield;events.append('restored')
        runtime=SimpleNamespace(model=SimpleNamespace(disable_adapter=disabled))
        with patch.object(A,'active_roles',return_value={'exploitation-prerequisites':None}):
            with A.inference_context(runtime,'exploitation-prerequisites') as spec:self.assertIsNone(spec)
        self.assertEqual(events,['disabled','restored'])


if __name__=='__main__':unittest.main()
