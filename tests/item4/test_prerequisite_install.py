"""Tiny synthetic files test import safety, never model accuracy or actual tuning."""
from pathlib import Path
import hashlib,json,tempfile,unittest
from unittest.mock import patch
from tools.item4 import install_prerequisite_role_adapters as I
from src.item4.models import review_adapter_config as A

def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value),encoding='utf-8')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

class Installation(unittest.TestCase):
    def fixture(self,root):
        base=root/'base';base.mkdir();(base/'model.safetensors').write_bytes(b'SYNTHETIC TEST ONLY')
        pins={'model.safetensors':sha(base/'model.safetensors')}
        write(root/'models/precision_roles_qwen25_14b_v1/training_complete.json',dict(base=str(base)))
        dataset=root/'benchmark/prerequisite_roles_20261119_v7/manifest.json'
        write(dataset,dict(population_count=12418,split_counts=dict(train=8692,dev=1863,test=1863)))
        source=root/'results/run/trained';metrics={};roles={}
        for role,alias in I.ROLES.items():
            folder=source/alias;folder.mkdir(parents=True)
            (folder/'adapter_model.safetensors').write_bytes(('SYNTHETIC TEST ONLY '+alias).encode())
            write(folder/'adapter_config.json',dict(base_model_name_or_path='/remote/test-base'))
            write(folder/'train_manifest.json',dict(role=role,dataset_manifest_sha256=sha(dataset)))
            marker=dict(role=role,base='/remote/test-base',adapter_sha256=sha(folder/'adapter_model.safetensors'),
                train_manifest_sha256=sha(folder/'train_manifest.json'),examples=8692,trained_cves=8692,
                optimizer_updates=1,heldout_loaded=False,initial_trainable_sha256='a'*64,final_trainable_sha256='b'*64,base_files_sha256=pins)
            write(folder/'training_complete.json',marker)
            metrics[role]=dict(test_cases=1863,adapter_sha256=marker['adapter_sha256'])
            roles[role]=dict(enabled=False,path='models/'+alias,alias=alias)
        write(source/'evaluation/report.json',dict(state='complete',test_cves=1863,dataset_manifest_sha256=sha(dataset),roles=metrics))
        config=root/'data/roles.json';write(config,dict(roles=roles))
        return source,config,base

    def test_relocation_preserves_source_and_weights_and_routes_distinct_roles(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source,config,base=self.fixture(root)
            original={alias:(source/alias/'training_complete.json').read_bytes() for alias in I.ROLES.values()}
            with patch.object(I,'ROOT',root),patch.object(A,'ROOT',root),patch.object(A,'CONFIG',config):
                I.install(source,activate=True);roles=A.active_roles()
                self.assertEqual(len({r['sha256'] for r in roles.values()}),2)
                for role,spec in roles.items():
                    alias=I.ROLES[role];folder=Path(spec['folder'])
                    self.assertEqual(Path(spec['base']),base)
                    self.assertEqual((folder/'training_complete.original.json').read_bytes(),original[alias])
                    self.assertEqual((source/alias/'training_complete.json').read_bytes(),original[alias])
                    self.assertEqual(sha(folder/'adapter_model.safetensors'),sha(source/alias/'adapter_model.safetensors'))

    def test_foreign_local_base_is_rejected_before_configuration_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source,config,base=self.fixture(root);before=config.read_bytes()
            (base/'model.safetensors').write_bytes(b'FOREIGN BASE')
            with patch.object(I,'ROOT',root),patch.object(A,'ROOT',root),patch.object(A,'CONFIG',config):
                with self.assertRaisesRegex(ValueError,'Local shared base differs'):I.install(source,activate=True)
            self.assertEqual(config.read_bytes(),before)
            self.assertFalse((root/'models/vep_extraction').exists())

    def test_partial_evaluation_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source,config,_=self.fixture(root);before=config.read_bytes()
            path=source/'evaluation/report.json';report=I.read(path);report['test_cves']=1862;write(path,report)
            with patch.object(I,'ROOT',root),patch.object(A,'CONFIG',config):
                with self.assertRaisesRegex(ValueError,'Incomplete role evaluation'):I.install(source)
            self.assertEqual(config.read_bytes(),before)

if __name__=='__main__':unittest.main()
