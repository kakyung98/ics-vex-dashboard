"""CPE reconstruction and balanced actual changes must agree with source evidence."""
import json
from pathlib import Path
import pytest

from tools.item3.rebuild_icsa_cpe_source import rebuild
from tools.item3.verify_rebuilt_cpe_source import verify
from tools.item3.build_item3_advisory_dataset import sha
from tools.item3.build_item3_balanced_dataset import build
from tools.item3.advisory_test_scoring import checked_dataset
from tools.item3.run_item3_test import predict,score


def put(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value),encoding='utf-8')


def source_fixture(tmp_path):
    original=tmp_path/'original';entries=[];cves=[]
    for i in range(10):
        cid=f'CVE-2020-{1000+i}'
        document=dict(bomFormat='CycloneDX',specVersion='1.7',components=[dict(
            type='application',**{'bom-ref':'native-'+str(i)},name='Native '+str(i),version='1.2')],
            vulnerabilities=[dict(id=cid,affects=[dict(ref='native-'+str(i))],properties=[
                dict(name='dataset:product-link-status',value='source-explicit')])])
        path=original/'sbom'/(str(i)+'.json');put(path,document)
        entries.append(dict(advisory_id=str(i),file='sbom/'+path.name,sha256=sha(path)))
        cves.append(dict(id=cid,configurations=[dict(cpeMatch=[dict(
            criteria=f'cpe:2.3:a:vendor:product_{i}:1.2:*:*:*:*:*:*:*',vulnerable=True)])]))
    path=original/'sbom/empty.json';put(path,dict(bomFormat='CycloneDX',components=[]))
    entries.append(dict(advisory_id='empty',file='sbom/empty.json',sha256=sha(path)))
    put(original/'index.json',dict(summary=dict(declared_unique_cves=10),advisories=entries))
    cvefile=tmp_path/'cves.jsonl';cvefile.write_text(''.join(json.dumps(r)+'\n' for r in cves),encoding='utf-8')
    return original,cvefile


def test_rebuild_preserves_native_components_and_uses_exact_CVE_CPE_links(tmp_path):
    original,cves=source_fixture(tmp_path);rebuilt=tmp_path/'rebuilt'
    before=sha(original/'sbom/0.json')
    manifest=rebuild(original,rebuilt,cves)
    result=verify(rebuilt,original,cves)
    assert result['passed'] and result['covered_CVEs']==10
    assert manifest['NVD_components']==10 and manifest['original_components']==10
    assert sha(original/'sbom/0.json')==before
    body=json.loads((rebuilt/'sbom/0.json').read_bytes())
    assert body['components'][0]==json.loads((original/'sbom/0.json').read_bytes())['components'][0]
    assert body['components'][1]['cpe']=='cpe:2.3:a:vendor:product_0:1.2:*:*:*:*:*:*:*'


def test_balanced_dataset_has_three_real_changes_per_common_parent_in_each_fold(tmp_path):
    original,cves=source_fixture(tmp_path);rebuilt=tmp_path/'rebuilt';dataset=tmp_path/'dataset'
    rebuild(original,rebuilt,cves)
    manifest=build(rebuilt/'sbom',dataset,cves)
    assert manifest['counts']['cases']==41
    assert manifest['counts']['I1']==manifest['counts']['I2']==manifest['counts']['I3']==10
    assert manifest['counts']['baseline_only_documents']==1
    for fold in ('train','test'):
        labels,groups,_,_=checked_dataset(dataset/fold)
        counts=manifest['by_fold'][fold]
        assert counts['I1']==counts['I2']==counts['I3']>0
        for members in groups.values():
            variants=[r for r in members if r['scenario']!='control']
            if variants:
                assert {r['axis'] for r in variants}=={'I1','I2','I3'}
                assert len({r['perturbation']['component_ref'] for r in variants})==1
                assert all(r['noise_applied'] and r['perturbation']['before']!=r['perturbation']['after'] for r in variants)
    def matcher(document,**options):
        return dict(components=[dict(component=dict(id=c['bom-ref']),cves=[]) for c in document['components']])
    path=predict(dataset/'test/sboms',tmp_path/'run',mode='rules',matcher=matcher)
    report=score(path,dataset/'test',tmp_path/'run')
    assert report['full_population_complete']
    assert report['pairs']['total']==3*manifest['by_fold']['test']['noise_eligible_documents']
    assert report['pairs']['noise_applied']==report['pairs']['total']
    # Saved predictions made before the label-only revision remain scoreable;
    # the existing per-input hash checks still bind them to the same SBOM bytes.
    import re
    legacy=tmp_path/'legacy_predictions.jsonl'
    saved=[json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
    for row in saved:
        row['id']=re.sub(r'-I([123])$',r'-C\1',row['id'])
        row['sbom_file']=re.sub(r'-I([123])\.json$',r'-C\1.json',row['sbom_file'])
    legacy.write_text(''.join(json.dumps(row)+'\n' for row in saved),encoding='utf-8')
    before=legacy.read_bytes()
    rescored=score(legacy,dataset/'test',tmp_path/'rescored')
    assert rescored['overall']==report['overall'] and rescored['by_role']==report['by_role']
    assert rescored['provenance']['renamed_prediction_cases']==report['pairs']['total']
    assert legacy.read_bytes()==before


def test_invented_cpe_is_rejected_even_if_file_index_is_rehashed(tmp_path):
    original,cves=source_fixture(tmp_path);rebuilt=tmp_path/'rebuilt'
    rebuild(original,rebuilt,cves)
    path=rebuilt/'sbom/0.json';doc=json.loads(path.read_bytes())
    doc['components'][1]['cpe']='cpe:2.3:a:invented:wrong:9:*:*:*:*:*:*:*';put(path,doc)
    index=json.loads((rebuilt/'index.json').read_bytes())
    next(r for r in index['advisories'] if r['file']=='sbom/0.json')['sha256']=sha(path)
    put(rebuilt/'index.json',index)
    with pytest.raises(ValueError,match='Unsupported'):
        verify(rebuilt,original,cves)
