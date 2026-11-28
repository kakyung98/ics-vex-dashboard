"""Preserve the selected source, open-world gold and exact multi-component bindings."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from tools.item3.build_item3_advisory_dataset import build, blind_document, perturb, source_gold, sha, partition, cpe_test_refs
from tools.item3.advisory_test_scoring import checked_dataset, score_component
from tools.item3.run_item3_test import match_document, predict, score


def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value),encoding='utf-8')


def original(cid='CVE-2020-1000', with_cpe=False):
    components=[dict(type='application',**{'bom-ref':ref},name=name,version='1.2',
        description='Original version 1.2 '+cid,
        properties=[dict(name='dataset:source-product-id',value=ref)])
        for ref,name in [('a','Alpha'),('b','Beta')]]
    if with_cpe:
        components[0]['cpe']='cpe:2.3:a:vendor:alpha:1.2:*:*:*:*:*:*:*'
    return dict(bomFormat='CycloneDX',specVersion='1.7',components=components,
        vulnerabilities=[dict(id=cid,affects=[dict(ref='a')],properties=[
            dict(name='dataset:product-link-status',value='source-explicit'),
            dict(name='dataset:source-product-status',value=json.dumps({'known_affected':['a'],'known_not_affected':['b']}))])],
        metadata=dict(component=dict(name=cid,**{'bom-ref':'source'})),
        externalReferences=[dict(url='https://source/'+cid)])


def build_fixture(tmp_path):
    source=tmp_path/'source'
    for i in range(10):
        value=original(f'CVE-2020-{1000+i}')
        value['components'][0]['name']+=' '+str(i)
        write(source/(str(i)+'.json'),value)
    # An empty document with no in-scope CVE remains in the population.
    write(source/'empty.json',dict(bomFormat='CycloneDX',components=[]))
    cves=tmp_path/'cves.jsonl'
    cves.write_text(''.join(json.dumps(dict(id=f'CVE-2020-{1000+i}'))+'\n' for i in range(10)),encoding='utf-8')
    output=tmp_path/'derived'
    manifest=build(source,output,cves)
    return source,output,manifest


def test_blind_input_removes_answers_and_duplicate_field_hints():
    source=original()
    untouched=deepcopy(source)
    document=blind_document(source,'opaque')
    assert source==untouched
    assert document['components'][0]['name']=='Alpha'
    assert 'vulnerabilities' not in document and 'CVE-' not in json.dumps(document)
    assert 'description' not in document['components'][0]
    assert 'properties' not in document['components'][0]
    assert 'externalReferences' not in document
    source['components'][0]['version']='Versions < 2.0 (only affected by CVE-2020-1000)'
    value=blind_document(source,'opaque')['components'][0]['version']
    assert value=='Versions < 2.0 (only affected by [redacted-cve])'


def test_source_relations_do_not_promote_document_cooccurrence():
    source=original()
    gold=source_gold(source,{'CVE-2020-1000'})
    assert gold['components'][0]['expected_cves']==['CVE-2020-1000']
    assert gold['components'][1]['expected_cves']==[]
    assert gold['components'][1]['negative_cves']==['CVE-2020-1000']
    source['vulnerabilities'][0]['properties'][0]['value']='unknown'
    assert not source_gold(source,{'CVE-2020-1000'})['components'][0]['expected_cves']
    assert not source_gold(original(),{'CVE-2020-1000'},rejected={'CVE-2020-1000'})['expected_cves']


def test_missing_cpe_does_not_become_an_invented_noise_success():
    document=blind_document(original(),'opaque')
    output,change=perturb(document,'CPE_noise','doc',{'alpha','beta'})
    assert output==document and not change['applied']
    assert change['reason']=='source_field_missing_or_unknown'
    document=blind_document(original(with_cpe=True),'opaque')
    output,change=perturb(document,'CPE_noise','doc',{'alpha','beta'})
    assert change['applied']
    assert output['components'][0]['cpe'][len(output['components'][0]['cpe'])-len(document['components'][0]['cpe'][8:]):]==document['components'][0]['cpe'][8:]
    assert output['components'][1]==document['components'][1]


def test_build_keeps_whole_documents_pairs_and_source_bytes(tmp_path):
    source,output,manifest=build_fixture(tmp_path)
    assert manifest['source_documents']==11 and manifest['counts']['cases']==22
    assert manifest['counts']['empty_source_sboms']==1
    split=json.loads((output/'CVE_split.json').read_bytes())
    assert not set(split['train'])&set(split['test'])
    assert len(split['train'])+len(split['test'])==10
    for fold in ('train','test'):
        labels,pairs,universe,actual=checked_dataset(output/fold)
        assert actual==fold and len(labels)==2*len(pairs)
        for label in labels.values():
            assert sha(source/label['source_file'])==label['source_sha256']
    with pytest.raises(FileExistsError):
        build(source,output,tmp_path/'cves.jsonl')


def test_component_swap_cannot_be_hidden_by_sbom_level_union():
    universe={'A','B'}
    truth=dict(expected_cves=['A'],negative_cves=['B'])
    mapping,_,outside=score_component(['B'],[],truth,universe)
    assert mapping['TP']==0 and mapping['FP']==1 and mapping['FN']==1 and outside==0
    truth=dict(expected_cves=['A'],negative_cves=[])
    mapping,_,outside=score_component(['B','OUT','B'],[],truth,universe)
    assert mapping['FP']==2 and mapping['unjudged']==0 and outside==1


def test_large_documents_are_batched_without_dropping_component_refs():
    document=dict(bomFormat='CycloneDX',components=[dict(name=str(i),**{'bom-ref':str(i)}) for i in range(205)])
    sizes=[]
    def matcher(part,**options):
        sizes.append(len(part['components']))
        return dict(components=[dict(component=dict(id=c['bom-ref']),cves=[]) for c in part['components']])
    result=match_document(document,matcher,'rules')
    assert sizes==[100,100,5]
    assert [r['component']['id'] for r in result['components']]==[str(i) for i in range(205)]
    assert len(document['components'])==205
    assert match_document(dict(bomFormat='CycloneDX',components=[]),matcher,'rules')['input_disposition']=='empty_source_document'


def test_file_prediction_and_new_scorer_keep_component_binding(tmp_path):
    _,output,_=build_fixture(tmp_path)
    def matcher(document,**options):
        return dict(components=[dict(component=dict(id=c['bom-ref']),cves=[]) for c in document['components']])
    path=predict(output/'test/sboms',tmp_path/'run',mode='rules',matcher=matcher)
    report=score(path,output/'test',tmp_path/'run')
    assert report['full_population_complete'] and report['split']=='test'
    assert report['overall']['FN']>0
    assert report['overall']['FP']==0
    assert report['overall']['precision_lower_bound_percent'] is None
    assert not report['acceptance']['passed']
    assert (tmp_path/'run/component_scores.jsonl').exists()


def test_dataset_scoring_rejects_misbound_or_duplicate_component_outputs(tmp_path):
    _,output,_=build_fixture(tmp_path)
    def matcher(document,**options):
        return dict(components=[dict(component=dict(id=c['bom-ref']),cves=[]) for c in document['components']])
    path=predict(output/'test/sboms',tmp_path/'run',mode='rules',matcher=matcher)
    records=[json.loads(s) for s in path.read_text(encoding='utf-8').splitlines()]
    records[0]['component_predictions'][1]['component_ref']=records[0]['component_predictions'][0]['component_ref']
    path.write_text(''.join(json.dumps(r)+'\n' for r in records),encoding='utf-8')
    with pytest.raises(ValueError,match='Duplicate'):
        score(path,output/'test',tmp_path/'score')


def test_active_dataset_pointer_is_hash_checked(tmp_path):
    from tools.item3.item3_splits import test_dataset
    _,output,_=build_fixture(tmp_path)
    write(tmp_path/'data/item3_test_dataset.json',dict(dataset_root='derived',manifest_sha256=sha(output/'manifest.json')))
    assert test_dataset(tmp_path)==output/'test'
    manifest=json.loads((output/'manifest.json').read_bytes())
    manifest['source_documents']=1
    write(output/'manifest.json',manifest)
    with pytest.raises(ValueError,match='integrity'):
        test_dataset(tmp_path)


def test_partition_groups_collisions_created_only_by_masking():
    records=[dict(source_id=str(i),semantic_sha256='clean-'+str(i),
                  variant_semantic_sha256='masked-shared' if i<2 else 'third',
                  gold=dict(declared_scope_cves=[str(i)])) for i in range(3)]
    folds,manifest=partition(records)
    assert folds['0']==folds['1']
    assert manifest['target_cve_overlap']==0
    assert manifest['counts']['train']+manifest['counts']['test']==3


def test_required_cpe_group_takes_priority_over_exact_seventy_thirty():
    records=[dict(source_id=str(i),semantic_sha256='clean-'+str(i),variant_semantic_sha256='variant-'+str(i),
                  requires_cpe_test=i==0,gold=dict(declared_scope_cves=['shared',str(i)] if i<4 else [str(i)]))
             for i in range(6)]
    folds,manifest=partition(records)
    assert all(folds[str(i)]=='test' for i in range(4))
    assert manifest['ratio_relaxed_for_CPE_coverage']
    assert manifest['actual_test_cves']>manifest['requested_test_cves']
    assert manifest['coverage_selection_uses_predictions'] is False
    assert manifest['mandatory_test_sources']==['0']


def test_cpe_coverage_uses_a_judged_component_not_just_document_cve_presence():
    source=original(with_cpe=True)
    record=dict(blind=blind_document(source,'opaque'),gold=source_gold(source,{'CVE-2020-1000'}))
    assert cpe_test_refs(record)==['a']
    record['gold']['components'][0]['expected_cves']=[]
    assert cpe_test_refs(record)==[]


def test_explicit_case_selection_stays_input_only_and_binds_the_real_cpe_change(tmp_path):
    source=tmp_path/'source'
    for i in range(8):
        value=original(f'CVE-2020-{1000+i}',with_cpe=i==0)
        value['components'][0]['name']+=' '+str(i)
        write(source/(str(i)+'.json'),value)
    cves=tmp_path/'cves.jsonl'
    cves.write_text(''.join(json.dumps(dict(id=f'CVE-2020-{1000+i}'))+'\n' for i in range(8)),encoding='utf-8')
    dataset=tmp_path/'derived'
    build(source,dataset,cves)
    labels,_,_,_=checked_dataset(dataset/'test')
    chosen=[r for r in labels.values() if r['source_id']=='0']
    variant=next(r for r in chosen if r['scenario']!='control')
    assert variant['scenario']=='CPE_noise' and variant['noise_applied']
    assert variant['perturbation']['component_ref']=='a'
    seen=[]
    def matcher(document,**options):
        seen.append(document['components'][0]['cpe'])
        return dict(components=[dict(component=dict(id=c['bom-ref']),cves=[]) for c in document['components']])
    path=predict(dataset/'test/sboms',tmp_path/'run',mode='rules',matcher=matcher,case_ids=[r['id'] for r in chosen])
    assert len(seen)==2 and len(set(seen))==2
    report=score(path,dataset/'test',tmp_path/'run')
    assert report['predicted_cases']==2 and not report['full_population_complete']
    variant_id = variant['id']
    variant_predictions = tmp_path/'variant_predictions.jsonl'
    records = [line for line in path.read_bytes().splitlines() if json.loads(line)['id'] == variant_id]
    variant_predictions.write_bytes(b'\n'.join(records))
    sample = score(variant_predictions, dataset/'test', tmp_path/'sample', case_ids=[variant_id])
    assert sample['cases'] == 1 and sample['missing_predictions'] == 0
    assert sample['selected_cases_complete'] and not sample['full_population_complete']
    assert sample['pairs']['total'] == 0
    missing = score(variant_predictions, dataset/'test', tmp_path/'missing', case_ids=[r['id'] for r in chosen])
    assert missing['missing_predictions'] == 1 and not missing['selected_cases_complete']
