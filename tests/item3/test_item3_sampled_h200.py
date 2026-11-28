import io
import json
import tarfile

import pytest

from benchmark.item3_evaluation.evaluation.llm_evaluation import select_inputs,main
from benchmark.item3_evaluation.evaluation.h200_evaluation import checked_members,WORKER
from benchmark.item3_evaluation.evaluation.run_item3_test import score
from tests.item3.test_item3_file_test import make_dataset,prediction_file


def test_help_documents_h200_and_sampling_without_starting_inference(capsys):
    with pytest.raises(SystemExit) as result:main(['--help'])
    assert result.value.code==0
    help_text=capsys.readouterr().out
    assert '--backend {h200,local}' in help_text and '--seed' in help_text and '30%' in help_text


def test_random_sample_is_reproducible_without_replacement_and_full_is_explicit(tmp_path):
    folder=tmp_path/'sboms';folder.mkdir()
    for i in range(100):(folder/f'{i:03}.json').write_text('{}')
    (tmp_path/'input_catalog.json').write_text(json.dumps({'entries':[dict(id=f'{i:03}',scenario='component_noise') for i in range(100)]}))
    a=select_inputs(tmp_path,percent=30,seed=12)
    assert a==select_inputs(tmp_path,percent=30,seed=12)
    assert a['selected_cases']==30 and len(set(a['case_ids']))==30
    assert a['case_ids']!=select_inputs(tmp_path,percent=30,seed=13)['case_ids']
    assert select_inputs(tmp_path)['selected_cases']==100
    assert select_inputs(tmp_path,full=True)['selected_cases']==100
    assert select_inputs(tmp_path,limit=4)['diagnostic_only']
    # Exact rounding used for the preserved population.
    assert int(18608*30/100+.5)==5582


def test_default_scope_excludes_controls_but_can_include_them_explicitly(tmp_path):
    dataset=tmp_path/'dataset';labels=make_dataset(dataset,[(['A'],[]),(['B'],[])])
    (dataset/'input_catalog.json').write_text(json.dumps({'entries':[{'id':r['id'],'scenario':r['scenario']} for r in labels]}))
    selection=select_inputs(dataset)
    assert selection['population_cases']==4 and selection['evaluation_population_cases']==2
    assert selection['case_ids']==['variant-0','variant-1']
    assert selection['input_scope']=='variants'
    assert select_inputs(dataset,include_controls=True)['selected_cases']==4
    frozen=tmp_path/'selection.json';frozen.write_text(json.dumps(selection))
    assert select_inputs(dataset,selection_file=frozen)==selection
    selection['case_ids'][0]='control-0';frozen.write_text(json.dumps(selection))
    with pytest.raises(ValueError):select_inputs(dataset,selection_file=frozen)


def test_sample_scoring_does_not_count_unselected_cases_as_missing(tmp_path):
    dataset=tmp_path/'dataset'
    labels=make_dataset(dataset,[(['A'],[]),(['B'],[])])
    selected=['control-0','variant-1']
    predictions=prediction_file(tmp_path/'predictions.jsonl',labels,{'control-0':['A'],'variant-1':['B']})
    report=score(predictions,dataset,dataset/'results/run',universe={'A','B'},case_ids=selected)
    assert report['cases']==2 and report['population_cases']==4
    assert report['selected_cases_complete'] and not report['full_population_complete']
    assert report['missing_predictions']==0 and report['overall']['execution_errors']==0
    assert report['overall']['FN']==0 and report['acceptance']['passed']
    assert report['pairs']['total']==0 and report['pairs']['population_pairs']==2
    missing=prediction_file(tmp_path/'missing.jsonl',labels,{'control-0':['A']})
    incomplete=score(missing,dataset,dataset/'results/incomplete',universe={'A','B'},case_ids=selected)
    assert not incomplete['selected_cases_complete'] and not incomplete['acceptance']['passed']
    assert incomplete['missing_predictions']==1 and incomplete['overall']['FN']==1


def test_result_archives_reject_links_and_path_traversal(tmp_path):
    for name,kind in [('../escape',tarfile.REGTYPE),('link',tarfile.SYMTYPE)]:
        buffer=io.BytesIO()
        with tarfile.open(fileobj=buffer,mode='w') as archive:
            member=tarfile.TarInfo(name);member.type=kind;member.linkname='/outside'
            archive.addfile(member)
        buffer.seek(0)
        with tarfile.open(fileobj=buffer) as archive,pytest.raises(ValueError):
            checked_members(archive,tmp_path)
    compile(WORKER.replace('WORKERS','4'),'<h200-worker>','exec')
