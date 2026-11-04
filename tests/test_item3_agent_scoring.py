import importlib.util
import json
from pathlib import Path

path=Path(__file__).resolve().parents[1]/'tools/eval_item3_agents_batched.py'
spec=importlib.util.spec_from_file_location('item3_batched',path)
item3=importlib.util.module_from_spec(spec);spec.loader.exec_module(item3)


def test_new_pipeline_uses_common_tp_fp_unlabelled_scoring(tmp_path):
    base={'component_id':'comp1','component':{'vendor':'vendor','product':'widget','version':'1.0'},
          'review_status':'verified','_sut_input':{'name':'Widget','publisher':'Vendor'}}
    rows=[{**base,'cve_id':'CVE-2099-1111','applicable':True},
          {**base,'cve_id':'CVE-2099-2222','applicable':False,'_negative_family':'version'}]
    gt=tmp_path/'gt.jsonl';gt.write_text(''.join(json.dumps(r)+'\n' for r in rows))
    output={'component':{'name':'Widget','version':'1.0','supplier':'Vendor','cpes':[]},
            'validation':{'status':'validated','product':'widget'},
            'cves':[{'cve_id':c,'match_status':'unknown'} for c in ['CVE-2099-1111','CVE-2099-2222','CVE-2099-3333']]}
    adapter=item3.CachedPipeline([output])
    r=item3.E3.score(str(gt),matcher_module=adapter)
    assert r['TP']==1 and r['FP']==1 and r['precision']==.5
    assert r['unlabelled_predictions']==1 and r['sut_runs']==1
    assert 'frozen v2' in r['sut']


def test_no_oracle_labels_passed_to_predictor(tmp_path):
    r={'component_id':'comp1','component':{'vendor':'secret-vendor','product':'secret-product','version':None},
       'review_status':'verified','_sut_input':{'name':'User input','publisher':'User supplier'},'cve_id':'CVE-2099-1111','applicable':True}
    file=tmp_path/'gt.jsonl';file.write_text(json.dumps(r)+'\n')
    class Predictor:
        def identify_product(self,comp):
            assert comp=={'name':'User input','version':'','supplier':'User supplier'}
            return None,'unresolved'
    result=item3.E3.score(str(file),matcher_module=Predictor())
    assert result['sut_abstained']==1 and result['scored']==0


def test_empty_dictionary_shortcut_cannot_create_identity():
    from ics_agent_matcher_full.ics_agent_matcher.matcher import make_l4,validate
    from src.identification_tasks import identity_gold
    class Empty:
        def get_all(self,*args):return {'products':[]}
    state={'component':{'name':'Widget','cpes':[]},'l2':{'normalized':'widget'},'l3':{'normalized':'1.0'}}
    for prediction in [lambda p:identity_gold(p),lambda p:{'vendor':'madeup','product':'widget','status':'validated'}]:
        stage=make_l4(Empty(),lambda task,p:{'prediction':prediction(p)})
        assert validate({**state,**stage(state)})['validation']['status']=='unresolved'
