"""Activate reviewed integration only after both full frozen tests pass."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from src.common.runtime.training_progress_io import atomic_json
from src.item4.decision.operating_scenario_assessment import affected_precision


def read(path):return json.loads(path.read_text(encoding='utf-8'))
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def finalize():
    three=ROOT/'results/item3_precision_v11/trained_evaluation'
    four=ROOT/'results/item4_operational_v1'
    report3=read(three/'precision_report.json');report4=read(four/'trained_precision_report.json')
    assert report3['full_population_complete'] and report3['completed_BOMs']==18608
    assert report3['target_met'] and report3['conservative_lower_bound_target_met']
    assert report3['execution_errors']==0
    assert report4['target_met'] and report4['cases']==1920
    # The coordinator imports the sealed v2 Gold before beginning #4 inference.
    gold=ROOT/'benchmark/item4_operational_gold_v2'
    labels=[json.loads(s) for s in (gold/'evaluation/labels.jsonl').read_text(encoding='utf-8').splitlines()]
    predictions=[json.loads(s) for s in (four/'trained_predictions.jsonl').read_text(encoding='utf-8').splitlines()]
    verified=affected_precision(predictions,labels)
    for k in ('cases','TP','FP','FN_including_abstentions','precision','recall','abstention_fraction','target_met'):
        assert verified[k]==report4[k],k
    assert all(row['id'].startswith('SYN-') and len(row['id'])==36 for row in predictions)
    dst=ROOT/'results/item4_operational_v2';dst.mkdir(exist_ok=True,parents=True)
    report4.update(gold_version='item4_operational_gold_v2',gold_manifest_sha256=sha(gold/'manifest.json'),
        identifier_integrity_audit=read(gold/'integrity_audit.json'),
        coordinator_original_output=str(four.relative_to(ROOT)))
    atomic_json(dst/'trained_precision_report.json',report4)
    shutil.copyfile(four/'trained_predictions.jsonl',dst/'trained_predictions.jsonl')
    shutil.copyfile(four/'trained_status.json',dst/'trained_status.json')
    # Confirm classification code still matches the frozen run; API changes below
    # only add scope-preserving export metadata and choose the sealed v2 report.
    signature=read(three/'run_config.json')
    assert all(sha(ROOT/p)==digest for p,digest in signature['code'].items())
    assert sha(ROOT/'tools/item3/item3_precision_pipeline.py')==signature['driver_sha256']
    snapshot=ROOT/'results/precision_evaluation_v1/frozen_evaluation_sources.zip'
    with zipfile.ZipFile(snapshot,'w',compression=zipfile.ZIP_DEFLATED) as archive:
        for relative in [*signature['code'],'tools/item3/item3_precision_pipeline.py',
                'tools/common/run_precision_evaluation.py','tools/item4/build_item4_operational_gold.py']:
            archive.write(ROOT/relative,relative)
    api=ROOT/'src/common/web/evaluation_api.py';before=sha(api)
    shutil.copyfile(ROOT/'tools/common/staged_precision_api.py',api)
    html=ROOT/'src/common/web/evaluation_dashboard.html'
    html.write_text(html.read_text(encoding='utf-8').replace("el('export').hidden=false", "el('export').hidden=!r.export_ready"),encoding='utf-8')
    marker=read(ROOT/'models/precision_roles_qwen25_14b_v1/training_complete.json')
    atomic_json(ROOT/'data/identification_runtime.json',dict(mode='agents',runtime='precision_shared_14b_v1',
        adapter_sha256=marker['adapter_sha256'],item3_gold='item3_gold_v11',item4_gold='item4_operational_gold_v2'))
    readme=ROOT/'README.md';text=readme.read_text(encoding='utf-8')
    text=text.replace('item4_operational_gold_v1','item4_operational_gold_v2').replace('results/item4_operational_v1/','results/item4_operational_v2/')
    text+='\n## 최종 학습 모델 전수 평가\n\n'
    text+=f"#3: 18,608건, Precision **{100*report3['precision']:.4f}%**, 목표 80% 초과 통과. "
    text+=f"#4: 합성 시험 1,920건, TP {report4['TP']}, FP {report4['FP']}, Precision **{100*report4['precision']:.4f}%**, 목표 85% 초과 통과. "
    text+=f"#4 재현율 {100*report4['recall']:.2f}%, 보류율 {100*report4['abstention_fraction']:.2f}%. 실제 ICS 영향 Precision은 미측정입니다.\n\n"
    text+='평가 범위·ID 교체·재현 기준은 [평가 절차](docs/PRECISION_EVALUATION_PROTOCOL.md)를 참조하세요. 실제 자산 주석이 준비되면 `python tools/item4/score_item4_real_assets.py --predictions predictions.jsonl --gold real_gold.jsonl --output real_precision_report.json`으로 별도 계산합니다.\n'
    readme.write_text(text,encoding='utf-8')
    atomic_json(ROOT/'results/precision_evaluation_v1/release.json',dict(activated=True,
        item3_report=str((three/'precision_report.json').relative_to(ROOT)),
        item4_report=str((dst/'trained_precision_report.json').relative_to(ROOT)),
        item3_precision=report3['precision'],item4_synthetic_precision=report4['precision'],real_asset_precision=None,
        adapter_sha256=marker['adapter_sha256'],integration_only_change_after_frozen_inference=dict(
            file='src/common/web/evaluation_api.py',before_sha256=before,after_sha256=sha(api),
            reason='Server timestamp, exact operational scope in OpenVEX, schema validation, v2 report paths'),
        classifier_files_unchanged=True,frozen_sources_sha256=sha(snapshot),frozen_sources=str(snapshot.relative_to(ROOT))))
    print('Both complete evaluations verified; runtime activated; v2 results bound to sealed Gold.')


if __name__=='__main__':finalize()
