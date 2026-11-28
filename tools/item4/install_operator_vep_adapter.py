"""Install only the evaluated operator-prerequisite role; preserve other roles."""
from pathlib import Path
import argparse,hashlib,json,shutil,sys,uuid
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))

def read(p):return json.loads(Path(p).read_text(encoding='utf-8'))
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for block in iter(lambda:f.read(8*1024*1024),b''):h.update(block)
    return h.hexdigest()
def write(p,v):
    p=Path(p);t=p.with_name(p.name+'.'+uuid.uuid4().hex+'.tmp')
    t.write_text(json.dumps(v,indent=2)+'\n',encoding='utf-8');t.replace(p)

def validate_gate(report):
    c=report['counts']
    if (report.get('state')!='complete' or report.get('passed') is not True or
        c['total']<1 or c['valid']/c['total']<.9 or
        c.get('positive_cases',0)<1 or c.get('positive_cases_recovered',0)/c['positive_cases']<.8 or
        c.get('admitted_defect_cases')!=0 or c.get('negative_cases',0)<1 or
        c.get('valid_negative_cases')!=c['negative_cases']):
        raise ValueError('Held-out operator-prerequisite evaluation did not pass; activation refused')

def validate_evaluation(report,logic,prediction_sha,allow_failed=False):
    if (report.get('state')!='complete' or logic.get('state')!='complete' or
        logic.get('total_heldout_cases')!=report['counts']['total'] or
        logic.get('adapter_sha256')!=report['adapter_sha256'] or
        logic.get('predictions_sha256')!=prediction_sha):
        raise ValueError('Incomplete evaluation or checkpoint/prediction fingerprint mismatch')
    try:validate_gate(report);coarse_pass=True
    except ValueError:coarse_pass=False
    passed=coarse_pass and logic.get('passed') is True
    if not passed and not allow_failed:
        raise ValueError('Operator-prerequisite evaluation did not pass; activation refused')
    return passed


def install(source,dataset,activate=False,allow_failed_evaluation=False,model_root=None):
    from src.item4.models import review_adapter_config as A
    from src.common.model_paths import pinned_base
    from src.item4.analysis.exploitation_prerequisites import VERSION
    source=Path(source).resolve();dataset=Path(dataset).resolve()
    report=read(source/'evaluation.json')
    logic=read(source/'semantic_audit.json')
    quality_passed=validate_evaluation(report,logic,sha(source/'predictions.json'),allow_failed_evaluation)
    manifest=read(dataset/'manifest.json');mh=sha(dataset/'manifest.json')
    if (report['dataset_manifest_sha256']!=mh or not manifest.get('source_groups_disjoint') or
        not manifest.get('all_unreviewed_cves_remain_unlabelled') or
        manifest.get('real_counts',{}).get('train',0)<1 or manifest['real_counts'].get('test',0)<1):
        raise ValueError('Source-disjoint, real-description evaluation provenance is required')
    if report['counts']['total']!=manifest['counts']['test']:raise ValueError('Incomplete test denominator')
    groups={}
    for split in ('train','test'):
        p=dataset/(split+'.jsonl')
        if sha(p)!=manifest['sha256'][p.name]:raise ValueError('Dataset fingerprint differs')
        rows=[json.loads(line) for line in p.read_text(encoding='utf-8').splitlines()]
        if len(rows)!=manifest['counts'][split]:raise ValueError('Dataset count differs')
        groups[split]={r['source_group'] for r in rows if not r['synthetic']}
    if groups['train']&groups['test']:raise ValueError('Source group leakage')
    folder=source/'vep_extraction';marker=read(folder/'training_complete.json');training=read(folder/'train_manifest.json')
    weights_sha=sha(folder/'adapter_model.safetensors')
    if marker['role']!='exploitation-prerequisites' or marker['adapter_sha256']!=weights_sha or report['adapter_sha256']!=weights_sha:
        raise ValueError('Checkpoint or role mismatch')
    if marker['train_manifest_sha256']!=sha(folder/'train_manifest.json') or training['dataset_manifest_sha256']!=mh:
        raise ValueError('Training provenance fingerprint differs')
    if marker['extraction_policy']!=VERSION or report['policy']!=VERSION:raise ValueError('Extraction policy differs')
    if marker.get('heldout_loaded') is not False or training.get('heldout_loaded') is not False or marker['optimizer_updates']<1:
        raise ValueError('Invalid or held-out-contaminated training')
    if marker['initial_trainable_sha256']==marker['final_trainable_sha256']:raise ValueError('Weights did not change')
    local=read(ROOT/'models/precision_roles_qwen25_14b_v1/training_complete.json');base=pinned_base(local).resolve()
    for name,expected in marker['base_files_sha256'].items():
        if sha(base/name)!=expected:raise ValueError('Shared base pin mismatch: '+name)
    before=read(A.CONFIG);config=json.loads(json.dumps(before))
    models=Path(model_root or ROOT/'models').resolve()
    if models.name.casefold()!='models':raise ValueError('Use a dedicated models directory for adapter storage')
    models.mkdir(parents=True,exist_ok=True)
    target=(models/'vep_extraction_qwen25_14b_v2').resolve()
    if not target.is_relative_to(models):raise ValueError('Destination escapes models')
    if target.exists():
        if sha(target/'adapter_model.safetensors')!=weights_sha:raise ValueError('A different adapter occupies destination')
    else:
        stage=target.with_name(target.name+'.staging-'+uuid.uuid4().hex).resolve()
        if not stage.is_relative_to(models):raise ValueError('Staging escapes models')
        stage.mkdir(parents=True)
        for p in folder.iterdir():
            if p.is_file():shutil.copyfile(p,stage/p.name)
        shutil.copyfile(folder/'training_complete.json',stage/'training_complete.original.json')
        shutil.copyfile(folder/'adapter_config.json',stage/'adapter_config.original.json')
        adapter=read(stage/'adapter_config.json');adapter['base_model_name_or_path']=str(base);write(stage/'adapter_config.json',adapter)
        write(stage/'training_complete.json',dict(marker,training_base=marker['base'],base=str(base),base_relocation='All pinned base and tokenizer bytes verified; adapter weights unchanged'))
        shutil.copyfile(source/'evaluation.json',stage/'evaluation.json')
        write(stage/'import_receipt.json',dict(source=str(source),adapter_sha256=weights_sha,evaluation_sha256=sha(source/'evaluation.json'),dataset_manifest_sha256=mh,
             real_counts=manifest['real_counts'],annotation_method=manifest['annotation_method'],expert_gold=False,
             evaluation_passed=quality_passed,user_requested_failed_evaluation_activation=not quality_passed and allow_failed_evaluation,
             imported_at=datetime.now(timezone.utc).isoformat()))
        stage.rename(target)
    if models!=(ROOT/'models').resolve():
        config['storage_roots']=list(dict.fromkeys(config.get('storage_roots',[])+[str(models)]))
    configured_path=target.relative_to(ROOT).as_posix() if target.is_relative_to(ROOT) else str(target)
    config['roles']['exploitation-prerequisites'].update(enabled=bool(activate),path=configured_path,
        state='trained_evaluated_operator_prerequisites' if quality_passed else 'enabled_by_user_request_evaluation_failed',
        evaluation_passed=quality_passed,evaluation_gate_override='explicit_user_request' if not quality_passed and allow_failed_evaluation else None,
        dataset=str(dataset),training_run=str(source),evaluation_report=str(source/'evaluation.json'))
    if config['roles']['operating-record-review']!=before['roles']['operating-record-review']:raise AssertionError('Unrelated role changed')
    write(A.CONFIG,config)
    if activate:
        try:A.selected('exploitation-prerequisites')
        except Exception:write(A.CONFIG,before);raise
    result=dict(activated=bool(activate),role='exploitation-prerequisites',path=str(target),adapter_sha256=weights_sha,
                real_counts=manifest['real_counts'],expert_gold=False,independent_real_asset_accuracy_verified=False,
                evaluation_passed=quality_passed,user_requested_failed_evaluation_activation=not quality_passed and allow_failed_evaluation)
    write(source/'installation.json',result);print(json.dumps(result));return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--dataset',type=Path,required=True);p.add_argument('--activate',action='store_true')
    p.add_argument('--allow-failed-evaluation',action='store_true',help='Use only after an explicit user request to activate the failed checkpoint; preserve failed evaluation provenance')
    p.add_argument('--model-root',type=Path,help='Explicit managed models directory, including storage on another drive')
    a=p.parse_args();install(a.source,a.dataset,a.activate,a.allow_failed_evaluation,a.model_root)
