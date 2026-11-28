"""Import evaluated role adapters with verified base relocation and provenance."""
from pathlib import Path
from datetime import datetime,timezone
import argparse,hashlib,json,shutil,sys,uuid
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
ROLES={'exploitation-prerequisites':'vep_extraction','operating-record-review':'operating_record_review'}

def read(path):return json.loads(Path(path).read_text(encoding='utf-8'))
def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(8*1024*1024),b''):h.update(block)
    return h.hexdigest()
def write(path,value):
    path=Path(path);tmp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    tmp.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');tmp.replace(path)

def install(source,activate=False):
    from src.item4.models import review_adapter_config as A
    source=Path(source).resolve();report=read(source/'evaluation/report.json')
    dataset=ROOT/'benchmark/prerequisite_roles_20261119_v7';manifest=read(dataset/'manifest.json')
    if manifest['population_count']!=12418 or manifest['split_counts']['train']!=8692 or manifest['split_counts']['test']!=1863:
        raise ValueError('Confirmed population and frozen split are required')
    if report['state']!='complete' or report['dataset_manifest_sha256']!=sha(dataset/'manifest.json'):
        raise ValueError('Complete evaluation of the frozen dataset is required')
    if report['test_cves']!=1863 or set(report['roles'])!=set(ROLES):raise ValueError('Incomplete role evaluation')
    # Reuse the already configured identification base, while checking actual
    # bytes against each adapter's training pins before any configuration change.
    local=read(ROOT/'models/precision_roles_qwen25_14b_v1/training_complete.json')
    base=Path(local['base']).resolve();config=read(A.CONFIG);prepared={};pins=None
    for role,alias in ROLES.items():
        folder=source/alias;marker=read(folder/'training_complete.json');training=read(folder/'train_manifest.json')
        if marker['role']!=role or marker['adapter_sha256']!=sha(folder/'adapter_model.safetensors'):
            raise ValueError('Role or trained weight fingerprint differs')
        if sha(folder/'train_manifest.json')!=marker['train_manifest_sha256'] or training['role']!=role:
            raise ValueError('Training provenance differs')
        if marker['examples']!=8692 or marker['trained_cves']!=8692 or marker['optimizer_updates']<1 or marker['heldout_loaded']:
            raise ValueError('Incomplete or held-out-contaminated training')
        if marker['initial_trainable_sha256']==marker['final_trainable_sha256']:raise ValueError('Unchanged adapter')
        if training['dataset_manifest_sha256']!=report['dataset_manifest_sha256']:raise ValueError('Train/evaluation dataset differs')
        if report['roles'][role]['test_cases']!=1863 or report['roles'][role]['adapter_sha256']!=marker['adapter_sha256']:
            raise ValueError('Evaluation checkpoint differs')
        if pins is not None and pins!=marker['base_files_sha256']:raise ValueError('Role base pins differ')
        pins=marker['base_files_sha256'];prepared[role]=(folder,marker)
    if len({m['adapter_sha256'] for _,m in prepared.values()})!=2:raise ValueError('Roles cannot share identical weights')
    for name,expected in pins.items():
        if sha(base/name)!=expected:raise ValueError('Local shared base differs: '+name)
    imports=[];models=(ROOT/'models').resolve()
    for role,(folder,marker) in prepared.items():
        target=(ROOT/config['roles'][role]['path']).resolve()
        if not target.is_relative_to(models):raise ValueError('Destination escapes models')
        if target.exists():
            prior=read(target/'import_receipt.json')
            if prior['source_training_marker_sha256']!=sha(folder/'training_complete.json') or sha(target/'adapter_model.safetensors')!=marker['adapter_sha256']:
                raise ValueError('A different installed model already occupies '+str(target))
        else:
            staging=target.with_name(target.name+'.staging-'+uuid.uuid4().hex).resolve()
            if not staging.is_relative_to(models):raise ValueError('Staging escapes models')
            staging.mkdir(parents=True)
            for file in folder.iterdir():
                if file.is_file():shutil.copyfile(file,staging/file.name)
            shutil.copyfile(folder/'training_complete.json',staging/'training_complete.original.json')
            shutil.copyfile(folder/'adapter_config.json',staging/'adapter_config.original.json')
            adapter=read(staging/'adapter_config.json');adapter['base_model_name_or_path']=str(base)
            write(staging/'adapter_config.json',adapter)
            relocated=dict(marker,training_base=marker['base'],base=str(base),base_relocation='Pinned model/tokenizer bytes verified equal; adapter weights unchanged')
            write(staging/'training_complete.json',relocated)
            write(staging/'evaluation_metrics.json',report['roles'][role])
            write(staging/'import_receipt.json',dict(role=role,source=str(folder),source_training_marker_sha256=sha(folder/'training_complete.json'),
                adapter_sha256=marker['adapter_sha256'],evaluation_report_sha256=sha(source/'evaluation/report.json'),base_files_sha256=pins,
                local_base=str(base),imported_at=datetime.now(timezone.utc).isoformat(),expert_gold=False))
            # Both resolved paths were checked under the intended model root.
            staging.rename(target)
        imports.append(dict(role=role,path=str(target),sha256=marker['adapter_sha256']))
        config['roles'][role].update(enabled=bool(activate),state='trained_evaluated_research',
            dataset_manifest_sha256=report['dataset_manifest_sha256'],evaluation_report=str(source/'evaluation/report.json'))
    previous=read(A.CONFIG);write(A.CONFIG,config)
    if activate:
        try:A.active_roles()
        except Exception:write(A.CONFIG,previous);raise
    result=dict(installed=imports,activated=bool(activate),population=12418,train_per_role=8692,test_per_role=1863,
        independent_real_asset_accuracy_verified=False)
    write(source.parent/'installation.json',result);print(json.dumps(result,ensure_ascii=False));return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=ROOT/'results/role_adapters_20261119_v2/trained')
    parser.add_argument('--activate',action='store_true');args=parser.parse_args();install(args.source,args.activate)
