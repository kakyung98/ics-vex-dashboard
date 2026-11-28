"""Verify external weight originals, slim a delivery copy, and plan local cache cleanup.

Only the exact C:/ICS-VEX workspace is mutable. Model originals on D: are read
and hashed, never moved or deleted. Directory deletion is a separate guarded
PowerShell operation using this script's exact plan.
"""
from pathlib import Path
from datetime import datetime,timezone
import argparse
import hashlib
import json
import os
import shutil
import stat
import zipfile

ROOT=Path('C:/ICS-VEX').resolve()
OUT=ROOT/'results/storage_cleanup_20261123'
BASE=Path('D:/ICS-VEX-support/cache/huggingface/hub/models--unsloth--Qwen2.5-Coder-14B-Instruct-bnb-4bit/snapshots/ecfc63c083900ce4f19daad695e711f38ab98fcf')


def sha(path):
    digest=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(8*1024*1024),b''):digest.update(b)
    return digest.hexdigest()


def local(path):
    path=Path(path).resolve()
    if path==ROOT or not path.is_relative_to(ROOT):raise ValueError('Target escapes workspace')
    return path


def reparse(path):
    return bool(path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def cache_plan():
    targets=[]
    for base,dirs,files in os.walk(ROOT,followlinks=False):
        current=Path(base)
        for name in list(dirs):
            p=current/name
            if reparse(p):dirs.remove(name);continue
            if name in ('__pycache__','.pytest_cache') or p==ROOT/'apps/cppg-pocket-native/node_modules':
                local(p);targets.append(dict(path=str(p),kind='directory',reason='regenerable_dependency_or_cache'))
                dirs.remove(name)
        if current==ROOT/'artifacts/item4_rule_evaluation_v1':
            for name in files:
                if name.startswith('qa-appendix-') and name.endswith('.png'):
                    targets.append(dict(path=str(local(current/name)),kind='file',reason='intermediate_render_preview'))
    return targets


def slim_submission(manifest):
    archive=local(next((ROOT/'submission').glob('*.zip')))
    sources={
        'models/base_model/model-00001-of-00002.safetensors':BASE/'model-00001-of-00002.safetensors',
        'models/base_model/model-00002-of-00002.safetensors':BASE/'model-00002-of-00002.safetensors',
        'models/precision_roles_qwen25_14b_v1/adapter_model.safetensors':ROOT/'models/precision_roles_qwen25_14b_v1/adapter_model.safetensors',
        'models/vep_extraction_qwen25_14b_v2/adapter_model.safetensors':Path('D:/ICS-VEX-support/models/vep_extraction_qwen25_14b_v2/adapter_model.safetensors'),
        'models/item4_v2_unlabeled/adapter_model.safetensors':Path('D:/ICS-VEX-support/results/item4_v2_unsupervised_20261120/adapter/adapter_model.safetensors'),
    }
    with zipfile.ZipFile(archive) as original:
        deps=json.loads(original.read('MODEL_DEPENDENCIES.json'))
        present={k:p for k,p in sources.items() if k in original.namelist()}
        if not present:return
        verified=[]
        for member,path in present.items():
            expected=(deps['base']['recorded_files_sha256'][path.name] if member.startswith('models/base_model/') else
                      deps['adapters'][member.split('/')[1]]['sha256'])
            if not path.is_file() or path.stat().st_size!=original.getinfo(member).file_size or sha(path)!=expected:
                raise ValueError('External original missing or mismatched; archive preserved: '+member)
            verified.append(dict(member=member,retained_original=str(path),sha256=expected,bytes=path.stat().st_size))
            print('Verified original:',member,flush=True)
        manifest['verified_external_weights']=verified
        (OUT/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
        for name in ('MODEL_DEPENDENCIES.json','DELIVERY_MANIFEST.json','README.md'):
            if name in original.namelist():(OUT/('submission_original_'+name)).write_bytes(original.read(name))
        deps['weights_included']=False
        deps['external_weight_originals']=verified
        deps['delivery_note']='Slim source delivery: load exact pinned weights separately; this ZIP is no longer self-contained.'
        temp=local(archive.with_suffix('.slim.tmp'))
        before=archive.stat().st_size;items=[]
        with zipfile.ZipFile(temp,'w',compression=zipfile.ZIP_DEFLATED,allowZip64=True) as slim:
            for info in original.infolist():
                if info.filename in present or info.filename in ('MODEL_DEPENDENCIES.json','DELIVERY_MANIFEST.json'):continue
                if info.filename=='README.md':
                    raw=('WEIGHTS EXTERNALIZED AFTER SHA-256 VERIFICATION\n'
                         'Read MODEL_DEPENDENCIES.json for exact retained originals.\n\n').encode()+original.read(info.filename)
                    slim.writestr(info,raw);items.append(dict(path=info.filename,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()));continue
                h=hashlib.sha256()
                with original.open(info) as src,slim.open(info,'w',force_zip64=info.file_size>=2**31) as dst:
                    for block in iter(lambda:src.read(1024*1024),b''):h.update(block);dst.write(block)
                items.append(dict(path=info.filename,bytes=info.file_size,sha256=h.hexdigest()))
            raw=(json.dumps(deps,ensure_ascii=False,indent=2)+'\n').encode();slim.writestr('MODEL_DEPENDENCIES.json',raw)
            items.append(dict(path='MODEL_DEPENDENCIES.json',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
            slim.writestr('DELIVERY_MANIFEST.json',json.dumps(dict(version=2,weights_included=False,files=items),ensure_ascii=False,indent=2))
        with zipfile.ZipFile(temp) as check:
            if check.testzip() is not None:raise ValueError('Rebuilt archive CRC failure')
            if any(k in check.namelist() for k in present):raise ValueError('Weight removal incomplete')
            if len(check.infolist())!=len(original.infolist())-len(present):raise ValueError('Unexpected archive member change')
    os.replace(temp,archive)
    manifest['submission']=dict(path=str(archive),before_bytes=before,after_bytes=archive.stat().st_size,
        reclaimed_bytes=before-archive.stat().st_size,removed_duplicate_weights=len(present),crc_verified=True,
        retained_source_files=True,weights_included=False)
    (OUT/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    print('Submission reclaimed bytes:',manifest['submission']['reclaimed_bytes'],flush=True)


def main():
    cli=argparse.ArgumentParser(description=__doc__);cli.add_argument('--apply-submission',action='store_true');args=cli.parse_args()
    OUT.mkdir(parents=True,exist_ok=True)
    manifest=dict(created_at=datetime.now(timezone.utc).isoformat(),root=str(ROOT),
        protected=['data','icsa','models','benchmark','results/item4_scenario_moe','research_records','local-service'],
        cache_targets=cache_plan(),deletions=[])
    (OUT/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    if args.apply_submission:slim_submission(manifest)
    print('Cache targets:',len(manifest['cache_targets']),flush=True)


if __name__=='__main__':main()
