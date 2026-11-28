"""Bundle pinned runtime weights into the application source ZIP."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
import hashlib
import json
import os
import shutil
import zipfile

ROOT=Path(__file__).resolve().parents[2]
DEST=ROOT/'submission/전남대_source.zip'
BASE=Path('D:/ICS-VEX-support/cache/huggingface/hub/models--unsloth--Qwen2.5-Coder-14B-Instruct-bnb-4bit/snapshots/ecfc63c083900ce4f19daad695e711f38ab98fcf')
ADAPTERS={
    'precision_roles_qwen25_14b_v1':ROOT/'models/precision_roles_qwen25_14b_v1',
    'vep_extraction_qwen25_14b_v2':Path('D:/ICS-VEX-support/models/vep_extraction_qwen25_14b_v2'),
    'item4_v2_unlabeled':Path('D:/ICS-VEX-support/results/item4_v2_unsupervised_20261120/adapter'),
}


def hash_stream(stream):
    h=hashlib.sha256()
    for chunk in iter(lambda:stream.read(8*1024*1024),b''):h.update(chunk)
    return h.hexdigest()


def file_hash(path):
    with path.open('rb') as f:return hash_stream(f)


def encoded(value):return (json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode('utf-8')


def main():
    with zipfile.ZipFile(DEST) as z:
        files={n:z.read(n) for n in z.namelist() if n!='DELIVERY_MANIFEST.json'}
    old_dependencies=json.loads(files['MODEL_DEPENDENCIES.json'])
    external={}
    for p in BASE.iterdir():
        if p.is_file():external['models/base_model/'+p.name]=p
    for name,expected in old_dependencies['base']['recorded_files_sha256'].items():
        assert file_hash(BASE/name)==expected,name
    dependencies=dict(weights_included=True,base=dict(old_dependencies['base']),adapters={})
    for name,folder in ADAPTERS.items():
        weight=folder/'adapter_model.safetensors'
        expected=(old_dependencies['adapters'].get(name,{}) or json.loads((folder/'training_complete.json').read_bytes()))
        expected_hash=expected.get('sha256',expected.get('adapter_sha256'))
        actual=file_hash(weight);assert actual==expected_hash,name
        external['models/'+name+'/adapter_model.safetensors']=weight
        dependencies['adapters'][name]=dict(target='models/'+name,bytes=weight.stat().st_size,sha256=actual,
            active_in_service=name!='item4_v2_unlabeled')
        allowed={'adapter_config.json','training_complete.json','tokenizer.json','tokenizer_config.json',
                 'chat_template.jinja','special_tokens_map.json','added_tokens.json','merges.txt','vocab.json'}
        if name == 'vep_extraction_qwen25_14b_v2':
            allowed.update({'import_receipt.json', 'evaluation.json'})
        for p in folder.iterdir():
            if p.name not in allowed or not p.is_file():continue
            # Prefer the already normalized submission model metadata.
            raw=files.get('model_setup/'+name+'/'+p.name,p.read_bytes())
            if p.name == 'import_receipt.json':
                receipt=json.loads(raw)
                receipt.pop('source',None)
                raw=encoded(receipt)
            if p.name in {'adapter_config.json','training_complete.json'}:
                value=json.loads(raw)
                value['base' if p.name=='training_complete.json' else 'base_model_name_or_path']='models/base_model'
                if p.name=='training_complete.json':
                    value={k:v for k,v in value.items() if k not in {'base_path','training_base','base_relocation',
                        'evaluation_report'}}
                raw=encoded(value)
            files['models/'+name+'/'+p.name]=raw
        # The extraction adapter shares the pinned base tokenizer.
        if not any(n.startswith('models/'+name+'/tokenizer') for n in files):
            for leaf in ['tokenizer.json','tokenizer_config.json','special_tokens_map.json','added_tokens.json','merges.txt','vocab.json']:
                external['models/'+name+'/'+leaf]=BASE/leaf
    for name in list(files):
        if name.startswith('model_setup/'):del files[name]
    files['MODEL_DEPENDENCIES.json']=encoded(dependencies)
    text='''ICS-VEX 시스템 소스코드 및 모델 (로컬 실행용)

SBOM/CVE 식별, 자산 운영 정보 입력, 취약점 영향 판정, MulVAL 연동,
모델 학습, 웹 화면과 실행에 필요한 참조 자료·모델 가중치를 포함합니다.

설치: Python 3.11 환경에서 pip install -r requirements-submission.txt
GPU용 PyTorch/CUDA는 장치에 맞게 별도로 설치합니다.
프로젝트 루트에서 실행: python -X utf8 -B tools/item4/serve_nist_operational_vex.py 8100
화면: http://127.0.0.1:8100/bom-vex.html 및 /item4.html

models/base_model: 고정 Qwen2.5-Coder-14B NF4 기저 모델과 토크나이저.
models/precision_roles_qwen25_14b_v1: 서비스 식별용 어댑터.
models/vep_extraction_qwen25_14b_v2: 서비스 전제조건 추출용 어댑터.
models/item4_v2_unlabeled: 별도 무라벨 학습 어댑터. 서비스 기본 모델을 자동 교체하지 않습니다.
모델 위치·버전·SHA-256은 MODEL_DEPENDENCIES.json을 참조합니다.

local-service는 현재 서버가 직접 불러오는 애플리케이션 구현입니다.
BOM/VEX API와 자산 운영 정보 입력 프로파일·화면 코드가 있으므로 함께 배치해야 합니다.
MulVAL/XSB는 native 또는 Docker 환경을 별도로 구성합니다.
전체 학습 데이터, 운영 DB, 인증정보는 포함하지 않습니다.
파일 목록과 SHA-256은 DELIVERY_MANIFEST.json을 참조합니다.
'''
    for name in ['README.md','제출용_README.txt']:files[name]=text.encode('utf-8')
    manifest={n:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()) for n,raw in files.items()}
    print('Hashing pinned model files',flush=True)
    for name,p in external.items():manifest[name]=dict(bytes=p.stat().st_size,sha256=file_hash(p))
    backup=DEST.with_name(DEST.stem+'.source_only_backup.zip')
    if backup.exists():raise FileExistsError(backup)
    shutil.copy2(DEST,backup)
    temp=DEST.with_suffix('.weights.tmp')
    with zipfile.ZipFile(temp,'w',zipfile.ZIP_DEFLATED,compresslevel=6,allowZip64=True) as z:
        for name,raw in files.items():z.writestr(name,raw)
        for name,p in external.items():
            print('Including '+name,flush=True)
            z.write(p,name,compress_type=zipfile.ZIP_STORED if p.suffix=='.safetensors' else zipfile.ZIP_DEFLATED)
        z.writestr('DELIVERY_MANIFEST.json',encoded(dict(files=manifest,package_scope='application_training_and_models',
            credentials_included=False,model_weights_included=True)))
    print('Verifying archive file hashes',flush=True)
    with zipfile.ZipFile(temp) as z:
        assert len(z.namelist())==len(set(z.namelist()))
        for name,meta in manifest.items():
            with z.open(name) as stream:assert hash_stream(stream)==meta['sha256'],name
        assert not any(n.startswith(('benchmark/','tests/','results/','evaluation/')) for n in z.namelist())
    os.replace(temp,DEST)
    receipt=dict(path=str(DEST),backup=str(backup),bytes=DEST.stat().st_size,files=len(manifest)+1,
        sha256=file_hash(DEST),all_file_hashes_verified=True,model_weights_included=True)
    DEST.with_suffix('.receipt.json').write_bytes(encoded(receipt))
    print(json.dumps(receipt,ensure_ascii=False),flush=True)


if __name__=='__main__':main()
