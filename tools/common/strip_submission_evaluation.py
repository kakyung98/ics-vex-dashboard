"""Make the delivered source archive contain application and training code only."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
import ast
import hashlib
import json
import os
import re
import shutil
import zipfile

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT/'submission/전남대_source.zip'


def remove_nodes(text, names):
    lines = text.splitlines(keepends=True)
    nodes = [n for n in ast.walk(ast.parse(text))
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name in names]
    for n in sorted(nodes, key=lambda n:n.lineno, reverse=True):
        start = min([n.lineno]+[d.lineno for d in getattr(n,'decorator_list',[])])-1
        lines[start:n.end_lineno] = []
    return ''.join(lines)


def main():
    with zipfile.ZipFile(DEST) as z:
        files = {n:z.read(n) for n in z.namelist() if not n.endswith('/')}
    files.pop('DELIVERY_MANIFEST.json')
    removed=[]
    docs_keep = {'ASSET_KEY_VEX_WORKFLOW.md','COMPONENT_VEX_WORKFLOW.md','ICS_OT_VEP_USER_SPEC_20261119.md',
        'ICS_OT_profiles_v0_1.md','ITEM4_GUIDANCE_MAPPING.md','ITEM4_OPERATOR_INPUTS.md',
        'ITEM4_STAGE1_EXTRACTION_DESIGN.md','MULVAL_DEFAULT_GRAPH.md','PREREQUISITE_ROLE_TRAINING_DATA.md',
        'VULNERABILITY_EXPLOITATION_PREREQUISITE.md','nist_selectable_answers.v1.json'}
    src_drop = {'cert_eval.py','cert_page.py','item4_benchmark_v2.py','item4_gold_grounding.py',
        'item4_source_simulation.py','item4_stage1_evaluation.py','precision_workbench.html'}
    tool_markers = ('benchmark','evaluation','evaluate_','experiment','fixture','_gold','truth_',
        '_truth','holdout','_metrics','expert_review','audit_','verify_','validate_','probe_',
        'check_','smoke_','summarize_','report_population','source_progress','reanalysis',
        'refresh_item4_csaf','package_','finalize_item3','finalize_item4','finalize_precision',
        'compare_full_population','score_item4','run_item4_full_actual','build_item3_cpe_faults',
        'build_item3_precision','build_dataset_statistics')
    for name in list(files):
        leaf=Path(name).name.lower()
        drop=name.startswith(('benchmark/','tests/','evaluation/','results/','validation/','submission_validation/'))
        drop |= name.startswith('docs/') and Path(name).name not in docs_keep
        drop |= name.startswith('src/') and Path(name).name in src_drop
        drop |= name=='requirements-evaluation.txt'
        drop |= name.startswith('tools/') and any(m in leaf for m in tool_markers)
        drop |= 'verification_20261117/' in name
        drop |= name.startswith('site/') and any(m in leaf for m in ['experiment','dataset_statistics','-method.html','precision','cert.html'])
        if drop:removed.append(name);del files[name]
    # Preserve unsupervised training, remove the separate benchmark inference
    # implementation, prompts, score calculation, and evaluate CLI action.
    name='tools/item4/run_item4_v2_unsupervised.py'
    text=files[name].decode('utf-8-sig')
    tree=ast.parse(text);lines=text.splitlines(keepends=True)
    edits=[]
    for n in tree.body:
        if isinstance(n,ast.Expr) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str):
            edits.append((n.lineno,n.end_lineno,'"""Label-free causal language model domain training."""\n'))
        if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in {'CHOICES','SYSTEM'} for t in n.targets):
            edits.append((n.lineno,n.end_lineno,''))
    for a,b,new in sorted(edits,reverse=True):lines[a-1:b]=[new]
    text=remove_nodes(''.join(lines),{'evaluation_payload','evaluate','main'})
    text=text.replace("if __name__=='__main__':main()",'')
    text += '''\ndef main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=['train'])
    p.add_argument('--data',type=Path,required=True)
    p.add_argument('--run',type=Path,required=True)
    p.add_argument('--base',type=Path,required=True)
    p.add_argument('--block-size',type=int,default=1024)
    p.add_argument('--train-batch',type=int,default=2)
    p.add_argument('--accumulation',type=int,default=8)
    p.add_argument('--seed',type=int,default=20261120)
    args=p.parse_args()
    train(args)

if __name__=='__main__':main()
'''
    files[name]=text.encode('utf-8')
    # Certification and benchmark APIs are removed; operational VEX APIs stay.
    name='src/common/web/api_server.py';text=files[name].decode('utf-8-sig')
    text=re.sub(r'^import cert_eval as CERT.*\n|^from cert_page import CERT_PAGE.*\n','',text,flags=re.M)
    text=remove_nodes(text,{'cert_items','cert_run','cert_job','cert_jobs','cert_upload','cert_page','CertRunReq','context_sensitivity'})
    text=re.sub(r'^.*"cert": \("Certification performance metrics", CERT_PAGE\),.*\n','',text,flags=re.M)
    files[name]=text.encode('utf-8')
    name='src/common/web/evaluation_api.py';text=files[name].decode('utf-8-sig')
    text=remove_nodes(text,{'read_report','metrics','simulation_cases','simulation_assess','workbench'})
    text=text.replace('Current precision reports and source-free operational assessment endpoints.',
                      'Operational assessment endpoints.')
    files[name]=text.encode('utf-8')
    name='tools/item4/serve_nist_operational_vex.py';text=files[name].decode('utf-8-sig')
    start=text.index("app.add_api_route('/nist-three-axis-method.html'")
    end=text.index("if __name__ == '__main__':",start)
    files[name]=(text[:start]+text[end:]).encode('utf-8')
    # Remove links to omitted standalone experiment pages from retained pages.
    dropped_pages={Path(n).name for n in removed if n.endswith('.html')}
    for name,raw in list(files.items()):
        if name.endswith('.html'):
            text=raw.decode('utf-8-sig')
            for page in dropped_pages:
                text=re.sub(r'<a\b[^>]*href=[\"\'][^\"\']*'+re.escape(page)+r'[\"\'][^>]*>.*?</a>','',text,flags=re.S|re.I)
            files[name]=text.encode('utf-8')
    readme='''ICS-VEX 시스템 소스코드 (로컬 실행용)

SBOM/CVE 식별, 자산 운영 정보 입력, 취약점 영향 판정, MulVAL 연동,
모델 학습, 웹 화면 및 실행에 필요한 정적 참조 자료를 포함합니다.

설치: Python 3.11 환경에서 pip install -r requirements-submission.txt
GPU용 PyTorch/CUDA는 장치에 맞게 별도로 설치합니다.
실행: python -X utf8 -B tools/item4/serve_nist_operational_vex.py 8100
화면: http://127.0.0.1:8100/bom-vex.html 및 /item4.html

모델 설치 정보는 MODEL_DEPENDENCIES.json을 참조합니다.
기저 모델은 models/base_model에, 어댑터 가중치는 해당 models/<이름>에 배치합니다.
model_setup/<이름>의 설정과 토크나이저도 해당 models/<이름>으로 복사합니다.
MulVAL/XSB는 native 또는 Docker 환경을 별도로 구성합니다.

tools/item4/run_item4_v2_unsupervised.py는 무라벨 학습 전용 도구입니다.
준비된 코퍼스와 입력 해시, 기저 모델, 실행 디렉터리를 지정하여 사용합니다.
전체 데이터와 모델 가중치, 운영 DB, 인증정보는 포함하지 않습니다.
파일 목록과 SHA-256은 DELIVERY_MANIFEST.json을 참조합니다.
'''
    for name in ['README.md','제출용_README.txt']:files[name]=readme.encode('utf-8')
    for name,raw in files.items():
        if name.endswith('.py'):ast.parse(raw.decode('utf-8-sig'),filename=name)
    backup=DEST.with_name(DEST.stem+'.before_remove_evaluation.zip')
    if backup.exists():raise FileExistsError(backup)
    shutil.copy2(DEST,backup)
    manifest={n:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()) for n,raw in files.items()}
    temp=DEST.with_suffix('.source.tmp')
    with zipfile.ZipFile(temp,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for n,raw in files.items():z.writestr(n,raw)
        z.writestr('DELIVERY_MANIFEST.json',json.dumps(dict(files=manifest,package_scope='application_and_training_source',
            credentials_included=False,model_weights_included=False),ensure_ascii=False,indent=2)+'\n')
    with zipfile.ZipFile(temp) as z:
        assert z.testzip() is None
        for n,m in manifest.items():assert hashlib.sha256(z.read(n)).hexdigest()==m['sha256']
    os.replace(temp,DEST)
    receipt=dict(path=str(DEST),backup=str(backup),files=len(manifest)+1,removed_count=len(removed),
        removed=removed,bytes=DEST.stat().st_size,sha256=hashlib.sha256(DEST.read_bytes()).hexdigest(),
        all_file_hashes_verified=True)
    DEST.with_suffix('.receipt.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in receipt.items() if k!='removed'},ensure_ascii=False))


if __name__=='__main__':main()
