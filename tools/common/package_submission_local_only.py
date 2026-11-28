"""Remove cloud orchestration from the source submission, preserving local code."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
import ast
import hashlib
import json
import os
import shutil
import zipfile

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / 'submission/전남대_source.zip'


def main():
    with zipfile.ZipFile(DEST) as z:
        files = {n: z.read(n) for n in z.namelist() if not n.endswith('/')}
    files.pop('DELIVERY_MANIFEST.json')
    removed = []
    for name, raw in list(files.items()):
        cloud = name in {'requirements-ncp.txt', 'requirements-ncp-transport.txt', 'docs/NCP_MIGRATION.md',
                         'tools/common/update_submission_source_only.py'}
        if name.startswith('tools/'):
            text = raw.decode('utf-8-sig', errors='replace')
            cloud |= 'ncp' in Path(name).name.lower() or any(
                token in text for token in ['tools.ncp', 'hysage-kubeconfig', 'kubectl', 'from kubernetes'])
            cloud |= name in {'tools/item4/monitor_item4_full_actual.py', 'tools/item4/monitor_item4_v2_unsupervised.py'}
        if cloud:
            removed.append(name)
            del files[name]
    name = 'src/item4/decision/mulval_attack_graphs.py'
    text = files[name].decode('utf-8-sig')
    tree = ast.parse(text)
    lines = text.splitlines(keepends=True)
    replacement = '''def execute_program(program):
    backend = os.environ.get('ICSVEX_MULVAL_BACKEND', 'auto')
    if backend == 'auto':
        backend = 'native' if shutil.which('graph_gen.sh') else 'docker' if shutil.which('docker') else 'unavailable'
    if backend in {'docker', 'native'}:
        return _local_run(program, backend)
    raise RuntimeError('MulVAL unavailable: configure native or Docker.')
'''
    for node in sorted([n for n in tree.body if isinstance(n, ast.FunctionDef)
                        and n.name in {'_remote_run', 'execute_program'}], key=lambda n:n.lineno, reverse=True):
        lines[node.lineno-1:node.end_lineno] = [replacement if node.name == 'execute_program' else '']
    files[name] = ''.join(lines).encode('utf-8')
    # Keep the non-cloud libraries that requirements-ncp previously aggregated.
    files['requirements-submission.txt'] = b'''-r requirements-precision.txt
requests==2.32.3
python-debian==0.1.40
accelerate==1.14.0
safetensors==0.8.0
tokenizers==0.22.2
ipykernel==6.29.5
'''
    for name in ['README.md', '제출용_README.txt']:
        text = files[name].decode('utf-8-sig')
        text = text.replace('MulVAL/XSB는 native, Docker 또는 본인 인증정보를 쓰는 원격 환경을 별도로 구성합니다.',
                            'MulVAL/XSB는 native 또는 Docker 환경을 별도로 구성합니다.')
        text += '\n제출본은 로컬 실행용이며 NCP·Kubernetes 접속/배포 도구와 해당 설치 의존성은 제외했습니다.\n'
        files[name] = text.encode('utf-8')
    # Old runbooks describe the development cluster. Remove cloud command
    # snippets from the submission copies; keep the workspace originals.
    for name in ['docs/ITEM4_AUTOMATIC_PIPELINE.md', 'docs/ITEM4_STAGE1_RUNBOOK.md']:
        text = files.get(name, b'').decode('utf-8-sig')
        if text:
            files[name] = ('> 제출본은 로컬 실행용입니다. 원격 클러스터 실행 절차는 이 패키지에 포함하지 않습니다.\n\n' +
                '\n'.join(line for line in text.splitlines() if not any(token in line for token in
                    ['hysage-kubeconfig', 'kubectl', 'tools.ncp', 'tools/item4/research/run_item4_stage1_h200.py',
                     'tools.item4.research.run_item4_stage1_h200', 'tools.deploy_item4', 'tools/deploy_item4']))).encode('utf-8')
    files['tools/common/package_submission_local_only.py'] = Path(__file__).read_bytes()
    for name, raw in files.items():
        if name.endswith('.py'):
            ast.parse(raw.decode('utf-8-sig'), filename=name)
        if name.endswith('.txt') and name.startswith('requirements'):
            for line in raw.decode('utf-8-sig').splitlines():
                if line.startswith('-r '):
                    assert line[3:].strip() in files, (name, line)
    manifest = {n:dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) for n,raw in files.items()}
    backup = DEST.with_name(DEST.stem + '.before_local_only.zip')
    if backup.exists():raise FileExistsError(backup)
    shutil.copy2(DEST, backup)
    temporary = DEST.with_suffix('.local.tmp')
    with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for name, raw in files.items():z.writestr(name, raw)
        z.writestr('DELIVERY_MANIFEST.json', json.dumps(dict(files=manifest, package_scope='local_source_code_only',
            credentials_included=False, model_weights_included=False, experiment_results_included=False,
            ncp_kubernetes_required=False), ensure_ascii=False, indent=2)+'\n')
    with zipfile.ZipFile(temporary) as z:
        assert z.testzip() is None
        for name, meta in manifest.items():assert hashlib.sha256(z.read(name)).hexdigest() == meta['sha256']
    os.replace(temporary, DEST)
    receipt = dict(path=str(DEST), backup=str(backup), bytes=DEST.stat().st_size,
        sha256=hashlib.sha256(DEST.read_bytes()).hexdigest(), removed=removed,
        files=len(manifest)+1, all_file_hashes_verified=True, ncp_kubernetes_required=False)
    DEST.with_suffix('.receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2)+'\n',encoding='utf-8')
    print(json.dumps(receipt, ensure_ascii=False, indent=2))


if __name__ == '__main__':main()
