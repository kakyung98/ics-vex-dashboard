"""Create the requested whole-system source submission after full evaluation."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
import ast
import hashlib
import json
import re
import zipfile

ROOT=Path(__file__).resolve().parents[2]
DEST=ROOT/'benchmark/전남대_Source code.zip'
REPORT=ROOT/'results/item4_full_actual_20261120/report.json'


def main(validate_only=False,allow_pending_evaluation=False):
    report=json.loads(REPORT.read_bytes()) if REPORT.is_file() else {}
    evaluation_complete=report.get('status')=='complete' and report.get('population_cves')==12418
    if not validate_only and not allow_pending_evaluation and not evaluation_complete:
        raise RuntimeError('Finish and fetch the 12,418-CVE actual-model evaluation before final submission packaging')
    files={}
    text_suffixes={'.py','.js','.html','.css','.json','.md','.txt','.toml','.csv','.svg','.png','.ico','.gz'}
    roots=['src','tools','schemas','site','icsa/csaf',
           'local-service/sbom-vex/operating_profiles_r4_rederived',
           'local-service/sbom-vex/vex_operational_logic_20261117']
    for directory in roots:
        for p in (ROOT/directory).rglob('*'):
            if not p.is_file() or (p.suffix.lower() not in text_suffixes and p.name.upper() not in {'LICENSE','COPYING','NOTICE'}):
                continue
            if any(x in p.parts for x in ('__pycache__','.pytest_cache','node_modules','.git','verification_20261117')):
                continue
            if p.suffix=='.gz' and p.name!='operator_asset_keys.csv.gz':
                continue
            files[p.relative_to(ROOT).as_posix()]=p.read_bytes()
    # Source cleanup may move raw advisories out of the checkout. The maintained
    # #4 reader still needs them at this namespace in the extracted submission.
    transfer=ROOT/'results/item4_full_actual_20261120/transfer_manifest.json'
    if not transfer.is_file():transfer=ROOT/'evaluation/source_csaf_manifest.json'
    expected_csaf={n:h for n,h in json.loads(transfer.read_bytes()).items() if n.startswith('icsa/csaf/')}
    if len(expected_csaf)!=3802:raise RuntimeError('The pinned CSAF source population is incomplete')
    archived_csaf=Path('D:/ICS-VEX-support/archive/sbom-vex-source-20261118/vex_operational_logic_20261117/verification_20261117/csaf_verified_bytes')
    original_csaf=Path('D:/ICS-VEX-support/task-temp/submission_csaf_original_20261120')
    for name,expected in expected_csaf.items():
        candidates=[ROOT/name,original_csaf/Path(name).name,archived_csaf/Path(name).name]
        for p in candidates:
            if p.is_file():
                raw=p.read_bytes()
                if hashlib.sha256(raw).hexdigest()==expected:
                    files[name]=raw
                    break
        else:raise RuntimeError('Missing or changed pinned source: '+name)
    files['evaluation/source_csaf_manifest.json']=(json.dumps(expected_csaf,indent=2)+'\n').encode()
    for directory in ['data/nist_auto_vex','data/standards','data/item3_identification_sources_v11']:
        for p in (ROOT/directory).rglob('*'):
            if not p.is_file() or p.suffix not in {'.json','.jsonl'}:continue
            files[p.relative_to(ROOT).as_posix()]=p.read_bytes()
    for rel in ['README.md','requirements-precision.txt','requirements-ncp.txt','requirements-ncp-transport.txt',
                'data/cpe_dictionary.jsonl','data/cisa_advisories.json','data/cisa_reference_manifest.json',
                'data/identity_aliases_v3.json','data/identification_runtime.json','data/operator_asset_keys.csv.gz',
                'docs/ASSET_KEY_VEX_WORKFLOW.md','docs/COMPONENT_VEX_WORKFLOW.md',
                'docs/ICS_OT_profiles_v0_1.md','docs/nist_selectable_answers.v1.json',
                'docs/ICS_OT_VEP_USER_SPEC_20261119.md','docs/PREREQUISITE_ROLE_TRAINING_DATA.md',
                'docs/VULNERABILITY_EXPLOITATION_PREREQUISITE.md']:
        p=ROOT/rel
        if p.is_file():files[rel]=p.read_bytes()
    # Tests for the maintained identification and current #4 path.
    maintained_tests={'test_item4_asset_key_workflow.py','test_item4_vex_assessment.py',
        'test_item4_advisory_context.py','test_prerequisite_adapters.py',
        'test_operator_prerequisites.py','test_operator_adapter_gate.py'}
    for p in (ROOT/'tests').glob('*'):
        if p.is_file() and (p.name in maintained_tests or p.name.startswith(('test_identification_','test_source_version_'))):
            files[p.relative_to(ROOT).as_posix()]=p.read_bytes()
    roles=json.loads((ROOT/'data/prerequisite_adapter_roles.json').read_bytes())
    roles.pop('storage_roots',None)
    roles['roles']['exploitation-prerequisites']['path']='models/vep_extraction_qwen25_14b_v2'
    for r in roles['roles'].values():
        for k in ('dataset','training_run','evaluation_report'):
            r.pop(k,None)
    files['data/prerequisite_adapter_roles.json']=(json.dumps(roles,ensure_ascii=False,indent=2)+'\n').encode()
    model_info={}
    for name,path in [('precision_roles_qwen25_14b_v1',ROOT/'models/precision_roles_qwen25_14b_v1'),
                      ('vep_extraction_qwen25_14b_v2',Path('D:/ICS-VEX-support/models/vep_extraction_qwen25_14b_v2'))]:
        marker=json.loads((path/'training_complete.json').read_bytes())
        model_info[name]=dict(marker)
        filenames = ['training_complete.json','adapter_config.json','tokenizer.json','tokenizer_config.json','chat_template.jinja','special_tokens_map.json']
        if name == 'vep_extraction_qwen25_14b_v2':
            filenames.extend(['evaluation.json', 'import_receipt.json'])
        for filename in filenames:
            p=path/filename
            if not p.is_file():continue
            raw=p.read_bytes()
            if filename == 'import_receipt.json':
                receipt=json.loads(raw)
                receipt.pop('source',None)
                raw=(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n').encode()
            if filename in ('training_complete.json','adapter_config.json'):
                value=json.loads(raw);key='base' if filename=='training_complete.json' else 'base_model_name_or_path'
                value[key]='models/base_model';raw=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
            files['models/'+name+'/'+filename]=raw
    files['MODEL_WEIGHTS_MANIFEST.json']=(json.dumps(model_info,ensure_ascii=False,indent=2)+'\n').encode()
    from importlib.metadata import version
    files['requirements-submission.txt']=(
        '-r requirements-ncp.txt\n-r requirements-ncp-transport.txt\nrequests=='+version('requests')+'\n').encode()
    files['requirements-evaluation.txt']=b'-r requirements-submission.txt\nxgrammar==0.1.27\n'
    for p in [REPORT, REPORT.parent/'run_config.json', REPORT.parent/'package_audit.json',
              REPORT.parent/'runtime_metadata.json',REPORT.parent/'independent_rescore.json',
              REPORT.parent/'runtime_environment.json',
              REPORT.parent/'optimization_probe.json',
              REPORT.parent/'source_integrity_audit.json',REPORT.parent/'delivery_receipt.json']:
        if p.is_file():files['evaluation/'+p.name]=p.read_bytes()
    if not evaluation_complete:
        files['evaluation/EVALUATION_PENDING.txt']=(
            '전수 평가 미완료. 이 ZIP은 소스코드 제출본이며 평가 완료/85% 초과 확인을 의미하지 않습니다.\n'
            '정답은 고정됐으나 전체 12,418개 CVE의 현재 모델 평가 결과는 아직 없습니다.\n'
            '다른 추가 학습의 H200 점유로 전수 평가가 대기 중입니다.\n'
            '평가 완료 후 전체 ID 검증과 독립 재집계를 통과해야 report.json 및 최종 수치가 추가됩니다.\n').encode('utf-8')
        state=REPORT.parent/'remote_status.json'
        if state.is_file():files['evaluation/pending_runtime_status.json']=state.read_bytes()
    full=json.loads((ROOT/'benchmark/item4_evaluation/full_population_manifest.json').read_bytes())
    files['evaluation/full_population_manifest.json']=(json.dumps(full,ensure_ascii=False,indent=2)+'\n').encode()
    readme='''전남대 제출용 시스템 소스코드

본 ZIP은 SBOM/CVE 식별(#3), 원문 전제조건 LLM 추출, 자산 유형별 입력 및 MulVAL/VEX 평가(#4)의
백엔드·화면·명령행 도구·학습/평가 코드·필수 정적 사전/원문을 포함합니다.
평가 데이터셋은 ZIP 바깥의 benchmark/item3_evaluation 및 benchmark/item4_evaluation으로 별도 제출합니다.
시스템 소스와 평가 데이터셋을 같은 프로젝트 루트 아래에 두십시오.

설치: Python 3.11 환경에서 pip install -r requirements-submission.txt
GPU용 PyTorch/CUDA는 해당 장치에 맞는 빌드를 별도로 설치합니다.
실행: 프로젝트 루트에서 python -X utf8 -B tools/item4/serve_nist_operational_vex.py 8100
화면: http://127.0.0.1:8100/index.html 및 /item4.html
핵심 #4 검사: python -m pytest tests/item4/test_item4_asset_key_workflow.py tests/item4/test_item4_vex_assessment.py tests/item4/test_item4_advisory_context.py -q

모델 가중치는 대용량 외부 의존성이므로 이 소스 ZIP에는 포함하지 않았습니다.
models/base_model 에 Qwen2.5-Coder-14B-Instruct 고정 스냅샷을 배치하고,
models/precision_roles_qwen25_14b_v1 및 models/vep_extraction_qwen25_14b_v2 에
각각 해당 adapter_model.safetensors를 배치합니다. 정확한 SHA-256은 MODEL_WEIGHTS_MANIFEST.json을 확인하십시오.
추출 전용 어댑터 활성/평가 미통과 상태는 제출 시점 설정을 보존합니다. 새 학습이나 가중치 변경은 하지 않았습니다.
서로 다른 모델이나 미학습 가중치로 대체하면 동등한 재현으로 간주할 수 없습니다.

MulVAL/XSB는 별도 실행 환경입니다. native 또는 Docker를 구성하거나 사용자 소유 NCP 연결을 설정하십시오.
Kubernetes kubeconfig, 토큰, 인증서, 비밀키 및 .env는 ZIP에서 제외했습니다.
NCP 방식 사용 시 본인 환경의 hysage-kubeconfig.yaml을 프로젝트 루트에 별도로 설정하십시오.
대용량 결과 회수 도구에는 kubectl 실행 파일이 PATH에 필요합니다.
모델/외부 도구가 없거나 근거가 부족하면 판정은 미확정으로 유지됩니다.

원격 H200 전수 평가 실행: python -m tools.item4.deploy_item4_full_actual deploy / start / status
해당 도구의 원격 저장 위치는 대상 환경에 맞춰 설정해야 합니다.
대규모 평가 환경은 requirements-evaluation.txt를 사용합니다.
실제 전수 평가는 기존 Transformers/Peft/bitsandbytes 모델 계산을 유지하고 JSON 토큰 제약만 XGrammar로 가속합니다.
NF4 본체, FP32 전용 어댑터, 원래 스키마·검증·재시도를 보존합니다. 디코더 구현의 비트 단위 출력 동등성은 주장하지 않습니다.
H200에서는 길이별 초기화 병목을 피하도록 SDPA의 cuDNN 경로를 끄고 지원되는 efficient/flash 커널을 사용합니다.
정확한 라이브러리 버전과 계산 설정은 evaluation/runtime_metadata.json에 기록했습니다.
동봉 evaluation/report.json은 12,418개 CVE 전체에 대한 합성 운영 시나리오 평가 기록입니다.
미확정 정답, 실패, 보류와 판정 가능 범위를 함께 해석하십시오. 실제 자산의 독립 정확도는 입증하지 않습니다.

제외: 모델 가중치, 평가 SBOM/정답 원본, 사용자 운영 DB, GPU/다운로드 캐시, 연구 중간 산출물,
중복 ZIP, 실행 로그, 임시 파일, 개인 인증정보. 체크섬과 포함 파일 목록은 SOURCE_MANIFEST.json입니다.
'''
    readme+='''
추론 최적화 도구는 완료된 행의 제거·빈 배치 슬롯 채우기와 NF4 해제값의 GPU 캐시를 지원합니다.
원본 NF4 가중치 및 FP32 어댑터는 보존하며 dense GEMM 커널을 사용합니다.
rolling 모드에서도 CVE/제품/출처 ID별 토큰 마스크와 원문 검증·재시도를 유지합니다.
개별 값 제약을 완화하는 공통 문법 실험은 토큰 비교 검사에서 탈락하여 적용하지 않았습니다.
소수 입력 비교는 전체 수치 동등성을 입증하지 않습니다.
'''
    if not evaluation_complete:
        readme='평가 상태: 미완료 — 정밀도 및 85% 초과 여부 미확정\n\n'+readme
        readme=readme.replace('동봉 evaluation/report.json은 12,418개 CVE 전체에 대한 합성 운영 시나리오 평가 기록입니다.',
            '현재 evaluation/report.json은 미완료이므로 동봉하지 않습니다. evaluation/EVALUATION_PENDING.txt를 확인하십시오.')
    files['제출용_README.txt']=readme.encode('utf-8')
    # Replace private chat handoff/history in the archive's top-level guide.
    files['README.md']=readme.encode('utf-8')
    secret=re.compile(rb'(?:Bearer\s+[A-Za-z0-9._-]{40,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bsk-[A-Za-z0-9]{32,})')
    forbidden=[]; syntax=[]
    for name,raw in files.items():
        if any(k in name.lower() for k in ('kubeconfig','.env','__pycache__')) or name.lower().endswith(('.safetensors','.sqlite3','.db','.pem','.key','.log','.tmp')):
            forbidden.append(name)
        if secret.search(raw):forbidden.append(name)
        if name.endswith('.py'):
            try:ast.parse(raw.decode('utf-8-sig'),filename=name)
            except (SyntaxError,UnicodeError) as exc:syntax.append(dict(file=name,error=str(exc)))
    if forbidden:raise ValueError('Submission contains prohibited secrets/state: '+str(forbidden))
    if syntax:raise ValueError('Submission Python syntax errors: '+str(syntax))
    manifest=dict(files={name:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()) for name,raw in sorted(files.items())},
                  weights_included=False,credentials_included=False,evaluation_datasets_included=False,
                  included_evaluation_population=report.get('population_cves') if evaluation_complete else None,
                  evaluation_complete=evaluation_complete,evaluation_target_population=12418,
                  python_syntax_checked=True)
    files['SOURCE_MANIFEST.json']=(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n').encode()
    if validate_only:
        preview=dict(source_preflight_passed=True,files=len(files),
                     uncompressed_bytes=sum(map(len,files.values())),
                     python_files=sum(n.endswith('.py') for n in files),
                     syntax_and_secret_scan_passed=True,archive_created=False,
                     evaluation_complete=report.get('status')=='complete')
        print(json.dumps(preview,ensure_ascii=False,indent=2))
        return preview
    temporary=DEST.with_suffix('.zip.tmp')
    with zipfile.ZipFile(temporary,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for name,raw in sorted(files.items()):z.writestr(name,raw)
    with zipfile.ZipFile(temporary) as z:
        assert z.testzip() is None
        assert len(z.namelist())==len(files)==len(set(z.namelist()))
        for name,raw in files.items():assert hashlib.sha256(z.read(name)).digest()==hashlib.sha256(raw).digest()
    temporary.replace(DEST)
    receipt=dict(file=str(DEST),bytes=DEST.stat().st_size,files=len(files),
                 sha256=hashlib.sha256(DEST.read_bytes()).hexdigest(),crc_and_sha256_verified=True,
                 secrets_excluded=True,model_weights_excluded=True,evaluation_complete=evaluation_complete)
    (ROOT/'research_records/submission_source_zip_20261120.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(receipt,ensure_ascii=False,indent=2))


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--validate-only',action='store_true',help='Check selected source files without writing a ZIP or requiring final evaluation results')
    parser.add_argument('--allow-pending-evaluation',action='store_true',help='Deliver a source ZIP with an explicit pending-evaluation notice; never invent a complete report or score')
    args=parser.parse_args()
    main(validate_only=args.validate_only,allow_pending_evaluation=args.allow_pending_evaluation)
