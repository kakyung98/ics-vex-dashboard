"""Deliver source, full-population data and a separate blinded review kit."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
import ast
import hashlib
import json
import re
import shutil
import zipfile

ROOT=Path(__file__).resolve().parents[2]
DATA=ROOT/'benchmark/item4_evaluation/csaf_vex_v2'
OUT=ROOT/'results/item4_csaf_v2_20261120'
SECRET=re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bsk-[A-Za-z0-9]{32,}|Bearer\s+[A-Za-z0-9._-]{60,}')
SUFFIXES={'.py','.js','.html','.css','.json','.jsonl','.md','.txt','.toml','.csv','.svg','.png','.ico','.gz','.hwp','.pdf'}


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def pack(destination,files,extra=None):
    extra=dict(extra or {})
    if destination.exists():
        backup=ROOT/'docs/archive/item4_csaf_v2_20261120'/destination.name
        if backup.exists():raise FileExistsError('Destination and backup both exist')
        backup.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(destination,backup)
    manifest={}
    for name,path in sorted(files.items()):
        if any(part in name.lower() for part in ('kubeconfig','.env','__pycache__','node_modules')):
            raise ValueError('Forbidden credential/state filename: '+name)
        raw=path.read_bytes()
        if SECRET.search(raw):raise ValueError('Possible credential: '+name)
        if name.endswith('.py'):ast.parse(raw.decode('utf-8-sig'),filename=name)
        manifest[name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    for name,raw in extra.items():manifest[name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    extra['DELIVERY_MANIFEST.json']=(json.dumps(dict(files=manifest,credentials_included=False,
        model_weights_included=False,expert_review_complete=False,gpu_training_executed=False),
        ensure_ascii=False,indent=2)+'\n').encode('utf-8')
    temp=destination.with_suffix('.zip.tmp')
    with zipfile.ZipFile(temp,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for name,path in sorted(files.items()):z.write(path,name)
        for name,raw in sorted(extra.items()):z.writestr(name,raw)
    with zipfile.ZipFile(temp) as z:
        assert z.testzip() is None
        assert len(z.namelist())==len(set(z.namelist()))==len(files)+len(extra)
        for name,meta in manifest.items():assert hashlib.sha256(z.read(name)).hexdigest()==meta['sha256']
    temp.replace(destination)
    return dict(path=str(destination),files=len(files)+len(extra),bytes=destination.stat().st_size,
        sha256=sha(destination),crc_and_sha256_verified=True)


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    audit=json.loads((OUT/'data_audit.json').read_bytes())
    assert audit['status']=='passed' and audit['scenarios']==86926
    source={}
    for directory in ['src','tools','tests','schemas','site','icsa/csaf','data/nist_auto_vex',
        'data/standards','data/item3_identification_sources_v11',
        'local-service/sbom-vex/operating_profiles_r4_rederived',
        'local-service/sbom-vex/vex_operational_logic_20261117']:
        for p in (ROOT/directory).rglob('*'):
            if p.is_file() and (p.suffix.lower() in SUFFIXES or p.name.upper() in {'LICENSE','NOTICE','COPYING'}) and not any(x in p.parts for x in
                ('__pycache__','.pytest_cache','node_modules','.git')):
                source[p.relative_to(ROOT).as_posix()]=p
    for p in (ROOT/'docs').glob('*'):
        if p.is_file() and p.suffix.lower() in SUFFIXES:source[p.relative_to(ROOT).as_posix()]=p
    for rel in ['README.md','requirements-ncp.txt','requirements-ncp-transport.txt','requirements-precision.txt','requirements-benchmark.txt',
        'data/cpe_dictionary.jsonl','data/cisa_advisories.json','data/cisa_reference_manifest.json',
        'data/identity_aliases_v3.json','data/identification_runtime.json','data/operator_asset_keys.csv.gz',
        'data/prerequisite_adapter_roles.json','benchmark/icsa-cpe-synthetic sbom/index.json']:
        p=ROOT/rel
        if p.is_file():source[rel]=p
    for p in ROOT.glob('*초안.hwp'):source[p.name]=p
    for kind in ['design','manual']:
        p=ROOT/'outputs/item4_csaf_v2'/(kind+'_final.hwp')
        if not p.is_file():raise FileNotFoundError('Finish the revised HWP document: '+str(p))
        source['documents/'+p.name]=p
    for p in (ROOT/'outputs/item4_csaf_v2').glob('*_final.pdf'):source['documents/'+p.name]=p
    for p in [OUT/'data_audit.json',ROOT/'outputs/item4_csaf_v2/document_audit.json',
              ROOT/'outputs/item4_csaf_v2/pending_kappa_report.json']:
        if p.is_file():source['validation/'+p.name]=p
    for name in ['manifest.json','README.txt']:
        source['benchmark/item4_evaluation/csaf_vex_v2/'+name]=DATA/name
    readme='''ICS-VEX 소스코드 및 #4 벤치마크 개정 스냅샷
제품·버전·CVE 식별(#3), 현행 운영 입력·MulVAL/VEX(#4), 새 벤치마크·전문가 검토·κ·채점 코드입니다.
12,418 CVE 전체 × 7개 = 86,926개 합성 사례. ICSA 학습 2,717 / 전문가 평가 1,164.
기존 affected 정밀도 TP/(TP+FP), 85% 초과. 전문가 실제 판정·신규 GPU 학습은 미완료입니다.
과거 실제 모델 실행기는 62,090건 v1 전용이며 새 v2 전수 실행 완료로 해석하지 않습니다.
벤치마크 ZIP은 같은 루트에 풀고, 전문가에게는 별도 blind_review ZIP만 전달합니다.
설치: Python 3.10 이상, pip install -r requirements-ncp.txt -r requirements-ncp-transport.txt -r requirements-benchmark.txt
검사: python -m pytest tests/item4/test_item4_benchmark_v2.py -q
새 데이터 감사: python -m tools.item4.verify_item4_csaf_benchmark
전문가 검토: python -m tools.item4.item4_expert_review --help
현행 서버: python -m tools.item4.serve_nist_operational_vex 8100
재생성에는 과거 v1의 고정 full_population 파일도 필요합니다. v2 배포 데이터는 과거 대용량 정답을 중복 포함하지 않습니다.
모델 가중치·개인 인증정보·운영 DB는 제외합니다. 모델과 MulVAL/XSB는 별도 설치합니다.
기존 어댑터 활성·평가 미통과 상태를 보존합니다. 모델 경로는 설치 환경에 맞게 설정합니다.
상세 설계·실행은 docs/ITEM4_CSAF_EXPERT_DESIGN.md 및 docs/ITEM4_CSAF_EXPERT_MANUAL.md입니다.
평가 개정 HWP는 documents/design_final.hwp 및 documents/manual_final.hwp입니다. 루트 초안은 다른 세션의 편집을 보존한 참고본입니다.
포함 파일별 SHA-256은 DELIVERY_MANIFEST.json입니다. 이 ZIP은 성능 통과 인증서가 아닙니다.
'''.encode('utf-8')
    receipts=[pack(ROOT/'benchmark/전남대_Source code_csaf_v2.zip',source,{'제출용_README.txt':readme})]
    all_data={p.relative_to(ROOT).as_posix():p for p in DATA.rglob('*') if p.is_file()}
    receipts.append(pack(ROOT/'benchmark/item4_csaf_v2_dataset.zip',all_data))
    blind={rel:DATA/rel for rel in ['review/packets.jsonl','review/rater_a.jsonl','review/rater_b.jsonl',
                'review/advisory_index.json','sources/cve_evidence.jsonl']}
    for p in (DATA/'sboms').glob('*.json'):blind['sboms/'+p.name]=p
    blind['MANUAL.md']=ROOT/'docs/ITEM4_CSAF_EXPERT_MANUAL.md'
    receipts.append(pack(ROOT/'benchmark/item4_csaf_v2_blind_review.zip',blind,
        {'README.txt':('맹검 검토용. 후보 정답과 모델 출력을 포함하지 않습니다. 각 평가자는 본인 rater 파일만 '
                       '작성하고 상대 파일을 보지 않습니다. 원문 저장소는 전체 CVE를 포함하며 검토 대상은 '
                       'review/packets에 한정됩니다.\n').encode('utf-8')}))
    (OUT/'delivery_receipts.json').write_text(json.dumps(receipts,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(receipts,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
