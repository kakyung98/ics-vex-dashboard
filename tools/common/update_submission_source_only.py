"""Refresh the existing submission archive without adding experiment outputs."""

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
DEST = ROOT / 'submission/ICS-VEX_source_20261120.zip'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    replacements = {}
    source_names = [
        'src/item4/evaluation/synthetic_vex_benchmark.py', 'tools/item4/build_item4_csaf_benchmark.py',
        'tools/item4/verify_item4_csaf_benchmark.py', 'tools/item4/item4_expert_review.py',
        'tools/item4/run_item4_v2_unsupervised.py', 'tools/item4/evaluate_item4_v2_prefix.py',
        'tools/item4/deploy_item4_v2_unsupervised.py', 'tools/item4/monitor_item4_v2_unsupervised.py',
        'tests/item4/test_item4_benchmark_v2.py', 'tests/item4/test_item4_v2_unsupervised.py',
        'tools/common/update_submission_source_only.py',
    ]
    for name in source_names:
        raw = (ROOT / name).read_bytes()
        ast.parse(raw.decode('utf-8-sig'), filename=name)
        replacements[name] = raw
    # The source manuals describe the method. Execution notices and linked
    # experiment reports belong to the separate experiment delivery.
    for name in ['docs/ITEM4_CSAF_EXPERT_DESIGN.md', 'docs/ITEM4_CSAF_EXPERT_MANUAL.md']:
        text = (ROOT / name).read_text(encoding='utf-8')
        text = '\n'.join(line for line in text.split('\n') if not line.startswith('> 실제 실행 추가:'))
        replacements[name] = text.encode('utf-8')
    with zipfile.ZipFile(DEST) as source:
        previous = json.loads(source.read('DELIVERY_MANIFEST.json'))
        readme = source.read('README.md').decode('utf-8-sig')
        readme = readme.split('검증: 최종 압축 해제본에서')[0].rstrip() + '\n\n'
        readme += '''소스코드 갱신: 무라벨 도메인 학습, 공유 prefix 기반 7종 판정,
벤치마크 생성·검사 및 전문가 검토 도구의 최신 코드를 반영했습니다.
이 ZIP에는 평가 점수·예측 파일·실행 결과 보고서를 동봉하지 않습니다.
학습·평가 데이터와 모델 가중치는 외부 의존성이며 이 소스에 포함되지 않습니다.
v2 학습·판정 도구는 생산 Agent·MulVAL 경로와 별도로 실행합니다.
관련 사용법은 docs/ITEM4_CSAF_EXPERT_MANUAL.md 및 각 도구의 --help를 참조합니다.
검사 명령: python -m pytest tests/item4/test_item4_benchmark_v2.py tests/item4/test_item4_v2_unsupervised.py -q
파일 목록과 SHA-256은 DELIVERY_MANIFEST.json을 참조합니다.
'''
        replacements['README.md'] = readme.encode('utf-8')
        replacements['제출용_README.txt'] = readme.encode('utf-8')
        backup = DEST.with_name(DEST.stem + '.before_source_refresh.zip')
        if backup.exists():
            raise FileExistsError(backup)
        shutil.copy2(DEST, backup)
        temporary = DEST.with_suffix('.refresh.tmp')
        contents = {}
        changed, added, removed = [], [], []
        names = set(source.namelist())
        with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as target:
            for name in source.namelist():
                if name == 'DELIVERY_MANIFEST.json':
                    continue
                if name.startswith(('results/', 'validation/', 'submission_validation/')) or name == 'docs/ITEM4_V2_ACTUAL_RUN.md':
                    removed.append(name)
                    continue
                old = source.read(name)
                raw = replacements.pop(name, old)
                if raw != old:
                    changed.append(name)
                target.writestr(name, raw)
                contents[name] = {'bytes': len(raw), 'sha256': digest(raw)}
            for name, raw in replacements.items():
                assert name not in names
                target.writestr(name, raw)
                added.append(name)
                contents[name] = {'bytes': len(raw), 'sha256': digest(raw)}
            manifest = dict(files=contents, credentials_included=False, model_weights_included=False,
                            package_scope='source_code_only', experiment_results_included=False)
            target.writestr('DELIVERY_MANIFEST.json', json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    with zipfile.ZipFile(temporary) as verified:
        assert verified.testzip() is None
        assert len(verified.namelist()) == len(set(verified.namelist()))
        for name, meta in contents.items():
            raw = verified.read(name)
            assert len(raw) == meta['bytes'] and digest(raw) == meta['sha256']
        assert not any(n.startswith(('results/', 'validation/', 'submission_validation/')) for n in verified.namelist())
    os.replace(temporary, DEST)
    receipt = dict(path=str(DEST), backup=str(backup), bytes=DEST.stat().st_size,
                   sha256=digest(DEST.read_bytes()), files=len(contents)+1,
                   changed=changed, added=added, removed=removed,
                   crc_and_all_file_hashes_verified=True, experiment_results_included=False,
                   previous_manifest_metadata={k:v for k,v in previous.items() if k != 'files'})
    DEST.with_suffix('.receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(receipt, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
