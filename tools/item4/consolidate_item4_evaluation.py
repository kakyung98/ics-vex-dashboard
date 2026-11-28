"""Preserve all advisory SBOMs and freeze a source-backed synthetic #4 benchmark.

Run with python -m tools.item4.consolidate_item4_evaluation. Refuses to overwrite a
completed package. No prediction is consulted while constructing labels.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import itertools
import json
from pathlib import Path
import zipfile

from src.item4.decision.evidence_based_vex import registry
from tools.item4.build_auto_vex_benchmark import REFERENCE, actual_status, physical_truth

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'benchmark/item4_evaluation'
AT = '2026-11-20T00:00:00+09:00'
VARIANTS = ('complete', 'missing', 'stale', 'wrong_scope', 'conflict', 'irrelevant_record')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def evidence(binding, quote, **extra):
    return dict(binding=deepcopy(binding), source='synthetic://operating-record',
                quote=quote, reviewer='synthetic-scenario-author',
                observed_at='2026-11-19T00:00:00+09:00',
                valid_until='2026-11-21T00:00:00+09:00',
                integrity_verified=True, **extra)


def scenarios(rules, parents):
    for cve, spec in sorted(REFERENCE.items()):
        if cve not in parents:
            continue  # Do not add a CVE outside the user's fixed population.
        configurations = [dict(zip(spec['dimensions'], v)) for v in
                          itertools.product(*(list(d) for d in spec['dimensions'].values()))]
        recipes = [(version, release, choices, variant)
                   for version, release in spec['versions'].items()
                   for choices in configurations for variant in VARIANTS]
        # Keep a deliberately inaccurate operator-record challenge for every CVE.
        # Its latent negative label is never changed to match the observation.
        version = next(v for v, s in spec['versions'].items() if s == 'vulnerable')
        negative = next(c for c in configurations if not physical_truth(spec, c))
        recipes.append((version, 'vulnerable', negative, 'incorrect_record'))
        for version, release, physical, variant in recipes:
            identity = json.dumps([cve, version, physical, variant], sort_keys=True)
            case_id = 'SYN-' + sha(identity.encode())[:24]
            binding = dict(cve=cve, asset_ref=case_id, product=spec['model'], build=version,
                           config_baseline='hypothetical-config-' + sha(identity.encode())[-12:],
                           mode='normal', actor_origin='hypothetical-assessed-origin')
            observed = deepcopy(physical)
            if variant == 'incorrect_record':
                observed = deepcopy(next(c for c in configurations if physical_truth(spec, c)))
            observations = [evidence(binding, 'SYNTHETIC configuration setting: ' + k + '=' + v,
                                    question_id=k, selected_value=v) for k, v in observed.items()]
            if variant == 'missing':
                observations = []
            elif variant == 'stale':
                for o in observations:
                    o['valid_until'] = '2026-11-01T00:00:00+09:00'
            elif variant == 'wrong_scope':
                for o in observations:
                    o['binding']['asset_ref'] = 'different-hypothetical-asset'
            elif variant == 'conflict':
                for k, dim in spec['dimensions'].items():
                    opposite = next(v for v in dim if dim[v] != dim[physical[k]])
                    observations.append(evidence(binding, 'SYNTHETIC contradictory setting',
                                                 question_id=k, selected_value=opposite))
            inputs = dict(synthetic=True, evaluated_at=AT, binding=binding,
                          inventory=evidence(binding, 'SYNTHETIC exact deployed product/build'),
                          observations=observations,
                          action_statement='Apply the supplier fix and review the assessed deployment.')
            if variant == 'irrelevant_record':
                inputs['unrelated_record'] = 'Backup exists; security budget approved. No CVE condition observation.'
            status = actual_status(spec, release, physical)
            rule = rules[cve]
            annotation = dict(id=case_id, fold='evaluation', sbom_file='sboms/' + case_id + '.json',
                case_kind='source_backed_synthetic_operating_scenario', synthetic=True,
                source_advisory_id=parents[cve], declared_cves=[cve], inputs=inputs,
                source_rule=deepcopy(rule),
                gold=dict(actual_affected=None if status is None else status == 'affected',
                          actual_status=status, latent_configuration=physical, release_reference=release,
                          variant=variant, label_method='Frozen supplier-transcribed literal release table and latent Boolean configuration; no evaluator called'),
                assumptions=['A hypothetical instance of the named product is installed at the exact stated release.',
                    'The selected supplier conditions define the complete assessed synthetic path.',
                    'No real installation, expert review or current model accuracy is asserted.',
                    'Parent advisory is a CVE provenance link, not proof that its components equal this hypothetical instance.'])
            bom = dict(bomFormat='CycloneDX', specVersion='1.7', version=1,
                       metadata=dict(component=dict(type='device', name=case_id, **{'bom-ref': case_id})),
                       components=[dict(type='application', name=spec['model'], version=version,
                                        **{'bom-ref': case_id + ':component'})],
                       properties=[dict(name='dataset:synthetic-inventory', value='true'),
                                   dict(name='dataset:deployment-verified', value='false')])
            yield annotation, bom


def main():
    if (OUT / 'summary.json').exists():
        raise FileExistsError('Completed package exists; refusing to overwrite frozen inputs or labels')
    training = ROOT / 'benchmark/item4_training'
    source = ROOT / 'benchmark/icsa-cpe-synthetic sbom'
    index = json.loads((source / 'index.json').read_bytes())
    rows = {r['advisory_id']: r for r in index['advisories']}
    original = [(fold, p) for fold, d in [('evaluation', OUT), ('training', training)]
                for p in sorted(d.glob('icsa-*.json'))]
    assert len(original) == len(rows) == 3881
    assert len({p.stem for _, p in original}) == 3881
    for _, p in original:
        assert sha(p.read_bytes()) == rows[p.stem]['sha256'], p
    reg = registry()  # Validate every supplier quote/span/hash before generating.
    parents = {}
    for aid, row in sorted(rows.items()):
        for cve in row['declared_cves']:
            parents.setdefault(cve, aid)
    generated = list(scenarios(reg['rules'], parents))
    archive = ROOT / 'research_records/item4_before_consolidation_20261120.zip'
    archive.parent.mkdir(exist_ok=True)
    if archive.exists():
        raise FileExistsError(archive)
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as z:
        for d in (OUT, training):
            for p in sorted((d / '_metadata').rglob('*')):
                if p.is_file():
                    z.write(p, p.relative_to(ROOT).as_posix())
    for name in ('sboms', 'annotations'):
        (OUT / name).mkdir(exist_ok=True)
    all_annotations = []
    counts = Counter()
    for fold, p in original:
        aid = p.stem
        target = OUT / 'sboms' / p.name
        assert not target.exists()
        p.rename(target)
        row = rows[aid]
        annotation = dict(id=aid, fold='evaluation', original_fold=fold,
            sbom_file='sboms/' + p.name, case_kind='retained_advisory_product_collection', synthetic=True,
            source_advisory_id=aid, declared_cves=row['declared_cves'],
            source=deepcopy(row), source_input_sha256=row['sha256'],
            gold=dict(actual_affected=None, label_state='unknown_no_exact_operating_context',
                      cves=[dict(cve=c, actual_affected=None) for c in row['declared_cves']]),
            inputs=None, source_link_is_impact_gold=False)
        all_annotations.append(annotation)
        counts['original_' + fold] += 1
    for annotation, bom in generated:
        write(OUT / annotation['sbom_file'], bom)
        all_annotations.append(annotation)
        counts['synthetic_variant:' + annotation['gold']['variant']] += 1
    with (OUT / 'gold.jsonl').open('w', encoding='utf-8', newline='\n') as f:
        for annotation in all_annotations:
            annotation['sbom_file_sha256'] = sha((OUT / annotation['sbom_file']).read_bytes())
            write(OUT / 'annotations' / (annotation['id'] + '.json'), annotation)
            f.write(json.dumps(annotation, ensure_ascii=False) + '\n')
    summary = dict(dataset='item4-unified-evaluation/1', created_at=datetime.now(timezone.utc).isoformat(),
        case_count=len(all_annotations), retained_advisory_sboms=3881,
        declared_unique_cves=len(parents), synthetic_operating_scenarios=len(generated),
        synthetic_scenario_unique_cves=len(set(REFERENCE) & set(parents)), counts=dict(counts),
        original_sbom_bytes_preserved=True, all_original_ids_retained=True,
        old_split_active=False, training_exposure_audited=False,
        historical_metadata_archive=archive.relative_to(ROOT).as_posix(),
        historical_metadata_archive_sha256=sha(archive.read_bytes()),
        source_index_sha256=sha((source / 'index.json').read_bytes()),
        source_registry_sha256=reg['sha256'], gold_jsonl_sha256=sha((OUT / 'gold.jsonl').read_bytes()),
        metric=dict(positive_status='affected', formula='TP / (TP + FP) * 100',
                    target_percent=85, comparison='strictly greater than',
                    unknown_predicted_affected='Report separately; full precision and pass are unavailable while any remain.',
                    empty_positive_denominator='undefined; never pass',
                    unit='exact hypothetical asset/CVE/build/configuration/mode/origin/time scope'),
        full_population_precision_percent=None, full_population_target_met=None,
        deployed_model_precision_percent=None, independent_real_asset_validation=False,
        layout=dict(sboms='One pure CycloneDX JSON per ID', annotations='Asset operational information, source provenance and separate gold per ID',
                    gold_jsonl='Exact annotation objects, one per line', README='Korean usage guide'),
        validation=dict(sbom_hashes_verified=len(all_annotations), original_source_hashes_verified=3881,
                        supplier_quote_span_hashes_verified=True))
    write(OUT / 'summary.json', summary)
    (OUT / 'README.txt').write_text('''시험 항목 #4: VEX 기반 식별된 취약점 영향 판단 정밀도

1. 통합 범위
기존 evaluation 1,164개와 training 2,717개를 모두 합쳐 원본 3,881개를 보존했습니다.
원본 SBOM 바이트와 자문 ID는 유지했습니다. 기존 7:3 분할은 더 이상 사용하지 않습니다.
원본 전체의 12,418개 CVE와 빈/근거 부족 자문도 제외하지 않았습니다.
과거 분할 메타데이터는 summary.json의 historical_metadata_archive에 보관했습니다.

2. 파일 구조
sboms/<ID>.json: 순수 CycloneDX 입력. 원본 3,881개와 SYN- 접두부 합성 입력.
annotations/<ID>.json: 출처, inputs(가상 운영 기록), gold(정답), 파일 해시.
gold.jsonl: annotations와 완전히 같은 객체를 ID당 한 줄로 수록.
summary.json: 수량, 목표, 해시, 평가 결과 요약. 사례 수를 세 폴더/파일에서 중복 합산하지 않습니다.
모델에는 SBOM과 inputs만 전달합니다. gold, 원래 분할, 시나리오 종류, 잠재 상태를 전달하지 않습니다.
source_rule은 공급사 근거/규칙이며 gold는 아닙니다. 실제 시스템은 원문 추출부터 별도 검증해야 합니다.

3. 정답 범위
원본 자문 제품 모음은 실제 설치 버전/패치/실행 환경을 확정하지 못하므로 actual_affected=null입니다.
자문에 언급된 CVE를 실제 영향 있음 정답으로 바꾸지 않았습니다.
공급사 원문의 인용 위치/해시가 검증되고 원본 모집단에 속하는 7개 실제 CVE에 가상 자산 운영 시나리오를 추가했습니다.
버전은 보존된 공급사 전사 표의 정확한 릴리스만 사용하며 실제 설치라고 주장하지 않습니다.
라벨은 모델 출력이 아닌 별도 릴리스 표와 잠재 물리 설정으로 생성합니다.
정상, 누락, 만료, 다른 자산 기록, 충돌, 무관 기록 및 잘못 입력된 운영 기록을 포함합니다.
잘못된 운영 기록의 정답도 실제 가상 상태를 유지합니다. FP가 발생해도 삭제하지 않습니다.
추가 사례들은 기존 자문의 실제 설치를 복원한 것이 아닙니다.

4. 목표와 측정
정밀도 = 실제 영향 있음으로 확인된 자동 Affected(TP) / 모든 자동 Affected(TP+FP) × 100.
통과 기준은 85% 초과입니다. 85%는 통과가 아닙니다. Affected 출력 0개도 통과가 아닙니다.
미확정 정답의 Affected는 별도 집계하고 전체 정밀도/통과 판정을 보류합니다.
Recall, 보류율, 판정 범위, CVE별/사례 종류별 성능을 함께 보고합니다.
실행: python -m tools.item4.evaluate_item4_unified
위 실행은 공급사 버전 비교 및 operational_assessment의 합성 평가 기준선입니다.
실행 결과는 results/item4_unified_evaluation_20261120에 저장합니다.
합성 기준선의 통과를 배포된 Agent 3/4, LLM 추출기, 전체 12,418 CVE 또는 실제 자산의 통과로 해석하지 않습니다.
전체 모집단은 유지하지만 독립 정답이 없는 부분은 점수 산출이 불가능합니다.
기존 학습 노출은 미감사이며 통합 데이터는 미학습 홀드아웃이 아닙니다.
''', encoding='utf-8')
    # Only remove archived metadata files, after validating exact workspace paths.
    for directory in (OUT / '_metadata', training / '_metadata'):
        assert directory.resolve().is_relative_to((ROOT / 'benchmark').resolve())
        for p in sorted(directory.rglob('*'), key=lambda p: len(p.parts), reverse=True):
            if p.is_file():
                p.unlink()
            else:
                p.rmdir()
        directory.rmdir()
    training.rmdir()  # Fails rather than removing any unexpected file.
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
