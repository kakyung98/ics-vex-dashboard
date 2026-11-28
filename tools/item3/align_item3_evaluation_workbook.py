"""Align exported Item 3 evaluation BOMs with the supplied workbook, preserving faults."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

from jsonschema import Draft7Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'benchmark/item3_evaluation'
SCHEMA_URL = 'https://raw.githubusercontent.com/CycloneDX/specification/1.7/schema/bom-1.7.schema.json'
WORKBOOK = ROOT / 'SBOM 데이터필드 정의-CycloneDX.xlsx'


def wire(obj):
    return (json.dumps(obj, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic(path, data):
    tmp = path.with_suffix(path.suffix + '.format-tmp')
    tmp.write_bytes(data)
    tmp.replace(path)


def workbook_fields():
    ns = {'s': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
    with zipfile.ZipFile(WORKBOOK) as z:
        strings = [''.join(t.itertext()) for t in ET.fromstring(z.read('xl/sharedStrings.xml')).findall('s:si', ns)]
        sheet = ET.fromstring(z.read('xl/worksheets/sheet1.xml'))
    stack = []
    fields = []
    for row in sheet.findall('.//s:sheetData/s:row', ns):
        if int(row.attrib['r']) < 3:
            continue
        for cell in row.findall('s:c', ns):
            col = ''.join(ch for ch in cell.attrib['r'] if ch.isalpha())
            if col not in ('A', 'B', 'C', 'D', 'E'):
                continue
            v = cell.find('s:v', ns)
            if v is None:
                continue
            name = strings[int(v.text)] if cell.get('t') == 's' else v.text
            if not name:
                continue
            level = ord(col) - ord('A')
            stack = stack[:level] + [name]
            fields.append({'cell': cell.attrib['r'], 'path': '.'.join(stack)})
    return fields


def align(original, stamp):
    bom = deepcopy(original)
    # Extension data belongs in the standard property array, not extra root keys.
    old = bom['properties']
    bom['properties'] = [
        {'name': 'SBOM_CREATION_DATE', 'value': old['BOM_CREATION_DATE']},
        {'name': 'SBOM_MODIFY_DATE', 'value': stamp},
        {'name': 'bom_type', 'value': bom.pop('bom_type')},
    ]
    bom['version'] = original['version'] + 1
    metadata = bom['metadata']
    metadata['timestamp'] = stamp
    metadata['lifecycles'] = [{'phase': metadata.pop('lifecycles_phase')}]
    for entity in (metadata['manufacturer'], metadata['component']['manufacturer']):
        entity.setdefault('address', {})
        entity.setdefault('contact', [])
    asset = metadata['component']
    asset.setdefault('publisher', '')
    asset.setdefault('copyright', '')
    asset.setdefault('supplier', {'address': {}, 'contact': []})
    asset.setdefault('tags', [])
    asset.setdefault('hashes', [])
    asset.setdefault('licenses', [])
    asset.setdefault('externalReferences', [])
    for component in bom['components']:
        component.setdefault('publisher', '')
        component.setdefault('supplier', {})
        component.setdefault('tags', [])
        component.setdefault('licenses', [])
        component.setdefault('copyright', '')
    for tool in metadata['tools']['components']:
        tool.setdefault('externalReferences', [])
    return bom


def main():
    report_path = OUT / 'workbook_format_report.json'
    if report_path.exists():
        raise FileExistsError('Already converted; inspect the report before rerunning.')
    stamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    reference = OUT / 'format_reference'
    reference.mkdir(exist_ok=True)
    schema_bytes = urllib.request.urlopen(SCHEMA_URL).read()
    atomic(reference / 'bom-1.7.schema.json', schema_bytes)
    validator = Draft7Validator(json.loads(schema_bytes), format_checker=FormatChecker())
    db_path = ROOT / 'benchmark/item3_evaluation/prep/dataset.sqlite3'
    with sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True) as db:
        rows = db.execute("SELECT id,condition_id,axis,scenario,sbom,perturbation FROM cases WHERE fold='evaluation' ORDER BY axis,scenario,id").fetchall()
    assert len(rows) == 18608
    schema_results = []
    # Validate transformed documents before modifying any exported input.
    for identity, condition, axis, scenario, raw, perturbation in rows:
        original = json.loads(raw)
        converted = align(original, stamp)
        errors = list(validator.iter_errors(converted))
        if errors:
            raise ValueError((identity, [(list(e.path), e.message) for e in errors[:3]]))
        # Every preexisting product field, CPE location and dependency stays intact.
        for old, new in [(original['metadata']['component'], converted['metadata']['component']),
                         *zip(original['components'], converted['components'])]:
            for key, value in old.items():
                if key == 'manufacturer':
                    assert all(new[key][k] == v for k, v in value.items())
                else:
                    assert new[key] == value, (identity, key)
        assert original['dependencies'] == converted['dependencies']
        assert original['serialNumber'] == converted['serialNumber']
        schema_results.append(identity)
    print('Preflight: 18,608 documents pass CycloneDX 1.7 JSON Schema; source product fields unchanged', flush=True)

    backup_path = OUT / 'before_workbook_format.zip'
    if backup_path.exists():
        raise FileExistsError(backup_path)
    original_ledger = [json.loads(s) for s in (OUT / 'gold.jsonl').read_text(encoding='utf-8').splitlines()]
    ledger = {a['id']: a for a in original_ledger}

    def prepare(row):
        identity, condition, axis, scenario, raw, perturbation = row
        sbom_path = OUT / 'sboms' / (identity + '.json')
        annotation_path = OUT / 'annotations' / (identity + '.json')
        old_wire = sbom_path.read_bytes()
        old_annotation_wire = annotation_path.read_bytes()
        assert json.loads(old_wire) == json.loads(raw), identity
        annotation = json.loads(old_annotation_wire)
        assert annotation == ledger[identity], identity
        assert annotation['perturbation'] == json.loads(perturbation)
        converted = align(json.loads(raw), stamp)
        new_wire = wire(converted)
        annotation['export_format'] = {
            'profile': 'supplied-workbook-cyclonedx-1.7',
            'source_database_sbom_preserved': True,
            'original_export_sha256': digest(old_wire),
            'sbom_file_sha256': digest(new_wire),
            'conversion_time': stamp,
            'json_schema_valid': True,
            'noise_values_and_gold_unchanged': True,
        }
        return identity, old_wire, old_annotation_wire, new_wire, annotation

    converted_annotations = {}
    checksums = []
    with zipfile.ZipFile(backup_path, 'x', zipfile.ZIP_DEFLATED, compresslevel=3) as backup:
        for name in ('gold.jsonl', 'summary.json', 'README.txt'):
            backup.write(OUT / name, name)
        # pool.map preserves order; the archive is completed before input mutations.
        with ThreadPoolExecutor(max_workers=8) as pool:
            for i, (identity, old_wire, old_annotation_wire, new_wire, annotation) in enumerate(pool.map(prepare, rows), 1):
                backup.writestr('sboms/' + identity + '.json', old_wire)
                backup.writestr('annotations/' + identity + '.json', old_annotation_wire)
                converted_annotations[identity] = (new_wire, annotation)
                checksums.append({'id': identity, 'before_sha256': digest(old_wire), 'after_sha256': digest(new_wire)})
                if i % 4000 == 0:
                    print(f'Backed up and prepared {i}/18608', flush=True)
    with zipfile.ZipFile(backup_path) as backup:
        assert backup.testzip() is None
        assert len(backup.namelist()) == 18608 * 2 + 3
    print('Original files safely backed up; applying format changes', flush=True)

    def save(item):
        identity, (new_wire, annotation) = item
        atomic(OUT / 'sboms' / (identity + '.json'), new_wire)
        atomic(OUT / 'annotations' / (identity + '.json'), wire(annotation))

    with ThreadPoolExecutor(max_workers=8) as pool:
        for i, _ in enumerate(pool.map(save, converted_annotations.items()), 1):
            if i % 4000 == 0:
                print(f'Updated {i}/18608', flush=True)
    new_ledger = ''.join(json.dumps(converted_annotations[a['id']][1], ensure_ascii=False, separators=(',', ':')) + '\n' for a in original_ledger)
    atomic(OUT / 'gold.jsonl', new_ledger.encode('utf-8'))

    def verify(item):
        identity, (expected_wire, expected_annotation) = item
        actual = (OUT / 'sboms' / (identity + '.json')).read_bytes()
        assert actual == expected_wire
        assert json.loads((OUT / 'annotations' / (identity + '.json')).read_bytes()) == expected_annotation
        for key, value in ledger[identity].items():
            assert expected_annotation[key] == value
        return identity

    with ThreadPoolExecutor(max_workers=8) as pool:
        verified = list(pool.map(verify, converted_annotations.items()))
    assert len(verified) == 18608
    for original_annotation, new_line in zip(original_ledger, new_ledger.splitlines(), strict=True):
        updated = json.loads(new_line)
        assert updated == converted_annotations[original_annotation['id']][1]

    mapping = {
        'workbook': str(WORKBOOK), 'workbook_sha256': digest(WORKBOOK.read_bytes()),
        'fields_from_sheet1': workbook_fields(),
        'changes': {
            'properties': 'Object converted to standard array of name/value entries.',
            'properties.BOM_CREATION_DATE': 'Renamed SBOM_CREATION_DATE; original creation timestamp preserved.',
            'properties.BOM_MODIFY_DATE': 'Renamed SBOM_MODIFY_DATE; conversion timestamp recorded.',
            'metadata.lifecycles_phase': 'Converted to metadata.lifecycles=[{phase: operations}].',
            'bom_type': 'Moved from nonstandard root field to standard properties entry.',
            'version': 'Incremented from 1 to 2; serialNumber retained.',
            'metadata.timestamp': 'Updated for the newly revised BOM.',
        },
        'unavailable_fields': {
            'address.country/region/locality': 'No source addresses; address remains an empty object.',
            'contact.name/email/phone': 'No source contacts; contact remains an empty array.',
            'supplier.name': 'No source supplier; supplier remains an empty object (with empty address/contact on representative asset).',
            'publisher/copyright': 'Empty strings where unknown; no publisher or copyright claim invented.',
            'purl': 'Omitted: CPE does not establish an authoritative package URL.',
            'hashes.alg/content': 'Empty hashes array: no real component binary is available. BOM file digests are kept in annotations only.',
            'licenses.license.id': 'Empty licenses array: no source-supported SPDX license claim.',
            'externalReferences.type/url/comment': 'Empty reference arrays: no product references inferred from CVE answers.',
            'tags': 'Empty arrays: no role, noise, answer or condition identifier inserted into model input.',
        },
        'preserved_layout': 'CPE stays only at metadata.component, including intentional noise or omission. Existing same-asset shared bom-ref is preserved for project_input_contract compatibility.',
        'validation_scope': 'Official JSON Schema validation; no assertion of globally unique bom-ref semantic conformance. Shared representative/component references are retained from the project layout. Malformed CPE prefixes are deliberate benchmark inputs and have not been repaired.',
    }
    atomic(OUT / 'workbook_field_mapping.json', wire(mapping))
    atomic(OUT / 'workbook_format_checksums.jsonl', ''.join(json.dumps(a) + '\n' for a in checksums).encode())
    report = {
        'converted_at': stamp, 'cases': 18608, 'schema_url': SCHEMA_URL,
        'schema_sha256': digest(schema_bytes), 'workbook_sha256': mapping['workbook_sha256'],
        'backup': backup_path.name, 'backup_crc_passed': True,
        'validation': {'schema_valid_documents': 18608, 'saved_files_verified': 18608,
                       'original_product_fields_preserved': True, 'gold_and_noise_preserved': True,
                       'source_database_modified': False, 'control_fault_pairing_preserved': True},
        'limits': mapping['validation_scope'],
    }
    summary = json.loads((OUT / 'summary.json').read_bytes())
    summary['original_extraction_validation'] = summary.pop('validation')
    summary['original_extraction_validation']['scope'] = 'Before workbook format conversion; current files have structural metadata changes.'
    summary['validation'] = report['validation']
    summary['format_conversion'] = {'report': report_path.name, 'mapping': 'workbook_field_mapping.json', 'backup': backup_path.name}
    atomic(OUT / 'summary.json', wire(summary))
    note = '''\n\n============================================================
엑셀 필드 정의에 따른 형식 수정 (2026-11-19)
============================================================
현재 sboms는 원본 DB에서 추출한 제품·버전·CPE 값과 노이즈를 유지하면서
엑셀의 필드명 및 CycloneDX 1.7 JSON 구조에 맞춰 수정한 버전입니다.
따라서 현재 SBOM 전체 JSON은 DB 원문과 완전히 같지 않습니다.
앞 절의 DB 일치 검증은 수정 전 추출본의 검증 기록입니다.
원본 DB는 변경하지 않았고, 수정 전 파일은 before_workbook_format.zip에 보존했습니다.

주요 변경: properties를 name/value 배열로 변환, SBOM_CREATION_DATE 및
SBOM_MODIFY_DATE로 명칭 정리, lifecycles=[{phase: operations}]로 변환,
bom_type을 properties로 이동, 문서 version=2 및 수정 시각 기록.
원래 생성 시각과 serialNumber는 유지했습니다.

주소·연락처·공급사·라이선스·바이너리 해시·purl은 원본에 없는 값을
추정하여 채우지 않았습니다. 빈 객체/배열/문자열 또는 생략으로 표시했습니다.
개별 필드의 처리 이유는 workbook_field_mapping.json을 확인하십시오.
실제 바이너리 해시 대신 JSON 해시를 component.hashes에 넣지 않았습니다.

정답 및 perturbation은 그대로이며 annotations와 gold.jsonl에만 있습니다.
annotations.export_format.sbom_file_sha256은 현재 SBOM 파일의 SHA-256입니다.
source_input_sha256/source_semantic_sha256은 원본 DB 기준 해시로 유지합니다.

18,608개 모두 공식 CycloneDX 1.7 JSON Schema 검증을 통과했습니다.
이는 모든 의미 규칙까지 만족한다는 뜻은 아닙니다. 프로젝트 입력 계약이
사용하는 대표 자산/구성요소의 동일 bom-ref 연결을 보존했습니다.
CPE 노이즈 사례의 잘못된 접두부와 CPE 누락도 평가 목적에 따라 유지했습니다.
공식 JSON Schema 통과를 CPE 자체의 유효성이나 평가 정확도로 해석하지 마십시오.
검증 상세: workbook_format_report.json
원본/수정본 파일별 해시: workbook_format_checksums.jsonl
'''
    atomic(OUT / 'README.txt', (OUT / 'README.txt').read_bytes() + note.encode('utf-8'))
    atomic(report_path, wire(report))
    print(json.dumps(report, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
