"""Audit every exported advisory BOM against workbook fields and source CSAF.

This audit does not call the generator or its product parser. Source-backed
coverage and schema checks are not independent real-installation validation.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from datetime import datetime, timezone
import argparse, hashlib, json, sys
from jsonschema import Draft7Validator, RefResolver, FormatChecker
import openpyxl
import fastjsonschema

ROOT = Path(__file__).resolve().parents[2]
DEFAULT = ROOT / 'benchmark/icsa-cpe-synthetic sbom'
WORKBOOK = ROOT / 'SBOM 데이터필드 정의-CycloneDX.xlsx'


def read(path): return json.loads(path.read_bytes())
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def properties(node): return {p['name']: p['value'] for p in node.get('properties', [])}


def definitions():
    book = openpyxl.load_workbook(WORKBOOK, read_only=True, data_only=True)
    out = []
    for sheet in book:
        parents = {}
        for n, row in enumerate(sheet.values, 1):
            if n < 3: continue
            for level, value in enumerate(row[:5]):
                if value is not None:
                    parents = {k: v for k, v in parents.items() if k < level}
                    parents[level] = str(value)
                    out.append({'sheet': sheet.title, 'row': n, 'path': '.'.join(parents[k] for k in sorted(parents))})
    book.close()
    return out


def values_at(value, path):
    if not path: return [value]
    if isinstance(value, list): return [v for item in value for v in values_at(item, path)]
    if not isinstance(value, dict) or path[0] not in value: return []
    return values_at(value[path[0]], path[1:])


def source_products(csaf):
    out = {}
    def walk(branches, trail=()):
        for branch in branches:
            lineage = trail + ((branch.get('category'), branch.get('name')),)
            if branch.get('product'):
                prod = branch['product']
                names = [name for kind, name in lineage if kind in ('product_name', 'product_family', 'model')]
                versions = [name for kind, name in lineage if kind in ('product_version', 'product_version_range')]
                vendors = [name for kind,name in lineage if kind=='vendor']
                out[prod['product_id']] = dict(label=prod['name'], name=names[-1] if names else prod['name'],
                    expression=versions[-1] if versions else None, vendor=vendors[-1] if vendors else None,
                    helper=prod.get('product_identification_helper', {}))
            walk(branch.get('branches', []), lineage)
    tree = csaf.get('product_tree', {})
    walk(tree.get('branches', []))
    for prod in tree.get('full_product_names', []) + [r['full_product_name'] for r in tree.get('relationships', []) if 'full_product_name' in r]:
        out.setdefault(prod['product_id'], dict(label=prod['name'], name=prod['name'], expression=None, vendor=None,
            helper=prod.get('product_identification_helper', {})))
    return out


def audit(dataset, output):
    output.mkdir(parents=True, exist_ok=True)
    source = read(ROOT / 'data/cisa_advisories.json')
    fields = definitions()
    schema_home = ROOT / 'data/standards/cyclonedx-1.7'
    schema = read(schema_home / 'bom-1.7.schema.json')
    store = {key: read(p) for p in schema_home.glob('*.json') for key in
             (p.name, 'http://cyclonedx.org/schema/' + p.name, 'https://cyclonedx.org/schema/' + p.name)}
    def local_schema(uri):
        key=uri.split('#')[0]
        if key not in store: raise ValueError('Unexpected schema reference: '+uri)
        return store[key]
    format_checker=FormatChecker()
    from tools.common.icsa_fast_schema import Validator
    check_fast=Validator().validate
    index=read(dataset/'index.json')
    indexed={r['advisory_id']:r for r in index['advisories']}
    files = sorted((dataset / 'sbom').glob('*.json'))
    def load(path):
        csaf = ROOT / 'icsa/csaf' / path.name
        if csaf.exists():
            wire=csaf.read_bytes()
            origin={'source_file':str(csaf.relative_to(ROOT)),'source_file_sha256':hashlib.sha256(wire).hexdigest()}
            structured=json.loads(wire)
        else:
            html=ROOT/'data/icsa_sbom_source_html'/(path.stem+'.html')
            origin={'source_file':str(html.relative_to(ROOT)),'source_file_sha256':sha(html)} if html.exists() else {'source_file':None,'source_file_sha256':None}
            structured=None
        return path, read(path), structured, origin
    counts = Counter(); field_counts = Counter(); findings = []; unique = set(); review = []
    with ThreadPoolExecutor(max_workers=12) as pool:
        for n, (path, doc, csaf, origin) in enumerate(pool.map(load, files), 1):
            aid = path.stem; raw = source.get(aid, {}); issues = []; warnings = []
            comps = doc.get('components', []); vulns = doc.get('vulnerabilities', [])
            root = doc.get('metadata', {}).get('component', {})
            props = properties(doc)
            counts['documents'] += 1; counts['components'] += len(comps)
            counts['empty_component_arrays'] += not bool(comps)
            counts['cve_occurrences'] += len(vulns)
            ids = {v['id'] for v in vulns}; unique.update(ids)
            if len(ids)!=len(vulns):issues.append({'kind':'duplicate_cve_id'})
            indexed_row=indexed.get(aid,{})
            if indexed_row.get('sha256')!=sha(path):issues.append({'kind':'index_digest_mismatch'})
            if indexed_row.get('component_count')!=len(comps):issues.append({'kind':'index_component_count_mismatch'})
            wanted = set(raw.get('cves', [])) | {v['cve'] for v in (csaf or {}).get('vulnerabilities', []) if v.get('cve')}
            if wanted - ids: issues.append({'kind': 'missing_source_cves', 'values': sorted(wanted - ids)})
            if ids - wanted: issues.append({'kind': 'unexpected_cves', 'values': sorted(ids - wanted)})
            if doc.get('specVersion') != '1.7': issues.append({'kind': 'workbook_version', 'actual': doc.get('specVersion')})
            else:
                try: check_fast(doc)
                except fastjsonschema.JsonSchemaException as error:
                    issues.append({'kind':'schema','errors':[{'path':error.path,'message':error.message}]})
                else: counts['schema_valid_documents'] += 1
            refs = [c.get('bom-ref') for c in comps] + [root.get('bom-ref')]
            refs += [c.get('bom-ref') for c in doc.get('metadata', {}).get('tools', {}).get('components', [])]
            refs = [r for r in refs if r]
            if len(refs) != len(set(refs)): issues.append({'kind': 'duplicate_bom_ref'})
            for v in vulns:
                for affected in v.get('affects', []):
                    if affected.get('ref') not in refs: issues.append({'kind': 'dangling_affects', 'cve': v['id'], 'ref': affected.get('ref')})
                if v.get('analysis'): issues.append({'kind': 'unexpected_vex_verdict', 'cve': v['id']})
            if doc.get('metadata', {}).get('manufacturer', {}).get('name') != 'unknown': issues.append({'kind': 'unverified_bom_author'})
            for key in ['SBOM_CREATION_DATE', 'SBOM_MODIFY_DATE']:
                if not props.get(key): issues.append({'kind': 'missing_workbook_date', 'field': key})
            source_rows = source_products(csaf) if csaf else {}
            by_pid = {properties(c).get('dataset:source-product-id'): c for c in comps if properties(c).get('dataset:source-product-id') not in (None, 'unknown')}
            missing = set(source_rows) - set(by_pid)
            if missing: issues.append({'kind': 'missing_csaf_products', 'product_ids': sorted(missing)})
            for pid in set(source_rows) & set(by_pid):
                original = source_rows[pid]; c = by_pid[pid]; cp = properties(c)
                if original['label'] != cp.get('dataset:source-label'): issues.append({'kind': 'changed_source_label', 'product_id': pid})
                if original['name'] != c['name']: issues.append({'kind': 'changed_source_name', 'product_id': pid})
                if original.get('vendor') and c.get('manufacturer',{}).get('name')!=original['vendor']: issues.append({'kind':'changed_source_vendor','product_id':pid})
                if original['expression'] and original['expression'] != cp.get('dataset:source-version-expression'):
                    issues.append({'kind': 'changed_version_expression', 'product_id': pid})
                for key in ['cpe', 'purl']:
                    if c.get(key) != original['helper'].get(key): issues.append({'kind': 'identifier_source_mismatch', 'product_id': pid, 'field': key})
            expected_status = {v.get('cve'): v.get('product_status', {}) for v in (csaf or {}).get('vulnerabilities', [])}
            for vuln in vulns:
                affected = {x['ref'] for x in vuln.get('affects', [])}
                expected_refs = {by_pid[pid]['bom-ref'] for pid in expected_status.get(vuln['id'], {}).get('known_affected', []) if pid in by_pid}
                conflict = props.get('dataset:source-conflict-review') == 'true'
                if affected != (set() if conflict else expected_refs): issues.append({'kind': 'affected_edge_mismatch', 'cve': vuln['id']})
            if csaf:
                labels = {properties(c).get('dataset:source-label') for c in comps}
                missing_labels = set(raw.get('affected_products', [])) - labels
                if missing_labels: issues.append({'kind': 'missing_advisory_product_labels', 'values': sorted(missing_labels)})
                names = {c['name'] for c in comps}
                if set(raw.get('products', [])) - names: issues.append({'kind': 'missing_advisory_product_names', 'values': sorted(set(raw.get('products', [])) - names)})
            for c in comps:
                cp = properties(c)
                if aid=='icsa-11-096-01' and c.get('manufacturer',{}).get('name')=='GLEG':issues.append({'kind':'aggregate_vendor_used_as_product_manufacturer'})
                if aid=='icsa-10-070-01a' and c['name']=='RSHWare.exe':issues.append({'kind':'executable_alias_as_product'})
                if aid in ['icsa-10-201-01c','icsa-10-238-01b','icsa-10-272-01','icsa-11-041-01a'] and c['name'].startswith(('Windows','Microsoft')) and c.get('manufacturer',{}).get('name')!='Microsoft':issues.append({'kind':'windows_manufacturer_mismatch','name':c['name']})
                if cp.get('dataset:parse-review-required') == 'true':
                    counts['components_flagged_for_parse_review'] += 1
                    warnings.append({'kind': 'parse_review', 'ref': c.get('bom-ref'), 'name': c.get('name'), 'version': c.get('version'), 'source_label': cp.get('dataset:source-label')})
                for field in cp.get('dataset:unknown-fields','').split(','):
                    if field and values_at(c,field.split('.')):issues.append({'kind':'unknown_marker_for_present_field','ref':c.get('bom-ref'),'field':field})
                if c.get('hashes'): issues.append({'kind': 'unexpected_component_binary_hash'})
                if not cp.get('dataset:source-label'): issues.append({'kind': 'missing_product_evidence', 'ref': c.get('bom-ref')})
            if not comps: warnings.append('No extracted product components: inspect original source and unresolved.json')
            for field in fields:
                path_parts = field['path'].split('.')
                values = [props.get(path_parts[1])] if path_parts[0] == 'properties' and len(path_parts) == 2 else values_at(doc, path_parts)
                if values and any(v is not None for v in values): field_counts[field['path']] += 1
            counts['documents_with_findings'] += bool(issues)
            findings.extend({'advisory_id': aid, **issue} for issue in issues)
            review.append({'advisory_id': aid, 'sha256': sha(path), 'components': len(comps), 'cves': len(ids),
                'source_csaf_products': len(source_rows), **origin, 'issues': issues, 'warnings': warnings})
            if n % 500 == 0: print(f'Audited {n}/{len(files)}', flush=True)
    names = {p.stem for p in files}
    missing_files = sorted(set(source) - names); extra_files = sorted(names - set(source))
    summary = dict(generated_at=datetime.now(timezone.utc).isoformat(), dataset=str(dataset), workbook_sha256=sha(WORKBOOK),
        source_cache_sha256=sha(ROOT/'data/cisa_advisories.json'), schema_validator='fastjsonschema Draft 7 without default injection, with jsonschema format checks; source-coverage audit is separate from generation', **counts, unique_cves=len(unique),
        missing_advisory_files=missing_files, unexpected_files=extra_files,
        passed=not findings and not missing_files and not extra_files,
        issue_counts=dict(Counter(f['kind'] for f in findings)),
        scope='Whole-corpus schema, workbook field presence, cached advisory/CSAF product/CVE/reference coverage. No generator/parser imports. Not independent real-installation accuracy validation.')
    (output/'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf8')
    (output/'findings.json').write_text(json.dumps(findings, ensure_ascii=False, indent=2), encoding='utf8')
    (output/'documents.jsonl').write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in review), encoding='utf8')
    (output/'workbook_field_coverage.json').write_text(json.dumps([dict(f,documents_present=field_counts[f['path']],documents_total=len(files)) for f in fields],ensure_ascii=False,indent=2),encoding='utf8')
    print(json.dumps(summary, ensure_ascii=True, indent=2), flush=True)
    return summary


if __name__ == '__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--dataset',type=Path,default=DEFAULT);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();audit(args.dataset,args.output)

