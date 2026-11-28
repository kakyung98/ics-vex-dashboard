"""Rebuild the selected advisory corpus with explicit, separate NVD CPE candidates."""
from collections import Counter,defaultdict
from copy import deepcopy
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import sys

ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0,str(ROOT))
from tools.item3.build_item3_advisory_dataset import compact,digest,sha,write,properties
from tools.item3.item3_truth_oracle import parts,literal

BOUNDS=('versionStartIncluding','versionStartExcluding','versionEndIncluding','versionEndExcluding')


def version_expression(match):
    fields=parts(match['criteria'])
    if fields[3] not in ('*',''):
        return literal(fields[3])
    expressions=[]
    for field,operator in zip(BOUNDS,('>=','>','<=','<')):
        if match.get(field) is not None:
            expressions.append(operator+str(match[field]))
    return ', '.join(expressions) if expressions else 'vers:all/*'


def rebuild(source,output,cve_source):
    source,output,cve_source=Path(source).resolve(),Path(output).resolve(),Path(cve_source).resolve()
    if output.exists():
        raise FileExistsError(output)
    index=json.loads((source/'index.json').read_bytes())
    if index['summary'].get('dataset_id')=='icsa-advisory-products-sbom-v3':
        raise ValueError('Use the preserved v2 corpus as input, not an already enriched corpus')
    records={r['id']:r for r in (json.loads(s) for s in cve_source.read_text(encoding='utf-8').splitlines())}
    cve_hash=sha(cve_source);index_hash=sha(source/'index.json')
    output.mkdir(parents=True);(output/'sbom').mkdir()
    # Preserve source metadata as provenance; current hashes are regenerated.
    provenance=output/'provenance_v2';provenance.mkdir()
    for path in source.iterdir():
        if path.is_file() and path.suffix.lower() in ('.json','.jsonl','.txt','.md'):
            shutil.copy2(path,provenance/path.name)
    coverage=defaultdict(set);stats=Counter();new_index=[];source_manifest=[]
    with (output/'nvd_conditions.jsonl').open('x',encoding='utf-8') as conditions:
        for entry in index['advisories']:
            path=source/entry['file']
            if sha(path)!=entry['sha256']:
                raise ValueError('Original index/source hash mismatch: '+path.name)
            original=json.loads(path.read_bytes());document=deepcopy(original)
            cid=entry['advisory_id'];grouped={};nvd_refs=defaultdict(list)
            for vulnerability in document.get('vulnerabilities',[]):
                vid=vulnerability['id']
                if vid not in records:
                    continue
                coverage[vid].add(cid)
                for ni,node in enumerate(records[vid].get('configurations',[])):
                    for mi,match in enumerate(node.get('cpeMatch',[])):
                        if match.get('vulnerable') is not True:
                            continue
                        key=digest([match['criteria'],{k:match.get(k) for k in BOUNDS}])
                        slot=grouped.setdefault(key,dict(criteria=match['criteria'],
                            bounds={k:match[k] for k in BOUNDS if match.get(k) is not None},
                            cves=set(),source_refs=[]))
                        slot['cves'].add(vid)
                        slot['source_refs'].append(dict(cve=vid,path=f'/configurations/{ni}/cpeMatch/{mi}',
                            matchCriteriaId=match.get('matchCriteriaId')))
            for key,condition in sorted(grouped.items()):
                fields=parts(condition['criteria'])
                ref='nvd-condition-'+digest([cid,key])[:40]
                match=dict(criteria=condition['criteria'],**condition['bounds'])
                component=dict(type={'a':'application','o':'operating-system','h':'device'}[fields[0]],
                    **{'bom-ref':ref},name=literal(fields[2]).replace('_',' '),version=version_expression(match),
                    cpe=condition['criteria'],manufacturer=dict(name=literal(fields[1]).replace('_',' ')),
                    description='NVD affected-product/version condition; a source candidate, not an observed installation.',
                    properties=[dict(name=k,value=str(v)) for k,v in {
                        'dataset:component-origin':'NVD-CPE-condition',
                        'dataset:nvd-condition-id':key,
                        'dataset:source-cpe-criteria':condition['criteria'],
                        'dataset:source-version-bounds':compact(condition['bounds']),
                        'dataset:version-semantics':'affected condition expression; not an installed release',
                        'dataset:installed-version':'unknown',
                        'dataset:deployment-verified':'false',
                        'dataset:source-cve-db-sha256':cve_hash,
                        'dataset:applicability-scope':'product/version/edition atoms; full platform AND/OR not asserted'
                    }.items()])
                document['components'].append(component)
                for vid in condition['cves']:
                    nvd_refs[vid].append(ref)
                conditions.write(compact(dict(advisory_id=cid,component_ref=ref,
                    **{k:v for k,v in condition.items() if k!='cves'},cves=sorted(condition['cves'])))+'\n')
            for vulnerability in document.get('vulnerabilities',[]):
                refs=nvd_refs.get(vulnerability['id'],[])
                if refs:
                    existing={a['ref'] for a in vulnerability.get('affects',[])}
                    vulnerability.setdefault('affects',[]).extend(dict(ref=ref) for ref in refs if ref not in existing)
                    vulnerability.setdefault('properties',[]).append(dict(name='dataset:nvd-cpe-component-refs',value=compact(sorted(refs))))
            document.setdefault('properties',[]).extend([
                dict(name='dataset:cpe-rebuild',value='CSAF/HTML products preserved; NVD CPE conditions added as separate candidates'),
                dict(name='dataset:cpe-rebuild-source-index-sha256',value=index_hash)])
            write(output/entry['file'],document)
            row=deepcopy(entry);row.update(component_count=len(document['components']),sha256=sha(output/entry['file']))
            new_index.append(row)
            source_manifest.append(dict(advisory_id=cid,original_file_sha256=entry['sha256'],
                rebuilt_file_sha256=row['sha256'],original_components=len(original['components']),added_CPE_components=len(grouped)))
            stats.update(documents=1,original_components=len(original['components']),NVD_components=len(grouped),
                components=len(document['components']),components_with_CPE=sum(bool(c.get('cpe')) for c in document['components']),
                documents_with_CPE=any(c.get('cpe') for c in document['components']),
                documents_with_NVD_CPE=bool(grouped),empty_documents=not bool(document['components']),
                nonempty_sboms=bool(document['components']),CVE_occurrences=len(document.get('vulnerabilities',[])))
    if set(coverage)!=set(records):
        raise ValueError('Some CPE-linked CVEs are absent from the selected advisory corpus')
    summary=dict(dataset_id='icsa-advisory-products-sbom-v3',**dict(stats),advisories=len(new_index),
        sbom_json_files=len(new_index),declared_unique_cves=index['summary']['declared_unique_cves'],
        included_unique_cves=index['summary']['declared_unique_cves'],CPE_linked_unique_CVEs=len(coverage),
        components_without_CPE=stats['components']-stats['components_with_CPE'],
        empty_sboms=stats['empty_documents'],schema_version='1.7',
        generated_at='2026-11-25',source_v2_generated_at=index['summary'].get('generated_at'),
        source_CVE_DB=str(cve_source),source_CVE_DB_sha256=cve_hash,
        source_v2_index_sha256=index_hash,source_v2_directory=str(source),
        builder_sha256=sha(Path(__file__)),
        product_membership_policy='Preserved CSAF/HTML candidates plus separately identified NVD vulnerable CPE condition candidates. No unsupported product merge.',
        dependency_graph='unknown',real_asset_accuracy_verified=False,source_semantic_accuracy_independently_verified=False)
    write(output/'manifest.json',summary);write(output/'index.json',dict(summary=summary,advisories=new_index))
    write(output/'source_rebuild_ledger.json',source_manifest)
    write(output/'CPE_coverage.json',dict(unique_CVEs=len(coverage),cves={k:sorted(v) for k,v in coverage.items()}))
    (output/'README.txt').write_text('Rebuilt from the selected 3,881 advisory SBOMs and the pinned CVE CPE database.\nOriginal CSAF/HTML products are preserved; NVD CPE/product/version conditions are separate source candidates.\nCPE ranges and wildcards are not observed installed releases. The corpus contains CVE answers and must be blinded before testing.\nOriginal v2 metadata is in provenance_v2; source and CPE coverage ledgers retain all evidence.\n',encoding='utf-8')
    return summary


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    backup=ROOT/'benchmark/icsa-cpe-synthetic sbom-v2-backup-20261125'
    parser.add_argument('--source',type=Path,default=backup if backup.exists() else ROOT/'benchmark/icsa-cpe-synthetic sbom')
    parser.add_argument('--output',type=Path,default=ROOT/'benchmark/icsa-cpe-source-v3-staged')
    parser.add_argument('--cve-source',type=Path,default=ROOT/'data/item3_identification_sources_v11/cves.jsonl')
    args=parser.parse_args()
    print(json.dumps(rebuild(args.source,args.output,args.cve_source),ensure_ascii=False,indent=2))
