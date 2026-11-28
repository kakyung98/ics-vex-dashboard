"""Audit every previously deferred case against source pointers and the new parser."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from collections import Counter,defaultdict
from pathlib import Path
import csv,hashlib,json,re
from src.item4.decision import population_condition_rules as P
from src.common.source_version_parser import concrete

ROOT=Path(__file__).resolve().parents[2]
HOME=ROOT/'results/nist_version_parser_20261118_v4'
PREVIOUS=ROOT/'results/nist_population_vex_comparison_20261118_v3/changed_cases.json'


def pointer(doc,path):
    for key in path.split('/')[1:]:
        key=key.replace('~1','/').replace('~0','~');doc=doc[int(key)] if isinstance(doc,list) else doc[key]
    return doc


def category(text):
    if text.startswith('vers:intdot/'):return 'VERS intdot'
    if text.startswith('vers:generic/'):return 'VERS generic opaque ordering'
    if text=='vers:all/*':return 'VERS all wildcard'
    if text.startswith('vers:all/'):return 'invalid VERS all constraints'
    if text.startswith('vers:'):return 'unsupported vendor VERS scheme'
    if re.search(r'_(?:and_)?[<>]',text,re.I):return 'explicit underscore bound conjunction'
    if re.search(r'\bwith|\busing|\bonly|[()]',text,re.I):return 'qualified product or operating scope'
    if '|' in text:return 'constraint sequence with pipe'
    if re.fullmatch(r'[<>=!\s]*[vVrR]?\d+(?:\.\d+)*',text):return 'numeric bound with nonnumeric observed build'
    return 'vendor suffix or release notation'


def main():
    original=json.loads(PREVIOUS.read_text(encoding='utf-8'));docs={};patterns={};cases=[];categories=defaultdict(set);states=Counter();checks=0
    assert len(original)==224 and len({r['cve'] for r in original})==224
    for case in original:
        parsed=[]
        for row in case['source_memberships']:
            if row['membership']!='unknown':continue
            filename=row['source_file']
            if filename not in docs:
                raw=(ROOT/filename).read_bytes()
                if hashlib.sha256(raw).hexdigest()!=row['document_sha256']:raise ValueError('Source hash changed')
                docs[filename]=json.loads(raw.decode('utf-8-sig'))
            doc=docs[filename];pid=pointer(doc,row['status_pointer']);product=pointer(doc,row['product_pointer'])
            if pid!=product['product_id']:raise ValueError('Source product/status mismatch')
            base=row['status_pointer'].split('/product_status/')[0]
            if pointer(doc,base+'/cve')!=case['cve']:raise ValueError('Source CVE mismatch')
            checks+=1;text=row['version_text'];kind=category(text);categories[kind].add(case['cve'])
            p=P.version_predicate(text);value=P.membership(p,case['build'])
            item=dict(row,category=kind,new_predicate=p,new_membership=value)
            parsed.append(item)
            key=(text,kind)
            pattern=patterns.setdefault(key,dict(text=text,category=kind,occurrences=0,cves=set(),new_memberships=Counter()))
            pattern['occurrences']+=1;pattern['cves'].add(case['cve']);pattern['new_memberships'][value]+=1
        rule=P.make_rule(case['cve'],case['product']);state=P.status(rule,case['build']);states[state]+=1
        cases.append(dict(cve=case['cve'],product=case['product'],build=case['build'],original_status=case['before'],
            conservative_status=case['after'],new_version_state=state,observed_build_concrete=concrete(case['build']),
            prior_unknown_rows=parsed,remaining_unknown_rows=[p for p in rule['source_product_rows'] if P.row_membership(p,case['build'])=='unknown']))
    pattern_rows=[dict(p,cves=sorted(p['cves']),new_memberships=dict(p['new_memberships'])) for p in patterns.values()]
    pattern_rows.sort(key=lambda r:(-r['occurrences'],r['text']))
    remaining=Counter()
    priority=['invalid VERS all constraints','unsupported vendor VERS scheme','qualified product or operating scope',
        'VERS generic opaque ordering','vendor suffix or release notation','constraint sequence with pipe',
        'numeric bound with nonnumeric observed build']
    for case in cases:
        if case['new_version_state']!='unknown':continue
        kinds={r['category'] for r in case['prior_unknown_rows'] if r['new_membership']=='unknown'}
        reason='installed version is not concrete' if not case['observed_build_concrete'] else next((k for k in priority if k in kinds),'other unresolved source ordering')
        case['remaining_primary_reason']=reason;remaining[reason]+=1
    report=dict(previously_deferred_cases=224,previously_deferred_cves=224,unknown_condition_occurrences=checks,
        distinct_condition_texts=len(pattern_rows),source_documents_checked=len(docs),all_source_hash_product_and_cve_bindings_verified=True,
        parser_version=P.PARSER_VERSION,version_states_after_parser=dict(states),
        remaining_primary_reasons=dict(remaining),remaining_primary_reasons_are_exclusive=True,
        category_cves={k:len(v) for k,v in categories.items()},category_counts_overlap=True,
        references=['https://www.packageurl.org/docs/vers/specification.html','https://raw.githubusercontent.com/package-url/www.packageurl.org/main/website/docs/vers/vers-types.md'],
        policy='No vendor ordering or observed installed version is invented. Invalid VERS all ranges, qualified scopes and unsupported schemes remain unknown.')
    HOME.mkdir(exist_ok=True)
    (HOME/'analysis.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    (HOME/'patterns.json').write_text(json.dumps(pattern_rows,ensure_ascii=False,indent=2),encoding='utf-8')
    (HOME/'cases.json').write_text(json.dumps(cases,ensure_ascii=False,indent=2),encoding='utf-8')
    with (HOME/'patterns.csv').open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=['text','category','occurrences','unique_cves','true','false','unknown']);writer.writeheader()
        for row in pattern_rows:writer.writerow(dict(text=row['text'],category=row['category'],occurrences=row['occurrences'],unique_cves=len(row['cves']),**{s:row['new_memberships'].get(s,0) for s in ('true','false','unknown')}))
    print(json.dumps(report,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
