"""Recover a fully committed Windows SQLite build after a rename lock."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from collections import Counter
from pathlib import Path
import hashlib,json,sqlite3
from src.item4.decision import scoped_vex_review as A
from src.item4.decision import population_condition_rules as P
def main():
    source=P.HOME/'catalog.building.sqlite3';target=P.HOME/'catalog.sqlite3'
    if target.exists():raise ValueError('A finalized catalogue already exists')
    counts=Counter();ledger=[]
    db=sqlite3.connect(source)
    for cve,payload,sha in db.execute('SELECT cve,payload,sha256 FROM records ORDER BY cve'):
        r=json.loads(payload)
        if P.digest(r)!=sha:raise ValueError('Committed row integrity failed')
        q=r['compiled'];counts['cves']+=1;counts['source_product_status_rows']+=len(r['products']);counts['with_primary_status' if r['products'] else 'without_primary_status']+=1;counts['with_translated_operational_questions' if q['questions'] else 'without_translated_operational_questions']+=1;counts['translated_operational_questions']+=len(q['questions']);counts['untranslated_source_gaps']+=len(q['gaps'])
        ledger.append(dict(cve=cve,sha256=r['sha256'],product_rows=len(r['products']),operating_questions=len(q['questions']),unknown_conditions=len(q['gaps'])))
    db.close();wanted={r['cve'] for r in A.catalogue()['cves']}
    if {r['cve'] for r in ledger}!=wanted or len(ledger)!=12418:raise ValueError('Exact population membership failed')
    documents=[dict(path=str(p.relative_to(P.ROOT)),sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted((P.ROOT/'icsa/csaf').glob('*.json'))]
    data=dict(version=P.VERSION,population_count=12418,population_sha256=P.digest(sorted(wanted)),source_documents=documents,counts=dict(counts),not_independent_semantic_validation=True,compiler_policy='All CVEs compiled. Untranslated source operands remain unknown; no LLM/CVSS/CWE truth mapping.',records=ledger,recovered_committed_windows_build=True)
    data['sha256']=P.digest(data);source.replace(target);(P.HOME/'manifest.json').write_text(json.dumps(data,indent=2),encoding='utf-8');print(json.dumps(dict(counts=counts,sha256=data['sha256'])))
if __name__=='__main__':main()
