"""Check split integrity, frozen test sources and explicit oracle boundaries."""
from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SUITE=ROOT/'data/source_training_sw'


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    frozen=json.loads((SUITE/'test100_frozen.json').read_text())
    test_root=ROOT/frozen['root']
    current={p.relative_to(test_root).as_posix():sha(p) for p in test_root.rglob('*') if p.is_file() and 'build' not in p.relative_to(test_root).parts}
    assert current==frozen['files'],'Test100 sources/metadata changed'
    cases=json.loads((SUITE/'oracle/cases.json').read_text())
    test=json.loads((test_root/'oracle/cases.json').read_text())
    splits={'train':[r for r in cases if r['split']=='train'],'validation':[r for r in cases if r['split']=='validation'],'test':test}
    expected={'train':800,'validation':100,'test':100}
    source_hashes={}
    report={'counts':{},'dependency_families':{},'scenarios':{},'template_groups':{},'test100_unchanged':True,'full_program_exact_hash_overlaps':{}}
    for name,rows in splits.items():
        assert len(rows)==expected[name]
        assert len({r['id'] for r in rows})==len(rows)
        report['counts'][name]=len(rows)
        families=sorted({r['component'] for r in rows});report['dependency_families'][name]=families
        report['scenarios'][name]=dict(Counter(r['scenario'] for r in rows))
        report['template_groups'][name]=dict(Counter(r.get('template_group',r.get('call_shape')) for r in rows))
        source_hashes[name]=set()
        base=test_root if name=='test' else SUITE
        for r in rows:
            p=base/r['source_path']
            files=sorted(q for q in p.iterdir() if q.suffix in ('.c','.h'))
            assert files and (p/'CMakeLists.txt').exists()
            h=hashlib.sha256()
            for f in files:h.update(f.name.encode());h.update(f.read_bytes())
            source_hashes[name].add(h.hexdigest())
            assert r['cve_exploitability_asserted'] is False
        if name!='test':
            examples=[json.loads(l) for l in (SUITE/f'{name}.jsonl').read_text().splitlines()]
            assert len(examples)==expected[name]
            for e in examples:
                assert 'target' in e and all('oracle' not in f for f in e['input']['files'])
                assert all((SUITE/f).exists() for f in e['input']['files'])
                context=json.loads((SUITE/e['input']['build_context']).read_text())
                assert not set(e['target']) & set(context), 'Target field copied into input metadata'
                assert (SUITE/e['input']['build_recipe']).exists()
    for a,b in [('train','validation'),('train','test'),('validation','test')]:
        assert not set(report['dependency_families'][a]) & set(report['dependency_families'][b])
        overlap=len(source_hashes[a]&source_hashes[b]);assert overlap==0
        report['full_program_exact_hash_overlaps'][a+'/'+b]=overlap
    prov=json.loads((SUITE/'provenance.json').read_text())
    verified=0
    for d in prov:
        for f in d['files']:
            assert sha(SUITE/f['file'])==f['sha256']==sha(ROOT/f['original'])
            verified+=1
    report.update({'unchanged_upstream_files_verified':verified,'ratio':'80:10:10','limitations':['Exact whole-program hashes and family separation do not establish absence of all near clones.','Synthetic variants share templates within splits.','Existing test100 is an already-inspected frozen regression suite, not a newly blinded test.','Targets are application structure, not final CVE exploitability labels.']})
    output=ROOT/'results/source_training_sw/split_audit.json';output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('template_groups','limitations')},indent=2))


if __name__=='__main__':main()
