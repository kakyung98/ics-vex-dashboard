"""Publish reviewed source/docs/public data with an isolated index; never stage local work."""
from pathlib import Path
from collections import Counter
import subprocess,json,os,uuid,hashlib,re

ROOT=Path(__file__).resolve().parents[1]
EXT={'.py','.js','.md','.ps1','.yml','.yaml','.mmd','.png','.svg','.c','.h'}
DATA=['cisa_advisories.json','cpe_index.json','nvd_cache.json','nvd_cpe_detail.json','nvd_cvss.json',
      'identity_aliases_v3.json','item4_routing_policy_v1.json','operational_runtime_models.json',
      'public_corpus_freshness.json','upstream_csaf_latest.zip']


def git(*args,env=None,body=None):
    return subprocess.run(['git',*args],cwd=ROOT,env=env,input=body,capture_output=True,check=True).stdout


def files():
    selected=set(json.loads((ROOT/'results/pages_frontend_deployment_manifest.json').read_text())['files'])
    for directory in ['src','tools','docs','tests','.github','ics_agent_matcher_full/ics_agent_matcher']:
        for p in (ROOT/directory).rglob('*'):
            if p.is_file() and p.suffix.lower() in EXT and not any(x in {'__pycache__','.venv','out'} for x in p.parts):selected.add(p.relative_to(ROOT).as_posix())
    for p in (ROOT/'evaluation').iterdir():
        if p.is_file() and p.suffix in {'.py','.md'}:selected.add(p.relative_to(ROOT).as_posix())
    selected.update(['README.md','requirements.txt','requirements-training.txt','sbom_index.json'])
    selected.update('data/'+n for n in DATA if (ROOT/'data'/n).is_file())
    for folder in ['data/cwe_taxonomy','data/cpe_feed','.tools/cyclonedx-schemas']:
        selected.update(p.relative_to(ROOT).as_posix() for p in (ROOT/folder).glob('**/*.json') if p.is_file())
    from sys import path
    path.insert(0,str(ROOT))
    from src.dataset_paths import public_sbom_directory
    snapshot=public_sbom_directory();assert snapshot.resolve().is_relative_to((ROOT/'data/public_sbom').resolve())
    for p in snapshot.glob('*.json'):
        doc=json.loads(p.read_text(encoding='utf-8'))
        props=(doc.get('metadata') or {}).get('component',{}).get('properties',[])
        assert any(x.get('name')=='dataset:synthetic-inventory' and str(x.get('value')).lower()=='true' for x in props),p
        selected.add(p.relative_to(ROOT).as_posix())
    for p in snapshot.parent.iterdir():
        if p.is_file() and p.suffix in {'.csv','.json'}:selected.add(p.relative_to(ROOT).as_posix())
    for name in selected:
        p=ROOT/name
        assert p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(ROOT.resolve()),name
        assert not set(p.relative_to(ROOT).parts)&{'models','results','cert_uploads','__pycache__'},name
        assert p.stat().st_size<95*1024*1024,('oversized',name)
        if p.suffix in {'.py','.js','.md','.json','.yml','.yaml','.ps1'}:
            text=p.read_text(encoding='utf-8',errors='replace')
            assert not re.search(r'gh[pousr]_[A-Za-z0-9]{25,}|sk-proj-[A-Za-z0-9_-]{30,}|AIza[0-9A-Za-z_-]{30,}',text),('possible credential in public candidate',name)
    return sorted(selected)


def main():
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--apply',action='store_true');args=parser.parse_args()
    selected=files();parent=git('rev-parse','origin/main').decode().strip()
    remote=set(git('ls-tree','-rz','--name-only',parent).decode('utf-8').rstrip('\0').split('\0'))
    removed=sorted(n for n in remote if n.startswith('reverse_sbom/') or n in {'data/cpe_dictionary.jsonl','data/cpe_dictionary.state'})
    prefixes=('src/','tools/','docs/','tests/','evaluation/','.github/','ics_agent_matcher_full/ics_agent_matcher/')
    removed+=sorted(n for n in remote if n.startswith(prefixes) and Path(n).suffix in EXT and not (ROOT/n).exists())
    plan={'parent':parent,'files':selected,'remove_from_git_only':removed,
          'excluded':['models/','results/','data/cert_uploads/','source snapshots/uploads','156 MiB generated CPE dictionary'],
          'counts':dict(Counter(n.split('/')[0] for n in selected))}
    ignore=git('show',parent+':.gitignore').decode('utf-8')
    ignore+='\n# Current generated caches and private runtime state\n/data/cpe_dictionary.jsonl\n/results/runtime_sessions.sqlite3*\n/results/*server*.log\n/vex_output/\n.env\n.env.*\n'
    plan['generated_gitignore_additions']=True
    (ROOT/'results/repository_publication_manifest.json').write_text(json.dumps(plan,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'selected':len(selected),'git_only_removals':len(removed),'groups':plan['counts']},ensure_ascii=False),flush=True)
    if not args.apply:return
    original_branch=git('symbolic-ref','HEAD');real_index=Path(git('rev-parse','--git-path','index').decode().strip())
    if not real_index.is_absolute():real_index=ROOT/real_index
    before=hashlib.sha256(real_index.read_bytes()).hexdigest()
    tag=uuid.uuid4().hex;index=ROOT/'results'/('publish-'+tag+'.index');paths=ROOT/'results'/('publish-'+tag+'.paths')
    env={**os.environ,'GIT_INDEX_FILE':str(index)}
    try:
        git('read-tree',parent,env=env)
        paths.write_bytes(b''.join(n.encode('utf-8')+b'\0' for n in selected))
        git('add','-f','--pathspec-from-file='+str(paths),'--pathspec-file-nul',env=env)
        ignore_sha=git('hash-object','-w','--stdin',body=ignore.encode('utf-8')).decode().strip()
        git('update-index','--add','--cacheinfo','100644',ignore_sha,'.gitignore',env=env)
        if removed:git('update-index','-z','--index-info',env=env,body=b''.join(('0 '+'0'*40+'\t'+n+'\0').encode('utf-8') for n in removed))
        tree=git('write-tree',env=env).decode().strip()
        changed=git('diff-tree','--no-commit-id','--name-only','-r','-z',parent,tree).decode('utf-8').rstrip('\0').split('\0')
        assert set(changed)<=set(selected)|set(removed)|{'.gitignore'}
        if changed==['']:print('Repository already current');return
        commit=git('commit-tree',tree,'-p',parent,body=b'Sync deterministic analysis, writer-only VEX, README and public web assets\n').decode().strip()
        print('Publishing commit',commit,'with',len(changed),'changed paths',flush=True)
        git('push','origin',commit+':refs/heads/main')
        receipt={'commit':commit,'parent':parent,'url':'https://github.com/kakyung98/ics-vex-dashboard/commit/'+commit,
                 'changed_paths':len(changed),'selected_files':len(selected),'public_sbom_documents':sum('/documents/' in n for n in selected),
                 'local_branch_or_index_modified':False,'private_runtime_or_weights_published':False}
        (ROOT/'results/repository_publication.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
        print(json.dumps(receipt,indent=2),flush=True)
    finally:
        assert git('symbolic-ref','HEAD')==original_branch
        assert hashlib.sha256(real_index.read_bytes()).hexdigest()==before
        index.unlink(missing_ok=True);paths.unlink(missing_ok=True)


if __name__=='__main__':main()
