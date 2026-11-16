"""Publish the advisory SBOM dataset to the existing private NCP service."""
from pathlib import Path
import base64,hashlib,json,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.ncp_transport import execute,upload

def main():
    config=Path.home()/'Downloads/hysage-kubeconfig.yaml'
    archive=ROOT/'benchmark/icsa-cpe-synthetic sbom/icsa-cpe-sbom-v1.zip'
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    remote='/home/irteam/data-vol1/ics-vex-migration-20261116/icsa-cpe-sbom-'+digest[:16]+'.zip'
    upload(config,archive,remote)
    names=['site/icsa-cpe-sbom.html','site/index.html','site/dataset.html','site/ics-sbom.html',
           'site/sbom-to-cve.html','src/identification_method_page.py',
           'src/candidate_widget.py','src/asset_vulntology.html','src/asset_vulntology_ui.js',
           'site/vex-decision.html','site/asset-vex.html','site/context-vex.html',
           'site/question-mining.html','site/vex-method.html',
           'site/published-vex.html','site/published_vex.json','src/published_vex.py',
           'tools/icsa_cpe_dataset_web.py','tools/ncp_evaluation_metrics.py','tools/build_icsa_cpe_sbom.py',
           'tools/audit_icsa_cpe_sbom.py','tools/deploy_icsa_cpe_dataset.py']
    names += [p.relative_to(ROOT).as_posix() for p in sorted((ROOT/'site/published_csaf').glob('*.json'))]
    payload={n:base64.b64encode((ROOT/n).read_bytes()).decode() for n in names}
    script='''from pathlib import Path
import json,base64,hashlib,zipfile,os,signal,subprocess,time,urllib.request,shutil
root=Path('/home/irteam/data-vol1/ics-vex-migration-20261116');project=root/'project'
out=project/'results/icsa_cpe_sbom_publication_v1';out.mkdir(exist_ok=True)
lease=json.loads((project/'results/operational_role_finetune_v2/gpu_lease.json').read_text())
assert not lease.get('active'),'Evaluation/training queue active'
archive=Path(ARCHIVE);assert hashlib.sha256(archive.read_bytes()).hexdigest()==DIGEST
dest=project/'benchmark/icsa-cpe-synthetic sbom';dest.mkdir(parents=True,exist_ok=True)
with zipfile.ZipFile(archive) as z:
 for info in z.infolist():
  target=(dest/info.filename).resolve()
  assert target.is_relative_to(dest.resolve()) and not info.is_dir()
  assert (info.external_attr>>16)&0o170000 in (0,0o100000)
 for info in z.infolist():
  target=dest/info.filename;target.parent.mkdir(parents=True,exist_ok=True)
  tmp=target.with_name(target.name+'.publish-tmp')
  with z.open(info) as src,tmp.open('wb') as output:shutil.copyfileobj(src,output)
  tmp.replace(target)
shutil.copyfile(archive,dest/'icsa-cpe-sbom-v1.zip')
records=[]
for name,value in json.loads(PAYLOAD).items():
 p=project/name;before=p.read_bytes() if p.exists() else None
 if before is not None:
  backup=out/'originals'/name
  if not backup.exists():backup.parent.mkdir(parents=True,exist_ok=True);backup.write_bytes(before)
 p.parent.mkdir(parents=True,exist_ok=True);tmp=p.with_name(p.name+'.publish-tmp');tmp.write_bytes(base64.b64decode(value));tmp.replace(p)
 records.append(dict(path=name,sha256=hashlib.sha256(p.read_bytes()).hexdigest()))
pid=int((root/'api.pid').read_text());args=Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\\0')
assert any(Path(os.fsdecode(a)).resolve()==(project/'tools/ncp_serve.py').resolve() for a in args if a)
os.kill(pid,signal.SIGTERM)
for _ in range(80):
 proc=Path('/proc')/str(pid)
 if not proc.exists() or (proc/'stat').read_text().rsplit(')',1)[1].split()[0]=='Z':break
 time.sleep(.25)
else:raise RuntimeError('Owned API did not exit')
subprocess.run([str(root/'venv/bin/python'),str(project/'tools/ncp_service.py'),'start'],capture_output=True,check=True)
for _ in range(100):
 try:
  def get(path):return urllib.request.urlopen('http://127.0.0.1:18100/'+path,timeout=3).read()
  assert 'ics-sbom.html' in get('dataset.html').decode()
  page=get('ics-sbom.html').decode()
  assert 'id="sbom-q"' in page and 'workspace-topbar' in page
  assert 'href="icsa-cpe-sbom.html"' not in page
  assert len(json.loads(get('api/sbom_index'))['assets'])==3881
  method=get('sbom-to-cve.html').decode()
  assert '<h1>Method Overview</h1>' in method and 'Documentation updated 2026-11-16' in method
  assert 'Qwen3-8B' not in method and '99.9894669%' in method
  published=json.loads(get('api/published_vex'))
  assert published['available'] and published['pairs']==21 and published['label_instances']==24
  manifest=json.loads(get('icsa-cpe-sbom/manifest.json'));assert manifest['declared_unique_cves']==12418
  index=json.loads(get('icsa-cpe-sbom/index.json'));assert len(index['advisories'])==manifest['advisories']
  sample=next(r for r in index['advisories'] if r['component_count'])
  assert hashlib.sha256(get('icsa-cpe-sbom/'+sample['file'])).hexdigest()==sample['sha256']
  assert json.loads(get('icsa-cpe-sbom/audit.json'))['passed']
  assert json.loads(get('api/precision/h200/full-evaluation'))['status']['status']=='complete'
  break
 except Exception:time.sleep(.3)
else:raise RuntimeError('Publication health check failed')
report=dict(published=True,url='http://127.0.0.1:18100/icsa-cpe-sbom.html',archive_sha256=DIGEST,
            summary=manifest,HTTP_checked=True,item3_evaluation_data_modified=False,files=records)
(out/'publication.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
print(json.dumps(report))
'''.replace('ARCHIVE',repr(remote)).replace('DIGEST',repr(digest)).replace('PAYLOAD',repr(json.dumps(payload)))
    result=json.loads(execute(config,script))
    p=ROOT/'results/icsa_cpe_sbom_publication_v1';p.mkdir(exist_ok=True)
    (p/'publication.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in {'summary','files'}}))
if __name__=='__main__':main()
