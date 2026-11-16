"""Health-check the updated app before replacing its owned local web process."""
from pathlib import Path
import subprocess,sys,time,urllib.request
import psutil

ROOT=Path(__file__).resolve().parents[1]
EXPECTED=['-m','uvicorn','tools.local_dataset_app:app','--host','127.0.0.1','--port','8100']

def page(port):
    return urllib.request.urlopen(f'http://127.0.0.1:{port}/sbom-to-cve.html',timeout=3).read().decode()

def healthy(port):
    for _ in range(40):
        try:
            html=page(port)
            assert '<h1>Method Overview</h1>' in html
            assert 'Documentation updated 2026-11-16' in html
            assert 'Qwen2.5-Coder-14B' in html and '99.9894669%' in html
            assert 'Qwen3-8B' not in html and 'data/item3_ics_cert_full_v1' not in html
            assert 'workspace-topbar' in html
            return html
        except Exception:time.sleep(.25)
    raise RuntimeError(f'Updated page health check failed on port {port}')

def main():
    owners={c.pid for c in psutil.net_connections(kind='tcp') if c.status==psutil.CONN_LISTEN and c.laddr.port==8100}
    assert len(owners)==1,'Expected one local development server'
    old=psutil.Process(owners.pop())
    assert old.cmdline()[1:]==EXPECTED,'Server command does not match this application'
    assert Path(old.cwd()).resolve()==ROOT,'Server belongs to another workspace'
    assert not any(c.status==psutil.CONN_LISTEN and c.laddr.port==18101 for c in psutil.net_connections(kind='tcp'))
    logs=ROOT/'results/icsa_cpe_sbom_publication_v1';logs.mkdir(exist_ok=True)
    flags=subprocess.CREATE_NO_WINDOW if sys.platform=='win32' else 0
    with (logs/'method_preview.log').open('ab') as log:
        candidate=subprocess.Popen([sys.executable,*EXPECTED[:-1],'18101'],cwd=ROOT,stdout=log,stderr=log,creationflags=flags)
        try:healthy(18101)
        finally:
            candidate.terminate();candidate.wait(timeout=15)
    # Replace only the command- and workspace-verified application after preflight.
    old.terminate();old.wait(timeout=15)
    with (logs/'local_8100.stdout.log').open('ab') as output,(logs/'local_8100.stderr.log').open('ab') as errors:
        replacement=subprocess.Popen([sys.executable,*EXPECTED],cwd=ROOT,stdout=output,stderr=errors,creationflags=flags)
    html=healthy(8100)
    (ROOT/'site/sbom-to-cve.html').write_text(html,encoding='utf-8')
    print(f'Method Overview verified on local port 8100; server PID {replacement.pid}')

if __name__=='__main__':main()
