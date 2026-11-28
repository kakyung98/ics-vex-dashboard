"""Start/status for the migrated API; checks ownership before reusing a PID."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
import json
import os
import subprocess
import sys
import urllib.request

PROJECT=Path(__file__).resolve().parents[2]
ROOT=PROJECT.parent
pidfile=ROOT/'api.pid'


def owned():
    try:
        pid=int(pidfile.read_text())
        args=Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
        return pid if any(Path(os.fsdecode(a)).resolve() in {PROJECT/'tools/common/ncp_serve.py',PROJECT/'tools/ncp_serve.py'} for a in args if a) else None
    except (OSError,ValueError):return None


def main():
    pid=owned()
    if sys.argv[1]=='start' and not pid:
        log=(ROOT/'logs/api.log').open('ab')
        p=subprocess.Popen([str(ROOT/'venv/bin/python'),str(PROJECT/'tools/common/ncp_serve.py')],cwd=PROJECT,
                           stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        pid=p.pid;pidfile.write_text(str(pid))
    print(json.dumps(dict(pid=pid,process_running=bool(pid),private_URL='http://127.0.0.1:18100/precision.html')))


if __name__=='__main__':main()
