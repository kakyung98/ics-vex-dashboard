"""Extract a pinned official Windows Clang locally; never run the installer."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
VERSION='18.1.8'


def main():
    if os.name!='nt':
        raise SystemExit('Install Clang with your OS package manager and set ICSVEX_CLANG to its absolute executable path.')
    seven=shutil.which('7z') or r'C:\Program Files\7-Zip\7z.exe'
    if not Path(seven).is_file():raise SystemExit('Install 7-Zip first or put 7z on PATH.')
    folder=ROOT/'.tools/llvm18';folder.mkdir(parents=True,exist_ok=True)
    archive=folder/f'LLVM-{VERSION}-win64.exe'
    url=f'https://github.com/llvm/llvm-project/releases/download/llvmorg-{VERSION}/LLVM-{VERSION}-win64.exe'
    if not archive.is_file():urllib.request.urlretrieve(url,archive)
    subprocess.run([seven,'x',str(archive),'-o'+str(folder),r'bin\clang.exe',r'lib\clang\18\include\*','-y'],check=True)
    executable=folder/'bin/clang.exe'
    version=subprocess.run([str(executable),'--version'],check=True,capture_output=True,text=True).stdout
    provenance={'url':url,'version':VERSION,'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),
                'compiler_sha256':hashlib.sha256(executable.read_bytes()).hexdigest(),
                'origin':'official LLVM HTTPS release; hashes record the downloaded bytes',
                'installation':'project-local extraction; installer not executed','compiler_version':version}
    (folder/'provenance.json').write_text(json.dumps(provenance,indent=2),encoding='utf-8')
    print(version)


if __name__=='__main__':main()
