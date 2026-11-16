from pathlib import Path
import hashlib
import os
import subprocess
import urllib.request
root=Path('/home/irteam/data-vol1/ics-vex-migration-20261116')
packages=root/'tool_packages'; packages.mkdir(exist_ok=True)
proot=root/'proot'; proot.mkdir(exist_ok=True)
for name,url,digest in [
 ('proot.deb','https://kr.archive.ubuntu.com/ubuntu/pool/universe/p/proot/proot_5.1.0-1.3_amd64.deb','01a5d27c4ac16e184bdb356c9e69fa7d494325ac653c4cd64fae4c3fc63cdbbb'),
 ('libtalloc.deb','https://kr.archive.ubuntu.com/ubuntu/pool/main/t/talloc/libtalloc2_2.3.3-2build1_amd64.deb','0910059bb0329add8d13b502f5a10d18d5b3c5202fbbbe25ef4f6d58e7edfe6c')]:
    wire=urllib.request.urlopen(url,timeout=60).read()
    assert hashlib.sha256(wire).hexdigest()==digest
    file=packages/name; file.write_bytes(wire)
    subprocess.run(['dpkg-deb','-x',str(file),str(proot)],check=True)
fs=root/'operational_rootfs'; fs.mkdir(exist_ok=True)
subprocess.run(['tar','--no-same-owner','--no-same-permissions','--exclude=dev/*','-xf',str(root/'incoming/operational-rootfs.tar'),'-C',str(fs)],check=True)
env=dict(os.environ,LD_LIBRARY_PATH=str(proot/'usr/lib/x86_64-linux-gnu'))
cmd=[str(proot/'usr/bin/proot'),'-r',str(fs),'-b','/dev','-b','/proc','-w','/work','/usr/bin/env',
     'PATH=/opt/xsb-source/XSB/bin:/opt/mulval/bin:/opt/mulval/utils:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','MULVALROOT=/opt/mulval']
subprocess.run(cmd+['oscap','--version'],env=env,check=True)
print('Unprivileged OpenSCAP runtime ready')
