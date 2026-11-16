from pathlib import Path
import subprocess,os
r=Path('/home/irteam/data-vol1/ics-vex-migration-20261116')
env=dict(os.environ,LD_LIBRARY_PATH=str(r/'proot/usr/lib/x86_64-linux-gnu'),PROOT_NO_SECCOMP='1')
cmd=[str(r/'proot/usr/bin/proot'),'-r',str(r/'operational_rootfs'),'-b','/dev','-b','/proc','-b',str(r/'project/results/cloud_migration/tools/oval')+':/work','-w','/work','oscap','oval','eval','--results','/work/diagnostic.xml','/work/definitions.xml']
for label,prefix in [('baseline',[]),('user',['unshare','--user','--map-root-user']),('network',['unshare','--user','--map-root-user','--net'])]:
 p=subprocess.run(prefix+cmd,env=env,capture_output=True,text=True,timeout=60)
 print(label,p.returncode,p.stdout[-300:],p.stderr[-800:])
py=str(r/'venv/bin/python')
p=subprocess.run([py,str(r/'project/tools/ncp_operational_runtime.py'),'exec-inner',str(r/'project/results/cloud_migration/tools/oval'),'oscap','oval','eval','--results','/work/limit.xml','/work/definitions.xml'],capture_output=True,text=True,timeout=60)
print('limits',p.returncode,p.stdout[-300:],p.stderr[-800:])
