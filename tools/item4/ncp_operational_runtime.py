"""Cloud-only external tools backend; frozen local evaluation code stays unchanged."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
import ctypes
import json
import fcntl
import os
import resource
import signal
import socket
import struct
import subprocess
import sys
import time
import uuid

PROJECT=Path(__file__).resolve().parents[2]
ROOT=PROJECT.parent


def limit_process():
    # Probes reserve large virtual arenas; aggregate resident memory is bounded below.
    resource.setrlimit(resource.RLIMIT_AS,(16*1024**3,16*1024**3))
    resource.setrlimit(resource.RLIMIT_CPU,(120,120))
    os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:2])


def legacy_path_syscall_fallback():
    # Ubuntu's PRoot 5.1 predates faccessat2. ENOSYS makes glibc use its
    # supported faccessat fallback; this filter is scoped to this tool process.
    class Filter(ctypes.Structure):
        _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_=[('length',ctypes.c_ushort),('filters',ctypes.POINTER(Filter))]
    filters=(Filter*4)(Filter(0x20,0,0,0),Filter(0x15,0,1,439),Filter(0x06,0,0,0x50000|38),Filter(0x06,0,0,0x7fff0000))
    program=Program(4,filters)
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(38,1,0,0,0) or libc.prctl(22,2,ctypes.byref(program),0,0):
        raise RuntimeError('Guest path compatibility filter could not be installed')


def exec_tool(folder,args):
    parent=int(os.environ['ICS_VEX_PARENT_NETNS'])
    if os.stat('/proc/self/ns/net').st_ino==parent:
        raise RuntimeError('Refusing tools without a private network namespace')
    # OpenSCAP system-info probes require a working loopback interface.
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as handle:
        current=fcntl.ioctl(handle.fileno(),0x8913,struct.pack('16sH14x',b'lo',0))
        flags=struct.unpack('16sH14x',current)[1]|1
        fcntl.ioctl(handle.fileno(),0x8914,struct.pack('16sH14x',b'lo',flags))
    interfaces=[x.split(':')[0].strip() for x in Path('/proc/net/dev').read_text().splitlines()[2:]]
    if interfaces!=['lo']:raise RuntimeError('Unexpected external interface in tool namespace')
    proot=ROOT/'proot'
    # This process already runs in a new network namespace without external interfaces.
    # Disable PRoot's syscall acceleration for current host-kernel compatibility.
    env=dict(os.environ,LD_LIBRARY_PATH=str(proot/'usr/lib/x86_64-linux-gnu'),PROOT_NO_SECCOMP='1')
    command=[str(proot/'usr/bin/proot'),'-r',str(ROOT/'operational_rootfs'),'-b','/dev','-b','/proc',
             '-b',str(Path(folder).resolve())+':/work','-w','/work','/usr/bin/env',
             'PATH=/opt/xsb-source/XSB/bin:/opt/mulval/bin:/opt/mulval/utils:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
             'MULVALROOT=/opt/mulval','JAVA_TOOL_OPTIONS=-Xmx512m -XX:ActiveProcessorCount=2',*args]
    limit_process()
    legacy_path_syscall_fallback()
    os.execve(command[0],command,env)


def run(args,folder,label,timeout=120):
    process=subprocess.Popen([sys.executable,str(Path(__file__)), 'exec',str(folder),*args],stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,text=True,encoding='utf-8',errors='replace',start_new_session=True)
    started=time.monotonic()
    try:
        while True:
            try:
                stdout,stderr=process.communicate(timeout=.25)
                break
            except subprocess.TimeoutExpired:
                rss=0
                for proc in Path('/proc').iterdir():
                    if not proc.name.isdigit():continue
                    try:
                        stat=(proc/'stat').read_text().rsplit(')',1)[1].split()
                        if int(stat[2])!=process.pid:continue
                        rss+=next((int(x.split()[1])*1024 for x in (proc/'status').read_text().splitlines() if x.startswith('VmRSS:')),0)
                    except (FileNotFoundError,ProcessLookupError,PermissionError):continue
                if rss>2*1024**3 or time.monotonic()-started>timeout:
                    raise RuntimeError('External tool exceeded aggregate 2 GiB RSS or execution deadline')
    except BaseException:
        os.killpg(process.pid,signal.SIGKILL)
        process.communicate()
        raise
    result=subprocess.CompletedProcess(process.args,process.returncode,stdout,stderr)
    (folder/(label+'.stdout.log')).write_text(result.stdout,encoding='utf-8')
    (folder/(label+'.stderr.log')).write_text(result.stderr,encoding='utf-8')
    return result


def run_mulval(payload):
    sys.path.insert(0,str(PROJECT))
    from src.item4.decision.operating_scenario_assessment import mulval_input
    from src.common.runtime.training_progress_io import atomic_json
    facts=mulval_input(payload['binding'],payload.get('network',[]),payload.get('services',[]),
                      payload.get('vulnerabilities',[]),payload['attacker_host'])
    identity=uuid.uuid4().hex
    folder=PROJECT/'results/operational_tool_runs'/identity;folder.mkdir(parents=True)
    (folder/'input.P').write_text(facts,encoding='utf-8')
    result=run(['graph_gen.sh','/work/input.P','-l'],folder,'execution')
    artifacts=[p.name for p in folder.iterdir() if p.name in ('VERTICES.CSV','ARCS.CSV','AttackGraph.xml','AttackGraph.txt')]
    completed=result.returncode==0 and 'VERTICES.CSV' in artifacts
    outcome=dict(id=identity,tool='MulVAL/XSB',state='complete' if completed else 'error',returncode=result.returncode,
        artifacts=artifacts,graph_has_nodes=bool((folder/'VERTICES.CSV').read_text().strip()) if completed else False,
        binding=payload['binding'],VEX_status='under_investigation',execution_backend='NCP unprivileged PRoot in a separate network namespace with resource limits',
        interpretation='Graph facts and rules bound the result. No derived path is not proof of non-impact; semantic gaps remain unknown.')
    atomic_json(folder/'result.json',outcome)
    return outcome


def install():
    from src.item4.analysis import analysis_tool_runner as operational_tool_runner
    operational_tool_runner.run_mulval=run_mulval


if __name__=='__main__':
    if sys.argv[1]=='exec':
        # Namespace root maps only to the existing unprivileged Notebook user.
        os.environ['ICS_VEX_PARENT_NETNS']=str(os.stat('/proc/self/ns/net').st_ino)
        os.execvp('unshare',['unshare','--user','--map-root-user','--net',sys.executable,str(Path(__file__)),
                            'exec-inner',*sys.argv[2:]])
    elif sys.argv[1]=='exec-inner':exec_tool(sys.argv[2],sys.argv[3:])
