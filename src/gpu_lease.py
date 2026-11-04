"""One local training queue owns GPU admission; stale PID leases expire safely."""
from pathlib import Path
import os
from src.training_io import read_json
FILE=Path(__file__).resolve().parents[1]/'results/operational_role_finetune_v2/gpu_lease.json'

def alive(pid):
    if not isinstance(pid,int) or pid<=0:return False
    if os.name!='nt':
        try:os.kill(pid,0);return True
        except OSError:return False
    import ctypes
    k=ctypes.WinDLL('kernel32',use_last_error=True)
    k.OpenProcess.argtypes=[ctypes.c_uint32,ctypes.c_int,ctypes.c_uint32];k.OpenProcess.restype=ctypes.c_void_p
    k.GetExitCodeProcess.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint32)]
    k.CloseHandle.argtypes=[ctypes.c_void_p]
    handle=k.OpenProcess(0x1000,False,pid)
    if not handle:return False
    code=ctypes.c_uint32()
    try:return bool(k.GetExitCodeProcess(handle,ctypes.byref(code))) and code.value==259
    finally:k.CloseHandle(handle)

def assert_inference_available():
    lease=read_json(FILE)
    # A queued research worker can own admission for its own inference process.
    # Other processes, including the web service, remain excluded while it runs.
    if lease.get('active') and os.getpid() in {lease.get('pid'),lease.get('child_pid')}:
        return
    if lease.get('active') and (alive(lease.get('pid')) or alive(lease.get('child_pid'))):
        raise RuntimeError('Local GPU is reserved for queued training or research work. Model inference is temporarily unavailable; corpus browsing remains available.')
