"""Progress files tolerate Windows readers and short-lived scanner locks."""
import json
import os
from pathlib import Path
import time


def atomic_json(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+f'.{os.getpid()}.tmp')
    tmp.write_text(json.dumps(value,indent=2,ensure_ascii=False),encoding='utf-8')
    for attempt in range(40):
        try:tmp.replace(path);return
        except PermissionError:
            if attempt==39:raise
            time.sleep(.05)


def read_json(path,default=None):
    """Read with FILE_SHARE_DELETE, so atomic writers can replace a live file."""
    path=Path(path)
    try:
        if os.name!='nt':return json.loads(path.read_text(encoding='utf-8'))
        import ctypes,msvcrt
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.CreateFileW.argtypes=[ctypes.c_wchar_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p]
        kernel.CreateFileW.restype=ctypes.c_void_p
        handle=kernel.CreateFileW(str(path.resolve()),0x80000000,7,None,3,0x80,None)
        if handle==ctypes.c_void_p(-1).value:raise OSError(ctypes.get_last_error(),'Cannot open progress file')
        fd=msvcrt.open_osfhandle(handle,os.O_RDONLY)
        with os.fdopen(fd,'r',encoding='utf-8') as f:return json.load(f)
    except (OSError,ValueError):return {} if default is None else default
