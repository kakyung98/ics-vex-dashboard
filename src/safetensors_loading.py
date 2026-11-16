"""Scoped streaming reads for Windows model loading without mmap tensor slices."""
from contextlib import contextmanager
from threading import RLock

_LOCK=RLock()

@contextmanager
def pread_weights(enabled):
    if not enabled:
        yield
        return
    import transformers.modeling_utils as modeling
    # Transformers exposes mmap/eager loading but does not expose its pread
    # backend selection for CPU. Scope this substitution to weight loading.
    with _LOCK:
        original=modeling.safe_open
        def streaming(*args,**kwargs):
            kwargs['backend']='pread'
            return original(*args,**kwargs)
        modeling.safe_open=streaming
        try:yield
        finally:modeling.safe_open=original
