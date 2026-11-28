"""Shared corpus display names and legacy exposure defaults."""
import hashlib

EXPOSURES = ["isolated-cell", "control-network", "dmz-routable", "remote-accessible"]

CWE_NAME = {
    "CWE-78": "OS command injection", "CWE-79": "cross-site scripting", "CWE-89": "SQL injection",
    "CWE-119": "memory buffer error", "CWE-120": "buffer copy without size check",
    "CWE-121": "stack-based buffer overflow", "CWE-122": "heap-based buffer overflow",
    "CWE-125": "out-of-bounds read", "CWE-190": "integer overflow", "CWE-200": "information exposure",
    "CWE-269": "improper privilege management", "CWE-287": "improper authentication",
    "CWE-295": "improper certificate validation", "CWE-306": "missing authentication",
    "CWE-311": "missing encryption", "CWE-327": "broken crypto algorithm",
    "CWE-352": "cross-site request forgery", "CWE-362": "race condition",
    "CWE-400": "uncontrolled resource consumption", "CWE-401": "memory leak",
    "CWE-416": "use after free", "CWE-434": "unrestricted file upload",
    "CWE-476": "null pointer dereference", "CWE-502": "deserialization of untrusted data",
    "CWE-787": "out-of-bounds write", "CWE-798": "hard-coded credentials",
    "CWE-862": "missing authorization", "CWE-863": "incorrect authorization",
}

def h(*p):
    return int(hashlib.sha256("::".join(map(str, p)).encode()).hexdigest(), 16)

def exposure_for(device):
    """Deployment exposure. Synthesised, because real plant-network information is not
    in public data. Sampled deterministically (by a hash of the device) from a prior
    distribution per device class."""
    d = device.lower()
    if any(k in d for k in ("plc", "rtu", "relay", "controller", "safety", "ied", "drive")):
        w = [0.42, 0.34, 0.16, 0.08]
    elif any(k in d for k in ("gateway", "firewall", "router", "switch", "vpn", "remote")):
        w = [0.05, 0.20, 0.40, 0.35]
    elif any(k in d for k in ("scada", "hmi", "historian", "server", "workstation", "engineering")):
        w = [0.10, 0.34, 0.34, 0.22]
    else:
        w = [0.25, 0.30, 0.28, 0.17]
    r = (h("exp", device) % 1000) / 1000.0
    acc = 0.0
    for e, wi in zip(EXPOSURES, w):
        acc += wi
        if r <= acc:
            return e
    return EXPOSURES[-1]
