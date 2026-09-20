#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VEX-v2 · step 1 — LLM agent: structured extraction from a CVE's CTI.

Replaces the old vulnerable-function localisation (tools/locate_vuln_funcs.py,
extract_vuln_funcs.py) with an agent that reads the public threat intel and emits
exactly the facts the downstream engines need:

  - the vulnerable COMPONENT and FUNCTION(S)          -> source search (step 2)
  - what must hold for the vuln to be REACHED         -> Joern reachability (step 4)
  - what an adversary must CONTROL to trigger it      -> Z3 controllability (step 3)

CTI in  = NVD description + CWE + reference URLs (data/nvd_cache.json).
Model   = Ollama qwen2.5-coder:14b (local, $0).
Out     = data/cti_extractions.json  { <CVE>: { ...schema... } }

Usage:
  python tools/cti_extract.py --cve CVE-2018-25032        # one, prints result
  python tools/cti_extract.py --all                       # all snapshot CVEs
"""
import argparse
import json
import os
import urllib.request

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CTI = os.path.join(BASE, "data", "nvd_cache.json")
SNAP = os.path.join(BASE, "data", "source_snapshots")
OUT = os.path.join(BASE, "data", "cti_extractions.json")
OLLAMA = "http://localhost:11434/api/chat"
MODEL = "qwen2.5-coder:14b"

SCHEMA_HINT = {
    "vulnerable_component": "string - the software/library the flaw is in, lowercase (e.g. zlib, openssl, spring-framework)",
    "vulnerable_functions": ["string - function/method names the CTI names or clearly implies; [] if none named"],
    "reachability": {
        "entry_points": ["string - public API / externally-callable functions that reach the vulnerable code"],
        "trigger_conditions": "string - what configuration, input shape or state must hold for the vulnerable path to execute",
    },
    "controllability": {
        "attacker_inputs": ["string - the inputs / parameters an adversary supplies or influences"],
        "constraints": "string - what the attacker must satisfy (values, encodings, preconditions) to drive the vulnerable state",
    },
    "cwe": "string - the primary CWE id",
    "confidence": "high | medium | low - how directly the CTI supports the above",
}

SYSTEM = (
    "You are a vulnerability-analysis agent. From a CVE's threat intelligence you "
    "extract, as strict JSON, only what is stated or directly implied - never invent "
    "function names or entry points that the text does not support. If something is "
    "unknown, use an empty list or empty string and lower the confidence. Output ONLY "
    "the JSON object, matching the given schema keys exactly."
)


def _ollama(messages, model=MODEL):
    body = json.dumps({"model": model, "messages": messages, "stream": False,
                       "format": "json", "options": {"temperature": 0}}).encode()
    req = urllib.request.Request(OLLAMA, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.load(r)["message"]["content"]


def extract(cve, cti, model=MODEL):
    """Structured extraction for one CVE. Returns the parsed dict (or {'error':...})."""
    refs = "\n".join("- " + u for u in (cti.get("references") or [])[:8])
    prompt = (
        "CVE: %s\nCWE: %s\n\nDescription:\n%s\n\nReferences:\n%s\n\n"
        "Extract this JSON (keys exactly as shown; values are your findings):\n%s"
        % (cve, ", ".join(cti.get("cwes") or []) or "unknown",
           cti.get("description") or "(none)", refs or "(none)",
           json.dumps(SCHEMA_HINT, ensure_ascii=False, indent=2))
    )
    try:
        raw = _ollama([{"role": "system", "content": SYSTEM},
                       {"role": "user", "content": prompt}], model)
        out = json.loads(raw)
        out["cve"] = cve
        return out
    except Exception as e:
        return {"cve": cve, "error": "%s: %s" % (type(e).__name__, e)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cve")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--model", default=MODEL)
    a = ap.parse_args()

    cti = json.load(open(CTI, encoding="utf-8"))
    if a.cve:
        cves = [a.cve]
    elif a.all:
        cves = sorted(c for c in os.listdir(SNAP) if c in cti)
    else:
        ap.error("pass --cve CVE-XXXX or --all")

    done = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}
    for i, cve in enumerate(cves, 1):
        if cve not in cti:
            print("  no CTI for %s - skip" % cve)
            continue
        if not a.cve and cve in done and "error" not in done[cve]:  # resume
            continue
        res = extract(cve, cti[cve], a.model)
        done[cve] = res
        if a.cve:
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            comp = res.get("vulnerable_component", "?")
            fns = res.get("vulnerable_functions") or []
            print("  [%3d/%3d] %-18s comp=%-16s funcs=%s conf=%s"
                  % (i, len(cves), cve, comp, fns[:3], res.get("confidence", "?")))
        json.dump(done, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("-> %s (%d extractions)" % (OUT, len(done)))


if __name__ == "__main__":
    main()
