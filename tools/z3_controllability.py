#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VEX-v2 · step 3 — controllability, decided by Z3 (not by the LLM).

Q3: can an adversary drive the vulnerable state? The LLM only *formalises* the CTI
controllability into a small constraint system - variables tagged by who controls
them (attacker vs environment) and a trigger predicate. Z3 then DECIDES:

  controllable  = SAT( trigger  AND  environment fixed at its defaults )
                  i.e. the attacker can choose inputs that satisfy the trigger even
                  when the environment sits at values the attacker cannot change.
  not-controllable = UNSAT under those environment defaults -> the trigger needs an
                  environment/config value the adversary cannot set
                  -> not_affected / vulnerable_code_cannot_be_controlled_by_adversary
  unknown       = the LLM could not produce a well-formed model (-> under_investigation)

The verdict is a solver result over the LLM's formalisation, so it is only as sound
as that formalisation - it is a decision procedure, not a proof of the real program.

Out: data/controllability.json  { <CVE>: {...} }
"""
import argparse
import ast
import json
import os
import re

import z3

from cti_extract import _ollama  # shared Ollama client

# Formalising a CVE into an SMT constraint system is natural-language reasoning, not
# code generation: the coder-tuned model returns `{}` for thin CTI, while the general
# model produces a real trigger. Use the general model here (the coder model still
# extracts CTI upstream). This alone recovers the 14 "no formal model" unknowns.
FORMALIZE_MODEL = "qwen2.5:14b"

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CTI = os.path.join(BASE, "data", "cti_extractions.json")
LOC = os.path.join(BASE, "data", "source_locations.json")
REACH = os.path.join(BASE, "data", "reachability.json")
OUT = os.path.join(BASE, "data", "controllability.json")

_SYS = (
    "You formalise a vulnerability's controllability as a small constraint system for "
    "an SMT solver to decide - you never decide it yourself. Output ONLY JSON: "
    '{"variables":[{"name":str,"type":"int|bool","owner":"attacker|environment"}],'
    '"trigger":"a Python boolean expression that must hold for the vulnerable state to '
    'be driven","environment_fixed":{"var":value}}. Almost every memory/parsing/logic '
    "flaw IS driven by attacker input, so produce a NON-EMPTY trigger: model the crafted "
    "input or its properties as attacker-owned variables and write the condition over "
    "them (e.g. a malformed length, a crafted byte, a flag the attacker sets). Represent "
    "quantities as integers; use Python operators only (and, or, not, <, <=, ==, !=). Put "
    "in environment_fixed only values the attacker cannot change (config/build defaults) - "
    "that is what makes something NOT controllable. Return an empty trigger ONLY if the "
    "flaw genuinely cannot be reached by any attacker-influenced input."
)

_OPS = {
    ast.And: lambda a: z3.And(*a), ast.Or: lambda a: z3.Or(*a),
    ast.Not: lambda a: z3.Not(a[0]),
    ast.Gt: lambda l, r: l > r, ast.GtE: lambda l, r: l >= r,
    ast.Lt: lambda l, r: l < r, ast.LtE: lambda l, r: l <= r,
    ast.Eq: lambda l, r: l == r, ast.NotEq: lambda l, r: l != r,
    ast.Add: lambda l, r: l + r, ast.Sub: lambda l, r: l - r,
    ast.Mult: lambda l, r: l * r,
}


_BV = 32   # bit-width for the overflow-aware (bit-vector) re-check


def _mk_var(v, bv=False):
    t = v.get("type")
    if t == "bool":
        return z3.Bool(v["name"])
    if bv:
        return z3.BitVec(v["name"], _BV)      # wrapping arithmetic -> models overflow
    if t == "real":
        return z3.Real(v["name"])
    return z3.Int(v["name"])


def _normalize(t):
    """LLMs mix C-style operators into the trigger; make it valid Python."""
    t = t.replace("&&", " and ").replace("||", " or ")
    return re.sub(r"!(?!=)", " not ", t)     # logical not, but keep !=


_STR2INT = {}


def _str_const(s):
    """A string literal -> a distinct symbolic integer, so `x == 'foo'` is decidable."""
    if s not in _STR2INT:
        _STR2INT[s] = len(_STR2INT) + 1
    return _STR2INT[s]


def _as_bool(e):
    """Coerce an expression to a Z3 Bool (an int in a boolean position means != 0)."""
    if isinstance(e, bool):
        return z3.BoolVal(e)
    if isinstance(e, (int, float)):
        return z3.BoolVal(e != 0)
    if z3.is_bool(e):
        return e
    return e != 0


_FRESH = [0]


def _fresh(env, owner, kind, bv=False):
    """A fresh symbolic variable for an opaque atom (function call, membership)."""
    _FRESH[0] += 1
    nm = "_f%d" % _FRESH[0]
    if kind == "bool":
        env[nm] = z3.Bool(nm)
    else:
        env[nm] = z3.BitVec(nm, _BV) if bv else z3.Int(nm)
    owner[nm] = "attacker"
    return env[nm]


def _to_z3(node, env, owner, bv=False):
    """Python-AST -> Z3. Permissive: an undeclared name / string / call / membership
    becomes a fresh symbolic (attacker-owned) atom rather than a parse failure, so a
    well-formed predicate is decidable even when the LLM did not declare every term.
    With bv=True, numeric atoms are fixed-width bit-vectors so overflow is modelled."""
    if isinstance(node, ast.Expression):
        return _to_z3(node.body, env, owner, bv)
    if isinstance(node, ast.BoolOp):
        return _OPS[type(node.op)]([_as_bool(_to_z3(v, env, owner, bv)) for v in node.values])
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return z3.Not(_as_bool(_to_z3(node.operand, env, owner, bv)))
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -_to_z3(node.operand, env, owner, bv)
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_to_z3(node.left, env, owner, bv), _to_z3(node.right, env, owner, bv))
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        op = type(node.ops[0])
        if op in (ast.In, ast.NotIn):
            return _fresh(env, owner, "bool", bv)       # membership is opaque
        return _OPS[op](_to_z3(node.left, env, owner, bv), _to_z3(node.comparators[0], env, owner, bv))
    if isinstance(node, ast.Name):
        if node.id in ("True", "False"):
            return z3.BoolVal(node.id == "True")
        if node.id not in env:
            env[node.id] = z3.BitVec(node.id, _BV) if bv else z3.Int(node.id)   # auto-declare
            owner.setdefault(node.id, "attacker")
        return env[node.id]
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return z3.BoolVal(node.value)
        if isinstance(node.value, (int, float)):
            return z3.BitVecVal(int(node.value), _BV) if bv else node.value
        if isinstance(node.value, str):
            return _str_const(node.value)
        raise ValueError("unsupported constant")
    if isinstance(node, ast.Call):
        return _fresh(env, owner, "int", bv)            # opaque function result
    raise ValueError("unsupported node %s" % type(node).__name__)


def _solve(model, trigger, bv):
    """z3 check result for the trigger over the given numeric domain (raises on parse).

    bv=False uses unbounded Int; bv=True uses _BV-bit vectors (wrapping arithmetic)."""
    vs = (model or {}).get("variables") or []
    env = {v["name"]: _mk_var(v, bv) for v in vs if v.get("name")}
    owner = {v["name"]: (v.get("owner") or "attacker") for v in vs if v.get("name")}
    expr = _as_bool(_to_z3(ast.parse(trigger, mode="eval"), env, owner, bv))
    s = z3.Solver()
    s.add(expr)
    # pin environment variables the attacker cannot change to their default values
    for name, val in (model.get("environment_fixed") or {}).items():
        if name in env and owner.get(name) == "environment":
            try:
                s.add(env[name] == val)
            except Exception:
                pass
    return s.check()


def decide(model):
    """(verdict, detail) from a formalised constraint model, using Z3.

    Only a genuinely empty trigger is 'no model'; declared variables are optional
    because _to_z3 auto-declares any term the LLM named in the predicate."""
    trigger = (model or {}).get("trigger") or ""
    if not trigger.strip():
        return "unknown", "no formal model produced"
    trigger = _normalize(trigger)
    try:
        r = _solve(model, trigger, bv=False)
    except Exception as e:
        return "unknown", "unparseable trigger: %s" % e
    if r == z3.sat:
        return "controllable", "attacker inputs satisfy the trigger under env defaults"
    if r == z3.unsat:
        # Unbounded Int can't see wraparound, so an overflow-driven trigger (CWE-190)
        # comes out UNSAT here. Retry over fixed-width bit-vectors before asserting
        # not-controllable, so a real overflow isn't mislabelled not_affected.
        try:
            if _solve(model, trigger, bv=True) == z3.sat:
                return "controllable", "attacker inputs satisfy the trigger via %d-bit integer overflow" % _BV
        except Exception:
            pass
        return "not-controllable", "trigger unsatisfiable even under integer overflow; needs an environment value the attacker cannot set"
    return "unknown", "z3 returned unknown"


_DESC = None


def _description(cve):
    """(description, cwe) from the NVD cache, for richer formalisation context."""
    global _DESC
    if _DESC is None:
        try:
            _DESC = json.load(open(os.path.join(BASE, "data", "nvd_cache.json"),
                                   encoding="utf-8"))
        except Exception:
            _DESC = {}
    e = _DESC.get(cve) or {}
    return (e.get("description") or "", ", ".join(e.get("cwes") or []))


def formalize(cve, extraction):
    c = (extraction or {}).get("controllability") or {}
    desc, cwe = _description(cve)
    prompt = (
        "CVE: %s (%s)\nDescription: %s\n\nComponent: %s\nAttacker-controlled inputs: %s\n"
        "Constraints: %s\nTrigger conditions: %s\n\nFrom the description, work out what "
        "input or condition an attacker controls to reach the flaw, and formalise the "
        "controllability as the JSON schema with a NON-EMPTY trigger."
        % (cve, cwe, desc, (extraction or {}).get("vulnerable_component", ""),
           c.get("attacker_inputs"), c.get("constraints"),
           ((extraction or {}).get("reachability") or {}).get("trigger_conditions"))
    )
    try:
        raw = _ollama([{"role": "system", "content": _SYS},
                       {"role": "user", "content": prompt}], FORMALIZE_MODEL)
        return json.loads(raw)
    except Exception as e:
        return {"variables": [], "trigger": "", "environment_fixed": {},
                "error": "%s: %s" % (type(e).__name__, e)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cve")
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()

    cti = json.load(open(CTI, encoding="utf-8")) if os.path.exists(CTI) else {}
    loc = json.load(open(LOC, encoding="utf-8")) if os.path.exists(LOC) else {}
    reach = json.load(open(REACH, encoding="utf-8")) if os.path.exists(REACH) else {}
    if a.cve:
        cves = [a.cve]
    elif a.all:
        # VEX flow: reachability (Joern) is the earlier gate, so controllability only
        # matters where the code is reachable. Skip the rest - they are already decided.
        if reach:
            cves = sorted(c for c in loc if reach.get(c, {}).get("verdict") == "reachable")
            print("  gating on reachability: %d reachable of %d located" % (len(cves), len(loc)))
        else:
            cves = sorted(loc)
            print("  note: no reachability.json yet - run joern_reachability first; processing all")
    else:
        ap.error("pass --cve CVE-XXXX or --all")

    out = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}
    for i, cve in enumerate(cves, 1):
        if not a.cve and cve in out:                 # resume: skip already-decided
            continue
        model = formalize(cve, cti.get(cve))
        verdict, detail = decide(model)
        out[cve] = {"cve": cve, "verdict": verdict, "detail": detail, "model": model}
        print("  [%3d/%3d] %-18s controllability=%-16s  %s" % (i, len(cves), cve, verdict, detail), flush=True)
        if a.cve:
            print(json.dumps(out[cve], ensure_ascii=False, indent=2))
        json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)  # incremental
    print("-> %s (%d)" % (OUT, len(out)))


if __name__ == "__main__":
    main()
