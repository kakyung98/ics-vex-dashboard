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

import z3

from cti_extract import _ollama  # shared Ollama client

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CTI = os.path.join(BASE, "data", "cti_extractions.json")
LOC = os.path.join(BASE, "data", "source_locations.json")
REACH = os.path.join(BASE, "data", "reachability.json")
OUT = os.path.join(BASE, "data", "controllability.json")

_SYS = (
    "You formalise a vulnerability's controllability as a small constraint system, "
    "for an SMT solver to decide - you never decide it yourself. Output ONLY JSON: "
    '{"variables":[{"name":str,"type":"int|real|bool","owner":"attacker|environment"}],'
    '"trigger":"a Python boolean expression over the variable names that must hold for '
    'the vulnerable state to be driven","environment_fixed":{"var":value}}. Put in '
    "environment_fixed only values the attacker cannot change (config/build defaults). "
    "Use only names you declared. If you cannot model it, output {\"variables\":[],"
    '"trigger":"","environment_fixed":{}}.'
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


def _mk_var(v):
    t = v.get("type")
    if t == "bool":
        return z3.Bool(v["name"])
    if t == "real":
        return z3.Real(v["name"])
    return z3.Int(v["name"])


def _to_z3(node, env):
    """Whitelisted Python-AST -> Z3 expression. Raises on anything unexpected."""
    if isinstance(node, ast.Expression):
        return _to_z3(node.body, env)
    if isinstance(node, ast.BoolOp):
        return _OPS[type(node.op)]([_to_z3(v, env) for v in node.values])
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _OPS[ast.Not]([_to_z3(node.operand, env)])
    if isinstance(node, ast.BinOp):
        return _OPS[type(node.op)](_to_z3(node.left, env), _to_z3(node.right, env))
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        return _OPS[type(node.ops[0])](_to_z3(node.left, env), _to_z3(node.comparators[0], env))
    if isinstance(node, ast.Name):
        if node.id in env:
            return env[node.id]
        if node.id in ("True", "False"):
            return z3.BoolVal(node.id == "True")
        raise ValueError("undeclared name %r" % node.id)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return z3.BoolVal(node.value)
        if isinstance(node.value, (int, float)):
            return node.value
        raise ValueError("unsupported constant")
    raise ValueError("unsupported node %s" % type(node).__name__)


def decide(model):
    """(verdict, detail) from a formalised constraint model, using Z3."""
    trigger = (model or {}).get("trigger") or ""
    vs = (model or {}).get("variables") or []
    if not trigger or not vs:
        return "unknown", "no formal model produced"
    env = {v["name"]: _mk_var(v) for v in vs if v.get("name")}
    try:
        expr = _to_z3(ast.parse(trigger, mode="eval"), env)
    except Exception as e:
        return "unknown", "unparseable trigger: %s" % e
    s = z3.Solver()
    s.add(expr)
    # pin environment variables the attacker cannot change to their default values
    owner = {v["name"]: v.get("owner") for v in vs}
    for name, val in (model.get("environment_fixed") or {}).items():
        if name in env and owner.get(name) == "environment":
            s.add(env[name] == val)
    r = s.check()
    if r == z3.sat:
        return "controllable", "attacker inputs satisfy the trigger under env defaults"
    if r == z3.unsat:
        return "not-controllable", "trigger requires an environment value the attacker cannot set"
    return "unknown", "z3 returned unknown"


def formalize(cve, extraction):
    c = (extraction or {}).get("controllability") or {}
    prompt = (
        "CVE: %s\nComponent: %s\nAttacker-controlled inputs: %s\nConstraints: %s\n"
        "Trigger conditions: %s\n\nFormalise the controllability as the JSON schema."
        % (cve, (extraction or {}).get("vulnerable_component", ""),
           c.get("attacker_inputs"), c.get("constraints"),
           ((extraction or {}).get("reachability") or {}).get("trigger_conditions"))
    )
    try:
        raw = _ollama([{"role": "system", "content": _SYS},
                       {"role": "user", "content": prompt}])
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
