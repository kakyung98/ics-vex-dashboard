#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VEX-v2 · step 3 — controllability, decided by Z3 (not by the LLM).

Q4: can an adversary drive the vulnerable state? The LLM only *formalises* the CTI
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
    ast.Mult: lambda l, r: l * r, ast.Mod: lambda l, r: l % r,
    ast.Div: lambda l, r: l / r, ast.FloorDiv: lambda l, r: l / r,
    # Bitwise only type-checks over bit-vectors, so a trigger using these is
    # solved in bv mode from the start - see _needs_bv.
    ast.BitAnd: lambda l, r: l & r, ast.BitOr: lambda l, r: l | r,
    ast.BitXor: lambda l, r: l ^ r,
    ast.LShift: lambda l, r: l << r, ast.RShift: lambda l, r: l >> r,
}

# Operators z3 rejects on Int: the trigger has to be solved over bit-vectors.
_BITWISE = (ast.BitAnd, ast.BitOr, ast.BitXor, ast.LShift, ast.RShift, ast.Invert)


def _needs_bv(tree):
    """True when the predicate uses a bitwise operator.

    `parser_flags & 0x0008` is a perfectly ordinary flag test, but z3's Int sort
    has no `&`, so translating it raises and the whole CVE used to come back
    `unparseable trigger`. Bit-vectors have the operator, so these triggers go
    straight to bv mode instead of trying Int first."""
    return any(isinstance(n, _BITWISE)
               or (isinstance(n, ast.BinOp) and isinstance(n.op, _BITWISE))
               for n in ast.walk(tree))


def _const_int(node):
    """The literal int a node folds to, or None if it is not a pure literal."""
    try:
        v = ast.literal_eval(node)
    except Exception:
        return None
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _dotted(node):
    """`sqlite.max_length` -> "sqlite.max_length", for an Attribute chain.

    The LLM sometimes writes a qualified name where it declared a flat one; a
    dotted atom keeps the two distinguishable instead of failing to parse."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _inline_model_refs(trigger, model):
    """Replace `environment_fixed['k']` in the trigger with the value declared for k.

    The LLM occasionally refers to its own environment table from inside the
    predicate instead of naming the variable. That is a reference to a value the
    model already states, so it is substituted rather than treated as an opaque
    subscript - otherwise the trigger is unparseable and the CVE scores no
    verdict at all."""
    env = (model or {}).get("environment_fixed") or {}
    for k, v in env.items():
        for q in ("'", '"'):
            trigger = trigger.replace("environment_fixed[%s%s%s]" % (q, k, q), repr(v))
    return trigger


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
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Invert):
        return ~_to_z3(node.operand, env, owner, bv)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow):
        # `2**32 - 1` is a bound, not a computation: fold it. A symbolic exponent
        # is left opaque rather than handed to z3, which has no BitVec power.
        l, r = _const_int(node.left), _const_int(node.right)
        if l is not None and r is not None and 0 <= r <= 64:
            v = l ** r
            return z3.BitVecVal(v, _BV) if bv else v
        return _fresh(env, owner, "int", bv)
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_to_z3(node.left, env, owner, bv), _to_z3(node.right, env, owner, bv))
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        op = type(node.ops[0])
        if op in (ast.In, ast.NotIn):
            return _fresh(env, owner, "bool", bv)       # membership is opaque
        return _OPS[op](_to_z3(node.left, env, owner, bv), _to_z3(node.comparators[0], env, owner, bv))
    if isinstance(node, ast.Attribute):
        nm = _dotted(node)
        if nm:
            if nm not in env:
                env[nm] = z3.BitVec(nm, _BV) if bv else z3.Int(nm)
                owner.setdefault(nm, "attacker")
            return env[nm]
        return _fresh(env, owner, "int", bv)
    if isinstance(node, ast.Subscript):
        # A model reference was already inlined by _inline_model_refs; anything
        # left is an index into attacker data (`buf[i]`), which is opaque.
        return _fresh(env, owner, "int", bv)
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


def _solve(model, trigger, bv, pin_env=True):
    """z3 check result for the trigger over the given numeric domain (raises on parse).

    bv=False uses unbounded Int; bv=True uses _BV-bit vectors (wrapping arithmetic).
    pin_env=False drops the environment defaults, which is how decide() tells a
    structural refutation apart from one the LLM's own numbers created."""
    vs = (model or {}).get("variables") or []
    env = {v["name"]: _mk_var(v, bv) for v in vs if v.get("name")}
    owner = {v["name"]: (v.get("owner") or "attacker") for v in vs if v.get("name")}
    expr = _as_bool(_to_z3(ast.parse(trigger, mode="eval"), env, owner, bv))
    s = z3.Solver()
    s.add(expr)
    # pin environment variables the attacker cannot change to their default values
    for name, val in ((model.get("environment_fixed") or {}) if pin_env else {}).items():
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
    trigger = _inline_model_refs(_normalize(trigger), model)
    try:
        bitwise = _needs_bv(ast.parse(trigger, mode="eval"))
    except Exception as e:
        return "unknown", "unparseable trigger: %s" % e
    bv_first = bitwise
    try:
        r = _solve(model, trigger, bv=bitwise)
    except Exception as e:
        return "unknown", "unparseable trigger: %s" % e
    if r == z3.sat:
        return "controllable", ("attacker inputs satisfy the trigger under env defaults"
                                + (" (bit-vector domain)" if bitwise else ""))
    if r == z3.unsat:
        # Unbounded Int can't see wraparound, so an overflow-driven trigger (CWE-190)
        # comes out UNSAT here. Retry over fixed-width bit-vectors before asserting
        # not-controllable, so a real overflow isn't mislabelled not_affected.
        try:
            if _solve(model, trigger, bv=True) == z3.sat:
                return "controllable", "attacker inputs satisfy the trigger via %d-bit integer overflow" % _BV
        except Exception:
            pass
        # UNSAT is not yet a refutation. The pinned environment values are the LLM's
        # guesses at defaults, and measurement over this corpus found that 9 of 10
        # refutations disappeared once the pins were dropped - the LLM had written an
        # `environment_fixed` value its own trigger contradicts (`max_recursion_depth
        # < 100` pinned to exactly 100; `table_info == 0` pinned to 1). A verdict that
        # rests on an unverifiable number is reported as such instead of being quoted
        # as "the attacker cannot reach this".
        pins = {k: v for k, v in (model.get("environment_fixed") or {}).items()
                if any(vv.get("name") == k and vv.get("owner") == "environment"
                       for vv in (model.get("variables") or []))}
        if pins:
            for dom in (bv_first, not bv_first):
                try:
                    if _solve(model, trigger, bv=dom, pin_env=False) == z3.sat:
                        return ("environment-dependent",
                                "trigger is satisfiable, and unsatisfiable only once the "
                                "model's environment defaults are pinned (%s); those "
                                "defaults are LLM-asserted and unverified, so this is "
                                "not a refutation"
                                % ", ".join("%s=%s" % kv for kv in sorted(pins.items())))
                except Exception:
                    pass
        return ("unknown",
                "trigger unsatisfiable with the environment unpinned: the constraint "
                "model contradicts itself, so it carries no verdict")
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
    ap.add_argument("--redecide", action="store_true",
                    help="re-run the solver over the models already in "
                         "data/controllability.json and report every verdict that "
                         "moves. Use after a change to decide()/_to_z3: the LLM is "
                         "not called, so the constraint models stay byte-identical "
                         "and the diff isolates the solver change")
    a = ap.parse_args()

    if a.redecide:
        out = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}
        moved = []
        for cve in sorted(out):
            rec = out[cve]
            old = rec.get("verdict")
            verdict, detail = decide(rec.get("model"))
            if verdict != old:
                moved.append((cve, old, verdict, detail))
            rec["verdict"], rec["detail"] = verdict, detail
        json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print("  re-decided %d stored models; %d verdicts moved" % (len(out), len(moved)))
        for cve, old, new, detail in moved:
            print("    %-18s %-16s -> %-16s %s" % (cve, old, new, detail))
        print("-> %s (%d)" % (OUT, len(out)))
        return

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
