#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Live inference wrappers for the three ICS-VEX models (STATIC-ANALYSIS mode).

  SecureBertVex       context leg   -> VEX status + rationale   (SecureBERT + VexModel)
  CodeBertRefMatch    code leg      -> vuln vs patched diff match (CodeBERT, static)
  SllmStaticAnalyst   analyst+critic-> static exploitability + VEX adjudication
                                       (Qwen2.5-Coder-7B + LoRA)

Redesign note (2026-08): the sLLM no longer generates or runs proof-of-concept
exploit code. It is a *static* vulnerability analyst — it reasons over the CVE
knowledge base (description, CWE, patch diff, reachability signals) to produce a
structured exploitability assessment and a grounded VEX verdict, WITHOUT emitting
runnable exploits and WITHOUT any execution/sandbox step. `SllmPoc.gen_poc` is
kept only as a hard-stop shim that points here.

Loaded lazily so callers pay only for the stage they use. Run this file directly
for a self-test of all three.
"""
import os, sys
import numpy as np
import torch

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SECUREBERT = "ehsanaghaei/SecureBERT"
CODEBERT = "microsoft/codebert-base"
QWEN_BASE = "Qwen/Qwen2.5-Coder-7B-Instruct"
LORA_ADAPTER = os.path.join(BASE, "models", "poc-sllm-lora")
VEX_MODEL_PT = os.path.join(BASE, "models", "vex-model", "vexmodel.pt")

LABELS = ["LIKELY_AFFECTED", "LIKELY_NOT_AFFECTED", "UNDER_INVESTIGATION"]


# ===========================================================================
# 1) SecureBERT context leg
# ===========================================================================
class SecureBertVex:
    def __init__(self):
        from transformers import AutoTokenizer, AutoModel
        import train_eval_vex as T
        self.tok = AutoTokenizer.from_pretrained(SECUREBERT)
        self.enc = AutoModel.from_pretrained(SECUREBERT).to(DEVICE).eval()
        ckpt = torch.load(VEX_MODEL_PT, map_location=DEVICE)
        self.max_k = ckpt["max_k"]
        self.labels = ckpt.get("labels", LABELS)
        self.model = T.VexModel(ckpt["dim"]).to(DEVICE)
        self.model.load_state_dict(ckpt["state_dict"])
        self.model.eval()

    @torch.no_grad()
    def _embed(self, texts):
        enc = self.tok(texts, padding=True, truncation=True, max_length=64,
                       return_tensors="pt").to(DEVICE)
        out = self.enc(**enc).last_hidden_state
        m = enc["attention_mask"].unsqueeze(-1).float()
        return (out * m).sum(1) / m.sum(1).clamp(min=1e-6)   # [N,768] masked mean

    @torch.no_grad()
    def predict(self, sentences):
        """sentences: [{"id","text","kind"?}]. Returns dict with label/conf/probs/rationale."""
        sents = sentences[: self.max_k]
        emb = self._embed([s["text"] for s in sents]).cpu().numpy()
        X = np.zeros((1, self.max_k, emb.shape[1]), np.float32)
        M = np.zeros((1, self.max_k), np.float32)
        for j, v in enumerate(emb):
            X[0, j] = v; M[0, j] = 1.0
        Xt, Mt = torch.tensor(X).to(DEVICE), torch.tensor(M).to(DEVICE)
        logits, rat, att = self.model(Xt, Mt)
        probs = torch.softmax(logits, 1)[0].cpu().numpy()
        rat_p = torch.sigmoid(rat)[0].cpu().numpy()
        pred_i = int(probs.argmax())
        rationale = [sents[j]["id"] for j in range(len(sents)) if rat_p[j] >= 0.5]
        return {
            "label": self.labels[pred_i],
            "confidence": float(probs[pred_i]),
            "probs": {self.labels[k]: float(probs[k]) for k in range(len(self.labels))},
            "rationale_ids": rationale,
            "attention": [float(a) for a in att[0].cpu().numpy()[: len(sents)]],
        }


# ===========================================================================
# 2) CodeBERT code leg (reference matching)
# ===========================================================================
class CodeBertRefMatch:
    def __init__(self):
        from transformers import AutoTokenizer, AutoModel
        self.tok = AutoTokenizer.from_pretrained(CODEBERT)
        self.model = AutoModel.from_pretrained(CODEBERT).to(DEVICE).eval()

    @torch.no_grad()
    def _embed(self, texts):
        enc = self.tok(texts, padding=True, truncation=True, max_length=256,
                       return_tensors="pt").to(DEVICE)
        out = self.model(**enc).last_hidden_state
        m = enc["attention_mask"].unsqueeze(-1).float()
        e = ((out * m).sum(1) / m.sum(1).clamp(min=1e-6)).cpu().numpy()
        return e / (np.linalg.norm(e, axis=1, keepdims=True) + 1e-9)

    def match(self, deployed_code, vuln_ref, patched_ref):
        """Which reference is the deployed code closer to? -> 'vulnerable' | 'patched'."""
        e = self._embed([deployed_code, vuln_ref, patched_ref])
        sim_v = float(e[0] @ e[1]); sim_p = float(e[0] @ e[2])
        return {
            "verdict": "vulnerable" if sim_v >= sim_p else "patched",
            "sim_vulnerable": round(sim_v, 4),
            "sim_patched": round(sim_p, 4),
        }


# ===========================================================================
# 3) sLLM exploit developer (Qwen2.5-Coder-7B + LoRA)
# ===========================================================================
# --- Static analyst (developer): reason about exploitability, NEVER emit exploits.
ANALYST_SYS = (
    "You are an ICS vulnerability analyst performing STATIC exploitability analysis "
    "for a VEX (Vulnerability Exploitability eXchange) decision. You are given a CVE "
    "knowledge base (description, CWE, optional patch diff / vulnerable code, CVSS "
    "attack vector, deployment exposure, and reachability). Reason ONLY about whether "
    "the flaw could be reached and controlled by an adversary in THIS deployment.\n"
    "HARD RULES:\n"
    "- Do NOT write, and do NOT output, any proof-of-concept, exploit, payload, or "
    "runnable trigger code. This is a paper analysis only; nothing is executed.\n"
    "- Ground every claim in the supplied evidence. If the patch diff or code is "
    "absent, say so and lower your certainty accordingly.\n"
    'Respond with ONLY a JSON object: {'
    '"root_cause": "<short static description of the weakness>", '
    '"precondition": "<what must hold for the flaw to be reached>", '
    '"adversary_controllable": "yes|no|uncertain", '
    '"reachable_in_deployment": "yes|conditional|no|unknown", '
    '"exploitability": "high|medium|low|none", '
    '"rationale": "<one sentence, evidence-grounded, no exploit steps>"}.')

# --- Static critic: check the analyst's assessment is grounded (ReAct self-critique).
CRITIC_SYS = (
    "You are a skeptical static-analysis critic reviewing another analyst's VEX "
    "exploitability assessment. You see the same evidence and the analyst's JSON "
    "assessment. Detect overreach: a 'no'/'none' verdict that lacks explicit "
    "counter-evidence, a 'yes'/'high' verdict not supported by a present patch diff "
    "or a clear reachability path, or any claim the evidence does not license. "
    "Reward conservative, grounded reasoning. Never ask for or reference exploit code.\n"
    'Respond with ONLY a JSON object: {"grounded": true|false, '
    '"issues": "<what is unsupported, or none>", '
    '"suggest_status": "LIKELY_AFFECTED|LIKELY_NOT_AFFECTED|UNDER_INVESTIGATION", '
    '"feedback": "<one sentence for the analyst to refine>"}.')

# --- Final adjudicator: fuse all static signals into a VEX status. No execution.
ADJUDICATE_SYS = (
    "You are the ICS VEX adjudicator. Decide the VEX status of a CVE for a SPECIFIC "
    "deployment using ONLY the provided STATIC evidence (component presence, CVSS "
    "attack vector x deployment exposure reachability, SecureBERT context signal, "
    "CodeBERT patch-diff signal, and the static exploitability assessment + critic). "
    "There is NO execution or PoC evidence; do not assume any. Be conservative, "
    "ICS-safety first:\n"
    "- LIKELY_AFFECTED only if the vulnerable component/version is present AND the "
    "flaw is reachable in this deployment AND the static analysis (code diff or "
    "reachability) supports adversary control.\n"
    "- LIKELY_NOT_AFFECTED only with clear STATIC counter-evidence (component/"
    "vulnerable code not present, or unreachable at this exposure).\n"
    "- Otherwise UNDER_INVESTIGATION (uncertain, code present but diff inconclusive, "
    "or reachability only conditional).\n"
    'Respond with ONLY a JSON object: {"status": "<one of the three>", '
    '"justification": "<one sentence grounded in the static evidence>"}.')


def _extract_json(raw):
    import json as _json, re as _re
    m = _re.search(r"\{.*\}", raw, _re.DOTALL)
    if m:
        try:
            return _json.loads(m.group(0))
        except Exception:
            return None
    return None


def _coerce_status(val, default="UNDER_INVESTIGATION"):
    s = str(val or "").upper().replace(" ", "_")
    for lab in ("LIKELY_AFFECTED", "LIKELY_NOT_AFFECTED", "UNDER_INVESTIGATION"):
        if lab in s:
            return lab
    return default


class SllmStaticAnalyst:
    """Static VEX analyst/critic/adjudicator. No exploit generation, no execution."""

    def __init__(self, load_4bit=True):
        from transformers import AutoTokenizer, AutoModelForCausalLM
        from peft import PeftModel
        self.tok = AutoTokenizer.from_pretrained(LORA_ADAPTER)
        kw = {"torch_dtype": torch.float16, "device_map": "auto"}
        if load_4bit:
            try:
                from transformers import BitsAndBytesConfig
                kw["quantization_config"] = BitsAndBytesConfig(
                    load_in_4bit=True, bnb_4bit_compute_dtype=torch.float16,
                    bnb_4bit_quant_type="nf4")
            except Exception as e:
                print("bitsandbytes unavailable, loading fp16:", e, file=sys.stderr)
        base = AutoModelForCausalLM.from_pretrained(QWEN_BASE, **kw)
        self.model = PeftModel.from_pretrained(base, LORA_ADAPTER).eval()

    @torch.no_grad()
    def _chat(self, system, user, max_new_tokens=400):
        msgs = [{"role": "system", "content": system},
                {"role": "user", "content": user}]
        prompt = self.tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
        ids = self.tok(prompt, return_tensors="pt").to(self.model.device)
        gen = self.model.generate(**ids, max_new_tokens=max_new_tokens, do_sample=False,
                                  pad_token_id=self.tok.eos_token_id)
        return self.tok.decode(gen[0][ids["input_ids"].shape[1]:], skip_special_tokens=True).strip()

    # -- developer: static exploitability assessment (no exploit code) ----------
    def assess_exploitability(self, evidence, max_new_tokens=320):
        raw = self._chat(ANALYST_SYS, evidence, max_new_tokens)
        d = _extract_json(raw) or {}
        return {
            "root_cause": d.get("root_cause", ""),
            "precondition": d.get("precondition", ""),
            "adversary_controllable": str(d.get("adversary_controllable", "uncertain")).lower(),
            "reachable_in_deployment": str(d.get("reachable_in_deployment", "unknown")).lower(),
            "exploitability": str(d.get("exploitability", "low")).lower(),
            "rationale": d.get("rationale", raw.strip()[:280]),
            "raw": raw,
        }

    # -- critic: is the assessment grounded? (ReAct self-critique) --------------
    def critique(self, evidence, assessment, max_new_tokens=220):
        import json as _json
        user = (evidence + "\n\nAnalyst assessment (JSON):\n"
                + _json.dumps({k: v for k, v in assessment.items() if k != "raw"},
                              ensure_ascii=False))
        raw = self._chat(CRITIC_SYS, user, max_new_tokens)
        d = _extract_json(raw) or {}
        return {
            "grounded": bool(d.get("grounded", True)),
            "issues": d.get("issues", ""),
            "suggest_status": _coerce_status(d.get("suggest_status")),
            "feedback": d.get("feedback", ""),
            "raw": raw,
        }

    # -- adjudicator: final static VEX verdict ----------------------------------
    def adjudicate_vex(self, evidence, max_new_tokens=260):
        raw = self._chat(ADJUDICATE_SYS, evidence, max_new_tokens)
        d = _extract_json(raw) or {}
        status = _coerce_status(d.get("status"))
        justification = d.get("justification", raw.strip())
        return {"status": status, "justification": justification, "raw": raw}

    # backward-compat alias (old callers used judge_vex)
    def judge_vex(self, evidence, max_new_tokens=260):
        return self.adjudicate_vex(evidence, max_new_tokens)


# Backward-compatible name. The PoC path is intentionally disabled: this system
# now decides VEX by static analysis only (no PoC generation, no execution).
class SllmPoc(SllmStaticAnalyst):
    def gen_poc(self, *_a, **_k):
        raise RuntimeError(
            "PoC generation is disabled in ICS-VEX static-analysis mode. Use "
            "assess_exploitability()/adjudicate_vex() — the system decides VEX "
            "without generating or running any exploit. See docs/GENIE_STYLE_VEX.md.")


# ===========================================================================
# self-test
# ===========================================================================
def _selftest():
    import json
    print("== SecureBertVex ==", flush=True)
    sv = SecureBertVex()
    rec = json.loads(open(os.path.join(BASE, "data", "vex_dataset.jsonl"), encoding="utf-8").readline())
    r = sv.predict(rec["sentences"])
    print("  cve:", rec["cve"], "| gold label:", rec.get("label"),
          "| pred:", r["label"], "conf %.3f" % r["confidence"], flush=True)

    print("== CodeBertRefMatch ==", flush=True)
    cb = CodeBertRefMatch()
    m = cb.match("char b[8]; strcpy(b, in);", "char b[8]; strcpy(b, in);",
                 "char b[8]; strncpy(b, in, 7);")
    print("  ", m, flush=True)

    if "--sllm" in sys.argv:
        print("== SllmStaticAnalyst (loading 7B, slow) ==", flush=True)
        sl = SllmStaticAnalyst()
        evidence = (
            "CVE-2024-4340 (sqlparse < 0.5.0): passing a deeply nested list to "
            "sqlparse.parse() causes uncontrolled recursion (CWE-674), a DoS.\n"
            "CVSS attack vector: N. Deployment exposure: control-network. "
            "Reachability: conditional. Patch diff available: no.")
        a = sl.assess_exploitability(evidence, max_new_tokens=200)
        print("  static assessment:", {k: a[k] for k in
              ("adversary_controllable", "reachable_in_deployment", "exploitability")},
              flush=True)
        v = sl.adjudicate_vex(evidence)
        print("  adjudicated VEX:", v["status"], "|", v["justification"][:160], flush=True)


if __name__ == "__main__":
    _selftest()
