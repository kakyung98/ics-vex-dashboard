#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
2-모델 VEX 통합 평가: SecureBERT(맥락) + CodeBERT(레퍼런스 매칭).

CodeBERT 의 정직한 역할은 "추상적 취약성 판단"(단독평가에서 실패, 0.50)이 아니라
"배포된 코드가 이 CVE 의 [취약 레퍼런스] vs [패치 레퍼런스] 중 어디에 가까운가" 매칭이다.

세 가지를 측정:
  (A) 레퍼런스 매칭 정확도 — 표면 변형된 배포 코드를 올바른 레퍼런스에 매칭하는가
  (B) 백포트 탐지 — 버전은 '취약'이나 코드가 패치된(백포트) 케이스를,
       CodeBERT 가 비영향으로 바로잡아 오탐을 제거하는가 (버전매칭/맥락 단독은 못 잡음)
  (C) 폐쇄코드 처리 — 코드 확인 불가 findings 는 UNDER_INVESTIGATION 으로 (README §7)

출력: results/two_model_metrics.json
"""
import json, os, sys, hashlib, numpy as np, torch

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(BASE, "src"))
from build_ground_truth import exposure_for, reachability  # noqa
CE = os.path.join(BASE, "data", "code_evidence.json")
FIND = os.path.join(BASE, "data", "findings.csv")
OUT = os.path.join(BASE, "results", "two_model_metrics.json")
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"


def h(*p):
    return int(hashlib.sha256("::".join(map(str, p)).encode()).hexdigest(), 16)


class CodeEmbedder:
    def __init__(self):
        from transformers import AutoTokenizer, AutoModel
        self.tok = AutoTokenizer.from_pretrained("microsoft/codebert-base")
        self.model = AutoModel.from_pretrained("microsoft/codebert-base").to(DEVICE).eval()

    def embed(self, snippets):
        out = []
        with torch.no_grad():
            for i in range(0, len(snippets), 32):
                b = snippets[i:i + 32]
                enc = self.tok(b, padding=True, truncation=True, max_length=256, return_tensors="pt").to(DEVICE)
                o = self.model(**enc).last_hidden_state
                m = enc["attention_mask"].unsqueeze(-1).float()
                v = (o * m).sum(1) / m.sum(1).clamp(min=1e-6)
                out.append(v.cpu().numpy())
        e = np.vstack(out).astype(np.float32)
        return e / (np.linalg.norm(e, axis=1, keepdims=True) + 1e-9)


def perturb(code, seed, lang_c=True):
    """의미 보존 표면 변형(배포 빌드가 레퍼런스와 완전히 동일하지 않은 상황 모사)."""
    cmt = "// vendor build\n" if lang_c else "# vendor build\n"
    lines = code.split("\n")
    r = h("pt", seed) % 3
    if r == 0:
        code = cmt + code
    elif r == 1:
        code = code + ("\n" + cmt.strip())
    else:
        code = "\n".join(("  " + ln if ln.strip() else ln) for ln in lines)  # 재들여쓰기
    # 흔한 변수 살짝 리네임(의미 보존)
    if h("rn", seed) % 2:
        code = code.replace(" len ", " length ").replace("(len)", "(length)")
    return code


def match(embedder, deployed, vuln_ref, patched_ref):
    """배포 코드를 두 레퍼런스에 매칭 -> 'vuln' or 'patched'."""
    e = embedder.embed([deployed, vuln_ref, patched_ref])
    dv = float(e[0] @ e[1]); dp = float(e[0] @ e[2])
    return ("vuln" if dv >= dp else "patched"), dv, dp


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ce = json.load(open(CE, encoding="utf-8"))
    pairs = {c: v for c, v in ce.items() if v.get("vuln_code") and v.get("patched_code")}
    print("code-evidence CVEs: %d" % len(pairs))
    emb = CodeEmbedder()

    # ---------- (A) 레퍼런스 매칭 정확도 ----------
    ident_ok = pert_ok = tot = 0
    for cve, p in pairs.items():
        is_c = not p["file"].lower().endswith((".java", ".py", ".js", ".rb", ".php"))
        # 무변형(identity) — 상한 확인
        for origin, dep in [("vuln", p["vuln_code"]), ("patched", p["patched_code"])]:
            pred, _, _ = match(emb, dep, p["vuln_code"], p["patched_code"])
            ident_ok += (pred == origin)
            # 표면 변형본
            depp = perturb(dep, cve + origin, is_c)
            predp, _, _ = match(emb, depp, p["vuln_code"], p["patched_code"])
            pert_ok += (predp == origin)
            tot += 1
    A = {"identity_match_acc": round(ident_ok / tot, 3),
         "perturbed_match_acc": round(pert_ok / tot, 3), "n": tot}
    print("(A) reference matching: identity %.3f | perturbed %.3f (n=%d)" %
          (A["identity_match_acc"], A["perturbed_match_acc"], tot))

    # ---------- (B) 백포트 탐지 (end-to-end) ----------
    import csv
    # 라우팅: vuln/patched 코드 쌍을 실제로 확보한 건만 코드 leg 로 들어온다.
    # 주의 — findings.csv 의 tier 는 SBOM 속성명이 component:source-availability 이지만
    # 실제로는 OSS 카탈로그 귀속 여부일 뿐이다(tier A 132 CVE 중 코드 보유는 15 CVE).
    # 따라서 게이트는 tier 가 아니라 code_evidence.json 실보유(`cve in pairs`)다.
    rows = [r for r in csv.DictReader(open(FIND, encoding="utf-8-sig"))
            if r["cve"] in pairs]
    # 각 finding: 맥락 판정 + 코드 상태(취약/백포트) 배정
    ctx_only_pred, two_model_pred, truth = [], [], []
    backport_caught = backport_total = 0
    for r in rows:
        cve, dev = r["cve"], r["device"]
        exp = exposure_for(dev)
        reach = reachability(r["av"] or "N", exp)
        # 맥락 단독 판정(코드 무시): 도달가능+취약버전 -> affected
        ctx = "AFFECTED" if reach == "yes" else ("NOT_AFFECTED" if reach == "no" else "UNDER")
        # 코드 상태: 30% 백포트(패치됨) 주입
        backport = (h("bp", dev, cve) % 100) < 30
        p = pairs[cve]
        is_c = not p["file"].lower().endswith((".java", ".py", ".js", ".rb", ".php"))
        deployed = perturb(p["patched_code"] if backport else p["vuln_code"], dev + cve, is_c)
        # 진짜 라벨: 백포트면 코드가 패치됨 -> NOT_AFFECTED (맥락 무관)
        true = "NOT_AFFECTED" if backport else ctx
        # CodeBERT 매칭
        code_state, _, _ = match(emb, deployed, p["vuln_code"], p["patched_code"])
        # 2-모델 결정: 코드가 패치로 매칭되면 NOT_AFFECTED, 아니면 맥락 따름
        two = "NOT_AFFECTED" if code_state == "patched" else ctx

        ctx_only_pred.append(ctx); two_model_pred.append(two); truth.append(true)
        if backport:
            backport_total += 1
            if two == "NOT_AFFECTED":
                backport_caught += 1

    def acc(pred):
        return round(np.mean([p == t for p, t in zip(pred, truth)]), 3)
    ctx_wrong_bp = sum(1 for c, t in zip(ctx_only_pred, truth) if t == "NOT_AFFECTED" and c == "AFFECTED")
    B = {"n_findings": len(rows), "backport_injected": backport_total,
         "backport_caught_by_codebert": backport_caught,
         "context_only_acc": acc(ctx_only_pred), "two_model_acc": acc(two_model_pred),
         "context_only_backport_falsepos": ctx_wrong_bp,
         "two_model_backport_falsepos": sum(1 for c, t in zip(two_model_pred, truth)
                                            if t == "NOT_AFFECTED" and c == "AFFECTED")}
    print("(B) backport: injected %d, caught by CodeBERT %d/%d" %
          (backport_total, backport_caught, backport_total))
    print("    accuracy  context-only %.3f  ->  +CodeBERT %.3f" % (B["context_only_acc"], B["two_model_acc"]))
    print("    backport false-positives  context-only %d  ->  two-model %d" %
          (B["context_only_backport_falsepos"], B["two_model_backport_falsepos"]))

    # ---------- (C) 폐쇄코드 -> UNDER 카운트 ----------
    all_rows = list(csv.DictReader(open(FIND, encoding="utf-8-sig")))
    n_closed = sum(1 for r in all_rows if r["tier"] == "E")                             # 벤더 폐쇄 펌웨어
    n_oss_nocode = sum(1 for r in all_rows if r["tier"] in ("A", "C")
                       and r["cve"] not in pairs)                                       # OSS 귀속이나 코드 미확보
    n_routed_code = sum(1 for r in all_rows if r["cve"] in pairs)                       # 코드 leg 진입
    n_oss_attributed = sum(1 for r in all_rows if r["tier"] == "A")                     # 코드 leg 확장 후보군
    C = {"vendor_closed_findings": n_closed, "oss_without_code": n_oss_nocode,
         "routed_to_under_investigation": n_closed + n_oss_nocode,
         "routed_to_code_leg": n_routed_code,
         "oss_attributed_expansion_pool": n_oss_attributed,
         "total_findings": len(all_rows),
         "note": "코드 미확보 건은 SecureBERT 맥락 leg 에서 종결하며 UNDER_INVESTIGATION 으로 남는다. "
                 "CodeBERT/sLLM 은 vuln/patched 코드 쌍을 실제 보유한 건에만 적용된다. "
                 "tier A(OSS 귀속)는 코드를 수집하면 코드 leg 로 승격 가능한 확장 후보군이다."}
    print("(C) code-unavailable -> UNDER_INVESTIGATION: %d/%d findings (%.0f%%)" %
          (C["routed_to_under_investigation"], C["total_findings"],
           100 * C["routed_to_under_investigation"] / C["total_findings"]))

    res = {"codebert_standalone_note": "abstract vuln-vs-patched classification = 0.50 (chance); "
           "CodeBERT used only for per-CVE reference matching",
           "A_reference_matching": A, "B_backport_detection": B, "C_closed_code_routing": C,
           "device": DEVICE}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("saved:", OUT)


if __name__ == "__main__":
    main()
