#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Semantic retrieval for the components the string cascade refuses to identify.

`cpe_match_l0l3.identify_product` abstains on 1,766 of 3,249 components (54%). The
abstention itself is right — guessing is what put `openssl` and `openssh` (Ratcliff-
Obershelp 0.857) in the same bucket in an earlier matcher — but edit distance cannot
reach the answer at all for an ICS display name:

    "Siemens SIMATIC S7-1500 CPU 1518F-4 PN/DP MFP (6ES7518-4FX00-1AC0)"
      -> simatic_s7-1500_firmware

Different tokens, different order, order codes and version ranges in the middle. This
module adds a retrieval stage that runs ONLY where the cascade gave up:

    identifier / exact / n-gram / unambiguous-fuzzy   (cpe_match_l0l3, unchanged)
        |- hit  -> returned as-is, this module never sees it
        `- miss -> encode the name, cosine against the 13,769 product keys,
                   keep the top candidate only if it clears MIN_SIM and beats the
                   runner-up by MIN_MARGIN, else abstain exactly as before

The accept rule mirrors the string path's on purpose: a similarity alone is a ranking,
not a decision, and the runner-up margin is what separates "this is the product" from
"these all look alike". Retrieval here is a CANDIDATE GENERATOR; the margin is the
verifier until the trained cross-encoder replaces it.

`cves_for` is NOT reimplemented. Once a product key is resolved the downstream work —
version range gating, vendor confidence, CVE dedup — is identical, so it delegates to
cpe_match_l0l3 with the resolved key, and the two matchers cannot drift apart.

Public contract matches cpe_match_l0l3 so tools/eval_cpe_match_precision.py can swap
the import:
    identify_product(component) -> (product_key | None, how)
    cves_for(component, sbom_vendor="", strict=False) -> [{cve, ...}]
    _norm(s)
"""
import json
import os
import re
import sys

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(BASE, "src"))

import cpe_match_l0l3 as L
from cpe_match_l0l3 import BY_PRODUCT, _norm  # noqa: F401  (re-exported for the eval)

DICT = os.path.join(BASE, "data", "cpe_dictionary.jsonl")
CACHE = os.path.join(BASE, "data", "cpe_product_embeddings.npz")
ENCODER = os.environ.get("ICSVEX_ENCODER", "ehsanaghaei/SecureBERT")

# A cosine score is a ranking, not a verdict. Both gates must pass, the same shape of
# rule the string path uses (RO_MIN / RO_MARGIN) — tuned on the ground truth, not guessed.
MIN_SIM = float(os.environ.get("ICSVEX_MIN_SIM", "0.86"))
MIN_MARGIN = float(os.environ.get("ICSVEX_MIN_MARGIN", "0.02"))
TOP_K = 5

_STATE = {"keys": None, "emb": None, "enc": None, "tok": None, "titles": None}


def product_titles():
    """product key -> the most descriptive display name available.

    NVD's CPE dictionary publishes a human title per product ("Siemens SIMATIC
    S7-1500"), which is far closer to what an SBOM writes than the underscored key
    is. Where the dictionary has not been fetched for a product, the key itself is
    used with separators turned back into spaces.
    """
    titles = {}
    if os.path.isfile(DICT):
        for line in open(DICT, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            p, t = r.get("product"), r.get("title")
            if p in BY_PRODUCT and t and p not in titles:
                titles[p] = t
    for p in BY_PRODUCT:
        titles.setdefault(p, p.replace("_", " ").replace("-", " "))
    return titles


def _encoder():
    if _STATE["enc"] is None:
        import torch
        from transformers import AutoTokenizer, AutoModel
        dev = "cuda" if torch.cuda.is_available() else "cpu"
        _STATE["tok"] = AutoTokenizer.from_pretrained(ENCODER)
        _STATE["enc"] = AutoModel.from_pretrained(ENCODER).to(dev).eval()
        _STATE["dev"] = dev
    return _STATE["tok"], _STATE["enc"], _STATE["dev"]


def embed(texts, batch=128):
    """Masked mean-pool, L2-normalised — the pooling src/vex_infer.py already uses,
    at the 64-token cap that suits short product names."""
    import numpy as np
    import torch
    tok, enc, dev = _encoder()
    out = []
    with torch.no_grad():
        for i in range(0, len(texts), batch):
            e = tok(texts[i:i + batch], padding=True, truncation=True,
                    max_length=64, return_tensors="pt").to(dev)
            h = enc(**e).last_hidden_state
            m = e["attention_mask"].unsqueeze(-1).float()
            v = ((h * m).sum(1) / m.sum(1).clamp(min=1e-6)).cpu().numpy()
            out.append(v)
    v = np.vstack(out).astype("float32")
    return v / (np.linalg.norm(v, axis=1, keepdims=True) + 1e-9)


def build_index(force=False):
    """Encode every product key once and cache it. 13,769 x 768 floats is 42 MB —
    small enough that a plain matrix product beats carrying an ANN dependency."""
    import numpy as np
    if not force and os.path.isfile(CACHE):
        z = np.load(CACHE, allow_pickle=True)
        _STATE["keys"] = list(z["keys"])
        _STATE["emb"] = z["emb"]
        return _STATE["keys"], _STATE["emb"]
    titles = product_titles()
    keys = sorted(BY_PRODUCT)
    emb = embed([titles[k] for k in keys])
    np.savez_compressed(CACHE, keys=np.array(keys, dtype=object), emb=emb)
    _STATE["keys"], _STATE["emb"] = keys, emb
    return keys, emb


def _index():
    if _STATE["emb"] is None:
        build_index()
    return _STATE["keys"], _STATE["emb"]


def retrieve(name, k=TOP_K):
    """[(product, score)] best first."""
    keys, emb = _index()
    q = embed([name])[0]
    sims = emb @ q
    import numpy as np
    top = np.argsort(-sims)[:k]
    return [(keys[i], float(sims[i])) for i in top]


def identify_product(component):
    """(product, how) or (None, reason). The string cascade decides first."""
    product, how = L.identify_product(component)
    if product:
        return product, how
    name = str(component.get("name") or "").strip()
    if not name:
        return None, how
    cands = retrieve(name)
    if not cands:
        return None, "ai: no candidate"
    best, score = cands[0]
    runner = cands[1][1] if len(cands) > 1 else 0.0
    if score >= MIN_SIM and (score - runner) >= MIN_MARGIN:
        return best, "ai-retrieve"
    return None, ("ai: ambiguous (%s %.3f/next %.3f)" % (best, score, runner))


def cves_for(component, sbom_vendor="", strict=False):
    """Resolve the product here, then hand the rest to cpe_match_l0l3 unchanged."""
    product, how = identify_product(component)
    if not product:
        return []
    if how != "ai-retrieve":
        return L.cves_for(component, sbom_vendor=sbom_vendor, strict=strict)
    # the cascade would abstain on this name, so give the downstream the resolved key
    # by its exact spelling; everything after identity is cpe_match_l0l3's logic
    shim = dict(component)
    shim["name"] = product
    out = L.cves_for(shim, sbom_vendor=sbom_vendor, strict=strict)
    for r in out:
        r["how"] = "ai-retrieve"
    return out


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="build or probe the retrieval index")
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--probe", nargs="*", help="names to retrieve for")
    a = ap.parse_args()
    if a.build:
        keys, emb = build_index(force=True)
        print("indexed %d products -> %s" % (len(keys), os.path.relpath(CACHE, BASE)))
    for name in a.probe or []:
        print("\n%r" % name)
        for p, s in retrieve(name):
            print("   %-44s %.4f" % (p, s))
