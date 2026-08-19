#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Train the SecureBERT VexModel on ALL records and persist it for live inference.

train_eval_vex.py trains the VexModel in-memory for evaluation but never saves it,
so live SBOM->VEX inference has nothing to load. This trains on the full dataset
(cached SecureBERT embeddings -> fast) and writes models/vex-model/vexmodel.pt.

Run:  python src/save_vex_model.py
"""
import os, sys
import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import train_eval_vex as T


def main():
    T.set_seed(T.SEED)
    recs, _tr, _te = T.load_dataset()
    emb = T.encode_sentences(recs)                       # cached npz -> instant
    max_k = max(len(r["sentences"]) for r in recs)
    X, M, R, Y, _meta = T.build_tensors(recs, emb, max_k)
    dim = X.shape[2]
    print(f"training VexModel on {len(recs)} records (dim={dim}, max_k={max_k})", flush=True)
    model = T.VexModel(dim).to(T.DEVICE)
    T.train(model, X, M, R, Y, epochs=25)
    outdir = os.path.join(T.BASE, "models", "vex-model")
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, "vexmodel.pt")
    torch.save({"state_dict": model.state_dict(), "dim": dim, "max_k": max_k,
                "labels": T.LABELS}, path)
    print("saved:", path, flush=True)


if __name__ == "__main__":
    main()
