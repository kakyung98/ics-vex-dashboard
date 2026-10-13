#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Contrastive-train a product-name encoder, because the pretrained one collapses.

Taking SecureBERT's masked mean-pool straight off the shelf and cosine-matching
product names does not work, and the index says why: over 300 randomly drawn
products the mean pairwise cosine is **0.9238** (min 0.79). Every vector points
roughly the same way, so ranking by similarity is ranking by noise — probing
"Siemens SIMATIC S7-1500 CPU 1513F-1 PN" returns five S7-**400** CPUs at 0.9920,
0.9919, 0.9916 … with 0.002 between first and fifth.

That is ordinary anisotropy in an MLM-pretrained encoder: nothing in its training
asked for the embedding space to spread out, and short strings sharing a vocabulary
("simatic", "cpu", "pn") land on top of each other. Sentence encoders fix it with a
contrastive objective, and the dictionary already gives us the pairs to do that
here — NVD publishes a display name beside each product key, which is exactly the
mapping the matcher is scored on.

Objective: MultipleNegativesRankingLoss over (display name -> product key). Every
other key in the batch is an implicit negative, and the swap negatives built by
tools/build_cpe_match_dataset go in as explicit hard negatives, which is what
teaches `simatic_s7-1500` apart from `simatic_s7-400` rather than merely apart from
`openssl`.

The evaluation set's component strings were already held out when the pairs were
built (by name, not by pair), so nothing the scorer will ask about is trained on.

Out: models/ics-cpe-encoder/
"""
import argparse
import collections
import json
import os
import random

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAIRS = os.path.join(BASE, "data", "cpe_match_pairs.jsonl")
OUT = os.path.join(BASE, "models", "ics-cpe-encoder")
ENCODER = os.environ.get("ICSVEX_ENCODER", "ehsanaghaei/SecureBERT")


def load_pairs(path):
    pos, neg = [], collections.defaultdict(list)
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        if r.get("label") == 1:
            pos.append((r["text"], r["product"]))
        else:
            neg[r["text"]].append(r["product"])
    return pos, neg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=1)
    ap.add_argument("--batch", type=int, default=64)
    ap.add_argument("--max-pairs", type=int, default=0)
    ap.add_argument("--seed", type=int, default=20261010)
    a = ap.parse_args()

    from sentence_transformers import (SentenceTransformer, InputExample, losses,
                                       models)
    from torch.utils.data import DataLoader

    pos, neg = load_pairs(PAIRS)
    if not pos:
        print("no training pairs: %s" % os.path.relpath(PAIRS, BASE))
        print("  build them first with python tools/build_cpe_match_dataset.py")
        return
    # --seed used to reach only this Random(), while the two places that
    # actually decide the weights - DataLoader(shuffle=True) and the dropout in
    # the encoder - draw from torch's global RNG. So a rerun produced a
    # DIFFERENT encoder, and the AI matcher's measured precision could not be
    # reproduced from the committed training pairs. Seeding torch (and numpy,
    # which sentence-transformers touches) closes that: the model is the thing
    # the figure depends on, so it has to be derivable from what is in the repo.
    import torch
    torch.manual_seed(a.seed)
    torch.cuda.manual_seed_all(a.seed)
    try:
        import numpy as np
        np.random.seed(a.seed)
    except Exception:
        pass
    random.seed(a.seed)

    rnd = random.Random(a.seed)
    rnd.shuffle(pos)
    if a.max_pairs:
        pos = pos[:a.max_pairs]

    # (anchor, positive, hard negative) where one exists; the loss falls back to
    # in-batch negatives for the rest
    examples = []
    for text, product in pos:
        hard = neg.get(text)
        key = product.replace("_", " ").replace("-", " ")
        if hard:
            wrong = rnd.choice(hard).replace("_", " ").replace("-", " ")
            examples.append(InputExample(texts=[text, key, wrong]))
        else:
            examples.append(InputExample(texts=[text, key]))

    word = models.Transformer(ENCODER, max_seq_length=64)
    pool = models.Pooling(word.get_word_embedding_dimension(),
                          pooling_mode_mean_tokens=True)
    model = SentenceTransformer(modules=[word, pool])

    loader = DataLoader(examples, shuffle=True, batch_size=a.batch, drop_last=True)
    loss = losses.MultipleNegativesRankingLoss(model)

    print("examples %d  (hard-negative %d)  batch %d  epochs %d"
          % (len(examples), sum(1 for e in examples if len(e.texts) == 3),
             a.batch, a.epochs))
    # No seed= here: this sentence-transformers' fit() does not take one, and
    # passing it raises. The global torch/numpy/random seeds set above are what
    # the DataLoader shuffle and the dropout actually draw from.
    model.fit(train_objectives=[(loader, loss)], epochs=a.epochs,
              warmup_steps=int(0.1 * len(loader)), show_progress_bar=True)
    os.makedirs(OUT, exist_ok=True)
    model.save(OUT)
    print("->", os.path.relpath(OUT, BASE))

    # the number that decides whether this worked: random pairs must stop being
    # near-identical, or ranking by cosine is still ranking by noise
    import numpy as np
    sample = [k for _t, k in pos[:400]]
    v = model.encode([s.replace("_", " ") for s in sample],
                     normalize_embeddings=True, show_progress_bar=False)
    sims = v @ v.T
    off = sims[~np.eye(len(v), dtype=bool)]
    print("random-pair cosine: mean %.4f  min %.4f  max %.4f  (was 0.9238 untrained)"
          % (off.mean(), off.min(), off.max()))


if __name__ == "__main__":
    main()
