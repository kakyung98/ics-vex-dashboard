"""Fine-tune a local product encoder; save weights, split hashes and retrieval metrics."""
import argparse
import hashlib
import json
import random
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def name_key(text):
    return re.sub('[^a-z0-9]', '', text.lower())


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--base', default='ehsanaghaei/SecureBERT')
    p.add_argument('--output', default=str(ROOT / 'models/product-name-encoder-v1'))
    p.add_argument('--max-train', type=int, default=12000)
    p.add_argument('--eval-size', type=int, default=512)
    p.add_argument('--epochs', type=int, default=1)
    p.add_argument('--batch', type=int, default=32)
    p.add_argument('--seed', type=int, default=20261031)
    a = p.parse_args()
    import numpy as np
    import torch
    from sentence_transformers import SentenceTransformer, models
    random.seed(a.seed); np.random.seed(a.seed); torch.manual_seed(a.seed)
    if not torch.cuda.is_available():
        raise RuntimeError('CUDA GPU required for this training run')
    torch.set_num_threads(4)
    pairs = ROOT / 'data/cpe_match_pairs.jsonl'
    positive = {}
    for line in pairs.open(encoding='utf-8'):
        row = json.loads(line)
        if row['label'] == 1:
            positive.setdefault(name_key(row['text']), (row['text'], row['product']))
    keys = sorted(positive); random.shuffle(keys)
    test_keys = keys[:a.eval_size]
    train_keys = keys[a.eval_size:][:a.max_train]
    train = [positive[k] for k in train_keys]
    test = [positive[k] for k in test_keys]
    if len(train) < 2 or len(test) < 2:
        raise ValueError('Insufficient split size')
    # Fresh upstream weights, not the previously trained encoder: new holdout stays unseen.
    word = models.Transformer(a.base, max_seq_length=64)
    model = SentenceTransformer(modules=[word, models.Pooling(word.get_word_embedding_dimension())], device='cuda')
    labels = sorted({v for _, v in test})
    def evaluate():
        model.eval()
        vectors = model.encode([x.replace('_',' ') for x in labels], normalize_embeddings=True, batch_size=64)
        queries = model.encode([x for x, _ in test], normalize_embeddings=True, batch_size=64)
        ranks = np.argsort(-(queries @ vectors.T), axis=1)
        return {'top1': float(np.mean([labels[r[0]] == target for r, (_, target) in zip(ranks, test)])),
                'top5': float(np.mean([target in [labels[j] for j in r[:5]] for r, (_, target) in zip(ranks, test)])),
                'queries': len(test), 'candidate_products': len(labels),
                'scope': 'name-disjoint NVD title holdout; retrieval within held-out product pool, not end-to-end CVE precision'}
    before = evaluate()
    print('baseline', json.dumps(before), flush=True)
    optimizer = torch.optim.AdamW(model.parameters(), lr=2e-5)
    losses = []
    for epoch in range(a.epochs):
        random.shuffle(train); model.train()
        for offset in range(0, len(train), a.batch):
            batch = train[offset:offset+a.batch]
            if len(batch) < 2: continue
            names, products = zip(*batch)
            optimizer.zero_grad(set_to_none=True)
            with torch.autocast('cuda', dtype=torch.bfloat16):
                def embed(texts):
                    features = {k: v.to('cuda') if hasattr(v, 'to') else v
                                for k, v in model.tokenize(list(texts)).items()}
                    return torch.nn.functional.normalize(model(features)['sentence_embedding'], dim=1)
                q = embed(names); d = embed([x.replace('_',' ') for x in products])
                scores = q @ d.T * 20
                # Same product may occur repeatedly; do not train it as a false negative.
                equal = torch.tensor([[x == y for y in products] for x in products], device='cuda')
                loss = (torch.logsumexp(scores, dim=1) - torch.logsumexp(scores.masked_fill(~equal, -torch.inf), dim=1)).mean()
            if not torch.isfinite(loss): raise RuntimeError('Non-finite training loss')
            loss.backward(); torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0); optimizer.step()
            losses.append(float(loss.detach()))
            if len(losses) % 25 == 0:
                print(f'epoch {epoch+1} step {len(losses)} loss {np.mean(losses[-25:]):.4f}', flush=True)
    after = evaluate()
    out = Path(a.output); out.mkdir(parents=True, exist_ok=True)
    model.save(str(out))
    index = json.loads((ROOT / 'data/cpe_index.json').read_text(encoding='utf-8'))
    products = sorted(index['by_product'])
    embeddings = model.encode([x.replace('_', ' ') for x in products], batch_size=64,
                              normalize_embeddings=True, show_progress_bar=False)
    np.savez_compressed(out / 'product_vectors.npz', products=np.array(products), embeddings=embeddings)
    report = {'base': a.base, 'seed': a.seed, 'train_examples': len(train), 'epochs': a.epochs,
              'steps': len(losses), 'mean_loss': float(np.mean(losses)), 'before': before, 'after': after,
              'data_sha256': hashlib.sha256(pairs.read_bytes()).hexdigest(),
              'train_name_hashes': [hashlib.sha256(k.encode()).hexdigest() for k in train_keys],
              'eval_name_hashes': [hashlib.sha256(k.encode()).hexdigest() for k in test_keys],
              'torch': torch.__version__, 'gpu': torch.cuda.get_device_name(0)}
    (out / 'training_report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    results = ROOT / 'results/product_name_finetune.json'
    results.write_text(json.dumps({k:v for k,v in report.items() if not k.endswith('_hashes')}, indent=2), encoding='utf-8')
    print('saved', out, 'evaluation', json.dumps(after), flush=True)


if __name__ == '__main__': main()
