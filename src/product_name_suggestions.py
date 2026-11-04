"""Local fine-tuned encoder suggestions. Never assigns a trusted CPE identity."""
import json
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / 'models/product-name-encoder-v1'
_state = None
_lock = threading.Lock()


def suggest(name, limit=3):
    global _state
    report_path = MODEL / 'training_report.json'
    if not report_path.is_file(): return []
    report = json.loads(report_path.read_text(encoding='utf-8'))
    # A completed, non-regressing run is required before exposing suggestions.
    if report['after']['top1'] < report['before']['top1']: return []
    with _lock:
        if _state is None:
            import numpy as np
            from sentence_transformers import SentenceTransformer
            model = SentenceTransformer(str(MODEL), device='cpu', local_files_only=True)
            index = json.loads((ROOT / 'data/cpe_index.json').read_text(encoding='utf-8'))
            products = sorted(index['by_product'])
            cache = MODEL / 'product_vectors.npz'
            cached = np.load(cache, allow_pickle=False) if cache.is_file() else None
            if cached is not None and cached['products'].tolist() == products:
                embeddings = cached['embeddings'].copy()
            else:
                embeddings = model.encode([p.replace('_', ' ') for p in products], batch_size=64,
                                          normalize_embeddings=True, show_progress_bar=False)
            if cached is not None: cached.close()
            _state = (model, products, embeddings)
        model, products, embeddings = _state
        query = model.encode([name], normalize_embeddings=True, show_progress_bar=False)[0]
        import numpy as np
        ranking = np.argsort(-(embeddings @ query))[:limit]
        return [products[i] for i in ranking]
