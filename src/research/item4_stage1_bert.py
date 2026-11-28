"""Fine-tune a BERT token classifier; every original word is accounted for."""
from copy import deepcopy
import json
from pathlib import Path
import random

from src.research.item4_stage1_spans import LABELS, bio, check_splits, decode, evaluate, sha, units, validate_record


def encode(tokenizer, row, max_length=512, stride=64, supervised=False):
    validate_record(row, annotated=supervised)
    if not tokenizer.is_fast:
        raise ValueError('A fast BERT tokenizer is required for exact word alignment')
    if not 8 <= max_length <= 512 or not 0 <= stride < max_length - 2:
        raise ValueError('Require 8 <= max_length <= 512 and 0 <= stride < max_length-2')
    words = [row['text'][a:b] for a, b in units(row['text'])]
    encoded = tokenizer(words, is_split_into_words=True, truncation=True,
                        max_length=max_length, stride=stride, return_overflowing_tokens=True,
                        return_offsets_mapping=True)
    gold = bio(row) if supervised else None
    features, alignments, covered = [], [], set()
    for i in range(len(encoded['input_ids'])):
        word_ids = encoded.word_ids(batch_index=i)
        offsets = encoded['offset_mapping'][i]
        mapping = [(j, w) for j, (w, offset) in enumerate(zip(word_ids, offsets))
                   if w is not None and offset[0] == 0 and offset[1] > 0]
        feature = {key: encoded[key][i] for key in ('input_ids', 'attention_mask', 'token_type_ids') if key in encoded}
        if supervised:
            labels = [-100] * len(word_ids)
            for j, w in mapping:
                if w not in covered:
                    labels[j] = LABELS.index(gold[w])
            feature['labels'] = labels
        covered.update(w for _, w in mapping)
        # An overlap-only window carries no extra training examples.
        if not supervised or any(v != -100 for v in feature['labels']):
            features.append(feature); alignments.append(mapping)
    if covered != set(range(len(words))):
        raise ValueError('Tokenizer omitted source words; no silent truncation is allowed: ' + row['id'])
    return features, alignments


class BertExtractor:
    def __init__(self, checkpoint, device=None, local_files_only=False):
        import torch
        from transformers import AutoConfig, AutoModelForTokenClassification, AutoTokenizer
        config = AutoConfig.from_pretrained(str(checkpoint), local_files_only=local_files_only)
        if config.model_type != 'bert':
            raise ValueError('This module requires a BERT checkpoint')
        if [config.id2label.get(i) for i in range(len(LABELS))] != LABELS:
            raise ValueError('Checkpoint lacks the item4 BIO label contract; fine-tune it first')
        self.tokenizer = AutoTokenizer.from_pretrained(str(checkpoint), use_fast=True, local_files_only=local_files_only)
        self.model = AutoModelForTokenClassification.from_pretrained(str(checkpoint), local_files_only=local_files_only)
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device).eval()

    def predict(self, row, max_length=512, stride=64):
        import torch
        features, alignments = encode(self.tokenizer, row, max_length, stride)
        totals = torch.zeros((len(units(row['text'])), len(LABELS)))
        counts = torch.zeros(len(totals))
        self.model.eval()
        with torch.inference_mode():
            for feature, mapping in zip(features, alignments):
                inputs = {key: torch.tensor([value], device=self.device) for key, value in feature.items()}
                scores = self.model(**inputs).logits[0].softmax(-1).cpu()
                for j, w in mapping:
                    totals[w] += scores[j]; counts[w] += 1
        if (counts == 0).any():
            raise ValueError('Incomplete prediction coverage')
        labels = [LABELS[i] for i in totals.argmax(-1).tolist()]
        result = deepcopy(row)
        result.update(spans=decode(row, labels), annotation_complete=False, annotator=None,
                      prediction_complete=True, review_status='pending_human_review',
                      logic=None, coverage_complete=False, vex_eligible=False,
                      semantic_accuracy_verified=False,
                      unknowns=['Product/path attachment, logical relations and unstated requirements are unresolved.'])
        # The model predicts source spans, not proof of operator observability.
        for span in result['spans']:
            span.update(operator_observable=None, scope_status='requires_human_review')
        return result


def train(train_rows, dev_rows, test_rows, base_model, output, *, epochs=3,
          batch_size=8, learning_rate=3e-5, seed=42, max_length=512, stride=64,
          device=None, local_files_only=False):
    import torch
    from torch.utils.data import DataLoader
    from transformers import AutoConfig, AutoModelForTokenClassification, AutoTokenizer, DataCollatorForTokenClassification
    if not train_rows or not dev_rows or not test_rows:
        raise ValueError('Nonempty human-annotated train, dev and test sets are required')
    if epochs < 1 or batch_size < 1 or learning_rate <= 0:
        raise ValueError('epochs, batch_size and learning_rate must be positive')
    check_splits(train_rows, dev_rows, test_rows)
    output = Path(output)
    if output.exists():
        raise FileExistsError('Use a new output directory: ' + str(output))
    random.seed(seed); torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    config = AutoConfig.from_pretrained(base_model, local_files_only=local_files_only)
    if config.model_type != 'bert':
        raise ValueError('base_model must be a BERT architecture')
    config.num_labels = len(LABELS)
    config.id2label = dict(enumerate(LABELS)); config.label2id = {v: i for i, v in enumerate(LABELS)}
    tokenizer = AutoTokenizer.from_pretrained(base_model, use_fast=True, local_files_only=local_files_only)
    model = AutoModelForTokenClassification.from_pretrained(base_model, config=config,
                local_files_only=local_files_only, ignore_mismatched_sizes=True)
    device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
    model.to(device)
    features = [feature for row in train_rows for feature in encode(tokenizer, row, max_length, stride, True)[0]]
    loader = DataLoader(features, batch_size=batch_size, shuffle=True,
                        collate_fn=DataCollatorForTokenClassification(tokenizer))
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate)
    extractor = BertExtractor.__new__(BertExtractor)
    extractor.tokenizer, extractor.model, extractor.device = tokenizer, model, device
    history = []; best = float('-inf')
    output.mkdir(parents=True)
    for epoch in range(1, epochs + 1):
        model.train(); losses = []
        for batch in loader:
            optimizer.zero_grad(set_to_none=True)
            loss = model(**{k: v.to(device) for k, v in batch.items()}).loss
            if not torch.isfinite(loss):
                raise ValueError('Nonfinite training loss')
            loss.backward(); torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step(); losses.append(loss.item())
        predictions = [extractor.predict(row, max_length, stride) for row in dev_rows]
        score = evaluate(dev_rows, predictions)
        kappa = score['primary_role_kappa']['kappa']
        history.append(dict(epoch=epoch, mean_loss=sum(losses)/len(losses), dev=score))
        # Undefined kappa is preserved; it cannot become a best score of 1.
        rank = kappa if kappa is not None else float('-inf')
        if epoch == 1 or rank > best:
            best = rank
            model.save_pretrained(output); tokenizer.save_pretrained(output)
            best_epoch = epoch
        print(json.dumps(dict(epoch=epoch, dev_kappa=kappa)), flush=True)
    selected = BertExtractor(output, device=device, local_files_only=True)
    test_predictions = [selected.predict(row, max_length, stride) for row in test_rows]
    report = dict(base_model=base_model, seed=seed, epochs=epochs, batch_size=batch_size,
        device=str(device), gpu_name=torch.cuda.get_device_name(torch.device(device)) if str(device).startswith('cuda') else None,
        learning_rate=learning_rate, max_length=max_length, stride=stride, best_epoch=best_epoch,
        selection='dev primary role Cohen kappa; first epoch retained when all are undefined',
        labels=LABELS, history=history, test=evaluate(test_rows, test_predictions),
        corpus_sha256={name: sha(json.dumps(rows, sort_keys=True, ensure_ascii=False))
                       for name, rows in [('train', train_rows), ('dev', dev_rows), ('test', test_rows)]},
        semantic_accuracy_verified=False)
    (output/'training_report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    with (output/'test_predictions.jsonl').open('w', encoding='utf-8') as stream:
        for row in test_predictions:
            stream.write(json.dumps(row, ensure_ascii=False) + '\n')
    return report
