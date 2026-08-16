#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SecureBERT / CodeBERT 가중치를 미리 받아 캐시에 적재한다."""
import sys, time
sys.stdout.reconfigure(encoding="utf-8")
from transformers import AutoModel, AutoTokenizer, AutoModelForMaskedLM

MODELS = [
    ("SecureBERT", "ehsanaghaei/SecureBERT", "mlm"),
    ("CodeBERT", "microsoft/codebert-base", "enc"),
]
for name, repo, kind in MODELS:
    t = time.time()
    try:
        AutoTokenizer.from_pretrained(repo)
        if kind == "mlm":
            AutoModelForMaskedLM.from_pretrained(repo)
        AutoModel.from_pretrained(repo)
        print("OK  %-12s %s  (%.0fs)" % (name, repo, time.time() - t), flush=True)
    except Exception as e:
        print("FAIL %-12s %s  %s: %s" % (name, repo, type(e).__name__, e), flush=True)
print("DONE", flush=True)
