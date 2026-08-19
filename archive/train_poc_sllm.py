#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sLLM PoC 생성기 — QLoRA 파인튜닝 (CVE -> exploit PoC).

CVE-GENIE 공개 익스플로잇(429개)으로 7B 코드 LLM 을 4-bit QLoRA 튜닝한다.
FORGE/CVE-GENIE 의 에이전트 두뇌를 로컬 sLLM 으로 대체하려는 첫 단계
(생성 엔진). 실행 검증 루프는 별도 단계.

출력: models/poc-sllm-lora/ (LoRA 어댑터), results/poc_sllm_samples.txt
"""
import json, os, sys, random
import torch

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DATA = os.path.join(BASE, "data", "poc_sft.jsonl")
ADAPTER = os.path.join(BASE, "models", "poc-sllm-lora")
SAMPLES = os.path.join(BASE, "results", "poc_sllm_samples.txt")
MODEL_ID = os.environ.get("POC_BASE_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct")
SEED = 20260416
MAXLEN = 1280


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    random.seed(SEED); torch.manual_seed(SEED)
    from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
    from peft import LoraConfig, prepare_model_for_kbit_training
    from trl import SFTConfig, SFTTrainer
    from datasets import Dataset

    recs = [json.loads(l) for l in open(DATA, encoding="utf-8")]
    random.shuffle(recs)
    n_eval = max(10, len(recs) // 10)
    ev, tr = recs[:n_eval], recs[n_eval:]
    print("SFT examples: total %d | train %d | held-out %d" % (len(recs), len(tr), len(ev)), flush=True)

    tok = AutoTokenizer.from_pretrained(MODEL_ID)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    def to_text(r):
        msgs = [{"role": "system", "content": "You are a security researcher writing proof-of-concept "
                 "exploits to reproduce known CVEs for defensive verification."},
                {"role": "user", "content": r["instruction"]},
                {"role": "assistant", "content": r["completion"]}]
        return {"text": tok.apply_chat_template(msgs, tokenize=False)}

    train_ds = Dataset.from_list([to_text(r) for r in tr])

    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
    print("loading base model (4-bit): %s ..." % MODEL_ID, flush=True)
    model = AutoModelForCausalLM.from_pretrained(MODEL_ID, quantization_config=bnb,
                                                 device_map="auto", torch_dtype=torch.bfloat16)
    model = prepare_model_for_kbit_training(model)
    lora = LoraConfig(r=16, lora_alpha=32, lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
                      target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                                      "gate_proj", "up_proj", "down_proj"])

    args = SFTConfig(output_dir=ADAPTER, per_device_train_batch_size=1, gradient_accumulation_steps=8,
                     num_train_epochs=3, learning_rate=2e-4,
                     bf16=True, logging_steps=10, save_strategy="no", report_to=[],
                     max_length=MAXLEN, packing=False, dataset_text_field="text")
    trainer = SFTTrainer(model=model, args=args, train_dataset=train_ds,
                         peft_config=lora, processing_class=tok)
    print("training ...", flush=True)
    trainer.train()
    trainer.save_model(ADAPTER); tok.save_pretrained(ADAPTER)
    print("adapter saved: %s" % ADAPTER, flush=True)

    # held-out CVE 에 PoC 생성 (정성 평가)
    model.eval()
    out = ["# held-out PoC generations (qualitative)\n"]
    for r in ev[:6]:
        msgs = [{"role": "system", "content": "You are a security researcher writing proof-of-concept "
                 "exploits to reproduce known CVEs for defensive verification."},
                {"role": "user", "content": r["instruction"]}]
        prompt = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
        ids = tok(prompt, return_tensors="pt").to(model.device)
        with torch.no_grad():
            gen = model.generate(**ids, max_new_tokens=400, do_sample=False,
                                 pad_token_id=tok.pad_token_id)
        text = tok.decode(gen[0][ids["input_ids"].shape[1]:], skip_special_tokens=True)
        out.append("=" * 60)
        out.append("CVE: %s" % r["cve"])
        out.append("--- generated PoC ---\n%s" % text[:1500])
        out.append("--- gold PoC (first 400 chars) ---\n%s\n" % r["completion"][:400])
    os.makedirs(os.path.dirname(SAMPLES), exist_ok=True)
    open(SAMPLES, "w", encoding="utf-8").write("\n".join(out))
    print("samples: %s" % SAMPLES, flush=True)
    print("DONE", flush=True)


if __name__ == "__main__":
    main()
