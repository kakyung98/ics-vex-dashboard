#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""QLoRA fine-tune a VEX-justification judge (direction B).

Given a component/CVE + code, output {status, justification, rationale} for the
four CISA questions (present? / in execute path? / adversary-controllable? /
mitigated?). This is a REASONING/classification task, not exploit generation, so
C vuln/fix pairs (BigVul) are valid training material here.

Base: Qwen2.5-Coder-14B-Instruct (4-bit QLoRA). Fits the 16GB GPU at bs=1 +
grad-accum + gradient checkpointing. Set POC_BASE_MODEL to override.

Train:  data/vex_justify_seed.jsonl (34 code pairs) + data/vulnfix_justify.jsonl (BigVul)
Eval :  data/vex_justify_eval.jsonl (18 CISA-gold pairs) -- never trained on
Output: models/vex-justifier-lora/ , results/vex_justifier_samples.txt
"""
import json, os, sys, random
import torch

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
TRAIN_FILES = [os.path.join(BASE, "data", "vex_justify_seed.jsonl"),
               os.path.join(BASE, "data", "vulnfix_justify.jsonl")]
ADAPTER = os.path.join(BASE, "models", "vex-justifier-lora")
SAMPLES = os.path.join(BASE, "results", "vex_justifier_samples.txt")
MODEL_ID = os.environ.get("POC_BASE_MODEL", "Qwen/Qwen2.5-Coder-14B-Instruct")
SEED = 20260416
MAXLEN = int(os.environ.get("MAXLEN", "1536"))
EPOCHS = float(os.environ.get("EPOCHS", "2"))
SYS = ("You are a VEX analyst judging whether an ICS/OT product is affected by a "
       "vulnerability, using the CISA justification questions. Answer only with the "
       "requested JSON object.")


def load_rows():
    rows = []
    for p in TRAIN_FILES:
        if os.path.exists(p):
            for l in open(p, encoding="utf-8"):
                l = l.strip()
                if l:
                    rows.append(json.loads(l))
    return rows


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    random.seed(SEED); torch.manual_seed(SEED)
    from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
    from peft import LoraConfig, prepare_model_for_kbit_training
    from trl import SFTConfig, SFTTrainer
    from datasets import Dataset

    rows = load_rows()
    random.shuffle(rows)
    print("training rows: %d (from %s)" % (len(rows), ", ".join(os.path.basename(f) for f in TRAIN_FILES)), flush=True)

    tok = AutoTokenizer.from_pretrained(MODEL_ID)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    def to_text(r):
        msgs = [{"role": "system", "content": SYS},
                {"role": "user", "content": r["instruction"]},
                {"role": "assistant", "content": r["completion"]}]
        return {"text": tok.apply_chat_template(msgs, tokenize=False)}

    train_ds = Dataset.from_list([to_text(r) for r in rows])

    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
    print("loading base (4-bit): %s ..." % MODEL_ID, flush=True)
    model = AutoModelForCausalLM.from_pretrained(MODEL_ID, quantization_config=bnb,
                                                 device_map="auto", torch_dtype=torch.bfloat16)
    model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    model.config.use_cache = False
    lora = LoraConfig(r=16, lora_alpha=32, lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
                      target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                                      "gate_proj", "up_proj", "down_proj"])
    args = SFTConfig(output_dir=ADAPTER, per_device_train_batch_size=1,
                     gradient_accumulation_steps=16, num_train_epochs=EPOCHS,
                     learning_rate=2e-4, bf16=True, logging_steps=10, save_strategy="no",
                     report_to=[], max_length=MAXLEN, packing=False,
                     dataset_text_field="text", gradient_checkpointing=True,
                     optim="paged_adamw_8bit")
    trainer = SFTTrainer(model=model, args=args, train_dataset=train_ds,
                         peft_config=lora, processing_class=tok)
    print("training ...", flush=True)
    trainer.train()
    trainer.save_model(ADAPTER); tok.save_pretrained(ADAPTER)
    print("adapter saved: %s" % ADAPTER, flush=True)

    # qualitative check on held-out CISA-gold CVEs
    ev = []
    evp = os.path.join(BASE, "data", "vex_justify_eval.jsonl")
    if os.path.exists(evp):
        ev = [json.loads(l) for l in open(evp, encoding="utf-8")][:8]
    model.eval()
    out = ["# held-out justification judgments (CISA gold)\n"]
    for r in ev:
        user = ("CVE: %s (advisory %s). Judge this vulnerability for the product per the "
                "CISA justification questions and answer with the JSON object."
                % (r["cve"], r.get("advisory", "")))
        msgs = [{"role": "system", "content": SYS}, {"role": "user", "content": user}]
        prompt = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
        ids = tok(prompt, return_tensors="pt").to(model.device)
        with torch.no_grad():
            gen = model.generate(**ids, max_new_tokens=160, do_sample=False,
                                 pad_token_id=tok.pad_token_id)
        text = tok.decode(gen[0][ids["input_ids"].shape[1]:], skip_special_tokens=True)
        out.append("=" * 56)
        out.append("CVE %s | gold: %s" % (r["cve"], r.get("gold_justification")))
        out.append("model: %s" % text[:400])
    os.makedirs(os.path.dirname(SAMPLES), exist_ok=True)
    open(SAMPLES, "w", encoding="utf-8").write("\n".join(out))
    print("samples: %s" % SAMPLES, flush=True)
    print("DONE", flush=True)


if __name__ == "__main__":
    main()
