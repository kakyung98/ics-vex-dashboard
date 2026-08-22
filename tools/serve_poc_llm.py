#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Minimal OpenAI-compatible server for the local PoC model (Qwen2.5-Coder-7B + LoRA).

Purpose: serve `models/poc-sllm-lora` over an OpenAI-compatible endpoint so the
execution-verification engine's per-role routing (EXPLOITER_MODEL=local-poc) can
point its exploit-developer step at a local, non-refusing model for AUTHORIZED
reproduction of PUBLISHED CVEs (research benchmark building). vLLM is unavailable
on native Windows, so this reuses the proven transformers+peft 4-bit load from vex_infer.

Endpoints (subset of the OpenAI API that agentlib/langchain uses):
  GET  /v1/models
  POST /v1/chat/completions        (streaming + non-streaming; tool-calling via
                                     Qwen's native <tool_call> template)

Run:
  python tools/serve_poc_llm.py --port 8000 --served-name ics-vex-poc-sllm
Then point the engine at it:
  LOCAL_LLM_BASE_URL=http://localhost:8000/v1  LOCAL_LLM_MODELS=local-poc=ics-vex-poc-sllm
  EXPLOITER_MODEL=local-poc

NOTE: from the engine's Docker container use http://host.docker.internal:8000/v1.
"""
import os, sys, json, time, argparse, re, uuid

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(BASE, "src"))

SERVED_NAME = os.environ.get("SERVED_NAME", "ics-vex-poc-sllm")
_MODEL = {"tok": None, "model": None}


def load_model():
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    from peft import PeftModel
    QWEN = "Qwen/Qwen2.5-Coder-7B-Instruct"
    LORA = os.path.join(BASE, "models", "poc-sllm-lora")
    tok = AutoTokenizer.from_pretrained(LORA)
    kw = {"torch_dtype": torch.float16, "device_map": "auto"}
    try:
        from transformers import BitsAndBytesConfig
        kw["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_compute_dtype=torch.float16, bnb_4bit_quant_type="nf4")
    except Exception as e:
        print("bitsandbytes unavailable, fp16:", e, file=sys.stderr)
    base = AutoModelForCausalLM.from_pretrained(QWEN, **kw)
    model = PeftModel.from_pretrained(base, LORA).eval()
    _MODEL["tok"], _MODEL["model"] = tok, model
    print("model loaded:", SERVED_NAME, flush=True)


def _generate(messages, tools=None, max_new_tokens=512, temperature=0.0):
    import torch
    tok, model = _MODEL["tok"], _MODEL["model"]
    kwargs = dict(tokenize=False, add_generation_prompt=True)
    if tools:
        kwargs["tools"] = tools
    prompt = tok.apply_chat_template(messages, **kwargs)
    ids = tok(prompt, return_tensors="pt").to(model.device)
    gen_kw = dict(max_new_tokens=max_new_tokens, pad_token_id=tok.eos_token_id)
    if temperature and temperature > 0:
        gen_kw.update(do_sample=True, temperature=temperature)
    else:
        gen_kw.update(do_sample=False)
    with torch.no_grad():
        out = model.generate(**ids, **gen_kw)
    return tok.decode(out[0][ids["input_ids"].shape[1]:], skip_special_tokens=True).strip()


def _mk_call(d):
    if not isinstance(d, dict) or "name" not in d:
        return None
    args = d.get("arguments", d.get("parameters", {}))
    return {
        "id": "call_" + uuid.uuid4().hex[:24], "type": "function",
        "function": {"name": d.get("name", ""),
                     "arguments": args if isinstance(args, str)
                     else json.dumps(args, ensure_ascii=False)},
    }


def _parse_tool_calls(text):
    """Extract tool calls. This LoRA emits <json>{name,arguments}</json>; also
    accept Qwen-native <tool_call>{...}</tool_call> and a bare top-level JSON
    object with a "name" field. Convert all to OpenAI tool_calls."""
    calls = []
    # wrapped forms: <json>...</json> or <tool_call>...</tool_call>
    for m in re.finditer(r"<(json|tool_call)>\s*(\{.*?\})\s*</\1>", text, re.DOTALL):
        try:
            c = _mk_call(json.loads(m.group(2)))
            if c:
                calls.append(c)
        except Exception:
            continue
    cleaned = re.sub(r"<(json|tool_call)>.*?</\1>", "", text, flags=re.DOTALL).strip()
    # fallback: whole (cleaned) content is a bare JSON tool object
    if not calls and cleaned.startswith("{") and '"name"' in cleaned:
        try:
            c = _mk_call(json.loads(cleaned))
            if c:
                calls.append(c); cleaned = ""
        except Exception:
            pass
    return calls, cleaned


def build_app():
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse, StreamingResponse
    app = FastAPI()

    @app.get("/v1/models")
    def models():
        return {"object": "list", "data": [
            {"id": SERVED_NAME, "object": "model", "owned_by": "ics-vex"}]}

    @app.post("/v1/chat/completions")
    async def chat(req: Request):
        body = await req.json()
        messages = body.get("messages", [])
        tools = body.get("tools")
        max_new = int(body.get("max_tokens") or 512)
        temp = float(body.get("temperature") or 0.0)
        stream = bool(body.get("stream"))
        text = _generate(messages, tools=tools, max_new_tokens=max_new, temperature=temp)
        tool_calls, content = _parse_tool_calls(text) if tools else ([], text)
        finish = "tool_calls" if tool_calls else "stop"
        msg = {"role": "assistant", "content": content or None}
        if tool_calls:
            msg["tool_calls"] = tool_calls
        cid = "chatcmpl-" + uuid.uuid4().hex[:24]
        created = int(time.time())
        if not stream:
            return JSONResponse({
                "id": cid, "object": "chat.completion", "created": created,
                "model": body.get("model", SERVED_NAME),
                "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            })

        def sse():
            head = {"id": cid, "object": "chat.completion.chunk", "created": created,
                    "model": body.get("model", SERVED_NAME),
                    "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}]}
            yield "data: " + json.dumps(head) + "\n\n"
            delta = {"tool_calls": tool_calls} if tool_calls else {"content": content}
            body_chunk = {"id": cid, "object": "chat.completion.chunk", "created": created,
                          "model": body.get("model", SERVED_NAME),
                          "choices": [{"index": 0, "delta": delta, "finish_reason": None}]}
            yield "data: " + json.dumps(body_chunk) + "\n\n"
            tail = {"id": cid, "object": "chat.completion.chunk", "created": created,
                    "model": body.get("model", SERVED_NAME),
                    "choices": [{"index": 0, "delta": {}, "finish_reason": finish}]}
            yield "data: " + json.dumps(tail) + "\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(sse(), media_type="text/event-stream")

    return app


def main():
    global SERVED_NAME
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--served-name", default=SERVED_NAME)
    a = ap.parse_args()
    SERVED_NAME = a.served_name
    import uvicorn
    print("loading model (Qwen2.5-Coder-7B + poc-sllm-lora, 4-bit)…", flush=True)
    load_model()
    app = build_app()
    print(f"serving OpenAI-compatible endpoint on http://{a.host}:{a.port}/v1", flush=True)
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
