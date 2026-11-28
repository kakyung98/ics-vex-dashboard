"""Encode the extractor's JSON schema with bounded whitespace between tokens."""
import json
import re


def compact_grammar(schema):
    # JSON strings still permit every legal character and escape, including
    # spaces in quotations. Only formatting outside values is bounded.
    rules = [
        r'ws ::= [ \t\n\r]?',
        r'jstring ::= "\"" ([^"\\\x00-\x1f] | "\\" (["\\/bfnrt] | "u" [0-9a-fA-F]{4}))* "\""',
    ]
    names = {}

    def literal(text):
        return json.dumps(text, ensure_ascii=True)

    def encode(node):
        signature = json.dumps(node, ensure_ascii=True)
        if signature in names:
            return names[signature]
        name = "v" + str(len(names))
        names[signature] = name
        if "enum" in node:
            expression = " | ".join(literal(json.dumps(v)) for v in node["enum"])
        elif node["type"] == "object":
            props = node["properties"]
            if set(props) != set(node["required"]) or node["additionalProperties"] is not False:
                raise ValueError("Expected closed object with all fields required")
            members = [literal(json.dumps(k)) + ' ws ":" ws ' + encode(v) for k, v in props.items()]
            expression = '"{" ws ' + ' ws "," ws '.join(members) + ' ws "}"'
        elif node["type"] == "array":
            item = encode(node["items"])
            if node.get("maxItems") == 2:
                expression = f'"[" ws ({item} (ws "," ws {item})? ws)? "]"'
            elif "maxItems" in node:
                raise ValueError("Unsupported array limit")
            else:
                expression = f'"[" ws ({item} (ws "," ws {item})* ws)? "]"'
        elif node["type"] == "boolean":
            expression = '"true" | "false"'
        elif node["type"] == "string":
            expression = "jstring"
        else:
            raise ValueError("Unsupported extractor schema: " + signature)
        rules.append(f"{name} ::= {expression}")
        return name

    root = encode(schema)
    return "\n".join([f"root ::= {root}", *rules])


class JsonWhitespace:
    """Track formatting across SSE chunk boundaries without inspecting string values."""
    def __init__(self):
        self.quoted = self.escaped = False
        self.run = 0

    def excessive(self, chunk):
        for ch in chunk:
            if self.quoted:
                if self.escaped:
                    self.escaped = False
                elif ch == "\\":
                    self.escaped = True
                elif ch == '"':
                    self.quoted = False
            elif ch in " \n\r\t":
                self.run += 1
                if self.run > 64:
                    return True
            else:
                self.quoted = ch == '"'
                self.run = 0
        return False


def structured_completion(backend, body, schema):
    url = backend.url + "/chat/completions"
    guard = JsonWhitespace()
    parts = []
    finish = None
    usage = {}
    with backend.session().post(url, json={**body, "stream": True,
                                "stream_options": {"include_usage": True}},
                                stream=True, timeout=(10,900)) as response:
        response.raise_for_status()
        for line in response.iter_lines():
            if not line.startswith(b"data: "):
                continue
            if line == b"data: [DONE]":
                break
            event = json.loads(line[6:])
            usage = event.get("usage") or usage
            if not event["choices"]:
                continue
            choice = event["choices"][0]
            chunk = choice["delta"].get("content") or ""
            parts.append(chunk)
            finish = choice.get("finish_reason") or finish
            if guard.excessive(chunk):
                break
    if guard.run <= 64:
        if not finish:
            raise ConnectionError("Incomplete event stream")
        return {"choices":[{"finish_reason":finish,"message":{"content":"".join(parts)}}],
                "usage":usage}
    # Reissue the same source and definitions with at most one formatting character
    # between JSON tokens. No changes to quoted text, enums, or array cardinality.
    compact = {k:v for k,v in body.items() if k != "response_format"}
    compact["structured_outputs"] = {"grammar": compact_grammar(schema)}
    response = backend.session().post(url, json=compact, timeout=(10,900))
    response.raise_for_status()
    reply = response.json()
    reply.setdefault("usage", {})["format_retry"] = True
    # Do not replace a decision, quotation or relation already emitted by the
    # original decoder. Whitespace inside JSON strings is significant.
    original = "".join(parts)
    candidate = reply["choices"][0]["message"].get("content") or ""
    if not json_without_formatting(candidate).startswith(json_without_formatting(original)):
        reply["choices"][0].update(finish_reason="length", message={"content": original})
        reply["usage"]["prefix_disagreement"] = True
    return reply


def json_without_formatting(text):
    return re.sub(r'"(?:\\.|[^"\\])*"|[ \t\r\n]+',
                  lambda m: m[0] if m[0].startswith('"') else "", text)
