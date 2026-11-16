"""Validate and assemble local-model native Vulntology proposals.

This module never interprets CVE text, calls a model, maps old fact labels, or
fills an unknown enum. Exact quotations prove grounding, not semantic truth.
Every asserted semantic leaf additionally needs a separate field-local source
review. Those model judgments are still drafts, not independent human accuracy.
Only complete, evidence-linked paths enter a pinned-schema native payload.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import uuid
from pathlib import Path

from jsonschema import Draft7Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
PINNED_SCHEMA = ROOT / "results/vulntology_design_v1/nist_schema.json"
if not PINNED_SCHEMA.is_file():
    PINNED_SCHEMA = ROOT / 'data/standards/vulntology-schema.json'
PINNED_SCHEMA_SHA256 = "fc2b278520b7035f5951b3b9e7a15d72a32735930ac86ab4dc41aac21f5ae0e8"
CONTRACT_DIRECTORY = ROOT / "results/vulntology_native_projection_design_v1"
VERSION = "native-projection/1.0"
REVIEW_VERSION = "native-projection-review/1.0"
CVE_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,}$"
DEFAULT_PRODUCT_SCHEME = "urn:ics-vex:source-product-text"
NATIVE_SEMANTIC_FIELDS = {
    "requiresAttackTheatre", "hasExploitedWeakness", "hasImpactMethodType",
    "hasGainedPrivilege", "hasEscapeContext", "affectsContext", "hasEntityRole",
    "hasLogicalImpact", "hasPhysicalImpact", "hasScope", "hasCriticality",
    "hasLocation", "hasBarrierType", "hasNeededPrivilege", "relatesToContext",
    "hasEngineeringMethod", "hasName",
}


def _read_schema():
    data = PINNED_SCHEMA.read_bytes()
    if hashlib.sha256(data).hexdigest() != PINNED_SCHEMA_SHA256:
        raise RuntimeError("Pinned NIST schema changed; projection refused")
    return json.loads(data.decode("utf-8"))


def _ref():
    return {
        "type": "object", "additionalProperties": False,
        "required": ["segment_id", "quote", "occurrence"],
        "properties": {
            "segment_id": {"type": "string", "minLength": 1},
            "quote": {"type": "string", "minLength": 1},
            "occurrence": {"type": "integer", "minimum": 0},
        },
    }


def candidate_contract():
    """Typed partial native shapes; incomplete fields are omitted, never Unknown.

    UUIDs and CVE identity are server-owned. Product output deliberately uses
    source text enumerations only; this avoids fetching external CVE/NVD schemas.
    Missing mandatory native fields remain valid drafts and block native export.
    """
    definitions = copy.deepcopy(_read_schema()["definitions"])
    definitions["Product"] = {
        "type": "object", "additionalProperties": False,
        "properties": {"hasProductEnumeration": {
            "type": "array", "minItems": 1,
            "items": {"$ref": "#/definitions/ProductEnumeration"},
        }},
    }
    definitions["ProductEnumeration"]["additionalProperties"] = False
    for name in ("Scenario", "Action", "Impact", "Barrier", "ImpactMethod"):
        def partial(node):
            if isinstance(node, dict):
                node.pop("required", None)
                if "properties" in node:
                    node["properties"].pop("id", None)
                    node["additionalProperties"] = False
                # A partial object can match more than one incomplete branch.
                if "oneOf" in node:
                    node["anyOf"] = node.pop("oneOf")
                for child in list(node.values()):
                    partial(child)
            elif isinstance(node, list):
                for child in node:
                    partial(child)
        partial(definitions[name])
    definitions["evidence_ref"] = _ref()
    definitions["origin_relation"] = {
        "type": "object", "additionalProperties": False,
        "required": ["relation", "evidence", "support_note"],
        "properties": {
            "relation": {"enum": ["originating_product", "undetermined"]},
            "evidence": {"type": "array", "items": {"$ref": "#/definitions/evidence_ref"}},
            "support_note": {"type": "string", "maxLength": 600},
        },
    }
    definitions["field_evidence"] = {
        "type": "object", "additionalProperties": False,
        "required": ["field_pointer", "evidence", "support_note"],
        "properties": {
            "field_pointer": {"type": "string", "pattern": r"^/", "minLength": 1},
            "evidence": {"type": "array", "minItems": 1, "items": {"$ref": "#/definitions/evidence_ref"}},
            "support_note": {"type": "string", "maxLength": 600},
        },
    }
    definitions["condition_ast"] = {"oneOf": [
        {"type": "object", "additionalProperties": False, "required": ["condition"], "properties": {"condition": {"type": "string", "minLength": 1}}},
        {"type": "object", "additionalProperties": False, "required": ["op", "args"], "properties": {
            "op": {"enum": ["and", "or"]}, "args": {"type": "array", "minItems": 2, "items": {"$ref": "#/definitions/condition_ast"}}}},
        {"type": "object", "additionalProperties": False, "required": ["op", "args"], "properties": {
            "op": {"const": "not"}, "args": {"type": "array", "minItems": 1, "maxItems": 1, "items": {"$ref": "#/definitions/condition_ast"}}}},
    ]}
    strings = {"type": "array", "uniqueItems": True, "items": {"type": "string", "minLength": 1}}
    fields = {"type": "array", "items": {"$ref": "#/definitions/field_evidence"}}
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": "urn:ics-vex:native-projection-candidate:1.0",
        "type": "object", "additionalProperties": False,
        "required": ["schema_version", "cve_id", "originating_product", "paths", "blocked_reasons"],
        "properties": {
            "schema_version": {"const": VERSION}, "cve_id": {"type": "string", "pattern": CVE_PATTERN},
            "originating_product": {
                "type": "object", "additionalProperties": False,
                "required": ["product_refs", "native", "field_evidence", "origin_relation", "blocked_reasons"],
                "properties": {"product_refs": strings, "native": {"anyOf": [{"type": "null"}, {"$ref": "#/definitions/Product"}]},
                               "field_evidence": fields, "origin_relation": {"$ref": "#/definitions/origin_relation"}, "blocked_reasons": strings},
            },
            "paths": {"type": "array", "items": {
                "type": "object", "additionalProperties": False,
                "required": ["path_id", "scope_id", "product_refs", "native_scenario", "field_evidence", "condition_ids", "condition_ast", "blocked_reasons"],
                "properties": {
                    "path_id": {"type": "string", "minLength": 1}, "scope_id": {"type": "string", "minLength": 1},
                    "product_refs": strings, "native_scenario": {"anyOf": [{"type": "null"}, {"$ref": "#/definitions/Scenario"}]},
                    "field_evidence": fields, "condition_ids": strings,
                    "condition_ast": {"anyOf": [{"type": "null"}, {"$ref": "#/definitions/condition_ast"}]},
                    "blocked_reasons": strings,
                },
            }},
            "blocked_reasons": strings,
        }, "definitions": definitions,
    }


def review_contract():
    judgment = {
        "type": "object", "additionalProperties": False,
        "required": ["field_pointer", "verdict", "evidence", "support_note"],
        "properties": {
            "field_pointer": {"type": "string", "pattern": r"^/", "minLength": 1},
            "verdict": {"enum": ["supported", "unsupported", "ambiguous"]},
            "evidence": {"type": "array", "items": _ref()},
            "support_note": {"type": "string", "maxLength": 600},
        },
    }
    judgments = {"type": "array", "items": judgment}
    relation_judgment = {
        "type": "object", "additionalProperties": False,
        "required": ["verdict", "evidence", "support_note"],
        "properties": {
            "verdict": {"enum": ["supported", "unsupported", "ambiguous"]},
            "evidence": {"type": "array", "items": _ref()},
            "support_note": {"type": "string", "maxLength": 600},
        },
    }
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": "urn:ics-vex:native-projection-review:1.0",
        "type": "object", "additionalProperties": False,
        "required": ["schema_version", "cve_id", "originating_product_judgments", "originating_product_relation_judgment", "paths", "blocked_reasons"],
        "properties": {
            "schema_version": {"const": REVIEW_VERSION}, "cve_id": {"type": "string", "pattern": CVE_PATTERN},
            "originating_product_judgments": judgments,
            "originating_product_relation_judgment": relation_judgment,
            "paths": {"type": "array", "items": {
                "type": "object", "additionalProperties": False,
                "required": ["path_id", "field_judgments", "blocked_reasons"],
                "properties": {"path_id": {"type": "string", "minLength": 1}, "field_judgments": judgments,
                               "blocked_reasons": {"type": "array", "items": {"type": "string", "minLength": 1}}},
            }},
            "blocked_reasons": {"type": "array", "items": {"type": "string", "minLength": 1}},
        },
    }


def _schema_errors(value, schema):
    messages = []
    def append(error):
        messages.append(f"/{'/'.join(map(str, error.absolute_path))}: {error.message}")
        for child in error.context:
            append(child)
    for error in Draft7Validator(schema, format_checker=FormatChecker()).iter_errors(value):
        append(error)
    return messages


def _leaves(value, pointer=""):
    if isinstance(value, dict):
        for key, child in value.items():
            token = str(key).replace("~", "~0").replace("/", "~1")
            yield from _leaves(child, pointer + "/" + token)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _leaves(child, pointer + "/" + str(index))
    else:
        yield pointer, value


def _semantic_pointers(value):
    result = set()
    for pointer, _ in _leaves(value):
        tokens = pointer.split("/")[1:]
        if any(token in NATIVE_SEMANTIC_FIELDS for token in tokens) or "values" in tokens:
            result.add(pointer)
    return result


def validate_condition_ast(expression, allowed_ids):
    """Check Boolean references and arity, never infer a logical relation."""
    if expression is None:
        return []
    schema = candidate_contract()
    ast_schema = {"$ref": "#/definitions/condition_ast", "definitions": schema["definitions"]}
    errors = _schema_errors(expression, ast_schema)
    if errors:
        return errors
    def visit(node):
        if "condition" in node:
            if node["condition"] not in allowed_ids:
                errors.append("Unknown condition reference: " + node["condition"])
        else:
            for child in node["args"]:
                visit(child)
    visit(expression)
    return errors


def _ground(refs, context, scope_ids):
    errors, grounded = [], []
    for ref in refs:
        segment = context.get("segments", {}).get(ref["segment_id"])
        if segment is None:
            errors.append("Unknown source segment: " + ref["segment_id"])
            continue
        text = segment.get("text", "")
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != segment.get("sha256"):
            errors.append("Source hash mismatch: " + ref["segment_id"])
            continue
        if context["cve_id"] not in segment.get("cve_ids", []):
            errors.append("Foreign CVE source segment: " + ref["segment_id"])
        if not set(scope_ids).intersection(segment.get("scope_ids", [])):
            errors.append("Foreign product/path scope segment: " + ref["segment_id"])
        positions = []
        start = 0
        while True:
            position = text.find(ref["quote"], start)
            if position < 0:
                break
            positions.append(position)
            start = position + 1
        if ref["occurrence"] >= len(positions):
            errors.append("Exact quotation occurrence unavailable: " + ref["segment_id"])
            continue
        position = positions[ref["occurrence"]]
        grounded.append(dict(ref, span=[position, position + len(ref["quote"])], offset_unit="unicode_codepoints", segment_sha256=segment["sha256"], uri=segment.get("uri")))
    return errors, grounded


def _field_checks(native, candidate_fields, review_fields, context, scope_ids):
    errors, provenance = [], {}
    needed = _semantic_pointers(native)
    candidates, judgments = {}, {}
    for fields, target, label in ((candidate_fields, candidates, "candidate"), (review_fields, judgments, "review")):
        for field in fields:
            pointer = field["field_pointer"]
            if pointer in target:
                errors.append(f"Duplicate {label} field pointer: {pointer}")
            target[pointer] = field
            if pointer not in needed:
                errors.append(f"Unknown or nonsemantic {label} field pointer: {pointer}")
    for pointer in sorted(needed):
        proposed, review = candidates.get(pointer), judgments.get(pointer)
        if not proposed:
            errors.append("Missing candidate field evidence: " + pointer)
        if not review or review["verdict"] != "supported" or not review["evidence"]:
            errors.append("Missing supported field-local review: " + pointer)
        entry = {}
        for label, item in (("candidate", proposed), ("review", review)):
            if item:
                issues, grounded = _ground(item["evidence"], context, scope_ids)
                errors.extend(f"{pointer}: {issue}" for issue in issues)
                entry[label] = {"evidence": grounded, "support_note": item["support_note"]}
        provenance[pointer] = entry
    return errors, provenance


def _product_errors(native, product_refs, context):
    products = context.get("products", {})
    errors = []
    if not product_refs or any(ref not in products for ref in product_refs):
        return ["Product references missing or unknown"]
    allowed = set()
    for ref in product_refs:
        product = products[ref]
        if context["cve_id"] not in product.get("cve_ids", []):
            errors.append("Product is not bound to target CVE: " + ref)
        allowed.update(product.get("native_values", []))
    values = set()
    for enumeration in native.get("hasProductEnumeration", []):
        if enumeration.get("scheme") not in context.get("product_schemes", [DEFAULT_PRODUCT_SCHEME]):
            errors.append("Unapproved product enumeration scheme")
        values.update(enumeration.get("values", []))
    if values - allowed:
        errors.append("Native product value is outside bound registry")
    for ref in product_refs:
        if values and not values.intersection(products[ref].get("native_values", [])):
            errors.append("Native product does not represent bound product: " + ref)
    return errors


def _with_ids(scenario, cve_id, path_id, scope_id):
    result = copy.deepcopy(scenario)
    def assign(node, pointer):
        identity = json.dumps(["urn:ics-vex:native:1.0", cve_id, scope_id, path_id, pointer], separators=(",", ":"))
        node["id"] = str(uuid.uuid5(uuid.NAMESPACE_URL, identity))
    assign(result, "/scenario")
    for index, action in enumerate(result.get("hasAction", [])):
        assign(action, f"/scenario/hasAction/{index}")
        for key in ("resultsInImpact", "doesNotResultInImpact"):
            for impact_index, impact in enumerate(action.get(key, [])):
                assign(impact, f"/scenario/hasAction/{index}/{key}/{impact_index}")
    for index, barrier in enumerate(result.get("blockedByBarrier", [])):
        assign(barrier, f"/scenario/blockedByBarrier/{index}")
    return result


def _native_errors(native):
    def external_product(node):
        if isinstance(node, dict):
            if set(node).intersection({"hasNvdCpeApplicabilityStatement", "hasCve5Product", "hasCve4Product"}):
                return True
            return any(external_product(value) for value in node.values())
        if isinstance(node, list):
            return any(external_product(value) for value in node)
        return False
    if external_product(native):
        return ["Only source text product enumerations are supported; external-schema product representations are refused without network access"]
    errors = _schema_errors(native, _read_schema())
    identifiers = [value for pointer, value in _leaves(native) if pointer.endswith("/id")]
    if len(identifiers) != len(set(identifiers)):
        errors.append("Native UUIDs are not globally unique within the record")
    for value in identifiers:
        try:
            if uuid.UUID(value).version not in {4, 5}:
                errors.append("Native object ID is not UUID v4/v5")
        except (ValueError, TypeError, AttributeError):
            errors.append("Invalid native UUID")
    return errors


def project_candidate(candidate, review, context):
    """Return an envelope for every call, with native null when blocked.

    ``context`` is caller-owned: cve_id; products keyed by product_ref with
    cve_ids/scope_ids/native_values; paths keyed by path_id with scope_id,
    product_refs, condition_ids; segments keyed by segment_id with immutable
    text/sha256/cve_ids/scope_ids/uri. Caller registries are not model assertions.
    A local-model supported review is required but is not semantic ground truth.
    """
    cve_id = context.get("cve_id")
    result = {"schema_version": VERSION, "cve_id": cve_id, "nist_vulntology": None,
              "projection_status": "blocked", "export_blockers": [], "path_diagnostics": [],
              "native_field_provenance": {}, "semantic_accuracy_validated": False,
              "human_review": "not_reviewed", "all_real_paths_complete": "unknown",
              "candidate_proposal": copy.deepcopy(candidate), "field_review": copy.deepcopy(review),
              "registered_path_ids": sorted(context.get("paths", {}))}
    errors = _schema_errors(candidate, candidate_contract()) + _schema_errors(review, review_contract())
    if not isinstance(cve_id, str) or not re.fullmatch(CVE_PATTERN, cve_id):
        errors.append("Caller CVE identity is invalid")
    if errors:
        result["export_blockers"] = errors
        return result
    if candidate["cve_id"] != cve_id or review["cve_id"] != cve_id:
        result["export_blockers"] = ["Candidate/review/caller CVE identities differ"]
        return result
    errors.extend(candidate["blocked_reasons"] + review["blocked_reasons"])
    origin = candidate["originating_product"]
    origin_native = origin["native"]
    errors.extend(origin["blocked_reasons"])
    if origin_native is None:
        errors.append("Originating product proposal is null")
    else:
        errors.extend(_product_errors(origin_native, origin["product_refs"], context))
        scopes = [scope for ref in origin["product_refs"] for scope in context.get("products", {}).get(ref, {}).get("scope_ids", [])]
        relation, relation_review = origin["origin_relation"], review["originating_product_relation_judgment"]
        if relation["relation"] != "originating_product" or not relation["evidence"]:
            errors.append("Originating-product relation is not explicitly proposed with source evidence")
        if relation_review["verdict"] != "supported" or not relation_review["evidence"]:
            errors.append("Originating-product relation lacks a separate supported source review; known_affected membership is insufficient")
        relation_provenance = {}
        for label, item in (("candidate", relation), ("review", relation_review)):
            issues, grounded = _ground(item["evidence"], context, scopes)
            errors.extend("origin_relation: " + issue for issue in issues)
            relation_provenance[label] = {"evidence": grounded, "support_note": item["support_note"]}
        result["native_field_provenance"]["originating_product_relation"] = relation_provenance
        issues, evidence = _field_checks(origin_native, origin["field_evidence"], review["originating_product_judgments"], context, scopes)
        errors.extend(issues)
        result["native_field_provenance"]["originating_product"] = evidence
    if errors:
        result["export_blockers"] = errors
        return result
    review_paths = {}
    for item in review["paths"]:
        if item["path_id"] in review_paths:
            result["export_blockers"] = ["Duplicate reviewed path ID"]
            return result
        review_paths[item["path_id"]] = item
    candidate_ids = [item["path_id"] for item in candidate["paths"]]
    if len(candidate_ids) != len(set(candidate_ids)) or set(review_paths) - set(candidate_ids):
        result["export_blockers"] = ["Duplicate candidate or foreign reviewed path ID"]
        return result
    scenarios = []
    for path in candidate["paths"]:
        pid, scope_id = path["path_id"], path["scope_id"]
        diagnostic = {"path_id": pid, "scope_id": scope_id, "status": "blocked", "blockers": [],
                      "condition_ids": path["condition_ids"], "condition_ast": path["condition_ast"]}
        issues = diagnostic["blockers"]
        known = context.get("paths", {}).get(pid)
        reviewed = review_paths.get(pid)
        issues.extend(path["blocked_reasons"])
        if reviewed:
            issues.extend(reviewed["blocked_reasons"])
        else:
            issues.append("Path source review is missing")
        if not known or known.get("scope_id") != scope_id or set(path["product_refs"]) != set(known.get("product_refs", [])):
            issues.append("CVE/product/path binding differs from caller registry")
        if not set(path["product_refs"]) <= set(origin["product_refs"]):
            issues.append("Path products are outside originating product proposal")
        if not path["product_refs"] or any(scope_id not in context.get("products", {}).get(ref, {}).get("scope_ids", []) for ref in path["product_refs"]):
            issues.append("Path product is outside the registered product scope")
        if known and not set(path["condition_ids"]) <= set(known.get("condition_ids", [])):
            issues.append("Path contains unregistered condition IDs")
        issues.extend(validate_condition_ast(path["condition_ast"], set(path["condition_ids"])))
        if known and "condition_ast" in known and path["condition_ast"] != known["condition_ast"]:
            issues.append("Native sidecar condition AST differs from caller-accepted formula")
        scenario = path["native_scenario"]
        if scenario is None:
            issues.append("Native scenario proposal is null")
        elif not issues:
            if "affectsProduct" in scenario:
                issues.extend(_product_errors(scenario["affectsProduct"], path["product_refs"], context))
            if set(scenario.get("hasExploitedWeakness", [])) - set(known.get("reported_cwes", [])):
                issues.append("Proposed CWE was not reported in caller source registry")
            issues2, evidence = _field_checks(scenario, path["field_evidence"], reviewed["field_judgments"], context, [scope_id])
            issues.extend(issues2)
            result["native_field_provenance"][pid] = evidence
            allowed_uris = {s.get("uri") for s in context.get("segments", {}).values()
                            if cve_id in s.get("cve_ids", []) and scope_id in s.get("scope_ids", [])}
            if any(uri not in allowed_uris for uri in scenario.get("evidencedBySource", [])):
                issues.append("Scenario evidence URI is outside scoped source registry")
            completed = _with_ids(scenario, cve_id, pid, scope_id)
            native = {"Vulnerability": {"hasIdentity": [{"scheme": context.get("cve_scheme", "https://www.cve.org/"), "value": cve_id}],
                                        "hasOriginatingProduct": origin_native, "hasScenario": [completed]}}
            issues.extend(_native_errors(native))
            if not issues:
                scenarios.append(completed)
                diagnostic["status"] = "native_validated_evidence_linked"
        result["path_diagnostics"].append(diagnostic)
    if not scenarios:
        result["export_blockers"] = ["No complete evidence-linked native scenario is exportable"]
        return result
    native = {"Vulnerability": {"hasIdentity": [{"scheme": context.get("cve_scheme", "https://www.cve.org/"), "value": cve_id}],
                                "hasOriginatingProduct": origin_native, "hasScenario": scenarios}}
    errors = _native_errors(native)
    if errors:
        result["export_blockers"] = errors
        return result
    result["nist_vulntology"] = native
    missing_paths = set(context.get("paths", {})) - set(candidate_ids)
    for pid in sorted(missing_paths):
        result["path_diagnostics"].append({"path_id": pid, "scope_id": context["paths"][pid].get("scope_id"),
                                           "status": "blocked", "blockers": ["Caller-registered path was not proposed"]})
    blocked = any(item["status"] == "blocked" for item in result["path_diagnostics"])
    result["projection_status"] = "native_validated_partial_described_paths" if blocked else "native_validated_described_paths"
    result["pinned_schema_sha256"] = hashlib.sha256(PINNED_SCHEMA.read_bytes()).hexdigest()
    result["note"] = "Schema validity, matching quotes and local-model review agreement do not prove semantic accuracy or complete exploitation-path coverage."
    return result


def write_projection_outputs(directory, result):
    """Write a per-CVE diagnostic envelope always; native file only if validated.

    Outputs are immutable within a run. Use a new run directory for changed
    predictions; a blocked record never leaves a stale native export behind.
    """
    cve_id = result.get("cve_id", "")
    if not isinstance(cve_id, str) or not re.fullmatch(CVE_PATTERN, cve_id):
        raise ValueError("Invalid CVE output identity")
    native = result.get("nist_vulntology")
    if native is not None and _native_errors(native):
        raise ValueError("Refusing to write an invalid native payload")
    if native is not None and not any(identity.get("value") == cve_id for identity in native["Vulnerability"]["hasIdentity"]):
        raise ValueError("Native CVE identity differs from output record")
    base = Path(directory)
    native_path = base / "native" / f"{cve_id}.json"
    if native is None and native_path.exists():
        raise FileExistsError("Existing native export conflicts with blocked result; use a new run directory")
    outputs = [(base / "records" / f"{cve_id}.json", result)]
    if native is not None:
        outputs.append((native_path, native))
    serialized = [(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n") for path, value in outputs]
    for path, text in serialized:
        if path.exists() and path.read_text(encoding="utf-8") != text:
            raise FileExistsError(f"Existing immutable projection output differs: {path}")
    for path, text in serialized:
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(text)
    return {"record_file": str(outputs[0][0]), "native_file": str(native_path) if native is not None else None}
