"""Ground LLM drafts against immutable scoped text and assemble conservative records.

These checks establish structural/evidence integrity, not semantic ground truth.
``machine_supported`` means two model passes plus these checks, never human review.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import uuid
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator
from .vulntology_extraction_contracts import load_effective_contracts

_DESIGN = Path(__file__).resolve().parents[1] / "results/vulntology_extraction_design_v2"
_UNKNOWN = {"unknown", "unspecified", "not stated", "n/a", "$unknown", "unresolved"}


@lru_cache(maxsize=1)
def _contracts():
    contracts = load_effective_contracts()
    return (Draft7Validator(contracts["candidate_schema"]), Draft7Validator(contracts["review_schema"]), contracts["predicate_registry"])


def _error(code, entity=None, detail=None):
    result = {"code": code}
    if entity is not None:
        result["entity"] = entity
    if detail is not None:
        result["detail"] = detail
    return result


def _schema_errors(validator, value):
    return [_error("schema", "/" + "/".join(map(str, e.path)), e.message)
            for e in validator.iter_errors(value)]


def _catalogues(packet):
    scopes = {s["id"]: s for s in packet.get("product_scope_catalogue", [])}
    segments = {s["segment_id"]: s for s in packet.get("segments", [])}
    duplicate_segments = {k for k, n in Counter(s["segment_id"] for s in packet.get("segments", [])).items() if n > 1}
    duplicate_scopes = {k for k, n in Counter(s["id"] for s in packet.get("product_scope_catalogue", [])).items() if n > 1}
    return scopes, segments, duplicate_scopes, duplicate_segments


def _cve_subject_scope_issue(packet, text, start, end):
    """Check explicit identifiers in the citation's own sentence/semicolon clause.

    Absence of an ID is not evidence of a mismatch: structured packet scope may
    supply it. Explicit sibling/other subjects require review rather than being
    silently inherited by the target CVE. Custom namespaces use the target's own
    prefix, so synthetic controls do not need hard-coded identifier exceptions.
    """
    target = str(packet.get("cve_id", ""))
    patterns = [r"\bCVE-\d{4}-\d{4,}\b"]
    if target and not re.fullmatch(patterns[0], target, re.I) and "-" in target:
        prefix = target.rsplit("-", 1)[0]
        patterns.append(r"\b" + re.escape(prefix) + r"-[A-Za-z0-9][A-Za-z0-9_.-]*\b")
    identifier = re.compile("|".join(patterns), re.I)
    boundaries = [0]
    for separator in re.finditer(r";|(?<=[.!?])\s+|[\r\n]+", text):
        boundaries.extend([separator.start(), separator.end()])
    boundaries.append(len(text))
    subjects = set()
    for left, right in zip(boundaries, boundaries[1:]):
        if left < end and right > start:
            subjects.update(match.group().upper() for match in identifier.finditer(text[left:right]))
    if subjects and (subjects != {target.upper()}):
        return {"target_cve": target, "explicit_clause_subjects": sorted(subjects), "span": [start, end],
                "requires_review": True}
    return None


def _ground(packet, evidence, scope_id, entity):
    scopes, segments, duplicate_scopes, duplicate_segments = _catalogues(packet)
    errors, grounded = [], []
    if scope_id is not None and (scope_id not in scopes or scope_id in duplicate_scopes):
        errors.append(_error("invalid_scope", entity, scope_id))
    for ref in evidence:
        sid = ref.get("segment_id")
        segment = segments.get(sid)
        if segment is None or sid in duplicate_segments:
            errors.append(_error("invalid_segment", entity, sid))
            continue
        text = segment.get("text", "")
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if segment.get("sha256") != digest:
            errors.append(_error("source_hash_mismatch", entity, sid))
            continue
        if scope_id is not None and scope_id not in segment.get("scope_ids", []):
            errors.append(_error("evidence_scope_mismatch", entity, sid))
            continue
        quote, occurrence = ref.get("quote"), ref.get("occurrence")
        if not isinstance(quote, str) or not quote or type(occurrence) is not int or occurrence < 0:
            errors.append(_error("invalid_quote_reference", entity, sid))
            continue
        start = -1
        for _ in range(occurrence + 1):
            start = text.find(quote, start + 1)
            if start < 0:
                break
        if start < 0:
            errors.append(_error("quote_not_found", entity, sid))
            continue
        subject_issue = _cve_subject_scope_issue(packet, text, start, start + len(quote)) if scope_id is not None else None
        if subject_issue:
            errors.append(_error("cve_subject_scope_mismatch", entity, subject_issue))
        grounded.append({**copy.deepcopy(ref), "span": [start, start + len(quote)],
                         "offset_unit": "unicode_codepoints", "segment_sha256": digest,
                         "source_id": segment.get("source_id"), "source_role": segment.get("source_role"),
                         "uri": segment.get("uri"), "source_json_pointer": segment.get("source_json_pointer"),
                         "cve_subject_scope_valid": subject_issue is None, "cve_subject_scope_issue": subject_issue})
    return grounded, errors


def _leaves(expression):
    if expression is None:
        return []
    if "fact_id" in expression:
        return [expression["fact_id"]]
    return [f for a in expression.get("args", []) for f in _leaves(a)]


def _has_not(expression):
    return bool(expression and (expression.get("op") == "not" or
                any(_has_not(a) for a in expression.get("args", []))))


def validate_candidate(packet: dict, candidate: Any) -> dict:
    """Return schema/ref/quote results; unresolved bindings are retained, not accepted."""
    errors = _schema_errors(_contracts()[0], candidate)
    result = {"valid": False, "schema_valid": not errors, "identity_valid": False,
              "errors": errors, "grounded_facts": [], "grounded_paths": []}
    if errors:
        return result
    result["identity_valid"] = candidate["packet_id"] == packet.get("packet_id")
    if not result["identity_valid"]:
        errors.append(_error("packet_id_mismatch"))
    facts = {f["id"]: f for f in candidate["facts"]}
    paths = {p["id"]: p for p in candidate["paths"]}
    duplicate_facts = {k for k, n in Counter(f["id"] for f in candidate["facts"]).items() if n > 1}
    duplicate_paths = {k for k, n in Counter(p["id"] for p in candidate["paths"]).items() if n > 1}
    for f in candidate["facts"]:
        refs, own = _ground(packet, f["evidence"], f["scope_id"], f["id"])
        if f["id"] in duplicate_facts:
            own.append(_error("duplicate_fact_id", f["id"]))
        path = paths.get(f["path_id"])
        if f["path_id"] is not None and (path is None or f["path_id"] in duplicate_paths):
            own.append(_error("invalid_path", f["id"], f["path_id"]))
        if path and path["scope_id"] != f["scope_id"]:
            own.append(_error("fact_path_scope_mismatch", f["id"]))
        result["grounded_facts"].append({**copy.deepcopy(f), "evidence": refs,
                                         "grounding_valid": not own, "grounding_errors": own})
        errors.extend(own)
    for p in candidate["paths"]:
        refs, own = _ground(packet, p["relation_evidence"], p["scope_id"], p["id"])
        if p["id"] in duplicate_paths:
            own.append(_error("duplicate_path_id", p["id"]))
        for fid in _leaves(p["logic_proposal"]):
            f = facts.get(fid)
            if f is None or fid in duplicate_facts:
                own.append(_error("invalid_formula_fact", p["id"], fid))
            elif f["path_id"] != p["id"] or f["scope_id"] != p["scope_id"]:
                own.append(_error("formula_fact_scope_mismatch", p["id"], fid))
        result["grounded_paths"].append({**copy.deepcopy(p), "relation_evidence": refs,
                                         "grounding_valid": not own, "grounding_errors": own})
        errors.extend(own)
    result["valid"] = not errors
    return result


def validate_review(packet: dict, candidate: Any, review: Any) -> dict:
    """Ground reviewer citations and reject fabricated/missing/duplicate judgments."""
    errors = _schema_errors(_contracts()[1], review)
    result = {"valid": False, "schema_valid": not errors, "identity_valid": False,
              "errors": errors, "judgments": [], "logic_judgments": [], "missed_claims": []}
    candidate_errors = _schema_errors(_contracts()[0], candidate)
    if candidate_errors:
        errors.append(_error("candidate_contract_invalid"))
    if errors:
        return result
    result["identity_valid"] = review["packet_id"] == packet.get("packet_id") == candidate.get("packet_id")
    if not result["identity_valid"]:
        errors.append(_error("packet_id_mismatch"))
    facts = {f.get("id"): f for f in candidate.get("facts", []) if isinstance(f, dict)}
    paths = {p.get("id"): p for p in candidate.get("paths", []) if isinstance(p, dict)}
    for group, key, catalogue in (("judgments", "fact_id", facts), ("logic_judgments", "path_id", paths)):
        counts = Counter(j[key] for j in review[group])
        for judgment in review[group]:
            target = catalogue.get(judgment[key])
            own = []
            if target is None:
                own.append(_error("unknown_review_target", judgment[key]))
            if counts[judgment[key]] != 1:
                own.append(_error("duplicate_review_target", judgment[key]))
            refs, issues = _ground(packet, judgment["evidence"], target.get("scope_id") if target else None, judgment[key])
            own.extend(issues)
            result[group].append({**copy.deepcopy(judgment), "evidence": refs,
                                  "grounding_valid": not own, "grounding_errors": own})
            errors.extend(own)
        for missing in catalogue.keys() - counts.keys():
            errors.append(_error("missing_review_judgment", missing))
    for index, claim in enumerate(review["missed_claims"]):
        refs, own = _ground(packet, [{k: claim[k] for k in ("segment_id", "quote", "occurrence")}], claim["scope_id"], f"missed:{index}")
        result["missed_claims"].append({**copy.deepcopy(claim), "grounded_evidence": refs,
                                       "grounding_valid": not own, "grounding_errors": own})
        errors.extend(own)
    result["valid"] = not errors
    return result


def _primary(refs, purpose):
    return [r for r in refs if r.get("source_role") == "cve_specific" and r.get("purpose") == purpose]


def _overlapping(left, right):
    return any(a["segment_id"] == b["segment_id"] and a["span"][0] < b["span"][1]
               and b["span"][0] < a["span"][1] for a in left for b in right)


def _argument_errors(fact, packet):
    predicates = _contracts()[2]
    predicate, args = fact["predicate"], fact["arguments"]
    if predicate not in predicates or predicate == "custom_unmapped":
        return ["unmapped_predicate"]
    errors = []
    for key in predicates[predicate]["arguments"]:
        value = args.get(key)
        if value is None or value == "" or isinstance(value, str) and value.strip().lower() in _UNKNOWN:
            errors.append(f"missing_argument:{key}")
        elif key != "required_value" and not isinstance(value, str):
            errors.append(f"invalid_argument_type:{key}")
        elif key == "required_value" and not isinstance(value, (str, bool, int, float)):
            errors.append(f"invalid_argument_type:{key}")
    scope = next((s for s in packet.get("product_scope_catalogue", []) if s["id"] == fact["scope_id"]), None)
    if "product_ref" in args and (scope is None or args["product_ref"] != scope.get("product_ref")):
        errors.append("argument_product_scope_mismatch")
    return errors


def necessity_source_relation_lint(fact: dict, references: list[dict]) -> dict:
    """Conservative acceptance lint, never extraction or a proof of necessity.

    An LLM/reviewer can agree on the same false causal inference. Auto-promotion
    therefore additionally requires an overt relation in the exact cited text.
    Unrecognized narrative relations remain candidates for human review. Passing
    this lint still does not establish semantic truth or attack-path completeness.
    """
    predicate, arguments = fact.get("predicate"), fact.get("arguments", {})
    normalize = lambda value: " ".join(re.findall(r"[a-z0-9]+", str(value).lower()))
    def argument_present(key, text):
        words = set(normalize(arguments.get(key, "")).split())
        words -= {"the", "a", "an", "is", "be", "must", "required", "interface", "endpoint", "port"}
        return bool(words) and words <= set(normalize(text).split())
    def matches_predicate(text):
        normalized = normalize(text)
        if predicate == "endpoint_reachable":
            reach = re.search(r"\b(?:network access|access to|reachab(?:le|ility)|connect(?:ion|ivity|ing)? to)\b", normalized)
            return bool(reach and argument_present("interface_ref", text))
        if predicate == "required_operating_mode":
            return bool(re.search(r"\bmode\b", normalized) and argument_present("mode", text))
        if predicate == "feature_enabled":
            return bool(re.search(r"\b(?:enabl\w*|activ\w*|running|turned on)\b", normalized) and argument_present("feature_ref", text))
        if predicate == "required_configuration_present":
            setting = normalize(arguments.get("setting", ""))
            # Affected version ranges are applicability, not runtime settings.
            if re.search(r"\b(?:version|versions|release|firmware)\b", setting):
                return False
            return argument_present("setting", text)
        if predicate == "required_environment_present":
            return argument_present("environment_fact", text)
        if predicate == "user_performs_required_action":
            return bool(re.search(r"\b(?:user|operator|victim)\b", normalized) and argument_present("action", text))
        if predicate == "attacker_is_authenticated":
            return bool(re.search(r"\b(?:authenticated|authentication|authenticate|logged in|log in)\b", normalized))
        if predicate == "attacker_has_required_privilege":
            privilege = normalize(arguments.get("privilege", ""))
            if privilege in {"admin", "administrator", "administrative"}:
                return bool(re.search(r"\badmin(?:istrator|istrative)?\b", normalized))
            return argument_present("privilege", text)
        if predicate == "attacker_has_physical_or_local_access":
            kind = normalize(arguments.get("access_kind", ""))
            return kind in {"local", "physical", "local access", "physical access"} and kind.split()[0] in normalized.split()
        if predicate == "attacker_has_required_artifact":
            # Sending, opening, crafting or loading an artifact is an event;
            # it does not establish a prerequisite to already possess one.
            possession = re.search(r"\b(?:know(?:s|ing|ledge)?|possess(?:es|ing|ion)?|already ha(?:s|ve)|ha(?:s|ve) (?:the |a |an )?(?:private |public |secret |valid )?(?:key|password|credential|token|certificate))\b", normalized)
            return bool(possession and argument_present("artifact_kind", text)
                        and re.search(r"\b(?:attacker|adversary|exploit\w*|attack|path)\b", normalized))
        return False
    def explicit_relation(clause):
        for match in re.finditer(r"\b(?:requires?|requiring|required|must|only\s+(?:if|when|with|after))\b", clause, re.I):
            before, after = clause[:match.start()].lower(), clause[match.end():].lower()
            if re.search(r"\b(?:not|never|no longer)\s+(?:\w+\s+){0,2}$", before):
                continue
            if re.search(r"\bno(?:\s+\w+){0,3}\s*$", before) or re.match(r"\s+not\b", after):
                continue
            # only-if/when and active requires govern the following condition;
            # passive required / must also need the immediately preceding subject.
            operator = match.group().lower()
            governed = after if operator.startswith(("only", "require")) and operator != "required" else before[-100:] + " " + after[:160]
            governed = re.split(r"\b(?:but|whereas|although)\b", governed, maxsplit=1)[0]
            if predicate == "attacker_is_authenticated":
                # A required key used to bypass authentication does not establish
                # a requirement to already be authenticated.
                if operator == "must":
                    if not re.match(r"\s+(?:already\s+)?(?:be\s+(?:successfully\s+)?authenticated|authenticate|log\s+in)\b", after):
                        continue
                elif operator == "required":
                    if not re.search(r"\b(?:authentication|authenticated (?:access|session))\b(?:\s+\w+){0,3}\s*$", before):
                        continue
                elif not re.search(r"\b(?:authentication|authenticated (?:attacker|user|session|access))\b", after[:100]):
                    continue
                if re.search(r"\b(?:unauthenticated|not authenticated|no authentication|without authentication|authentication (?:is )?(?:disabled|off))\b", governed):
                    continue
            if matches_predicate(governed):
                return True
        return False
    def qualified_actor(clause):
        text = normalize(clause)
        if predicate == "endpoint_reachable":
            qualification = re.search(r"\b(?:attacker|adversary|actor)s?\b.{0,100}?\b(?:with|having|who has) (?:direct |local |remote )?(?:network access|access to)\b", text)
            return bool(qualification and matches_predicate(text))
        if predicate == "attacker_is_authenticated":
            return bool(re.search(r"\bauthenticated (?:remote |local )?(?:attacker|adversary|user)s?\b", text))
        if predicate == "attacker_has_required_privilege":
            qualification = re.search(r"\b(?:privileged|administrative|administrator|root) (?:remote |local )?(?:attacker|adversary|user)s?\b|\b(?:attacker|adversary|user)s? with (?:\w+ ){0,4}(?:privileges|permissions)\b", text)
            return bool(qualification and matches_predicate(text))
        if predicate == "attacker_has_physical_or_local_access":
            qualification = re.search(r"\b(?:local|physical) (?:attacker|adversary|user)s?\b|\b(?:attacker|adversary|user)s? (?:with|having|who has) (?:local|physical) access\b", text)
            return bool(qualification and matches_predicate(text))
        if predicate == "attacker_has_required_artifact":
            qualification = re.search(r"\b(?:attacker|adversary|user)s?\b.{0,60}?\b(?:possessing|knowing|who knows|who has|having|with knowledge of|with possession of)\b", text)
            return bool(qualification and matches_predicate(text))
        return False
    for ref in references:
        if ref.get("source_role") != "cve_specific" or ref.get("purpose") != "necessity":
            continue
        for clause in re.split(r"(?<=[.!?;])\s+|[\r\n]+|\b(?:but|whereas|although)\b", ref.get("quote", ""), flags=re.I):
            if explicit_relation(clause):
                return {"eligible": True, "matched_relation": "overt_path_relative_necessity", "semantic_truth_verified": False}
            if qualified_actor(clause):
                return {"eligible": True, "matched_relation": "predicate_matching_actor_qualification", "semantic_truth_verified": False}
    return {"eligible": False, "reason": "necessity_relation_requires_human_review", "semantic_truth_verified": False}


def nonrequirement_source_relation_lint(fact: dict, references: list[dict]) -> dict:
    """Require an overt, predicate-matching nonrequirement in the cited source.

    Cleartext credentials, a missing model statement, and authentication bypass
    impact do not by themselves state that prior authentication is unnecessary.
    """
    predicate, arguments = fact.get("predicate"), fact.get("arguments", {})
    normalize = lambda value: " ".join(re.findall(r"[a-z0-9]+", str(value).lower()))
    for ref in references:
        if ref.get("source_role") != "cve_specific" or ref.get("purpose") == "counterevidence":
            continue
        text = normalize(ref.get("quote", ""))
        if re.search(r"\b(?:cannot|unable|not able|not without|not unauthenticated|not an unauthenticated)\b", text):
            continue
        matched = False
        if predicate == "attacker_is_authenticated":
            matched = bool(re.search(
                r"\bauthentication (?:is |was )?(?:not (?:required|necessary|needed)|unnecessary)\b|"
                r"\b(?:no|without) (?:prior |any )?authentication\b|"
                r"\b(?:does not|do not|not) require (?:prior |any )?authentication\b|"
                r"\b(?:unauthenticated|anonymous|non authenticated) (?:remote |local )?(?:attacker|adversary|user)s?\b|"
                r"\bwithout (?:being authenticated|logging in)\b", text))
        elif predicate == "user_performs_required_action":
            matched = bool(re.search(r"\b(?:no|without) (?:any )?user interaction\b|\buser interaction (?:is )?not (?:required|necessary|needed)\b|\bdoes not require (?:any )?user interaction\b", text))
        else:
            key = {"attacker_has_required_privilege": "privilege", "attacker_has_required_artifact": "artifact_kind",
                   "required_operating_mode": "mode", "feature_enabled": "feature_ref", "required_configuration_present": "setting",
                   "required_environment_present": "environment_fact", "endpoint_reachable": "interface_ref",
                   "attacker_has_physical_or_local_access": "access_kind"}.get(predicate)
            target = normalize(arguments.get(key, "")) if key else ""
            if target and target in text:
                escaped = re.escape(target)
                matched = bool(re.search(r"\b" + escaped + r" (?:is |are )?not (?:required|necessary|needed)\b|\b(?:without|no) (?:any |the |a )?" + escaped + r"\b|\bdoes not require (?:the |a |any )?" + escaped + r"\b", text))
        if matched:
            return {"eligible": True, "matched_relation": "predicate_matching_explicit_nonrequirement", "semantic_truth_verified": False}
    return {"eligible": False, "reason": "nonrequirement_relation_requires_human_review", "semantic_truth_verified": False}


def assemble_packet(packet: dict, candidate: Any, review: Any) -> dict:
    """Retain all drafts; automatically accept only conservatively grounded claims.

    Semantic model agreement remains fallible. NOT expressions are held because
    this candidate contract has no independent atomic-state polarity declaration.
    """
    cv = validate_candidate(packet, candidate)
    rv = validate_review(packet, candidate, review)
    global_ready = cv["schema_valid"] and cv["identity_valid"] and rv["schema_valid"] and rv["identity_valid"]
    judgments = {j["fact_id"]: j for j in rv["judgments"] if j["grounding_valid"]}
    facts = []
    for f in cv["grounded_facts"]:
        reasons = []
        relation_lint = None
        nonrequirement_lint = None
        j = judgments.get(f["id"])
        if not global_ready:
            reasons.append("contract_or_identity_invalid")
        if not f["grounding_valid"]:
            reasons.append("candidate_grounding_invalid")
        if f["scope_id"] is None or f["path_id"] is None:
            reasons.append("unresolved_binding")
        scope = next((s for s in packet.get("product_scope_catalogue", []) if s["id"] == f["scope_id"]), None)
        resolution = str(scope.get("resolution_status", "")).lower() if scope else ""
        if "unresolved" in resolution or resolution in {"unknown", "unbound", "not_bound"}:
            reasons.append("product_scope_resolution_unresolved")
        if j is None or j["verdict"] != "supported" or not j["scope_correct"]:
            reasons.append("review_not_supporting_fact_and_scope")
        elif not j["evidence"]:
            reasons.append("review_has_no_grounded_evidence")
        if any(r.get("purpose") == "counterevidence" for r in f["evidence"] + (j["evidence"] if j else [])):
            reasons.append("counterevidence_requires_resolution")
        if f["category"] in {"applicability", "conditional_context", "trigger_event", "impact", "explicit_nonrequirement"}:
            primary = [r for r in f["evidence"] if r.get("source_role") == "cve_specific" and r.get("purpose") != "counterevidence"]
            reviewed_primary = [r for r in j["evidence"] if r.get("source_role") == "cve_specific" and r.get("purpose") != "counterevidence"] if j else []
            if not primary or not reviewed_primary or not _overlapping(primary, reviewed_primary):
                reasons.append("cve_specific_role_evidence_not_jointly_supported")
        if f["category"] == "necessary_condition":
            if f["support_relation"] != "necessary_for_described_path":
                reasons.append("necessity_relation_unproven")
            if j is None or not j["necessity_supported"]:
                reasons.append("review_not_supporting_necessity")
            primary = _primary(f["evidence"], "necessity")
            reviewed_primary = _primary(j["evidence"], "necessity") if j else []
            if not primary or not reviewed_primary or not _overlapping(primary, reviewed_primary):
                reasons.append("direct_cve_necessity_evidence_not_jointly_supported")
            relation_lint = {"candidate": necessity_source_relation_lint(f, primary),
                             "review": necessity_source_relation_lint(f, reviewed_primary)}
            if not all(value["eligible"] for value in relation_lint.values()):
                reasons.append("necessity_relation_requires_human_review")
            reasons.extend(_argument_errors(f, packet))
        if f["category"] == "explicit_nonrequirement":
            if f["support_relation"] != "explicitly_not_required":
                reasons.append("nonrequirement_relation_unproven")
            nonrequirement_lint = {"candidate": nonrequirement_source_relation_lint(f, f["evidence"]),
                                  "review": nonrequirement_source_relation_lint(f, j["evidence"] if j else [])}
            if not all(value["eligible"] for value in nonrequirement_lint.values()):
                reasons.append("nonrequirement_relation_requires_human_review")
        if f["support_relation"] in {"inferred", "undetermined"}:
            reasons.append("unreviewed_inference_or_undetermined")
        facts.append({**f, "machine_support_status": "machine_supported" if not reasons else "candidate_unresolved",
                      "acceptance_reasons": reasons, "human_review": "not_reviewed",
                      "necessity_relation_lint": relation_lint,
                      "nonrequirement_relation_lint": nonrequirement_lint,
                      "operator_question_eligible": not reasons and f["category"] == "necessary_condition"
                      and _contracts()[2].get(f["predicate"], {}).get("operator_question_eligible", False)})
    accepted = {f["id"] for f in facts if f["machine_support_status"] == "machine_supported" and f["category"] == "necessary_condition"}
    logic_reviews = {j["path_id"]: j for j in rv["logic_judgments"] if j["grounding_valid"]}
    scenarios = []
    for path in cv["grounded_paths"]:
        expression, reasons = path["logic_proposal"], []
        j = logic_reviews.get(path["id"])
        if not global_ready or not path["grounding_valid"] or path["scope_id"] is None:
            reasons.append("invalid_or_unresolved_path")
        if expression is None:
            reasons.append("logic_not_proposed")
        elif not set(_leaves(expression)) <= accepted:
            reasons.append("formula_contains_unaccepted_or_nonrequirement_fact")
        if j is None or j["verdict"] != "supported":
            reasons.append("logic_review_not_supported")
        if expression and "fact_id" not in expression:
            primary = _primary(path["relation_evidence"], "relation")
            reviewed = _primary(j["evidence"], "relation") if j else []
            if not primary or not reviewed or not _overlapping(primary, reviewed):
                reasons.append("relation_evidence_not_jointly_supported")
        if _has_not(expression):
            reasons.append("negation_requires_explicit_polarity_review")
        if any(r.get("purpose") == "counterevidence" for r in path["relation_evidence"] + (j["evidence"] if j else [])):
            reasons.append("logic_counterevidence_requires_resolution")
        members = [f for f in facts if f["path_id"] == path["id"]]
        scenarios.append({"id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"urn:ics-vex:{packet.get('packet_id')}:{path['id']}")),
                          "local_path_id": path["id"], "scope_id": path["scope_id"],
                          "conditions": [f for f in members if f["id"] in accepted],
                          "nonrequirements": [f for f in members if f["category"] == "explicit_nonrequirement" and f["machine_support_status"] == "machine_supported"],
                          "known_necessary_expression": copy.deepcopy(expression) if not reasons else None,
                          "logic_acceptance_reasons": reasons, "logic_candidate": copy.deepcopy(expression),
                          "coverage": {"all_real_paths_complete": "unknown", "conditions_complete": "unknown"},
                          "human_review": "not_reviewed"})
    return {"schema_version": "0.2.0", "record_id": packet.get("cve_id"), "packet_id": packet.get("packet_id"),
            "nist_vulntology": None,
            "ics_vex": {"export_status": "draft_native_export_blocked",
                        "export_blockers": ["No complete source-backed native Action/Impact/theatre projection has been assembled."],
                        "products": copy.deepcopy(packet.get("product_scope_catalogue", [])),
                        "scenario_instances": scenarios, "facts": facts,
                        "unknowns": copy.deepcopy(candidate.get("unknowns", [])) if isinstance(candidate, dict) else [],
                        "unpromoted_missed_claims": rv["missed_claims"],
                        "candidate_validation": cv, "review_validation": rv,
                        "raw_candidate": copy.deepcopy(candidate), "raw_review": copy.deepcopy(review),
                        "provenance": {"method": "source_grounded_llm_and_deterministic_checks",
                                       "human_review": "not_reviewed", "independent_accuracy_validation": False,
                                       "source_coverage": copy.deepcopy(packet.get("source_coverage", {}))}}}
