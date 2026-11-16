"""Versioned runtime contracts; original design artifacts remain immutable."""
from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

DESIGN = Path(__file__).resolve().parents[1] / "results/vulntology_extraction_design_v2"
RUNTIME_CONTRACT_VERSION = "0.2.1-nullable-unbound-missed-claim"


@lru_cache(maxsize=1)
def load_effective_contracts():
    names = {"candidate_schema": "model_contract.schema.json", "review_schema": "review_contract.schema.json", "predicate_registry": "predicate_registry.json"}
    loaded = {key: json.loads((DESIGN / name).read_text(encoding="utf-8")) for key, name in names.items()}
    field = loaded["review_schema"]["properties"]["missed_claims"]["items"]["properties"]["scope_id"]
    assert field == {"type": "string"}, "Unexpected original contract; audit before patching"
    field["type"] = ["string", "null"]
    loaded["runtime_contract_version"] = RUNTIME_CONTRACT_VERSION
    loaded["patches"] = [{"contract": "review_schema", "json_pointer": "/properties/missed_claims/items/properties/scope_id/type",
                          "before": "string", "after": ["string", "null"],
                          "reason": "Preserve a missed source claim when no product scope exists; it remains unpromoted evidence, never an invented binding."}]
    loaded["original_contract_hashes"] = {name: hashlib.sha256((DESIGN / name).read_bytes()).hexdigest() for name in names.values()}
    return loaded
