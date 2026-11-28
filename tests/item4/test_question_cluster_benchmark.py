from tools.item4.evaluate_question_cluster_benchmark import condition_value, decide, expression_value


def test_required_negative_and_partial_answers():
    unit = {"verified": True, "source_grounding": "supported", "original_condition": {"necessity":"required"},
            "atoms":[{"qid":"q","required":"x","verification":{"exact":True}}]}
    defs = {"q":{"key":"enabled","rows":[{"asset_type_id":"A"}]}}
    assert condition_value(unit,"A",{"A:enabled":"x"},defs)[0] is True
    assert condition_value(unit,"A",{"A:enabled":"o"},defs)[0] is False
    assert condition_value(unit,"A",{"A:enabled":"unknown"},defs)[0] is None
    assert condition_value(unit,"B",{},defs)[0] is None
    unit["atoms"][0]["verification"]["exact"] = False
    assert condition_value(unit,"A",{"A:enabled":"x"},defs)[0] is None


def test_bound_synthetic_routes_and_abstention():
    a,b={"key":"a","source_condition":"a"},{"key":"b","source_condition":"b"}
    values={"a":True, "b":None}
    assert expression_value({"op":"and","args":[a,b]},values) is None
    true_branch=expression_value({"op":"or","args":[a,b]},values)
    false_branch=expression_value({"op":"not","args":[a]},values)
    branches={("source","s1"):true_branch, ("source","s2"):false_branch}
    facts=dict(scope_confirmed=True,product_bound=True,conflicting=False,deployment="running",
               inventory_complete=True,runtime_exact=True,supplier_status="known_affected",
               condition_binding_valid=True,route_sufficient=True,paths_exhaustive=True)
    binding=dict(synthetic=True,scope_id="demo",asset_type_id="A",component_ref="c",facts=facts,
                 evidence_refs=["fixture"],alternative_scenarios=[["source","s1"]])
    assert decide(binding,branches,{"c"},"A")[:2]==("affected","R5")
    assert decide(binding,branches,{"other"},"A")[:2]==("under_investigation","R0")
    binding["alternative_scenarios"]=[["source","s2"]]
    assert decide(binding,branches,{"c"},"A")[:2]==("not_affected","R6")
    facts["paths_exhaustive"]=False
    assert decide(binding,branches,{"c"},"A")[:2]==("under_investigation","R7")
    facts["supplier_status"]="fixed"
    assert decide(binding,branches,{"c"},"A")[:2]==("fixed","R3")
