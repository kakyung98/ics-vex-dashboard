import json
from unittest.mock import Mock

from tools.item4.extract_source_conditions_for_question_links import (
    JsonWhitespace, finished_members, source_completion, source_schema,
)


def test_whitespace_in_quoted_evidence_is_never_a_stall():
    evidence = json.dumps({"quote": 'A "quoted" \\ path ' + " " * 500 + " end"})
    guard = JsonWhitespace()
    assert not any(guard.excessive(ch) for ch in evidence)
    assert not guard.excessive("\t" * 64)
    assert guard.excessive("\n")


def test_only_whole_schema_valid_cases_survive_truncation():
    schema = source_schema()
    packet = {"cases": {"0": {}, "1": {}}, "schema": {"properties": {"0": schema, "1": schema}}}
    first = dict(conditions=[], scenarios=[], unknowns_ko="unspecified", complete=False)
    prefix = '{"0":' + json.dumps(first) + ',"1":{"conditions":['
    assert finished_members(prefix, packet) == {"0": first}
    assert finished_members('{"0":{"conditions":[]},', packet) == {}


def test_conditional_retry_rejects_changed_string_contents():
    backend = Mock()
    backend.url = "http://localhost/v1"
    stream = Mock()
    prefix = '{"0":{"label":"A  B",'
    delta = {"choices": [{"delta": {"content": prefix + " " * 65}}]}
    stream.iter_lines.return_value = [b"data: " + json.dumps(delta).encode()]
    from unittest.mock import MagicMock
    wrapper = MagicMock()
    wrapper.__enter__.return_value = stream
    retry = Mock()
    retry.json.return_value = {"choices": [{"finish_reason": "stop",
                              "message": {"content": '{"0":{"label":"A B","active":true}}'}}]}
    backend.session.return_value.post.side_effect = [wrapper, retry]
    reply = source_completion(backend, {}, source_schema())
    assert reply["choices"][0]["finish_reason"] == "length"
    assert reply["usage"]["prefix_disagreement"]
