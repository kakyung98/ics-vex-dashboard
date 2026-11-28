"""Version routing and schema regressions, including v4 absent from the frozen corpus."""
import re

import pytest

from tools.item4 import run_blind_cvss_description as audit


@pytest.mark.parametrize(("versions","expected"), [
    (["4.0","3.0","3.1"], "3.1"),
    (["3.0","4.0"], "4.0"),
    (["2.0","3.0"], "3.0"),
    (["2.0"], None),
    ([], None),
])
def test_first_available_version(versions, expected):
    vectors = [{"vector": "CVSS:"+version+"/AV:N"} for version in versions]
    assert audit.selected_version(vectors) == expected


def test_version_controls_model_wire_and_cache(monkeypatch, tmp_path):
    calls = []
    class Backend:
        def __init__(self, *args, **kwargs):
            pass

        def _one(self, request):
            calls.append(request)
            return {"prediction":{"0":[]}}

    monkeypatch.setattr(audit, "remote", lambda _: "NVIDIA H200")
    monkeypatch.setattr(audit, "NemotronBatch", Backend)
    monkeypatch.setattr(audit, "OUT", tmp_path)
    inputs = ["The description provides no operational details. CVSS:4.0/AT:P/UI:A"]
    for version in ("3.1","4.0","3.0","4.0"):
        audit.classify(inputs,version)
    assert len(calls)==3
    for version,request in zip(("3.1","4.0","3.0"),calls):
        assert version in request["system"]
        packet=request["packet"]
        assert packet["documents"]=={"0":{"1":"The description provides no operational details."}}
        pattern=packet["schema"]["properties"]["0"]["items"]["pattern"]
        for claim in ("AT=P@1","UI=A@1","UI=P@1"):
            assert bool(re.fullmatch(pattern,claim)) == (version=="4.0")
        assert bool(re.fullmatch(pattern,"UI=R@1")) == (version!="4.0")
        assert not re.fullmatch(pattern,"Au=S@1")
    audit.classify(inputs,"3.1",evidence_policy=True)
    evidence_pattern=calls[-1]["packet"]["schema"]["properties"]["0"]["items"]["pattern"]
    assert re.fullmatch(evidence_pattern,"AC=H@1")
    assert not re.fullmatch(evidence_pattern,"AC=H@2")
