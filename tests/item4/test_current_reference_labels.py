import hashlib
import json
from pathlib import Path
from unittest.mock import patch
from src.item4.evaluation.assistant_reference_scoring import score
from src.item4.models import review_adapter_config as adapters


def test_frozen_labels_have_provenance_and_no_fabricated_exploitability():
    folder=Path(__file__).resolve().parents[2]/'benchmark/item4_evaluation/current_reference_v1'
    manifest=json.loads((folder/'manifest.json').read_text(encoding='utf-8'))
    raw=(folder/'labels.jsonl').read_bytes();assert hashlib.sha256(raw).hexdigest()==manifest['labels_sha256']
    labels=[json.loads(l) for l in raw.decode().splitlines()]
    assert len(labels)==82 and sum(not r['synthetic'] for r in labels)==18
    assert all(r['independent_gold'] is False and r['actual_exploitable'] is None and r['expert_review_status']=='pending' for r in labels)
    assert manifest['independent_expert_labels']==manifest['actual_exploitability_labels']==0


def test_assistant_reference_failure_cannot_score_as_correct_empty_output():
    label=dict(id='r',cve='CVE-2099-12345',source_record_sha256='s',draft=dict(prerequisites=[],scenarios=[]),completeness='partial')
    report=score([dict(reference_id='r',source_sha256='s',v2_status='failed')],[label])
    assert report['counts']['failed']==1 and report['counts']['logic_matching']==0
    assert report['independent_semantic_accuracy'] is None


def test_base_ablation_is_explicit_and_does_not_persist_selection():
    assert adapters._BASE_EVALUATION.get() is False
    with adapters.base_model_evaluation():
        with patch.object(adapters,'configuration',side_effect=AssertionError('Base ablation should bypass the adapter')):
            assert adapters.selected('exploitation-prerequisites') is None
    assert adapters._BASE_EVALUATION.get() is False
