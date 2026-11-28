from concurrent.futures import ThreadPoolExecutor
import pytest
from src.item3.agents.batched_provider import BatchedIdentificationProvider


def test_concurrent_packets_are_bound_to_their_own_results_and_reused_in_run():
    seen=[]
    def infer(task,packets):
        seen.extend((task,p['value']) for p in packets)
        return [dict(prediction=p['value']) for p in packets]
    provider=BatchedIdentificationProvider(infer)
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(lambda n:provider('I2',{'value':n}),range(8)))
        assert [r['prediction'] for r in results]==list(range(8))
        assert provider('I2',{'value':3})=={'prediction':3}
        assert sorted(seen)==[('I2',n) for n in range(8)]
        assert provider.statistics()['reused_source_packets']==1
    finally:provider.close()


def test_provider_failure_is_returned_and_does_not_kill_later_requests():
    def infer(task,packets):
        if any(p['fail'] for p in packets):raise ValueError('fixture failure')
        return [{'prediction':'ok'} for p in packets]
    provider=BatchedIdentificationProvider(infer)
    try:
        with pytest.raises(ValueError,match='fixture failure'):provider('I2',{'fail':True})
        assert provider('I2',{'fail':False})=={'prediction':'ok'}
    finally:provider.close()


def test_version_packets_reach_model_provider_even_when_structurally_classifiable():
    seen=[]
    def infer(task,packets):
        seen.extend(packets)
        return [dict(prediction=None,llm_used=True) for p in packets]
    provider=BatchedIdentificationProvider(infer)
    try:
        packet=dict(observations=[],evidence=[dict(id='input:name',value='fixture')])
        assert provider.require_identity_review
        assert provider('I2',packet)['llm_used']
        assert seen==[packet]
    finally:provider.close()
