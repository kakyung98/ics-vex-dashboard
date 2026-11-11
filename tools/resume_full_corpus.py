"""Resume the existing source-model cache with safe batches and periodic snapshots."""
import gc
import os
import tempfile
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.run_sentence_conditions import Worker as SentenceWorker
from tools.discover_ics_clusters import write_jsonl
from src.training_io import read_json
from src import gpu_lease


class Worker(SentenceWorker):
    def execute_batch(self,packets,limit=1024,feedback=''):
        try:return super().execute_batch(packets,limit,feedback)
        except Exception as exc:
            if 'out of memory' not in str(exc).lower():raise
            import torch
            gc.collect();torch.cuda.empty_cache()
            if len(packets)>1:
                middle=len(packets)//2
                return self.execute_batch(packets[:middle],limit,feedback)+self.execute_batch(packets[middle:],limit,feedback)
            return [dict(packet_id=packets[0]['packet_id'],error='cuda_memory_exhausted',facts=[],source_state=None,source_reading_complete=False)]

    def store(self,packet,payload):
        super().store(packet,payload)
        self.stored=getattr(self,'stored',0)+1
        if self.stored%250==0:self.publish_snapshot()

    def publish_snapshot(self):
        records=self.aggregate()
        with tempfile.NamedTemporaryFile(dir=self.output,suffix='.jsonl.pending',delete=False,mode='w',encoding='utf-8') as out:
            temporary=Path(out.name)
            import json
            for key in sorted(records):out.write(json.dumps(records[key],ensure_ascii=False)+'\n')
        os.replace(temporary,self.output/'semantic_extractions.jsonl')
        self.save(completed_cves=sum(r['all_packets_read'] for r in records.values()),snapshot_published=True)


if __name__=='__main__':
    output=ROOT/'results/ics_sentence_conditions_v1'
    previous=read_json(output/'run_status.json')
    if gpu_lease.alive(previous.get('pid')):raise RuntimeError('An extraction worker already owns this output')
    worker=Worker(output,previous['model_path'],batch_size=2)
    try:worker.run()
    finally:
        if worker.db:
            # run() normally closes this connection; always retain the latest completed snapshot.
            try:worker.publish_snapshot()
            except Exception:pass
    if read_json(output/'run_status.json').get('phase') in {'complete','complete_with_pending'}:
        import torch
        gc.collect();torch.cuda.empty_cache()
        from tools.build_operational_corpus import cluster,STATUS
        from src import operational_corpus
        from src.training_io import atomic_json
        operational_corpus.build();cluster()
        atomic_json(STATUS,dict(phase='complete',**operational_corpus.summary()))
