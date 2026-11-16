"""Track every product-bound source chunk through explicit LLM draft extraction."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import threading
import uuid
from . import asset_vulntology as A,review_store

_executor=ThreadPoolExecutor(max_workers=1,thread_name_prefix='operational-source')
_lock=threading.Lock()
_active=set()


def packets(record,product_key,chunk_chars=3000):
    selected=next((p for p in record['products'] if p['key']==product_key),None)
    if selected is None:raise ValueError('Select a product present in the CVE source record')
    output=[];ledger=[]
    for source in record['sources']:
        if product_key not in source.get('product_keys',[]):continue
        if source.get('subject_ambiguous'):
            ledger.append(dict(source_id=source['id'],state='unknown_ambiguous_CVE_subject'))
            continue
        text=source['text']
        if hashlib.sha256(text.encode()).hexdigest()!=source['text_sha256']:raise ValueError('Source hash changed')
        for start in range(0,len(text),chunk_chars):
            end=min(len(text),start+chunk_chars);chunk=text[start:end]
            sid=source['id']+':'+str(start)
            output.append(dict(packet_id=A.digest([record['cve'],product_key,sid,chunk])[:32],
                cve=record['cve'],identity_status=record.get('source_record_status','not_rejected'),
                scopes=[dict(id=product_key,member_count=1,product_names=[selected['name']])],
                sources=[dict(id=sid,scope_id=product_key,text=chunk,text_sha256=hashlib.sha256(chunk.encode()).hexdigest(),
                    url=source['url'],original_source_id=source['id'],original_span=[start,end],
                    original_text_sha256=source['text_sha256'],subject_ambiguous=False)]))
        ledger.append(dict(source_id=source['id'],state='all_text_chunked',characters=len(text)))
    return output,ledger


def submit(cve,product_key):
    from .gpu_lease import assert_inference_available
    assert_inference_available()
    record=A.detail(cve);inputs,ledger=packets(record,product_key)
    if not inputs:raise ValueError('No unambiguous product-bound source passages; keep source status unknown')
    with _lock:
        if len(_active)>=2:raise OverflowError('Source extraction queue is full')
        identity=uuid.uuid4().hex;_active.add(identity)
    job=dict(id=identity,status='queued',cve=cve,product_key=product_key,completed=0,total=len(inputs),
        ledger=ledger,results=[],semantic_accuracy_verified=False,vex_eligible=False,native_export_ready=False)
    review_store.put('operational-source-job',identity,job,7*86400)
    def work():
        from .precision_role_runtime import get_precision_runtime
        from .llm_scenario_extraction import native_drafts
        try:
            job['status']='running'
            for packet in inputs:
                result=get_precision_runtime().extract_prerequisites(packet)
                if result.get('draft') is not None:result['partial_native_drafts']=native_drafts(packet,result['draft'])
                job['results'].append(dict(packet=packet,result=result));job['completed']+=1
                review_store.put('operational-source-job',identity,job,7*86400)
            job['status']='completed_with_drafts' if all(r['result'].get('draft') is not None for r in job['results']) else 'completed_with_unresolved_outputs'
        except Exception as exc:job.update(status='failed',error=type(exc).__name__+': '+str(exc))
        finally:
            review_store.put('operational-source-job',identity,job,7*86400)
            with _lock:_active.discard(identity)
    _executor.submit(work)
    return dict(id=identity,status='queued',total=len(inputs))
