"""Atomically refresh the corpus-vendor CPE dictionary from the official NVD 2.0 feed."""
from pathlib import Path
import sys,json,hashlib,gzip,tarfile,os
from datetime import datetime,timezone
import requests
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from fetch_cpe_dictionary import english_title,ics_vendors
from src.training_io import atomic_json
URL='https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz'
META='https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.meta'


def cpe_parts(name):
    """Keep official escaped CPE values; runtime support is a separate check."""
    if not isinstance(name,str) or not name.startswith('cpe:2.3:'):return []
    fields=[];field=[];escaped=False
    for char in name:
        if char==':' and not escaped:fields.append(''.join(field));field=[]
        else:field.append(char)
        escaped=char=='\\' and not escaped
    fields.append(''.join(field))
    return fields if len(fields)==13 else []


def main():
    cache=ROOT/'data/cpe_feed';cache.mkdir(exist_ok=True)
    state=ROOT/'results/cpe_dictionary_refresh.json'
    def status(phase,**kw):atomic_json(state,{'phase':phase,'updated_at':datetime.now(timezone.utc).isoformat(),**kw})
    try:
        status('metadata')
        r=requests.get(META,timeout=60);r.raise_for_status()
        meta=dict(line.split(':',1) for line in r.text.splitlines() if ':' in line)
        raw=cache/'nvdcpe-2.0.tar.gz';partial=cache/'nvdcpe-2.0.tar.gz.part'
        if raw.is_file() and raw.stat().st_size==int(meta['gzSize']) and not partial.exists():partial=raw
        status('downloading',source=URL,feed_last_modified=meta['lastModifiedDate'])
        total=int(meta['gzSize']);size=partial.stat().st_size if partial.is_file() else 0
        if size>total:raise ValueError('Partial feed is larger than current publication')
        # Bounded ranges survive stalled long-lived feed transfers. The complete
        # uncompressed official SHA below verifies all resumed bytes together.
        with requests.Session() as session,partial.open('ab') as handle:
            while size<total:
                end=min(size+1024*1024,total)-1
                with session.get(URL,headers={'Range':f'bytes={size}-{end}'},timeout=(30,45)) as response:
                    response.raise_for_status()
                    if response.status_code!=206 or response.headers.get('Content-Range')!=f'bytes {size}-{end}/{total}':
                        raise ValueError('Server did not honor the bounded feed range')
                    chunk=response.content
                if len(chunk)!=end-size+1:raise ValueError('Feed range length mismatch')
                handle.write(chunk);handle.flush();size+=len(chunk)
                status('downloading',downloaded_bytes=size,total_bytes=total,feed_last_modified=meta['lastModifiedDate'])
        if size!=int(meta['gzSize']):raise ValueError('Compressed feed size mismatch')
        digest=hashlib.sha256();uncompressed=0
        status('verifying',compressed_bytes=size)
        with gzip.open(partial,'rb') as handle:
            while True:
                chunk=handle.read(1024*1024)
                if not chunk:break
                digest.update(chunk);uncompressed+=len(chunk)
        checksum_representation='uncompressed_archive'
        if uncompressed!=int(meta['size']) or digest.hexdigest().lower()!=meta['sha256'].lower():
            # Chunked NVD publications can describe the concatenated JSON
            # payloads rather than tar headers/padding. Require an exact official
            # size AND digest match; never accept a locally invented checksum.
            payload_digest=hashlib.sha256();payload_size=0
            with tarfile.open(partial,'r|gz') as archive:
                for member in archive:
                    if not member.isfile() or not member.name.endswith('.json'):continue
                    handle=archive.extractfile(member)
                    while True:
                        chunk=handle.read(1024*1024)
                        if not chunk:break
                        payload_digest.update(chunk);payload_size+=len(chunk)
            if payload_size!=int(meta['size']) or payload_digest.hexdigest().lower()!=meta['sha256'].lower():
                raise ValueError('Official feed checksum/size mismatch for archive and JSON payloads')
            digest=payload_digest;checksum_representation='concatenated_json_payloads'
        if partial!=raw:os.replace(partial,raw)
        vendors=set(ics_vendors())
        if not vendors:raise ValueError('No corpus vendors found; refusing empty dictionary')
        # Bring the nightly publication forward to the current API snapshot.
        status('api_delta',feed_last_modified=meta['lastModifiedDate'])
        api='https://services.nvd.nist.gov/rest/json/cpes/2.0'
        delta_end=datetime.now(timezone.utc)
        delta_start=datetime.fromisoformat(meta['lastModifiedDate']).astimezone(timezone.utc)
        delta={};start=0
        while True:
            params={'resultsPerPage':10000,'startIndex':start,
                'lastModStartDate':delta_start.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'lastModEndDate':delta_end.strftime('%Y-%m-%dT%H:%M:%S.000')}
            response=requests.get(api,params=params,timeout=90);response.raise_for_status();page=response.json()
            items=page.get('products',[])
            for entry in items:
                cpe=entry.get('cpe',{});name=cpe.get('cpeName','')
                if name:delta[name]=entry
            start+=len(items)
            if start>=page.get('totalResults',0):break
            if not items:raise ValueError('CPE delta pagination ended before totalResults')
            __import__('time').sleep(6.2)
        dest=ROOT/'data/cpe_dictionary.jsonl';pending=ROOT/'data/cpe_dictionary.jsonl.pending'
        fetched=0;scanned=0;chunks=0;output_hash=hashlib.sha256()
        status('converting',vendor_count=len(vendors),scope='all releases of vendors named in the local ICS CVE index')
        with pending.open('wb') as out,tarfile.open(raw,'r|gz') as archive:
            for member in archive:
                if not member.isfile() or not member.name.endswith('.json'):continue
                handle=archive.extractfile(member)
                data=json.load(handle);chunks+=1
                entries=data.get('products',[])
                if chunks==1:entries=entries+list(delta.values())
                for entry in entries:
                    scanned+=1;cpe=entry.get('cpe',{});name=cpe.get('cpeName','');parts=cpe_parts(name)
                    if name in delta and entry is not delta[name]:continue
                    if len(parts)!=13 or parts[3] not in vendors or cpe.get('deprecated'):continue
                    row={'cpe':name,'part':parts[2],'vendor':parts[3],'product':parts[4],'version':parts[5],
                         'title':english_title(cpe.get('titles')) or name,'deprecated':False,
                         'cpe_name_id':cpe.get('cpeNameId'),'last_modified':cpe.get('lastModified')}
                    encoded=(json.dumps(row,ensure_ascii=False)+'\n').encode('utf-8');out.write(encoded);output_hash.update(encoded);fetched+=1
        if not fetched or not chunks:raise ValueError('Official feed yielded no dictionary records')
        provenance={'source':URL,'metadata_source':META,'feed_last_modified':meta['lastModifiedDate'],
            'official_uncompressed_sha256':digest.hexdigest(),'checksum_representation':checksum_representation,
            'dictionary_sha256':output_hash.hexdigest(),
            'delta_source':api,'delta_records':len(delta),'delta_through_utc':delta_end.isoformat(),
            'retrieved_at':datetime.now(timezone.utc).isoformat(),'scanned':scanned,'fetched':fetched,'chunks':chunks,
            'scope':'corpus_vendor_subset_of_complete_official_feed','vendors':sorted(vendors)}
        atomic_json(cache/'provenance.json',provenance)
        os.replace(pending,dest)
        atomic_json(ROOT/'data/cpe_dictionary.state',{**provenance,'complete':True,'mode':'official_bulk_feed'})
        status('complete',**provenance)
        print(json.dumps({'phase':'complete','scanned':scanned,'fetched':fetched}),flush=True)
    except Exception as e:
        status('failed',error=str(e));raise


if __name__=='__main__':main()
