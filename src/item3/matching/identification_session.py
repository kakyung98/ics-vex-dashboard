"""Memoize identical component work within one live identification run.

No predictions are loaded from disk. Component references are rebound on every
hit, and source/provider objects remain bound to this session.
"""
from copy import deepcopy
from threading import Lock


class IdentificationSession:
    def __init__(self, *, compact=False):
        self.compact=compact
        self.rows={}
        self.contexts={}
        self.hits=0
        self.misses=0
        self.lock=Lock()

    def key(self, component, index, source, provider, synthetic, mapping_scope):
        context=(id(index),id(source),id(provider),synthetic,mapping_scope)
        with self.lock:self.contexts[context]=(index,source,provider)
        fields=tuple(component.get(k) for k in
                     ('name','version','supplier','manufacturer','component_type','purl'))
        return context,fields,tuple(component.get('cpes',()))

    def get(self, key, component):
        with self.lock:
            template=self.rows.get(key)
            if template is None:
                self.misses+=1
                return None
            self.hits+=1
        row=deepcopy(template)
        row['component']=component
        row['session_reused']=True
        return row

    def store(self, key, row):
        if self.compact:
            row=deepcopy(row)
            candidates=row['i1'].get('candidates',[])
            row['i1']['checked_candidate_count']=len(candidates)
            row['i1']['candidates']=candidates[:3]
            row['i3']['candidates']=row['i1']['candidates']
            row['nonmatching_cve_count']=sum(c.get('match_status')=='no_match' for c in row['cves'])
            row['cves']=[c for c in row['cves'] if c.get('match_status')!='no_match']
            row['response_detail']='compact; all candidates checked before display projection'
        stored=deepcopy(row)
        with self.lock:self.rows[key]=stored
        return row

    def statistics(self):
        return dict(unique_component_inputs=self.misses,reused_component_inputs=self.hits,
                    cache_scope='this live run only',stored_predictions_loaded=False,
                    compact_response=self.compact)
