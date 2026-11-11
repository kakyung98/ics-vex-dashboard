"""Operational condition clustering and NIST-informed question compilation.

Structured feature vectors are intentionally not represented as LLM embeddings.
Source review, Boolean semantics and asset evidence remain independent gates.
"""
from collections import Counter, defaultdict
from copy import deepcopy
import math
import re

from .context_vex_pipeline import approved, leaves, validate_review
from .cluster_question_pipeline import compile_plan, digest

NIST_URL = 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r3.pdf'
DOMAINS = [
    dict(id='O1', name='Features and configuration', references=['5.2.5', '6.2.4', 'Table 16']),
    dict(id='O2', name='Network and communication access', references=['5.2.3', '6.2.9', 'Table 19']),
    dict(id='O3', name='Authentication and privileges', references=['6.2.1', 'Tables 16 and 18']),
    dict(id='O4', name='Physical and local access', references=['5.2.2', 'Table 17']),
    dict(id='O5', name='Files and removable media', references=['6.2.7', 'Table 17']),
    dict(id='O6', name='Maintenance and remote access', references=['6.2.5', '6.2.10']),
]
PREDICATES = {
    'interface_reachable': ('O2', 'Can the assessed origin reach {target} through the specified network path?'),
    'authentication_required': ('O3', 'Does the configuration of {target} require authentication?'),
    'privilege_required': ('O3', 'Do the access rules permit the role {value} to use {target}?'),
    'file_import': ('O5', 'Are externally supplied {value} files imported into {target}?'),
    'feature_enabled': ('O1', 'Is {target} enabled in the assessed operating mode?'),
    'configuration_required': ('O1', 'Does the configuration of {target} match this requirement: {value}?'),
    'network_reachable': ('O2', 'Can the assessed origin reach {target} through the specified network path?'),
    'on_path_access': ('O2', 'Can the assessed actor access the communication path for {target}?'),
    'attacker_authenticated': ('O3', 'Does the assessed actor have an authenticated session for {target}?'),
    'attacker_has_required_privilege': ('O3', 'Does the assessed actor have the required privilege ({value}) for {target}?'),
    'physical_access': ('O4', 'Can the assessed actor physically access {target}?'),
    'local_console_access': ('O4', 'Can the assessed actor access the local console of {target}?'),
    'input_processed': ('O5', 'Is {target} processed in this operating workflow?'),
    'external_file_source': ('O5', 'Can externally supplied files enter {target}?'),
    'user_performs_action': ('O5', 'Does the operator perform this action in {target}: {value}?'),
    'maintenance_access': ('O6', 'Is maintenance access to {target} available in the assessed mode?'),
    'remote_maintenance': ('O6', 'Is the remote maintenance path to {target} available?'),
    'adversary_can_write': ('unmapped', 'Can the assessed actor write to {target}?'),
    'custom': ('unmapped', 'Does the following reviewed condition hold for {target}: {value}?'),
}


def normalize(value):
    return ' '.join(str(value).casefold().split())


def condition_key(c):
    # Do not merge service aliases or privilege levels without explicit review.
    return (c['predicate'], normalize(c['target']), normalize(c.get('value', '')))


def question(c):
    domain, template = PREDICATES.get(c['predicate'].split(':',1)[0], PREDICATES['custom'])
    return dict(domain=domain, template=template, slots={'target': c['target'], 'value': c.get('value', '')},
                text=template.format(target=c['target'], value=c.get('value', '')),
                answer_type='yes_no_unknown')


def cluster_profiles(reviews, k=0, embedding_mode='structured', similarity_threshold=0.0):
    """Cluster source-supported paths, retaining signed literals and exceptions."""
    import numpy as np
    from .prerequisite_paths import attack_paths
    if not reviews or len(reviews) > 500:
        raise ValueError('Provide between 1 and 500 CVE reviews per batch')
    if isinstance(similarity_threshold,bool) or not isinstance(similarity_threshold,(int,float)) or not math.isfinite(similarity_threshold) or not 0<=similarity_threshold<=1:
        raise ValueError('Exception similarity must be between zero and one')
    profiles=[]; features=[]
    for review in sorted(reviews,key=lambda r:r['cve']):
        conditions={c['id']:c for c in review['conditions']}
        for index,literals in enumerate(attack_paths(review['formula']['expression'])):
            row=Counter(); sentences=[]
            for cid,positive in literals:
                c=conditions[cid]
                p,t,v=condition_key(c)
                sign='required' if positive else 'required_absent'
                row['predicate:'+p+':'+sign]+=2
                row['value:'+p+':'+v+':'+sign]+=2
                # A coarse embedding feature is not an assertion that two services are identical.
                categories=[name for name,pattern in (
                    ('web_management',r'\b(?:web|http|https)\b'),('file_processing',r'\b(?:file|project|import|upload)\b'),
                    ('local_console',r'\b(?:console|local|terminal)\b'),('maintenance',r'\b(?:maintenance|repair)\b'),
                    ('network_service',r'\b(?:network|protocol|tcp|udp)\b')) if re.search(pattern,t)]
                for category in categories:row['target_category:'+category]+=1
                # Specific targets are retained for questions; identity metadata is never embedded.
                sentences.append(f'predicate={p}; target_category={",".join(categories) or "unspecified"}; value={v}; polarity={sign}')
            features.append(row)
            profiles.append(dict(cve=review['cve'],path_id=review['cve']+':path:'+str(index+1),
                literals=[dict(condition_id=cid,positive=sign) for cid,sign in literals],
                normalized_text=' | '.join(sorted(sentences))))
    if len(profiles)>2000:
        raise ValueError('Batch exceeds 2,000 attack paths; split the CVE basket')
    if embedding_mode=='semantic':
        from .prerequisite_models import embed_conditions
        x,model_id=embed_conditions([p['normalized_text'] for p in profiles])
    elif embedding_mode=='structured':
        vocabulary=sorted(set().union(*(set(r) for r in features)))
        x=np.array([[r.get(f,0) for f in vocabulary] for r in features],dtype=float)
        model_id='structured predicate/value/polarity features (no language embedding model)'
    else:
        raise ValueError('Embedding mode must be structured or semantic')
    x=np.asarray(x,dtype=float)
    if x.ndim!=2 or len(x)!=len(profiles) or not np.isfinite(x).all() or np.any(np.linalg.norm(x,axis=1)==0):
        raise ValueError('Invalid embedding vectors')
    x/=np.linalg.norm(x,axis=1,keepdims=True)
    unique=len(np.unique(x,axis=0))
    if not isinstance(k,int) or isinstance(k,bool) or k<0 or k>min(len(x),unique):
        raise ValueError('K must be 0 (automatic) or at most the number of distinct path profiles')
    def run(count):
        centers=[x[0]]
        for _ in range(1,count):
            centers.append(x[np.argmin(np.max(x@np.array(centers).T,axis=1))])
        centers=np.array(centers);old=None
        for _ in range(100):
            labels=np.argmax(x@centers.T,axis=1)
            if old is not None and np.array_equal(labels,old):break
            old=labels.copy()
            for j in range(count):
                members=x[labels==j]
                if len(members):
                    center=members.mean(axis=0);norm=np.linalg.norm(center)
                    if norm:centers[j]=center/norm
        labels=np.argmax(x@centers.T,axis=1)
        realized=len(set(labels.tolist()));silhouette=None
        if 1<realized<len(x):
            from sklearn.metrics import silhouette_score
            silhouette=float(silhouette_score(x,labels,metric='cosine'))
        similarities=np.array([x[i]@centers[label] for i,label in enumerate(labels)])
        # Condition consistency and predicate-level question reuse are research diagnostics.
        reuse=[]
        for label in set(labels.tolist()):
            indexes=np.where(labels==label)[0]
            total=sum(len(profiles[i]['literals']) for i in indexes)
            predicates={f for i in indexes for f in features[i] if f.startswith('predicate:')}
            reuse.append(1-len(predicates)/max(1,total))
        return labels,centers,silhouette,float(similarities.mean()),float(np.mean(reuse))
    candidates=[k] if k else ([1] if unique<2 or len(x)<3 else list(range(2,min(10,unique,len(x)-1)+1)))
    runs=[(count,*run(count)) for count in candidates]
    best=max(runs,key=lambda r:(r[3] if r[3] is not None else -2,-r[0]))
    count,labels,centers,*_=best
    paths=[];members={r['cve']:set() for r in reviews}
    for i,(profile,label) in enumerate(zip(profiles,labels)):
        similarity=float(x[i]@centers[label]);exception=similarity<similarity_threshold
        gid=('exception:'+profile['path_id']) if exception else 'G'+str(int(label)+1)
        paths.append(dict(profile,cluster_id=gid,similarity=similarity,exception=exception))
        members[profile['cve']].add(gid)
    return dict(method='spherical_kmeans_'+embedding_mode,embedding=model_id,
        requested_k=k,selected_k=len({p['cluster_id'] for p in paths if not p['exception']}),
        candidate_scores=[dict(k=r[0],silhouette=r[3],condition_consistency=r[4],question_reuse=r[5]) for r in runs],
        selection='Explicit K' if k else 'Highest cosine silhouette; compare consistency and question reuse before accepting K',
        memberships=[dict(cve=cve,cluster_ids=sorted(groups),similarity=min(p['similarity'] for p in paths if p['cve']==cve)) for cve,groups in sorted(members.items())],
        paths=paths,exception_similarity=similarity_threshold,exception_count=sum(p['exception'] for p in paths),
        unit='attack path; signed Boolean literals preserved separately',semantic_validation_required=True)


def build_workflow(reviews, records, k=0, threshold=.8, min_support=2, embedding_mode='structured', similarity_threshold=0.0):
    if isinstance(threshold,bool) or not isinstance(threshold,(int,float)) or not math.isfinite(threshold) or not 0<threshold<=1:
        raise ValueError('Support threshold must be in (0, 1]')
    if not isinstance(min_support,int) or isinstance(min_support,bool) or min_support<2:
        raise ValueError('Minimum support must be at least two distinct CVEs')
    reviews=deepcopy(reviews)
    records_by_cve={r['cve']:r for r in records}
    if len(records_by_cve)!=len(records) or len({r['cve'] for r in reviews})!=len(reviews) or set(records_by_cve)!={r['cve'] for r in reviews}:
        raise ValueError('One source bundle and one review per CVE are required')
    for review in reviews:
        if not approved(review.get('formula',{})):raise ValueError('Review the formula before compiling')
        for c in review['conditions']:
            if not approved(c):raise ValueError('Review every included condition')
            if c.get('explicitness') not in {'explicit','reviewed_inference'}:raise ValueError('Declare explicit or reviewed_inference for every condition')
        validate_review(review,records_by_cve[review['cve']])
    clustering=cluster_profiles(reviews,k,embedding_mode,similarity_threshold)
    plan=compile_plan(reviews,records,clustering['memberships'])
    byreview={r['cve']:r for r in reviews}
    groups=defaultdict(list)
    for path in clustering['paths']:groups[path['cluster_id']].append(path)
    catalog=[]
    for gid,paths in groups.items():
        occurrences=defaultdict(set);examples={};participants=defaultdict(set)
        for path in paths:
            conditions={c['id']:c for c in byreview[path['cve']]['conditions']}
            for literal in path['literals']:
                c=conditions[literal['condition_id']];key=(*condition_key(c),literal['positive'])
                occurrences[key].add(path['path_id']);participants[key].add(path['cve']);examples[key]=c
        for key,pathids in sorted(occurrences.items()):
            support=len(pathids)/len(paths);c=examples[key];cves=participants[key]
            catalog.append(dict(id='T-'+digest([gid,key])[:12],cluster_id=gid,predicate=key[0],
                target=c['target'],value=c.get('value',''),positive=key[3],condition_kind=key[0].split(':',1)[0],
                condition_ids=[dict(cve=p['cve'],condition_id=l['condition_id']) for p in paths for l in p['literals']
                    if (*condition_key(next(c for c in byreview[p['cve']]['conditions'] if c['id']==l['condition_id'])),l['positive'])==key],
                distinct_cves=len(cves),cluster_size=len(paths),confirmed_paths=len(pathids),unknown_paths=len(paths)-len(pathids),
                operator_observable=c.get('operator_observable') is True,
                support=support,common=not gid.startswith('exception:') and len(cves)>=min_support and support>=threshold,
                applicable_cves=sorted(cves),applicable_paths=sorted(pathids),
                unconfirmed_cves=sorted({p['cve'] for p in paths}-cves),
                evidence_requirements=['Asset inventory','Configuration record or ACL','Operating procedure or vendor documentation'],
                interpretation='CVE-specific signed literal; unknown remains unknown; account roles do not establish attacker possession',
                **question(c)))
    # Reuse is allowed only for questions whose conditions qualify in the same path cluster.
    retained=[]
    for q in plan['common_questions']:
        qualifying=[];members=[]
        for gid in q['cluster_ids']:
            eligible=set()
            for m in q['members']:
                review=byreview[m['cve']]
                item=next(x for x in review['questions'] if x['id']==m['question_id'])
                if all(any(t['common'] and t['cluster_id']==gid and any(z['cve']==m['cve'] and z['condition_id']==mapping['condition_id'] for z in t['condition_ids']) for t in catalog) for mapping in item['mappings']):
                    eligible.add((m['cve'],m['question_id']))
            if len({cve for cve,_ in eligible})>=min_support:
                qualifying.append(gid);members += [m for m in q['members'] if (m['cve'],m['question_id']) in eligible]
        members=list({(m['cve'],m['question_id']):m for m in members}.values())
        for cp in plan['cves']:
            if q['id'] in cp['common_question_ids'] and not any(m['cve']==cp['cve'] for m in members):
                cp['common_question_ids'].remove(q['id'])
                for m in q['members']:
                    if m['cve']==cp['cve']:cp['specific_questions'].append(next(x for x in byreview[cp['cve']]['questions'] if x['id']==m['question_id']))
        if members:q.update(cluster_ids=qualifying,members=members);retained.append(q)
    plan['common_questions']=retained
    plan['support_policy']=dict(threshold=threshold,min_distinct_cves=min_support,denominator='attack paths in cluster',missing='unconfirmed, never false',probability=False)
    plan.pop('plan_id');plan['plan_id']=digest(plan)
    return dict(clustering=clustering,template_catalog=catalog,plan=plan,domains=DOMAINS,
        nist=dict(version='SP 800-82 Rev. 3',url=NIST_URL,classification='Research-defined question domains informed by NIST, not a NIST CVE taxonomy'),
        support_policy=plan['support_policy'])
